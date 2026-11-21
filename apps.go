package main

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,64}$`)

func generateClientID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "app_" + hex.EncodeToString(b[:])
}

func (s *idpStore) canAccessAppLocked(user userAccount, app registeredApp) bool {
	if user.Deleted || !user.Enabled || !app.Enabled {
		return false
	}
	if user.Admin || app.AccessPolicy == "ALL_AUTHENTICATED" {
		return true
	}
	return slices.Contains(app.AllowedUserIDs, user.ID)
}

func normalizeRedirectURIs(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("请至少填写一个回调 URL")
	}
	normalized := make([]string, 0, len(raw))
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		uri, err := validateRedirectURI(item)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(normalized, uri) {
			normalized = append(normalized, uri)
		}
	}
	if len(normalized) == 0 {
		return nil, errors.New("请至少填写一个有效的回调 URL")
	}
	return normalized, nil
}

func (s *idpStore) parseAllowedUsersLocked(raw []string) ([]int64, error) {
	ids := make([]int64, 0, len(raw))
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		id, err := strconv.ParseInt(strings.TrimSpace(item), 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.New("授权名单中包含无效的用户 ID")
		}
		u, ok := s.state.Users[id]
		if !ok || u.Deleted {
			return nil, errors.New("授权名单中的用户不存在")
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (s *idpStore) revokeAppTokensLocked(clientID string, onlyDisallowed *registeredApp) {
	for k, g := range s.grants {
		if g.ClientID == clientID {
			if onlyDisallowed == nil || !s.canAccessAppLocked(s.state.Users[g.UserID], *onlyDisallowed) {
				delete(s.grants, k)
			}
		}
	}
	for k, tok := range s.accessTokens {
		if tok.ClientID == clientID {
			if onlyDisallowed == nil || !s.canAccessAppLocked(s.state.Users[tok.UserID], *onlyDisallowed) {
				delete(s.accessTokens, k)
			}
		}
	}
	for k, tok := range s.refreshTokens {
		if tok.ClientID == clientID {
			if onlyDisallowed == nil || !s.canAccessAppLocked(s.state.Users[tok.UserID], *onlyDisallowed) {
				delete(s.refreshTokens, k)
			}
		}
	}
}

func (s *idpStore) handleListApps(w http.ResponseWriter, _ *http.Request, _ userAccount) {
	s.mu.Lock()
	items := make([]appView, 0, len(s.state.Apps))
	for _, app := range s.state.Apps {
		items = append(items, app.view())
	}
	s.mu.Unlock()
	slices.SortFunc(items, func(a, b appView) int {
		return cmp.Compare(a.ID, b.ID)
	})
	writeOK(w, items)
}

func (s *idpStore) handleCreateApp(w http.ResponseWriter, r *http.Request, _ userAccount) {
	var req struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		ClientID       string   `json:"clientId"`
		RedirectURIs   []string `json:"redirectUris"`
		HomepageURL    string   `json:"homepageUrl"`
		WebhookURL     string   `json:"webhookUrl"`
		AccessPolicy   string   `json:"accessPolicy"`
		AllowedUserIDs []string `json:"allowedUserIds"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len([]rune(name)) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请填写应用名称（不超过 100 个字符）")
		return
	}
	redirects, err := normalizeRedirectURIs(req.RedirectURIs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	policy := strings.ToUpper(strings.TrimSpace(req.AccessPolicy))
	if policy == "" {
		policy = "ALL_AUTHENTICATED"
	}
	if policy != "ALL_AUTHENTICATED" && policy != "RESTRICTED" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "访问控制策略必须是 ALL_AUTHENTICATED 或 RESTRICTED")
		return
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		clientID = generateClientID()
	} else if !clientIDPattern.MatchString(clientID) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "应用 Client ID 须为 3-64 位字母、数字或 ._-")
		return
	}
	homepage := strings.TrimSpace(req.HomepageURL)
	if homepage != "" {
		if _, err := validateRedirectURI(homepage); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "应用主页 URL 无效")
			return
		}
	}
	webhook := strings.TrimSpace(req.WebhookURL)
	if webhook != "" {
		if _, err := validateRedirectURI(webhook); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Webhook URL 无效")
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.state.Apps {
		if strings.EqualFold(existing.ClientID, clientID) {
			writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "该 Client ID 已被其他应用使用")
			return
		}
	}
	allowedUsers, err := s.parseAllowedUsersLocked(req.AllowedUserIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	secret := randomToken()
	now := s.now()
	id := s.state.NextAppID
	s.state.NextAppID++
	app := registeredApp{
		ID:             id,
		Name:           name,
		Description:    strings.TrimSpace(req.Description),
		ClientID:       clientID,
		SecretHash:     sha256Hex(secret),
		RedirectURIs:   redirects,
		HomepageURL:    homepage,
		WebhookURL:     webhook,
		AccessPolicy:   policy,
		AllowedUserIDs: allowedUsers,
		Enabled:        true,
		Version:        1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.state.Apps[id] = app
	if err := s.persistLocked(); err != nil {
		delete(s.state.Apps, id)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存应用注册信息")
		return
	}
	writeOK(w, map[string]any{
		"app":          app.view(),
		"clientSecret": secret,
	})
}

func (s *idpStore) handleUpdateApp(w http.ResponseWriter, r *http.Request, _ userAccount) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "应用不存在")
		return
	}
	var req struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		RedirectURIs   []string `json:"redirectUris"`
		HomepageURL    string   `json:"homepageUrl"`
		WebhookURL     string   `json:"webhookUrl"`
		AccessPolicy   string   `json:"accessPolicy"`
		AllowedUserIDs []string `json:"allowedUserIds"`
		Enabled        bool     `json:"enabled"`
		Version        int      `json:"version"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len([]rune(name)) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请填写应用名称")
		return
	}
	redirects, err := normalizeRedirectURIs(req.RedirectURIs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	policy := strings.ToUpper(strings.TrimSpace(req.AccessPolicy))
	if policy != "ALL_AUTHENTICATED" && policy != "RESTRICTED" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "访问控制策略必须是 ALL_AUTHENTICATED 或 RESTRICTED")
		return
	}
	homepage := strings.TrimSpace(req.HomepageURL)
	if homepage != "" {
		if _, err := validateRedirectURI(homepage); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "应用主页 URL 无效")
			return
		}
	}
	webhook := strings.TrimSpace(req.WebhookURL)
	if webhook != "" {
		if _, err := validateRedirectURI(webhook); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Webhook URL 无效")
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.state.Apps[id]
	if !ok {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "应用不存在")
		return
	}
	if req.Version > 0 && app.Version != req.Version {
		writeError(w, http.StatusConflict, "RESOURCE_STATE_CONFLICT", "应用已被其他操作修改，请刷新后重试")
		return
	}
	allowedUsers, err := s.parseAllowedUsersLocked(req.AllowedUserIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	app.Name = name
	app.Description = strings.TrimSpace(req.Description)
	app.RedirectURIs = redirects
	app.HomepageURL = homepage
	app.WebhookURL = webhook
	app.AccessPolicy = policy
	app.AllowedUserIDs = allowedUsers
	app.Enabled = req.Enabled
	app.Version++
	app.UpdatedAt = s.now()
	s.state.Apps[id] = app
	s.revokeAppTokensLocked(app.ClientID, &app)
	if err := s.persistLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存应用修改")
		return
	}
	writeOK(w, app.view())
}

func (s *idpStore) handleRotateAppSecret(w http.ResponseWriter, r *http.Request, _ userAccount) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "应用不存在")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.state.Apps[id]
	if !ok {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "应用不存在")
		return
	}
	secret := randomToken()
	app.SecretHash = sha256Hex(secret)
	app.Version++
	app.UpdatedAt = s.now()
	s.state.Apps[id] = app
	if err := s.persistLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法重置应用密钥")
		return
	}
	writeOK(w, map[string]any{
		"app":          app.view(),
		"clientSecret": secret,
	})
}

func (s *idpStore) handleDeleteApp(w http.ResponseWriter, r *http.Request, _ userAccount) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "应用不存在")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.state.Apps[id]
	if !ok {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "应用不存在")
		return
	}
	s.revokeAppTokensLocked(app.ClientID, nil)
	delete(s.state.Apps, id)
	if err := s.persistLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法删除应用")
		return
	}
	writeOK(w, nil)
}
