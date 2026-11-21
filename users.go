package main

import (
	"cmp"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

var (
	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,64}$`)
	wecomPattern    = regexp.MustCompile(`^[A-Za-z0-9_@.-]{0,64}$`)
	emailPattern    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

const passwordChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
const dummyBcryptHash = "$2a$10$wHhY5zYDsMdG2mvvEJPi7eM6FBfXwLwqEyqfL7IGRBxV6JrxEzk3q"

func cleanUsername(value string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(value) {
		if r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff' {
			continue
		}
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func cleanEmail(value string) string {
	cleaned := strings.ToLower(cleanUsername(value))
	return cleaned
}

func validPassword(password string) bool {
	if len(password) < 10 || len(password) > 72 {
		return false
	}
	var hasLetter, hasDigit bool
	for _, r := range password {
		if unicode.IsLetter(r) {
			hasLetter = true
		} else if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	return hasLetter && hasDigit
}

func generateInitialPassword() string {
	var raw [13]byte
	_, _ = rand.Read(raw[:])
	var b strings.Builder
	b.WriteString("P1!")
	for _, v := range raw {
		b.WriteByte(passwordChars[int(v)%len(passwordChars)])
	}
	return b.String()
}

func (s *idpStore) usernameTakenLocked(username string, excludeID int64) bool {
	for id, u := range s.state.Users {
		if !u.Deleted && id != excludeID && strings.EqualFold(u.Username, username) {
			return true
		}
	}
	for _, app := range s.state.Applications {
		if app.Status == "PENDING" && strings.EqualFold(app.PendingUsername, username) {
			return true
		}
	}
	return false
}

func (s *idpStore) emailTakenLocked(email string, excludeID int64) bool {
	if email == "" {
		return false
	}
	for id, u := range s.state.Users {
		if !u.Deleted && id != excludeID && u.Email != "" && strings.EqualFold(u.Email, email) {
			return true
		}
	}
	for _, app := range s.state.Applications {
		if app.Status == "PENDING" && app.PendingEmail != "" && strings.EqualFold(app.PendingEmail, email) {
			return true
		}
	}
	return false
}

func (s *idpStore) wecomTakenLocked(wecom string, excludeID int64) bool {
	if wecom == "" {
		return false
	}
	for id, u := range s.state.Users {
		if !u.Deleted && id != excludeID && u.WecomUserid != "" && strings.EqualFold(u.WecomUserid, wecom) {
			return true
		}
	}
	return false
}

func (s *idpStore) isLastEnabledAdminLocked(targetID int64) bool {
	target, ok := s.state.Users[targetID]
	if !ok || target.Deleted || !target.Admin || !target.Enabled {
		return false
	}
	count := 0
	for _, u := range s.state.Users {
		if !u.Deleted && u.Admin && u.Enabled {
			count++
		}
	}
	return count <= 1
}

func (s *idpStore) revokeUserSessionsLocked(userID int64) {
	for k, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, k)
		}
	}
	for k, tok := range s.accessTokens {
		if tok.UserID == userID {
			delete(s.accessTokens, k)
		}
	}
	for k, tok := range s.refreshTokens {
		if tok.UserID == userID {
			delete(s.refreshTokens, k)
		}
	}
	for k, g := range s.grants {
		if g.UserID == userID {
			delete(s.grants, k)
		}
	}
}

func (s *idpStore) authenticate(identifier, password string) (userAccount, error) {
	cleaned := cleanUsername(identifier)
	email := cleanEmail(identifier)
	s.mu.Lock()
	var candidates []userAccount
	for _, u := range s.state.Users {
		if u.Deleted {
			continue
		}
		if u.Username == cleaned || u.Username == strings.TrimSpace(identifier) {
			candidates = append([]userAccount{u}, candidates...)
		} else if email != "" && strings.Contains(email, "@") && strings.EqualFold(u.Email, email) {
			candidates = append(candidates, u)
		}
	}
	s.mu.Unlock()

	if len(candidates) == 0 {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
		return userAccount{}, errors.New("账号、邮箱或密码错误")
	}
	for _, candidate := range candidates {
		if bcrypt.CompareHashAndPassword([]byte(candidate.PasswordHash), []byte(password)) == nil {
			if !candidate.Enabled {
				return userAccount{}, errors.New("该账号已被停用，请联系管理员")
			}
			return candidate, nil
		}
	}
	return userAccount{}, errors.New("账号、邮箱或密码错误")
}

func (s *idpStore) createSession(w http.ResponseWriter, userID int64) string {
	token := randomToken()
	now := s.now()
	s.mu.Lock()
	for k, v := range s.sessions {
		if !now.Before(v.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
	s.sessions[token] = webSession{UserID: userID, ExpiresAt: now.Add(sessionDuration)}
	s.mu.Unlock()
	setCookie(w, sessionCookieName, token, int(sessionDuration.Seconds()))
	return token
}

func (s *idpStore) currentUser(r *http.Request) (userAccount, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || !validToken(cookie.Value) {
		return userAccount{}, false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[cookie.Value]
	if !ok || !now.Before(sess.ExpiresAt) {
		delete(s.sessions, cookie.Value)
		return userAccount{}, false
	}
	user, ok := s.state.Users[sess.UserID]
	if !ok || user.Deleted || !user.Enabled {
		delete(s.sessions, cookie.Value)
		return userAccount{}, false
	}
	return user, true
}

func (s *idpStore) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	settings := s.state.Settings
	s.mu.Unlock()
	writeOK(w, settings)
}

func (s *idpStore) handleUpdateSettings(w http.ResponseWriter, r *http.Request, _ userAccount) {
	var req struct {
		Slogan string `json:"slogan"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	slogan := strings.TrimSpace(req.Slogan)
	if slogan == "" || len([]rune(slogan)) > 120 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "标语不能为空，且不能超过 120 个字符")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Settings = siteSettings{Slogan: slogan, UpdatedAt: s.now()}
	if err := s.persistLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存标语设置")
		return
	}
	writeOK(w, s.state.Settings)
}

func (s *idpStore) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &req); err != nil || strings.TrimSpace(req.Username) == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请输入账号或邮箱以及密码")
		return
	}
	user, err := s.authenticate(req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
		return
	}
	s.createSession(w, user.ID)
	writeOK(w, map[string]any{
		"user":               user.view(),
		"mustChangePassword": user.MustChangePassword,
	})
}

func (s *idpStore) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	setCookie(w, sessionCookieName, "", -1)
	writeOK(w, nil)
}

func (s *idpStore) handleMe(w http.ResponseWriter, _ *http.Request, user userAccount) {
	s.mu.Lock()
	apps := make([]map[string]string, 0)
	for _, app := range s.state.Apps {
		if app.Enabled && s.canAccessAppLocked(user, app) {
			apps = append(apps, map[string]string{
				"id":          strconv.FormatInt(app.ID, 10),
				"name":        app.Name,
				"clientId":    app.ClientID,
				"description": app.Description,
				"homepageUrl": app.HomepageURL,
			})
		}
	}
	slogan := s.state.Settings.Slogan
	s.mu.Unlock()
	writeOK(w, map[string]any{
		"user":   user.view(),
		"apps":   apps,
		"slogan": slogan,
	})
}

func (s *idpStore) handleInitialPassword(w http.ResponseWriter, r *http.Request, user userAccount) {
	var req struct {
		InitialPassword string `json:"initialPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	if !validPassword(req.NewPassword) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "密码至少10位，且必须包含字母和数字")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.InitialPassword)) != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "初始密码错误")
		return
	}
	if req.InitialPassword == req.NewPassword {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "新密码不能与初始密码相同")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "密码更新失败")
		return
	}
	s.mu.Lock()
	current := s.state.Users[user.ID]
	current.PasswordHash = string(hash)
	current.MustChangePassword = false
	current.Version++
	current.UpdatedAt = s.now()
	s.state.Users[user.ID] = current
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存密码")
		return
	}
	s.mu.Unlock()
	writeOK(w, current.view())
}

func (s *idpStore) handleChangePassword(w http.ResponseWriter, r *http.Request, user userAccount) {
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	if !validPassword(req.NewPassword) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "密码至少10位，且必须包含字母和数字")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)) != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "当前密码错误")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "密码加密失败")
		return
	}
	s.mu.Lock()
	current := s.state.Users[user.ID]
	current.PasswordHash = string(hash)
	current.MustChangePassword = false
	current.Version++
	current.UpdatedAt = s.now()
	s.state.Users[user.ID] = current
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存新密码")
		return
	}
	s.revokeUserSessionsLocked(user.ID)
	s.mu.Unlock()
	s.createSession(w, user.ID)
	writeOK(w, nil)
}

func (s *idpStore) handleListUsers(w http.ResponseWriter, r *http.Request, _ userAccount) {
	keyword := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("keyword")))
	s.mu.Lock()
	items := make([]userView, 0, len(s.state.Users))
	for _, u := range s.state.Users {
		if u.Deleted {
			continue
		}
		if keyword != "" &&
			!strings.Contains(strings.ToLower(u.Username), keyword) &&
			!strings.Contains(strings.ToLower(u.DisplayName), keyword) &&
			!strings.Contains(strings.ToLower(u.Email), keyword) {
			continue
		}
		items = append(items, u.view())
	}
	s.mu.Unlock()
	slices.SortFunc(items, func(a, b userView) int {
		return cmp.Compare(a.ID, b.ID)
	})
	writeOK(w, items)
}

func (s *idpStore) handleCreateUser(w http.ResponseWriter, r *http.Request, _ userAccount) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
		Phone       string `json:"phone"`
		WecomUserid string `json:"wecomUserid"`
		Admin       bool   `json:"admin"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	username := cleanUsername(req.Username)
	displayName := strings.TrimSpace(req.DisplayName)
	email := cleanEmail(req.Email)
	phone := strings.TrimSpace(req.Phone)
	wecom := strings.TrimSpace(req.WecomUserid)
	if !usernamePattern.MatchString(username) || strings.HasPrefix(strings.ToLower(username), "del.") {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "登录账号须为 3-64 位字母、数字或 ._-，且不能以 del. 开头")
		return
	}
	if displayName == "" || len([]rune(displayName)) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请填写显示姓名（不超过 100 个字符）")
		return
	}
	if email != "" && (!emailPattern.MatchString(email) || len(email) > 255) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请输入有效的邮箱地址")
		return
	}
	if !wecomPattern.MatchString(wecom) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "企业微信 UserID 只能包含字母、数字和 _-@. ，且不超过 64 个字符")
		return
	}
	initialPassword := generateInitialPassword()
	hash, err := bcrypt.GenerateFromPassword([]byte(initialPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法生成初始密码")
		return
	}

	s.mu.Lock()
	if s.usernameTakenLocked(username, 0) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "登录账号已被其他用户或待审核的注册申请使用")
		return
	}
	if s.emailTakenLocked(email, 0) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "邮箱已被其他用户或待审核的注册申请使用")
		return
	}
	if s.wecomTakenLocked(wecom, 0) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "企业微信 UserID 已被其他用户使用")
		return
	}
	now := s.now()
	id := s.state.NextUserID
	s.state.NextUserID++
	created := userAccount{
		ID:                 id,
		Username:           username,
		PasswordHash:       string(hash),
		DisplayName:        displayName,
		Email:              email,
		Phone:              phone,
		WecomUserid:        wecom,
		Admin:              req.Admin,
		Enabled:            true,
		MustChangePassword: true,
		Version:            1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	s.state.Users[id] = created
	if err := s.persistLocked(); err != nil {
		delete(s.state.Users, id)
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存账号")
		return
	}
	s.mu.Unlock()
	writeOK(w, map[string]any{
		"user":            created.view(),
		"initialPassword": initialPassword,
	})
}

func (s *idpStore) handleUpdateUser(w http.ResponseWriter, r *http.Request, _ userAccount) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "用户不存在")
		return
	}
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
		Phone       string `json:"phone"`
		WecomUserid string `json:"wecomUserid"`
		Admin       bool   `json:"admin"`
		Enabled     bool   `json:"enabled"`
		Version     int    `json:"version"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" || len([]rune(displayName)) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请填写显示姓名")
		return
	}
	email := cleanEmail(req.Email)
	if email != "" && (!emailPattern.MatchString(email) || len(email) > 255) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请输入有效的邮箱地址")
		return
	}
	wecom := strings.TrimSpace(req.WecomUserid)
	if !wecomPattern.MatchString(wecom) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "企业微信 UserID 格式不合法")
		return
	}

	s.mu.Lock()
	existing, ok := s.state.Users[id]
	if !ok || existing.Deleted {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "用户不存在")
		return
	}
	if req.Version > 0 && existing.Version != req.Version {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "RESOURCE_STATE_CONFLICT", "用户已被其他操作修改，请刷新后重试")
		return
	}
	if s.isLastEnabledAdminLocked(id) && (!req.Admin || !req.Enabled) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "RESOURCE_STATE_CONFLICT", "不能停用或移除唯一可用管理员的权限")
		return
	}
	username := existing.Username
	if strings.TrimSpace(req.Username) != "" {
		username = cleanUsername(req.Username)
	}
	if !usernamePattern.MatchString(username) || strings.HasPrefix(strings.ToLower(username), "del.") {
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "登录账号须为 3-64 位字母、数字或 ._-，且不能以 del. 开头")
		return
	}
	if s.usernameTakenLocked(username, id) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "登录账号已被其他用户或待审核的注册申请使用")
		return
	}
	if s.emailTakenLocked(email, id) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "邮箱已被其他用户或待审核的注册申请使用")
		return
	}
	if s.wecomTakenLocked(wecom, id) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "企业微信 UserID 已被其他用户使用")
		return
	}
	existing.Username = username
	existing.DisplayName = displayName
	existing.Email = email
	existing.Phone = strings.TrimSpace(req.Phone)
	existing.WecomUserid = wecom
	existing.Admin = req.Admin
	existing.Enabled = req.Enabled
	existing.Version++
	existing.UpdatedAt = s.now()
	s.state.Users[id] = existing
	if !existing.Enabled {
		s.revokeUserSessionsLocked(id)
	}
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存账号更改")
		return
	}
	s.mu.Unlock()
	writeOK(w, existing.view())
}

func (s *idpStore) handleToggleUser(enabled bool) func(http.ResponseWriter, *http.Request, userAccount) {
	return func(w http.ResponseWriter, r *http.Request, _ userAccount) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "用户不存在")
			return
		}
		s.mu.Lock()
		existing, ok := s.state.Users[id]
		if !ok || existing.Deleted {
			s.mu.Unlock()
			writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "用户不存在")
			return
		}
		if !enabled && s.isLastEnabledAdminLocked(id) {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "RESOURCE_STATE_CONFLICT", "不能停用唯一可用的管理员")
			return
		}
		existing.Enabled = enabled
		existing.Version++
		existing.UpdatedAt = s.now()
		s.state.Users[id] = existing
		if !enabled {
			s.revokeUserSessionsLocked(id)
		}
		if err := s.persistLocked(); err != nil {
			s.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存状态")
			return
		}
		s.mu.Unlock()
		writeOK(w, existing.view())
	}
}

func (s *idpStore) handleResetPassword(w http.ResponseWriter, r *http.Request, _ userAccount) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "用户不存在")
		return
	}
	initialPassword := generateInitialPassword()
	hash, err := bcrypt.GenerateFromPassword([]byte(initialPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法生成新密码")
		return
	}
	s.mu.Lock()
	existing, ok := s.state.Users[id]
	if !ok || existing.Deleted {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "用户不存在")
		return
	}
	existing.PasswordHash = string(hash)
	existing.MustChangePassword = true
	existing.Version++
	existing.UpdatedAt = s.now()
	s.state.Users[id] = existing
	s.revokeUserSessionsLocked(id)
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法重置密码")
		return
	}
	s.mu.Unlock()
	writeOK(w, map[string]string{"initialPassword": initialPassword})
}

func (s *idpStore) handleDeleteUser(w http.ResponseWriter, r *http.Request, current userAccount) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "用户不存在")
		return
	}
	if id == current.ID {
		writeError(w, http.StatusConflict, "RESOURCE_STATE_CONFLICT", "不能删除当前登录的账号")
		return
	}
	s.mu.Lock()
	existing, ok := s.state.Users[id]
	if !ok || existing.Deleted {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "用户不存在")
		return
	}
	if s.isLastEnabledAdminLocked(id) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "RESOURCE_STATE_CONFLICT", "不能删除唯一可用的管理员")
		return
	}
	freed := "del." + strconv.FormatInt(id, 10) + "." + existing.Username
	if len(freed) > 64 {
		freed = freed[:64]
	}
	existing.Username = freed
	existing.Email = ""
	existing.WecomUserid = ""
	existing.Enabled = false
	existing.Deleted = true
	existing.Version++
	existing.UpdatedAt = s.now()
	s.state.Users[id] = existing
	s.revokeUserSessionsLocked(id)
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法删除账号")
		return
	}
	s.mu.Unlock()
	writeOK(w, nil)
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	defer body.Close()
	return json.NewDecoder(body).Decode(dst)
}
