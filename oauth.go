package main

import (
	"cmp"
	"crypto/subtle"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

func (s *idpStore) findAppByClientIDLocked(clientID string) (registeredApp, bool) {
	for _, app := range s.state.Apps {
		if app.ClientID == clientID {
			return app, true
		}
	}
	return registeredApp{}, false
}

func matchesRedirectURI(app registeredApp, redirectURI string) (string, bool) {
	normalized, err := validateRedirectURI(redirectURI)
	if err != nil {
		return "", false
	}
	for _, allowed := range app.RedirectURIs {
		if allowed == normalized {
			return normalized, true
		}
	}
	return "", false
}

func (s *idpStore) handleOpenIDConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.origin,
		"authorization_endpoint":                s.origin + "/oauth/authorize",
		"token_endpoint":                        s.origin + "/api/v1/oauth/token",
		"userinfo_endpoint":                     s.origin + "/api/v1/oauth/userinfo",
		"revocation_endpoint":                   s.origin + "/api/v1/oauth/token/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	})
}

func (s *idpStore) handleBrowserAuthorizeRedirect(w http.ResponseWriter, r *http.Request) {
	target := "/#authorize"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *idpStore) handleInspectAuthorize(w http.ResponseWriter, r *http.Request, user userAccount) {
	q := r.URL.Query()
	clientID := strings.TrimSpace(q.Get("client_id"))
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
	state := strings.TrimSpace(q.Get("state"))
	challenge := strings.TrimSpace(q.Get("code_challenge"))
	if challenge == "" {
		challenge = strings.TrimSpace(q.Get("challenge"))
	}
	if !validToken(state) || !validToken(challenge) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "单点登录参数（state 或 challenge）无效，请从原应用重新发起登录")
		return
	}
	s.mu.Lock()
	app, ok := s.findAppByClientIDLocked(clientID)
	if !ok || !app.Enabled {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "未找到已启用的注册应用")
		return
	}
	matchedRedirect, redirectOK := matchesRedirectURI(app, redirectURI)
	if !redirectOK {
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "回调 URL 未在该应用中注册")
		return
	}
	allowed := s.canAccessAppLocked(user, app)
	s.mu.Unlock()
	writeOK(w, map[string]any{
		"app": map[string]string{
			"id":          app.view().ID,
			"name":        app.Name,
			"description": app.Description,
			"clientId":    app.ClientID,
			"redirectUri": matchedRedirect,
		},
		"user":    user.view(),
		"allowed": allowed,
	})
}

func (s *idpStore) handleApproveAuthorize(w http.ResponseWriter, r *http.Request, user userAccount) {
	if user.MustChangePassword {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "首次登录请先修改初始密码")
		return
	}
	var req struct {
		ClientID      string `json:"clientId"`
		RedirectURI   string `json:"redirectUri"`
		State         string `json:"state"`
		CodeChallenge string `json:"codeChallenge"`
		Challenge     string `json:"challenge"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	challenge := strings.TrimSpace(req.CodeChallenge)
	if challenge == "" {
		challenge = strings.TrimSpace(req.Challenge)
	}
	state := strings.TrimSpace(req.State)
	if !validToken(state) || !validToken(challenge) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "无效的单点登录请求参数")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.findAppByClientIDLocked(strings.TrimSpace(req.ClientID))
	if !ok || !app.Enabled {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "应用未注册或已停用")
		return
	}
	matchedRedirect, redirectOK := matchesRedirectURI(app, req.RedirectURI)
	if !redirectOK {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "回调 URL 与应用注册的地址不匹配")
		return
	}
	if !s.canAccessAppLocked(user, app) {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "当前账号未获授权访问「"+app.Name+"」")
		return
	}
	now := s.now()
	for k, g := range s.grants {
		if !now.Before(g.ExpiresAt) {
			delete(s.grants, k)
		}
	}
	if len(s.grants) >= 512 {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "待兑换授权较多，请稍后重试")
		return
	}
	code := randomToken()
	s.grants[code] = authGrant{
		Code:          code,
		ClientID:      app.ClientID,
		RedirectURI:   matchedRedirect,
		CodeChallenge: challenge,
		UserID:        user.ID,
		ExpiresAt:     now.Add(authCodeDuration),
	}
	callbackURL, err := url.Parse(matchedRedirect)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "回调 URL 解析失败")
		return
	}
	query := callbackURL.Query()
	query.Set("code", code)
	query.Set("state", state)
	callbackURL.RawQuery = query.Encode()
	writeOK(w, map[string]string{
		"callbackUrl": callbackURL.String(),
	})
}

func extractClientCredentials(r *http.Request, bodyClientID, bodySecret string) (string, string) {
	clientID := strings.TrimSpace(bodyClientID)
	secret := strings.Trim(strings.TrimSpace(bodySecret), `'"`)
	if clientID == "" {
		clientID = strings.TrimSpace(r.Header.Get("X-Idp-Client-Id"))
	}
	if secret == "" {
		secret = strings.Trim(strings.TrimSpace(r.Header.Get("X-Idp-Client-Secret")), `'"`)
	}
	if secret == "" {
		secret = strings.Trim(strings.TrimSpace(r.Header.Get("X-Deplyt-Client-Secret")), `'"`)
	}
	if u, p, ok := r.BasicAuth(); ok {
		if clientID == "" {
			clientID = strings.TrimSpace(u)
		}
		if secret == "" {
			secret = strings.Trim(strings.TrimSpace(p), `'"`)
		}
	}
	return clientID, secret
}

func (s *idpStore) verifyClientLocked(clientID, secret string) (registeredApp, bool) {
	if secret == "" {
		return registeredApp{}, false
	}
	secretHash := sha256Hex(secret)
	if clientID != "" {
		app, ok := s.findAppByClientIDLocked(clientID)
		if !ok || !app.Enabled {
			return registeredApp{}, false
		}
		if subtle.ConstantTimeCompare([]byte(app.SecretHash), []byte(secretHash)) != 1 {
			return registeredApp{}, false
		}
		return app, true
	}
	for _, app := range s.state.Apps {
		if app.Enabled && subtle.ConstantTimeCompare([]byte(app.SecretHash), []byte(secretHash)) == 1 {
			return app, true
		}
	}
	return registeredApp{}, false
}

func (s *idpStore) issueAppTokensLocked(clientID string, userID int64) (string, string, int64) {
	now := s.now()
	for k, tok := range s.accessTokens {
		if !now.Before(tok.ExpiresAt) {
			delete(s.accessTokens, k)
		}
	}
	for k, tok := range s.refreshTokens {
		if !now.Before(tok.ExpiresAt) {
			delete(s.refreshTokens, k)
		}
	}
	access := randomToken()
	refresh := randomToken()
	s.accessTokens[access] = issuedToken{
		Token:     access,
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: now.Add(accessTokenDuration),
	}
	s.refreshTokens[refresh] = issuedToken{
		Token:     refresh,
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: now.Add(refreshDuration),
		Refresh:   true,
	}
	return access, refresh, int64(accessTokenDuration.Seconds())
}

func (s *idpStore) handleExchangeToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"clientId"`
		ClientID2    string `json:"client_id"`
		ClientSecret string `json:"clientSecret"`
		ClientSec2   string `json:"client_secret"`
		Code         string `json:"code"`
		Verifier     string `json:"verifier"`
		CodeVerifier string `json:"code_verifier"`
		RedirectURI  string `json:"redirectUri"`
		RedirectURI2 string `json:"redirect_uri"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	bodyClientID := req.ClientID
	if bodyClientID == "" {
		bodyClientID = req.ClientID2
	}
	bodySecret := req.ClientSecret
	if bodySecret == "" {
		bodySecret = req.ClientSec2
	}
	clientID, secret := extractClientCredentials(r, bodyClientID, bodySecret)
	verifier := req.CodeVerifier
	if verifier == "" {
		verifier = req.Verifier
	}
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = req.RedirectURI2
	}
	code := strings.TrimSpace(req.Code)
	if !validToken(code) || !validToken(verifier) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "无效或已过期的授权码")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.verifyClientLocked(clientID, secret)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "应用客户端凭证无效")
		return
	}
	grant, exists := s.grants[code]
	delete(s.grants, code)
	if !exists || !s.now().Before(grant.ExpiresAt) || grant.ClientID != app.ClientID {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "无效或已过期的授权码")
		return
	}
	if redirectURI != "" {
		normalizedRedirect, err := validateRedirectURI(redirectURI)
		if err != nil || normalizedRedirect != grant.RedirectURI {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "回调地址与授权请求不一致")
			return
		}
	}
	if subtle.ConstantTimeCompare([]byte(grant.CodeChallenge), []byte(pkceChallenge(verifier))) != 1 {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "PKCE 校验未通过")
		return
	}
	user, userOK := s.state.Users[grant.UserID]
	if !userOK || !s.canAccessAppLocked(user, app) || user.MustChangePassword {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "该账号无权访问此应用")
		return
	}
	access, refresh, expiresIn := s.issueAppTokensLocked(app.ClientID, user.ID)
	view := user.view()
	writeOK(w, map[string]any{
		"id":           view.ID,
		"username":     view.Username,
		"displayName":  view.DisplayName,
		"email":        view.Email,
		"phone":        view.Phone,
		"wecomUserid":  view.WecomUserid,
		"admin":        view.Admin,
		"enabled":      view.Enabled,
		"accessToken":  access,
		"refreshToken": refresh,
		"tokenType":    "Bearer",
		"expiresIn":    expiresIn,
		"user":         view,
	})
}

func (s *idpStore) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		RefreshToken string `json:"refreshToken"`
	}
	if err := readJSON(w, r, &req); err != nil || !validToken(req.RefreshToken) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "刷新令牌无效")
		return
	}
	clientID, secret := extractClientCredentials(r, req.ClientID, req.ClientSecret)
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, exists := s.refreshTokens[req.RefreshToken]
	delete(s.refreshTokens, req.RefreshToken)
	if !exists || !tok.Refresh || !s.now().Before(tok.ExpiresAt) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "刷新令牌已过期或失效")
		return
	}
	if clientID != "" || secret != "" {
		app, ok := s.verifyClientLocked(clientID, secret)
		if !ok || app.ClientID != tok.ClientID {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "应用凭证不匹配")
			return
		}
	}
	app, appOK := s.findAppByClientIDLocked(tok.ClientID)
	user, userOK := s.state.Users[tok.UserID]
	if !appOK || !userOK || !s.canAccessAppLocked(user, app) || user.MustChangePassword {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "账号已被停用或应用访问权已撤销")
		return
	}
	access, refresh, expiresIn := s.issueAppTokensLocked(app.ClientID, user.ID)
	view := user.view()
	writeOK(w, map[string]any{
		"status":       "APPROVED",
		"accessToken":  access,
		"refreshToken": refresh,
		"tokenType":    "Bearer",
		"expiresIn":    expiresIn,
		"user":         view,
	})
}

func (s *idpStore) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refreshToken"`
		Token        string `json:"token"`
	}
	_ = readJSON(w, r, &req)
	token := strings.TrimSpace(req.RefreshToken)
	if token == "" {
		token = strings.TrimSpace(req.Token)
	}
	if token != "" {
		s.mu.Lock()
		delete(s.refreshTokens, token)
		delete(s.accessTokens, token)
		s.mu.Unlock()
	}
	writeOK(w, nil)
}

func (s *idpStore) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	bearer = strings.TrimSpace(bearer)
	if !ok || !validToken(bearer) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "访问令牌无效")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, exists := s.accessTokens[bearer]
	if !exists || !s.now().Before(tok.ExpiresAt) {
		delete(s.accessTokens, bearer)
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "访问令牌已过期")
		return
	}
	app, appOK := s.findAppByClientIDLocked(tok.ClientID)
	user, userOK := s.state.Users[tok.UserID]
	if !appOK || !userOK || !s.canAccessAppLocked(user, app) || user.MustChangePassword {
		delete(s.accessTokens, bearer)
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "账号无权访问此应用")
		return
	}
	writeOK(w, user.view())
}

func (s *idpStore) handleAppUsersSync(w http.ResponseWriter, r *http.Request) {
	clientID, secret := extractClientCredentials(r, r.URL.Query().Get("clientId"), "")
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.verifyClientLocked(clientID, secret)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "应用客户端凭证无效")
		return
	}
	users := make([]userView, 0, len(s.state.Users))
	for _, u := range s.state.Users {
		if u.Deleted {
			continue
		}
		v := u.view()
		v.Enabled = s.canAccessAppLocked(u, app)
		users = append(users, v)
	}
	slices.SortFunc(users, func(a, b userView) int {
		return cmp.Compare(a.ID, b.ID)
	})
	writeOK(w, users)
}
