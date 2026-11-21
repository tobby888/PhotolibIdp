package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*idpStore, http.Handler) {
	t.Helper()
	cfg, err := parseConfig(map[string]string{
		"IDP_PUBLIC_URL":         "https://auth.example.test",
		"IDP_STATE_DIR":          t.TempDir(),
		"IDP_ADMIN_USERNAME":     "admin",
		"IDP_ADMIN_DISPLAY_NAME": "系统管理员",
		"IDP_ADMIN_PASSWORD":     "AdminPass123",
		"IDP_ADMIN_EMAIL":        "admin@example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newServerHandler(store)
	if err != nil {
		t.Fatal(err)
	}
	return store, handler
}

func requestJSON(t *testing.T, handler http.Handler, method, path string, body any, cookie *http.Cookie, headers map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if method != http.MethodGet {
		req.Header.Set("Origin", "https://auth.example.test")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var payload map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	return rec, payload
}

func TestAdminLoginSloganAndAccountLifecycle(t *testing.T) {
	_, handler := newTestServer(t)

	rec, body := requestJSON(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": "AdminPass123",
	}, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin login failed: %d %s", rec.Code, rec.Body.String())
	}
	adminCookie := rec.Result().Cookies()[0]

	// Update slogan (IdP has no icon, only admin-configurable slogan)
	rec, body = requestJSON(t, handler, http.MethodPut, "/api/v1/settings", map[string]string{
		"slogan": "校园摄影部统一身份认证与门禁中心",
	}, adminCookie, nil)
	if rec.Code != http.StatusOK || body["data"].(map[string]any)["slogan"] != "校园摄影部统一身份认证与门禁中心" {
		t.Fatalf("update slogan failed: %d %s", rec.Code, rec.Body.String())
	}

	// Create a regular user account
	rec, body = requestJSON(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username":    "photographer1",
		"displayName": "张摄影",
		"email":       "photo1@example.test",
		"wecomUserid": "ZhangPhoto",
		"admin":       false,
	}, adminCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create user failed: %d %s", rec.Code, rec.Body.String())
	}
	data := body["data"].(map[string]any)
	initialPassword := data["initialPassword"].(string)
	createdUser := data["user"].(map[string]any)
	userID := createdUser["id"].(string)

	// New user logs in and must change initial password first
	rec, _ = requestJSON(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "photo1@example.test",
		"password": initialPassword,
	}, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("email login failed: %d %s", rec.Code, rec.Body.String())
	}
	memberCookie := rec.Result().Cookies()[0]

	rec, _ = requestJSON(t, handler, http.MethodPut, "/api/v1/auth/initial-password", map[string]string{
		"initialPassword": initialPassword,
		"newPassword":     "NewSecure123",
	}, memberCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("change initial password failed: %d %s", rec.Code, rec.Body.String())
	}

	// Admin disables and deletes user, releasing username and email
	rec, _ = requestJSON(t, handler, http.MethodPost, "/api/v1/users/"+userID+"/disable", nil, adminCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable user failed: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = requestJSON(t, handler, http.MethodGet, "/api/v1/auth/me", nil, memberCookie, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled user session should be revoked, got %d", rec.Code)
	}
	rec, _ = requestJSON(t, handler, http.MethodDelete, "/api/v1/users/"+userID, nil, adminCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete user failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRegistrationCodeApplicationAndAppAccessOAuthFlow(t *testing.T) {
	_, handler := newTestServer(t)

	rec, _ := requestJSON(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": "AdminPass123",
	}, nil, nil)
	adminCookie := rec.Result().Cookies()[0]

	// 1. Register two applications: PhotoLib (ALL_AUTHENTICATED) and Deplyt (RESTRICTED)
	rec, photoAppBody := requestJSON(t, handler, http.MethodPost, "/api/v1/apps", map[string]any{
		"name":         "PhotoLib",
		"clientId":     "photolib",
		"redirectUris": []string{"https://photolib.example.test/auth/callback"},
		"accessPolicy": "ALL_AUTHENTICATED",
	}, adminCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create photolib app failed: %d %s", rec.Code, rec.Body.String())
	}
	photoSecret := photoAppBody["data"].(map[string]any)["clientSecret"].(string)

	rec, deplytAppBody := requestJSON(t, handler, http.MethodPost, "/api/v1/apps", map[string]any{
		"name":         "Deplyt",
		"clientId":     "deplyt",
		"redirectUris": []string{"https://deploy.example.test/auth/callback"},
		"accessPolicy": "RESTRICTED",
	}, adminCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create deplyt app failed: %d %s", rec.Code, rec.Body.String())
	}
	deplytData := deplytAppBody["data"].(map[string]any)
	deplytApp := deplytData["app"].(map[string]any)
	deplytAppID := deplytApp["id"].(string)
	deplytSecret := deplytData["clientSecret"].(string)

	// 2. Create a registration code
	rec, codeBody := requestJSON(t, handler, http.MethodPost, "/api/v1/registration-codes", map[string]any{
		"name":       "秋季招新码",
		"maxUses":    2,
		"validUntil": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	}, adminCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create registration code failed: %d %s", rec.Code, rec.Body.String())
	}
	regCode := codeBody["data"].(map[string]any)["code"].(string)

	// 3. Student submits registration application with formatted code
	rec, subBody := requestJSON(t, handler, http.MethodPost, "/api/v1/public/registrations", map[string]string{
		"code":            regCode[:4] + "-" + regCode[4:],
		"username":        "newmember",
		"displayName":     "李新同",
		"email":           "newmember@example.test",
		"password":        "MemberPass123",
		"confirmPassword": "MemberPass123",
	}, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("submit registration failed: %d %s", rec.Code, rec.Body.String())
	}
	appID := subBody["data"].(map[string]any)["id"].(string)

	// Before approval, login must fail
	rec, _ = requestJSON(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "newmember",
		"password": "MemberPass123",
	}, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unapproved applicant should not log in, got %d", rec.Code)
	}

	// 4. Admin approves registration application
	rec, approveBody := requestJSON(t, handler, http.MethodPost, "/api/v1/registration-applications/approve", map[string]any{
		"ids": []string{appID},
	}, adminCookie, nil)
	if rec.Code != http.StatusOK || len(approveBody["data"].(map[string]any)["succeeded"].([]any)) != 1 {
		t.Fatalf("approve application failed: %d %s", rec.Code, rec.Body.String())
	}

	// 5. Approved member logs in
	rec, loginBody := requestJSON(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "newmember",
		"password": "MemberPass123",
	}, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approved member login failed: %d %s", rec.Code, rec.Body.String())
	}
	memberCookie := rec.Result().Cookies()[0]
	memberID := loginBody["data"].(map[string]any)["user"].(map[string]any)["id"].(string)

	// 6. Member can authorize PhotoLib (ALL_AUTHENTICATED) via OAuth2 PKCE
	state := randomToken()
	verifier := randomToken()
	challenge := pkceChallenge(verifier)
	rec, authBody := requestJSON(t, handler, http.MethodPost, "/api/v1/oauth/authorize", map[string]string{
		"clientId":      "photolib",
		"redirectUri":   "https://photolib.example.test/auth/callback",
		"state":         state,
		"codeChallenge": challenge,
	}, memberCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize photolib failed: %d %s", rec.Code, rec.Body.String())
	}
	callbackURL, err := url.Parse(authBody["data"].(map[string]any)["callbackUrl"].(string))
	if err != nil || callbackURL.Query().Get("state") != state {
		t.Fatalf("unexpected callback URL: %v", authBody)
	}
	code := callbackURL.Query().Get("code")

	// Exchange code for token
	rec, tokenBody := requestJSON(t, handler, http.MethodPost, "/api/v1/oauth/token", map[string]string{
		"clientId":     "photolib",
		"clientSecret": photoSecret,
		"code":         code,
		"verifier":     verifier,
	}, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange photolib token failed: %d %s", rec.Code, rec.Body.String())
	}
	tokenData := tokenBody["data"].(map[string]any)
	if tokenData["username"] != "newmember" || tokenData["id"] != memberID {
		t.Fatalf("unexpected exchanged user: %v", tokenData)
	}
	accessToken := tokenData["accessToken"].(string)
	rec, _ = requestJSON(t, handler, http.MethodGet, "/api/v1/oauth/userinfo", nil, nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo failed: %d %s", rec.Code, rec.Body.String())
	}

	// 7. Member is DENIED access to Deplyt (RESTRICTED) until admin grants access
	rec, _ = requestJSON(t, handler, http.MethodPost, "/api/v1/oauth/authorize", map[string]string{
		"clientId":      "deplyt",
		"redirectUri":   "https://deploy.example.test/auth/callback",
		"state":         state,
		"codeChallenge": challenge,
	}, memberCookie, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for restricted app before grant, got %d", rec.Code)
	}

	// Admin grants member access to Deplyt
	rec, _ = requestJSON(t, handler, http.MethodPut, "/api/v1/apps/"+deplytAppID, map[string]any{
		"name":           "Deplyt",
		"redirectUris":   []string{"https://deploy.example.test/auth/callback"},
		"accessPolicy":   "RESTRICTED",
		"allowedUserIds": []string{memberID},
		"enabled":        true,
		"version":        1,
	}, adminCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("grant app access failed: %d %s", rec.Code, rec.Body.String())
	}

	// Now member can authorize and exchange token for Deplyt
	rec, authBody = requestJSON(t, handler, http.MethodPost, "/api/v1/oauth/authorize", map[string]string{
		"clientId":      "deplyt",
		"redirectUri":   "https://deploy.example.test/auth/callback",
		"state":         state,
		"codeChallenge": challenge,
	}, memberCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize deplyt after grant failed: %d %s", rec.Code, rec.Body.String())
	}
	deplytCallback, _ := url.Parse(authBody["data"].(map[string]any)["callbackUrl"].(string))
	deplytCode := deplytCallback.Query().Get("code")

	rec, _ = requestJSON(t, handler, http.MethodPost, "/api/v1/oauth/token", map[string]string{
		"code":     deplytCode,
		"verifier": verifier,
	}, nil, map[string]string{
		"X-Deplyt-Client-Secret": "'" + deplytSecret + "'", // Even single-quoted secret header is tolerated!
	})
	if rec.Code != http.StatusOK && !strings.Contains(rec.Body.String(), "newmember") {
		t.Fatalf("deplyt token exchange failed: %d %s", rec.Code, rec.Body.String())
	}
}
