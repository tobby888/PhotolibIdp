package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("photolib-idp stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := loadConfig(".env")
	if err != nil {
		return err
	}
	store, err := openStore(cfg)
	if err != nil {
		return err
	}
	handler, err := newServerHandler(store)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("photolib-idp listening", "address", cfg.listenAddr, "origin", cfg.publicOrigin)
		serverErr <- server.ListenAndServe()
	}()
	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		stop()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
		if err := <-serverErr; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func newServerHandler(store *idpStore) (http.Handler, error) {
	mux := http.NewServeMux()
	limiter := newRegistrationRateLimiter()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", store.handleOpenIDConfig)
	mux.HandleFunc("GET /oauth/authorize", store.handleBrowserAuthorizeRedirect)

	// Public & OAuth token endpoints (called server-to-server or before authentication)
	mux.HandleFunc("GET /api/v1/settings", store.handleGetSettings)
	mux.HandleFunc("POST /api/v1/public/registrations", store.requireSameOrigin(store.handlePublicRegister(limiter)))
	mux.HandleFunc("POST /api/v1/oauth/token", store.handleExchangeToken)
	mux.HandleFunc("POST /api/v1/oauth/token/refresh", store.handleRefreshToken)
	mux.HandleFunc("POST /api/v1/oauth/token/revoke", store.handleRevokeToken)
	mux.HandleFunc("GET /api/v1/oauth/userinfo", store.handleUserInfo)
	mux.HandleFunc("GET /api/v1/oauth/users", store.handleAppUsersSync)

	// Browser session authentication endpoints
	mux.HandleFunc("POST /api/v1/auth/login", store.requireSameOrigin(store.handleLogin))
	mux.HandleFunc("POST /api/v1/auth/logout", store.requireSameOrigin(store.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/me", store.requireAuth(false, store.handleMe))
	mux.HandleFunc("PUT /api/v1/auth/initial-password", store.requireAuth(false, store.handleInitialPassword))
	mux.HandleFunc("PUT /api/v1/auth/password", store.requireAuth(false, store.handleChangePassword))

	// Browser OAuth authorization consent endpoints
	mux.HandleFunc("GET /api/v1/oauth/authorize", store.requireAuth(false, store.handleInspectAuthorize))
	mux.HandleFunc("POST /api/v1/oauth/authorize", store.requireAuth(false, store.handleApproveAuthorize))

	// Administrator management endpoints
	mux.HandleFunc("PUT /api/v1/settings", store.requireAuth(true, store.handleUpdateSettings))
	mux.HandleFunc("GET /api/v1/users", store.requireAuth(true, store.handleListUsers))
	mux.HandleFunc("POST /api/v1/users", store.requireAuth(true, store.handleCreateUser))
	mux.HandleFunc("PUT /api/v1/users/{id}", store.requireAuth(true, store.handleUpdateUser))
	mux.HandleFunc("POST /api/v1/users/{id}/enable", store.requireAuth(true, store.handleToggleUser(true)))
	mux.HandleFunc("POST /api/v1/users/{id}/disable", store.requireAuth(true, store.handleToggleUser(false)))
	mux.HandleFunc("PUT /api/v1/users/{id}/password", store.requireAuth(true, store.handleResetPassword))
	mux.HandleFunc("DELETE /api/v1/users/{id}", store.requireAuth(true, store.handleDeleteUser))

	mux.HandleFunc("GET /api/v1/apps", store.requireAuth(true, store.handleListApps))
	mux.HandleFunc("POST /api/v1/apps", store.requireAuth(true, store.handleCreateApp))
	mux.HandleFunc("PUT /api/v1/apps/{id}", store.requireAuth(true, store.handleUpdateApp))
	mux.HandleFunc("POST /api/v1/apps/{id}/secret", store.requireAuth(true, store.handleRotateAppSecret))
	mux.HandleFunc("DELETE /api/v1/apps/{id}", store.requireAuth(true, store.handleDeleteApp))

	mux.HandleFunc("GET /api/v1/registration-codes", store.requireAuth(true, store.handleListCodes))
	mux.HandleFunc("POST /api/v1/registration-codes", store.requireAuth(true, store.handleCreateCode))
	mux.HandleFunc("PUT /api/v1/registration-codes/{id}", store.requireAuth(true, store.handleUpdateCode))
	mux.HandleFunc("DELETE /api/v1/registration-codes/{id}", store.requireAuth(true, store.handleDeleteCode))

	mux.HandleFunc("GET /api/v1/registration-applications", store.requireAuth(true, store.handleListApplications))
	mux.HandleFunc("POST /api/v1/registration-applications/approve", store.requireAuth(true, store.handleApproveApplications))
	mux.HandleFunc("POST /api/v1/registration-applications/reject", store.requireAuth(true, store.handleRejectApplications))

	if err := registerUI(mux); err != nil {
		return nil, err
	}
	return securityHeaders(mux), nil
}

func (s *idpStore) requireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("Origin") != s.origin {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "请求来源无效")
			return
		}
		next(w, r)
	}
}

func (s *idpStore) requireAuth(adminOnly bool, next func(http.ResponseWriter, *http.Request, userAccount)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("Origin") != s.origin {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "请求来源无效")
			return
		}
		user, ok := s.currentUser(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "未登录或会话已过期")
			return
		}
		if user.MustChangePassword && r.URL.Path != "/api/v1/auth/me" && r.URL.Path != "/api/v1/auth/initial-password" {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "首次登录必须先修改初始密码")
			return
		}
		if adminOnly && !user.Admin {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "此操作需要统一认证中心管理员权限")
			return
		}
		next(w, r, user)
	}
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, map[string]any{
		"code":    "OK",
		"message": "success",
		"data":    data,
	})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"code":    code,
		"message": message,
		"details": []any{},
	})
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	return host
}
