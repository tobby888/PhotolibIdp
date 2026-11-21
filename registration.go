package main

import (
	"cmp"
	"crypto/rand"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

const (
	registrationCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	registrationCodeLength   = 16
	maxRegistrationCodeUses  = 1000
	maxReviewBatch           = 200
)

type registrationRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitorLimiter
}

type visitorLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newRegistrationRateLimiter() *registrationRateLimiter {
	return &registrationRateLimiter{visitors: make(map[string]*visitorLimiter)}
}

func (l *registrationRateLimiter) allow(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range l.visitors {
		if now.Sub(v.lastSeen) > 30*time.Minute {
			delete(l.visitors, k)
		}
	}
	v, ok := l.visitors[ip]
	if !ok {
		v = &visitorLimiter{limiter: rate.NewLimiter(rate.Every(10*time.Second), 6)}
		l.visitors[ip] = v
	}
	v.lastSeen = now
	return v.limiter.Allow()
}

func randomRegistrationCode() string {
	var raw [registrationCodeLength]byte
	_, _ = rand.Read(raw[:])
	var b strings.Builder
	b.Grow(registrationCodeLength)
	for _, v := range raw {
		b.WriteByte(registrationCodeAlphabet[int(v)%len(registrationCodeAlphabet)])
	}
	return b.String()
}

func normalizeRegistrationCode(value string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(value) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type codeView struct {
	ID            string    `json:"id"`
	Code          string    `json:"code"`
	Name          string    `json:"name"`
	AllowedAppIDs []string  `json:"allowedAppIds"`
	MaxUses       int       `json:"maxUses"`
	UsedCount     int       `json:"usedCount"`
	PendingCount  int       `json:"pendingCount"`
	ValidFrom     time.Time `json:"validFrom"`
	ValidUntil    time.Time `json:"validUntil"`
	Enabled       bool      `json:"enabled"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`
	Version       int       `json:"version"`
}

func (s *idpStore) codeStatusLocked(c registrationCode, now time.Time) string {
	if !c.Enabled {
		return "DISABLED"
	}
	if now.Before(c.ValidFrom) {
		return "NOT_STARTED"
	}
	if !now.Before(c.ValidUntil) {
		return "EXPIRED"
	}
	if c.UsedCount >= c.MaxUses {
		return "EXHAUSTED"
	}
	return "ACTIVE"
}

func (s *idpStore) toCodeViewLocked(c registrationCode, now time.Time) codeView {
	pending := 0
	for _, app := range s.state.Applications {
		if app.CodeID == c.ID && app.Status == "PENDING" {
			pending++
		}
	}
	allowed := make([]string, 0, len(c.AllowedAppIDs))
	for _, id := range c.AllowedAppIDs {
		allowed = append(allowed, strconv.FormatInt(id, 10))
	}
	return codeView{
		ID:            strconv.FormatInt(c.ID, 10),
		Code:          c.Code,
		Name:          c.Name,
		AllowedAppIDs: allowed,
		MaxUses:       c.MaxUses,
		UsedCount:     c.UsedCount,
		PendingCount:  pending,
		ValidFrom:     c.ValidFrom,
		ValidUntil:    c.ValidUntil,
		Enabled:       c.Enabled,
		Status:        s.codeStatusLocked(c, now),
		CreatedAt:     c.CreatedAt,
		Version:       c.Version,
	}
}

func parseTimeField(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Truncate(time.Second), nil
		}
	}
	return time.Time{}, errInvalidTime
}

var errInvalidTime = &httpError{status: http.StatusBadRequest, code: "VALIDATION_ERROR", message: "时间格式无效"}

type httpError struct {
	status  int
	code    string
	message string
}

func (e *httpError) Error() string { return e.message }

func (s *idpStore) handleListCodes(w http.ResponseWriter, r *http.Request, _ userAccount) {
	keyword := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("keyword")))
	normCode := strings.ToLower(normalizeRegistrationCode(keyword))
	now := s.now()
	s.mu.Lock()
	items := make([]codeView, 0, len(s.state.Codes))
	for _, c := range s.state.Codes {
		if keyword != "" &&
			!strings.Contains(strings.ToLower(c.Name), keyword) &&
			(normCode == "" || !strings.Contains(strings.ToLower(c.Code), normCode)) {
			continue
		}
		items = append(items, s.toCodeViewLocked(c, now))
	}
	s.mu.Unlock()
	slices.SortFunc(items, func(a, b codeView) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(b.ID, a.ID)
	})
	writeOK(w, items)
}

func (s *idpStore) handleCreateCode(w http.ResponseWriter, r *http.Request, admin userAccount) {
	var req struct {
		Name          string   `json:"name"`
		AllowedAppIDs []string `json:"allowedAppIds"`
		MaxUses       int      `json:"maxUses"`
		ValidFrom     string   `json:"validFrom"`
		ValidUntil    string   `json:"validUntil"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len([]rune(name)) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请填写注册码名称（不超过 100 个字符）")
		return
	}
	if req.MaxUses < 1 || req.MaxUses > maxRegistrationCodeUses {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "可注册数量须在 1 到 1000 之间")
		return
	}
	now := s.now()
	validFrom := now
	if strings.TrimSpace(req.ValidFrom) != "" {
		parsed, err := parseTimeField(req.ValidFrom)
		if err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "生效开始时间无效")
			return
		}
		validFrom = parsed
	}
	validUntil, err := parseTimeField(req.ValidUntil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请输入截止时间")
		return
	}
	if !validUntil.After(validFrom) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "截止时间必须晚于开始时间")
		return
	}
	if !validUntil.After(now) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "截止时间必须晚于当前时间")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	appIDs, err := s.parseAppIDsLocked(req.AllowedAppIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	codeValue := randomRegistrationCode()
	for s.codeValueExistsLocked(codeValue) {
		codeValue = randomRegistrationCode()
	}
	id := s.state.NextCodeID
	s.state.NextCodeID++
	created := registrationCode{
		ID:            id,
		Code:          codeValue,
		Name:          name,
		AllowedAppIDs: appIDs,
		MaxUses:       req.MaxUses,
		UsedCount:     0,
		ValidFrom:     validFrom,
		ValidUntil:    validUntil,
		Enabled:       true,
		Version:       1,
		CreatedBy:     admin.ID,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	s.state.Codes[id] = created
	if err := s.persistLocked(); err != nil {
		delete(s.state.Codes, id)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存注册码")
		return
	}
	writeOK(w, s.toCodeViewLocked(created, now))
}

func (s *idpStore) codeValueExistsLocked(code string) bool {
	for _, c := range s.state.Codes {
		if c.Code == code {
			return true
		}
	}
	return false
}

func (s *idpStore) parseAppIDsLocked(raw []string) ([]int64, error) {
	var ids []int64
	for _, item := range raw {
		id, err := strconv.ParseInt(strings.TrimSpace(item), 10, 64)
		if err != nil || id <= 0 {
			return nil, &httpError{status: http.StatusBadRequest, code: "VALIDATION_ERROR", message: "关联的应用不存在"}
		}
		if _, ok := s.state.Apps[id]; !ok {
			return nil, &httpError{status: http.StatusBadRequest, code: "VALIDATION_ERROR", message: "关联的应用不存在"}
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (s *idpStore) handleUpdateCode(w http.ResponseWriter, r *http.Request, _ userAccount) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "注册码不存在")
		return
	}
	var req struct {
		Name          string   `json:"name"`
		AllowedAppIDs []string `json:"allowedAppIds"`
		MaxUses       int      `json:"maxUses"`
		ValidFrom     string   `json:"validFrom"`
		ValidUntil    string   `json:"validUntil"`
		Enabled       bool     `json:"enabled"`
		Version       int      `json:"version"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len([]rune(name)) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请填写注册码名称")
		return
	}
	if req.MaxUses < 1 || req.MaxUses > maxRegistrationCodeUses {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "可注册数量须在 1 到 1000 之间")
		return
	}
	validFrom, err := parseTimeField(req.ValidFrom)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "生效开始时间无效")
		return
	}
	validUntil, err := parseTimeField(req.ValidUntil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "截止时间无效")
		return
	}
	if !validUntil.After(validFrom) {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "截止时间必须晚于开始时间")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.state.Codes[id]
	if !ok {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "注册码不存在")
		return
	}
	if req.Version > 0 && code.Version != req.Version {
		writeError(w, http.StatusConflict, "RESOURCE_STATE_CONFLICT", "注册码已被其他操作修改，请刷新后重试")
		return
	}
	if req.MaxUses < code.UsedCount {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
			"可注册数量不能少于已占用的 "+strconv.Itoa(code.UsedCount)+" 个名额（待审核和已通过的申请都占名额）")
		return
	}
	if req.AllowedAppIDs != nil {
		appIDs, err := s.parseAppIDsLocked(req.AllowedAppIDs)
		if err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		code.AllowedAppIDs = appIDs
	}
	code.Name = name
	code.MaxUses = req.MaxUses
	code.ValidFrom = validFrom
	code.ValidUntil = validUntil
	code.Enabled = req.Enabled
	code.Version++
	code.UpdatedAt = s.now()
	s.state.Codes[id] = code
	if err := s.persistLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存注册码修改")
		return
	}
	writeOK(w, s.toCodeViewLocked(code, s.now()))
}

func (s *idpStore) handleDeleteCode(w http.ResponseWriter, r *http.Request, _ userAccount) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "注册码不存在")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Codes[id]; !ok {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "注册码不存在")
		return
	}
	for _, app := range s.state.Applications {
		if app.CodeID == id {
			writeError(w, http.StatusConflict, "RESOURCE_STATE_CONFLICT", "已经有同学用这个注册码提交过申请，不能删除；不想再让人使用的话请停用它")
			return
		}
	}
	delete(s.state.Codes, id)
	if err := s.persistLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法删除注册码")
		return
	}
	writeOK(w, nil)
}

func (s *idpStore) handlePublicRegister(limiter *registrationRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(clientAddress(r)) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "提交过于频繁，请稍后再试")
			return
		}
		var req struct {
			Code            string `json:"code"`
			Username        string `json:"username"`
			DisplayName     string `json:"displayName"`
			Email           string `json:"email"`
			Password        string `json:"password"`
			ConfirmPassword string `json:"confirmPassword"`
		}
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请求内容无法解析")
			return
		}
		if req.Password != req.ConfirmPassword {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "两次输入的密码不一致")
			return
		}
		if !validPassword(req.Password) {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "密码至少10位，且必须包含字母和数字")
			return
		}
		username := cleanUsername(req.Username)
		if !usernamePattern.MatchString(username) {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "登录账号为 3-64 位字母、数字或 ._-")
			return
		}
		if strings.HasPrefix(strings.ToLower(username), "del.") {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "登录账号不能以 del. 开头")
			return
		}
		displayName := strings.TrimSpace(req.DisplayName)
		if displayName == "" || len([]rune(displayName)) > 50 {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请输入真实姓名（不超过 50 个字符）")
			return
		}
		email := cleanEmail(req.Email)
		if email == "" || !emailPattern.MatchString(email) || len(email) > 255 {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请输入有效的邮箱地址")
			return
		}
		normalizedCode := normalizeRegistrationCode(req.Code)
		if len(normalizedCode) != registrationCodeLength {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "注册码无效，请核对后重新输入")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法处理密码")
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		var matched *registrationCode
		for _, c := range s.state.Codes {
			if c.Code == normalizedCode {
				copyCode := c
				matched = &copyCode
				break
			}
		}
		if matched == nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "注册码无效，请核对后重新输入")
			return
		}
		now := s.now()
		if !matched.Enabled {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "该注册码已停用")
			return
		}
		if now.Before(matched.ValidFrom) {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "该注册码尚未生效")
			return
		}
		if !now.Before(matched.ValidUntil) {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "该注册码已过期")
			return
		}
		if matched.UsedCount >= matched.MaxUses {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "该注册码的注册名额已满")
			return
		}
		if s.usernameTakenLocked(username, 0) {
			writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "该登录账号已被使用，请换一个")
			return
		}
		if s.emailTakenLocked(email, 0) {
			writeError(w, http.StatusConflict, "DUPLICATE_RESOURCE", "该邮箱已被使用，请换一个")
			return
		}

		matched.UsedCount++
		matched.Version++
		matched.UpdatedAt = now
		s.state.Codes[matched.ID] = *matched

		appID := s.state.NextApplicationID
		s.state.NextApplicationID++
		application := registrationApplication{
			ID:              appID,
			CodeID:          matched.ID,
			Username:        username,
			DisplayName:     displayName,
			Email:           email,
			PasswordHash:    string(hash),
			Status:          "PENDING",
			PendingUsername: username,
			PendingEmail:    email,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		s.state.Applications[appID] = application
		if err := s.persistLocked(); err != nil {
			delete(s.state.Applications, appID)
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存注册申请")
			return
		}
		writeOK(w, map[string]string{
			"id":          strconv.FormatInt(application.ID, 10),
			"username":    application.Username,
			"displayName": application.DisplayName,
		})
	}
}

type applicationView struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"displayName"`
	Email        string     `json:"email"`
	Status       string     `json:"status"`
	CodeID       string     `json:"codeId"`
	CodeName     string     `json:"codeName,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	ReviewedAt   *time.Time `json:"reviewedAt,omitempty"`
	ReviewerName string     `json:"reviewerName,omitempty"`
	RejectReason string     `json:"rejectReason,omitempty"`
	UserID       string     `json:"userId,omitempty"`
}

func (s *idpStore) handleListApplications(w http.ResponseWriter, r *http.Request, _ userAccount) {
	keyword := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("keyword")))
	status := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	codeIDFilter := strings.TrimSpace(r.URL.Query().Get("codeId"))
	s.mu.Lock()
	items := make([]applicationView, 0, len(s.state.Applications))
	for _, app := range s.state.Applications {
		if status != "" && app.Status != status {
			continue
		}
		if codeIDFilter != "" && strconv.FormatInt(app.CodeID, 10) != codeIDFilter {
			continue
		}
		if keyword != "" &&
			!strings.Contains(strings.ToLower(app.Username), keyword) &&
			!strings.Contains(strings.ToLower(app.DisplayName), keyword) &&
			!strings.Contains(strings.ToLower(app.Email), keyword) {
			continue
		}
		codeName := ""
		if c, ok := s.state.Codes[app.CodeID]; ok {
			codeName = c.Name
		}
		reviewerName := ""
		if app.ReviewerID > 0 {
			if u, ok := s.state.Users[app.ReviewerID]; ok {
				reviewerName = u.DisplayName
			}
		}
		userID := ""
		if app.UserID > 0 {
			userID = strconv.FormatInt(app.UserID, 10)
		}
		items = append(items, applicationView{
			ID:           strconv.FormatInt(app.ID, 10),
			Username:     app.Username,
			DisplayName:  app.DisplayName,
			Email:        app.Email,
			Status:       app.Status,
			CodeID:       strconv.FormatInt(app.CodeID, 10),
			CodeName:     codeName,
			CreatedAt:    app.CreatedAt,
			ReviewedAt:   app.ReviewedAt,
			ReviewerName: reviewerName,
			RejectReason: app.RejectReason,
			UserID:       userID,
		})
	}
	s.mu.Unlock()
	slices.SortFunc(items, func(a, b applicationView) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(b.ID, a.ID)
	})
	writeOK(w, items)
}

type reviewFailure struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Message  string `json:"message"`
}

func (s *idpStore) handleApproveApplications(w http.ResponseWriter, r *http.Request, admin userAccount) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(w, r, &req); err != nil || len(req.IDs) == 0 || len(req.IDs) > maxReviewBatch {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请选择要通过的注册申请")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	succeeded := make([]string, 0, len(req.IDs))
	failed := make([]reviewFailure, 0)
	now := s.now()
	seen := make(map[string]bool)
	for _, rawID := range req.IDs {
		if seen[rawID] {
			continue
		}
		seen[rawID] = true
		id, err := strconv.ParseInt(rawID, 10, 64)
		if err != nil || id <= 0 {
			failed = append(failed, reviewFailure{ID: rawID, Message: "注册申请不存在"})
			continue
		}
		app, ok := s.state.Applications[id]
		if !ok {
			failed = append(failed, reviewFailure{ID: rawID, Message: "注册申请不存在"})
			continue
		}
		if app.Status != "PENDING" {
			failed = append(failed, reviewFailure{ID: rawID, Username: app.Username, Message: "这份申请已经审核过了"})
			continue
		}
		code, codeOK := s.state.Codes[app.CodeID]
		if !codeOK {
			failed = append(failed, reviewFailure{ID: rawID, Username: app.Username, Message: "注册码不存在，无法通过，请驳回"})
			continue
		}
		app.PendingUsername = ""
		app.PendingEmail = ""
		s.state.Applications[id] = app
		if s.usernameTakenLocked(app.Username, 0) || s.emailTakenLocked(app.Email, 0) {
			app.PendingUsername = app.Username
			app.PendingEmail = app.Email
			s.state.Applications[id] = app
			failed = append(failed, reviewFailure{ID: rawID, Username: app.Username, Message: "登录账号或邮箱已被其他用户使用"})
			continue
		}
		userID := s.state.NextUserID
		s.state.NextUserID++
		user := userAccount{
			ID:                 userID,
			Username:           app.Username,
			PasswordHash:       app.PasswordHash,
			DisplayName:        app.DisplayName,
			Email:              app.Email,
			Admin:              false,
			Enabled:            true,
			MustChangePassword: false,
			Version:            1,
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		s.state.Users[userID] = user
		for _, appIDToGrant := range code.AllowedAppIDs {
			if targetApp, exists := s.state.Apps[appIDToGrant]; exists && !slices.Contains(targetApp.AllowedUserIDs, userID) {
				targetApp.AllowedUserIDs = append(targetApp.AllowedUserIDs, userID)
				targetApp.UpdatedAt = now
				s.state.Apps[appIDToGrant] = targetApp
			}
		}
		reviewedAt := now
		app.Status = "APPROVED"
		app.ReviewerID = admin.ID
		app.ReviewedAt = &reviewedAt
		app.UserID = userID
		app.UpdatedAt = now
		s.state.Applications[id] = app
		succeeded = append(succeeded, rawID)
	}
	if err := s.persistLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存审核结果")
		return
	}
	writeOK(w, map[string]any{"succeeded": succeeded, "failed": failed})
}

func (s *idpStore) handleRejectApplications(w http.ResponseWriter, r *http.Request, admin userAccount) {
	var req struct {
		IDs    []string `json:"ids"`
		Reason string   `json:"reason"`
	}
	if err := readJSON(w, r, &req); err != nil || len(req.IDs) == 0 || len(req.IDs) > maxReviewBatch {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "请选择要驳回的注册申请")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len([]rune(reason)) > 500 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "驳回原因不能超过 500 个字符")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	succeeded := make([]string, 0, len(req.IDs))
	failed := make([]reviewFailure, 0)
	now := s.now()
	seen := make(map[string]bool)
	for _, rawID := range req.IDs {
		if seen[rawID] {
			continue
		}
		seen[rawID] = true
		id, err := strconv.ParseInt(rawID, 10, 64)
		if err != nil || id <= 0 {
			failed = append(failed, reviewFailure{ID: rawID, Message: "注册申请不存在"})
			continue
		}
		app, ok := s.state.Applications[id]
		if !ok {
			failed = append(failed, reviewFailure{ID: rawID, Message: "注册申请不存在"})
			continue
		}
		if app.Status != "PENDING" {
			failed = append(failed, reviewFailure{ID: rawID, Username: app.Username, Message: "这份申请已经审核过了"})
			continue
		}
		reviewedAt := now
		app.Status = "REJECTED"
		app.PendingUsername = ""
		app.PendingEmail = ""
		app.RejectReason = reason
		app.ReviewerID = admin.ID
		app.ReviewedAt = &reviewedAt
		app.UpdatedAt = now
		s.state.Applications[id] = app
		if code, exists := s.state.Codes[app.CodeID]; exists && code.UsedCount > 0 {
			code.UsedCount--
			code.Version++
			code.UpdatedAt = now
			s.state.Codes[app.CodeID] = code
		}
		succeeded = append(succeeded, rawID)
	}
	if err := s.persistLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "无法保存驳回结果")
		return
	}
	writeOK(w, map[string]any{"succeeded": succeeded, "failed": failed})
}
