package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultSlogan       = "统一身份认证与访问准入中心"
	sessionCookieName   = "__Host-photolib-idp-session"
	sessionDuration     = 8 * time.Hour
	authCodeDuration    = 60 * time.Second
	accessTokenDuration = 15 * time.Minute
	refreshDuration     = 30 * 24 * time.Hour
)

type siteSettings struct {
	Slogan    string    `json:"slogan"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type userAccount struct {
	ID                 int64     `json:"id"`
	Username           string    `json:"username"`
	PasswordHash       string    `json:"passwordHash"`
	DisplayName        string    `json:"displayName"`
	Email              string    `json:"email,omitempty"`
	Phone              string    `json:"phone,omitempty"`
	WecomUserid        string    `json:"wecomUserid,omitempty"`
	Admin              bool      `json:"admin"`
	Enabled            bool      `json:"enabled"`
	MustChangePassword bool      `json:"mustChangePassword"`
	Version            int       `json:"version"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
	Deleted            bool      `json:"deleted,omitempty"`
}

type userView struct {
	ID                 string    `json:"id"`
	Sub                string    `json:"sub"`
	Username           string    `json:"username"`
	DisplayName        string    `json:"displayName"`
	Email              string    `json:"email,omitempty"`
	Phone              string    `json:"phone,omitempty"`
	WecomUserid        string    `json:"wecomUserid,omitempty"`
	Admin              bool      `json:"admin"`
	Enabled            bool      `json:"enabled"`
	MustChangePassword bool      `json:"mustChangePassword"`
	Version            int       `json:"version"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

func (u userAccount) view() userView {
	id := strconv.FormatInt(u.ID, 10)
	return userView{
		ID:                 id,
		Sub:                id,
		Username:           u.Username,
		DisplayName:        u.DisplayName,
		Email:              u.Email,
		Phone:              u.Phone,
		WecomUserid:        u.WecomUserid,
		Admin:              u.Admin,
		Enabled:            u.Enabled,
		MustChangePassword: u.MustChangePassword,
		Version:            u.Version,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
}

type registeredApp struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	ClientID       string    `json:"clientId"`
	SecretHash     string    `json:"secretHash"`
	RedirectURIs   []string  `json:"redirectUris"`
	HomepageURL    string    `json:"homepageUrl,omitempty"`
	WebhookURL     string    `json:"webhookUrl,omitempty"`
	AccessPolicy   string    `json:"accessPolicy"` // "ALL_AUTHENTICATED" or "RESTRICTED"
	AllowedUserIDs []int64   `json:"allowedUserIds"`
	Enabled        bool      `json:"enabled"`
	Version        int       `json:"version"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type appView struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	ClientID       string    `json:"clientId"`
	RedirectURIs   []string  `json:"redirectUris"`
	HomepageURL    string    `json:"homepageUrl,omitempty"`
	WebhookURL     string    `json:"webhookUrl,omitempty"`
	AccessPolicy   string    `json:"accessPolicy"`
	AllowedUserIDs []string  `json:"allowedUserIds"`
	Enabled        bool      `json:"enabled"`
	Version        int       `json:"version"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (a registeredApp) view() appView {
	allowed := make([]string, 0, len(a.AllowedUserIDs))
	for _, id := range a.AllowedUserIDs {
		allowed = append(allowed, strconv.FormatInt(id, 10))
	}
	return appView{
		ID:             strconv.FormatInt(a.ID, 10),
		Name:           a.Name,
		Description:    a.Description,
		ClientID:       a.ClientID,
		RedirectURIs:   slices.Clone(a.RedirectURIs),
		HomepageURL:    a.HomepageURL,
		WebhookURL:     a.WebhookURL,
		AccessPolicy:   a.AccessPolicy,
		AllowedUserIDs: allowed,
		Enabled:        a.Enabled,
		Version:        a.Version,
		CreatedAt:      a.CreatedAt,
		UpdatedAt:      a.UpdatedAt,
	}
}

type registrationCode struct {
	ID             int64     `json:"id"`
	Code           string    `json:"code"`
	Name           string    `json:"name"`
	AllowedAppIDs  []int64   `json:"allowedAppIds,omitempty"`
	MaxUses        int       `json:"maxUses"`
	UsedCount      int       `json:"usedCount"`
	ValidFrom      time.Time `json:"validFrom"`
	ValidUntil     time.Time `json:"validUntil"`
	Enabled        bool      `json:"enabled"`
	Version        int       `json:"version"`
	CreatedBy      int64     `json:"createdBy"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type registrationApplication struct {
	ID              int64      `json:"id"`
	CodeID          int64      `json:"codeId"`
	Username        string     `json:"username"`
	DisplayName     string     `json:"displayName"`
	Email           string     `json:"email"`
	PasswordHash    string     `json:"passwordHash"`
	Status          string     `json:"status"` // "PENDING", "APPROVED", "REJECTED"
	PendingUsername string     `json:"pendingUsername,omitempty"`
	PendingEmail    string     `json:"pendingEmail,omitempty"`
	ReviewerID      int64      `json:"reviewerId,omitempty"`
	ReviewedAt      *time.Time `json:"reviewedAt,omitempty"`
	RejectReason    string     `json:"rejectReason,omitempty"`
	UserID          int64      `json:"userId,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

type persistentState struct {
	NextUserID        int64                              `json:"nextUserId"`
	NextAppID         int64                              `json:"nextAppId"`
	NextCodeID        int64                              `json:"nextCodeId"`
	NextApplicationID int64                              `json:"nextApplicationId"`
	Settings          siteSettings                       `json:"settings"`
	Users             map[int64]userAccount              `json:"users"`
	Apps              map[int64]registeredApp            `json:"apps"`
	Codes             map[int64]registrationCode         `json:"codes"`
	Applications      map[int64]registrationApplication  `json:"applications"`
}

type webSession struct {
	UserID    int64
	ExpiresAt time.Time
}

type authGrant struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	UserID        int64
	ExpiresAt     time.Time
}

type issuedToken struct {
	Token     string
	ClientID  string
	UserID    int64
	ExpiresAt time.Time
	Refresh   bool
}

type idpStore struct {
	mu           sync.Mutex
	path         string
	origin       string
	state        persistentState
	sessions     map[string]webSession
	grants       map[string]authGrant
	accessTokens map[string]issuedToken
	refreshTokens map[string]issuedToken
	now          func() time.Time
}

func openStore(cfg config) (*idpStore, error) {
	if err := os.MkdirAll(cfg.stateDir, 0700); err != nil {
		return nil, err
	}
	store := &idpStore{
		path:          filepath.Join(cfg.stateDir, "idp-state.json"),
		origin:        cfg.publicOrigin,
		sessions:      make(map[string]webSession),
		grants:        make(map[string]authGrant),
		accessTokens:  make(map[string]issuedToken),
		refreshTokens: make(map[string]issuedToken),
		now:           func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	}
	data, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		store.state = persistentState{
			NextUserID:        1,
			NextAppID:         1,
			NextCodeID:        1,
			NextApplicationID: 1,
			Settings:          siteSettings{Slogan: defaultSlogan, UpdatedAt: store.now()},
			Users:             make(map[int64]userAccount),
			Apps:              make(map[int64]registeredApp),
			Codes:             make(map[int64]registrationCode),
			Applications:      make(map[int64]registrationApplication),
		}
	} else if err != nil {
		return nil, err
	} else {
		if err := json.Unmarshal(data, &store.state); err != nil {
			return nil, fmt.Errorf("invalid PhotolibIdp state file: %w", err)
		}
		if store.state.Users == nil {
			store.state.Users = make(map[int64]userAccount)
		}
		if store.state.Apps == nil {
			store.state.Apps = make(map[int64]registeredApp)
		}
		if store.state.Codes == nil {
			store.state.Codes = make(map[int64]registrationCode)
		}
		if store.state.Applications == nil {
			store.state.Applications = make(map[int64]registrationApplication)
		}
		if strings.TrimSpace(store.state.Settings.Slogan) == "" {
			store.state.Settings.Slogan = defaultSlogan
		}
	}
	if err := store.bootstrapAdmin(cfg); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *idpStore) bootstrapAdmin(cfg config) error {
	for _, u := range s.state.Users {
		if !u.Deleted && u.Admin && u.Enabled {
			return nil
		}
	}
	if cfg.adminPassword == "" {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := s.now()
	id := s.state.NextUserID
	s.state.NextUserID++
	s.state.Users[id] = userAccount{
		ID:                 id,
		Username:           cleanUsername(cfg.adminUsername),
		PasswordHash:       string(hash),
		DisplayName:        cfg.adminDisplayName,
		Email:              cleanEmail(cfg.adminEmail),
		Admin:              true,
		Enabled:            true,
		MustChangePassword: false,
		Version:            1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	return s.persistLocked()
}

func (s *idpStore) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	file, err := os.CreateTemp(dir, ".idp-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("persist PhotolibIdp state: %w", err)
	}
	if err := os.Rename(file.Name(), s.path); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func randomToken() string {
	var data [32]byte
	_, _ = rand.Read(data[:])
	return base64.RawURLEncoding.EncodeToString(data[:])
}

func validToken(token string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(b) == 32 && len(token) == 43
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
