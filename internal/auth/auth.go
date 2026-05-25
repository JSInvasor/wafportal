// Package auth protects the control plane with a single administrator account.
// Passwords are stored as bcrypt hashes and sessions are stateless, signed
// cookies (HMAC-SHA256) so they survive restarts without server-side storage.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jsinvasor/wafportal/internal/store"
)

const (
	cookieName      = "wafportal_session"
	sessionDuration = 7 * 24 * time.Hour

	keyUsername = "admin_username"
	keyHash     = "admin_password_hash"
	keySecret   = "session_secret"
)

var ErrInvalidCredentials = errors.New("invalid username or password")

type Authenticator struct {
	store  *store.Store
	secret []byte

	// GeneratedPassword is non-empty only when New created a random initial
	// password; the caller should log it once so the operator can sign in.
	GeneratedPassword string
}

// New ensures an admin account and session secret exist. A bootstrapPassword
// (from config/env) is authoritative and overwrites the stored password when
// provided; otherwise, if no password is set yet, a strong random one is
// generated and surfaced via GeneratedPassword.
func New(st *store.Store, bootstrapUser, bootstrapPassword string) (*Authenticator, error) {
	a := &Authenticator{store: st}

	secret, err := loadOrCreateSecret(st)
	if err != nil {
		return nil, err
	}
	a.secret = secret

	username := strings.TrimSpace(bootstrapUser)
	if username == "" {
		if v, ok, _ := st.GetSetting(keyUsername); ok && v != "" {
			username = v
		} else {
			username = "admin"
		}
	}
	if err := st.SetSetting(keyUsername, username); err != nil {
		return nil, err
	}

	_, hasHash, err := st.GetSetting(keyHash)
	if err != nil {
		return nil, err
	}

	switch {
	case bootstrapPassword != "":
		if err := a.setPassword(bootstrapPassword); err != nil {
			return nil, err
		}
	case !hasHash:
		pw, err := randomPassword()
		if err != nil {
			return nil, err
		}
		if err := a.setPassword(pw); err != nil {
			return nil, err
		}
		a.GeneratedPassword = pw
	}

	return a, nil
}

func (a *Authenticator) Username() string {
	v, _, _ := a.store.GetSetting(keyUsername)
	return v
}

// Check verifies a login attempt in constant time with respect to the username.
func (a *Authenticator) Check(username, password string) bool {
	storedUser, _, _ := a.store.GetSetting(keyUsername)
	hash, ok, _ := a.store.GetSetting(keyHash)
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(storedUser)) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	return userOK && passOK
}

// ChangePassword verifies the current password and stores a new one.
func (a *Authenticator) ChangePassword(current, next string) error {
	if !a.Check(a.Username(), current) {
		return ErrInvalidCredentials
	}
	if len(next) < 8 {
		return errors.New("new password must be at least 8 characters")
	}
	return a.setPassword(next)
}

func (a *Authenticator) setPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return a.store.SetSetting(keyHash, string(hash))
}

// IssueCookie writes a signed session cookie identifying username.
func (a *Authenticator) IssueCookie(w http.ResponseWriter, r *http.Request, username string) {
	exp := time.Now().Add(sessionDuration)
	payload := username + "|" + strconv.FormatInt(exp.Unix(), 10)
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + a.sign(payload)

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *Authenticator) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// verify validates the session cookie and returns the authenticated username.
func (a *Authenticator) verify(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	encoded, sig, found := strings.Cut(c.Value, ".")
	if !found {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	payload := string(raw)
	if !hmac.Equal([]byte(sig), []byte(a.sign(payload))) {
		return "", false
	}
	username, expStr, found := strings.Cut(payload, "|")
	if !found {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return username, true
}

// Middleware rejects requests without a valid session cookie.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.verify(r); !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"authentication required"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CurrentUser returns the username for an authenticated request, if any.
func (a *Authenticator) CurrentUser(r *http.Request) (string, bool) {
	return a.verify(r)
}

func (a *Authenticator) sign(payload string) string {
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func loadOrCreateSecret(st *store.Store) ([]byte, error) {
	if v, ok, err := st.GetSetting(keySecret); err != nil {
		return nil, err
	} else if ok && v != "" {
		return hex.DecodeString(v)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate session secret: %w", err)
	}
	if err := st.SetSetting(keySecret, hex.EncodeToString(buf)); err != nil {
		return nil, err
	}
	return buf, nil
}

func randomPassword() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
