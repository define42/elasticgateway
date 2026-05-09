package server

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/define42/elasticgateway/internal/authz"
	appconfig "github.com/define42/elasticgateway/internal/config"
	"github.com/gorilla/securecookie"
)

// SessionCookieName is the cookie that carries the gateway session token.
const SessionCookieName = "elasticgateway_session"

// Session is the value carried inside the encrypted session cookie. It holds
// every per-request fact the gateway needs to authorize the user and proxy
// Kibana, so the gateway can scale horizontally without a shared session
// store: the cookie itself is the session. Expiry is enforced by
// gorilla/securecookie's configured MaxAge at decode time, so no timing fields
// are tracked here.
type Session struct {
	User       *authz.User
	Access     []authz.Access
	AuthHeader string
}

// String returns a redacted representation so accidental fmt-based logging
// cannot expose the Basic credentials carried in AuthHeader.
func (s Session) String() string {
	return fmt.Sprintf("Session{User:%+v Access:%+v AuthHeader:%q}", s.User, s.Access, redactedAuthHeader(s.AuthHeader))
}

// GoString ensures verbose %#v formatting uses the redacted representation
// instead of reflecting the exported AuthHeader field.
func (s Session) GoString() string {
	return s.String()
}

// LogValue returns a redacted structured representation for slog.Any.
func (s Session) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("User", s.User),
		slog.Any("Access", s.Access),
		slog.String("AuthHeader", redactedAuthHeader(s.AuthHeader)),
	)
}

func redactedAuthHeader(header string) string {
	if header == "" {
		return ""
	}
	return "<redacted>"
}

func sessionLogUsername(sessionData Session) string {
	if sessionData.User == nil {
		return ""
	}
	return strings.TrimSpace(sessionData.User.Name)
}

// newSecureCookie builds a securecookie codec. With no configured secret,
// keys are generated per process so cookies do not survive a restart.
func newSecureCookie(sessionSecret string, sessionMaxAge int) *securecookie.SecureCookie {
	sessionSecret = strings.TrimSpace(sessionSecret)
	if sessionSecret != "" {
		hashKey, blockKey := deriveSessionKeys(sessionSecret)
		return securecookie.New(hashKey, blockKey).MaxAge(sessionMaxAge)
	}

	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)
	return securecookie.New(hashKey, blockKey).MaxAge(sessionMaxAge)
}

func deriveSessionKeys(sessionSecret string) ([]byte, []byte) {
	const (
		hashKeyBytes  = 64
		blockKeyBytes = 32
	)

	keys, err := hkdf.Key(
		sha256.New,
		[]byte(sessionSecret),
		nil,
		"elasticgateway session cookie keys",
		hashKeyBytes+blockKeyBytes,
	)
	if err != nil {
		panic(fmt.Sprintf("derive session cookie keys: %v", err))
	}

	return keys[:hashKeyBytes], keys[hashKeyBytes:]
}

func newInternalPasswordSecret(sessionSecret string) []byte {
	sessionSecret = strings.TrimSpace(sessionSecret)
	if sessionSecret != "" {
		return []byte(sessionSecret)
	}

	secret := securecookie.GenerateRandomKey(32)
	if len(secret) == 0 {
		panic("generate internal password fallback secret: entropy unavailable")
	}
	return secret
}

// EncodeSessionCookieValue encodes a session into a securecookie value.
// Exported so tests can mint cookies without going through the login flow.
func (g *Gateway) EncodeSessionCookieValue(s Session) (string, error) {
	return g.SecureCookie.Encode(SessionCookieName, s)
}

// decodeSessionCookieValue decodes a cookie value back into a Session, or
// returns an error if the value is missing, tampered with, or expired by
// gorilla/securecookie's MaxAge.
func (g *Gateway) decodeSessionCookieValue(value string) (Session, error) {
	var s Session
	if err := g.SecureCookie.Decode(SessionCookieName, value, &s); err != nil {
		return Session{}, err
	}
	return s, nil
}

// currentSession decodes the session cookie attached to r, returning the
// session and true if the cookie is present and well-formed. Expiry is
// enforced inside the cookie codec (gorilla/securecookie's MaxAge), which
// returns a decode error once the cookie is older than the configured
// lifetime — there is no server-side store.
func (g *Gateway) currentSession(r *http.Request) (Session, bool) {
	return g.readSessionCookie(r)
}

// readSessionCookie returns the decoded session value from the request's
// session cookie, or false if the cookie is missing or fails verification.
func (g *Gateway) readSessionCookie(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return Session{}, false
	}
	s, err := g.decodeSessionCookieValue(cookie.Value)
	if err != nil {
		return Session{}, false
	}
	return s, true
}

// setSessionCookie encodes s and writes it as the gateway session cookie.
// The browser MaxAge mirrors gorilla/securecookie's MaxAge so the browser
// drops the cookie at the same moment the gateway stops accepting it.
func (g *Gateway) setSessionCookie(w http.ResponseWriter, r *http.Request, s Session) error {
	encoded, err := g.EncodeSessionCookieValue(s)
	if err != nil {
		// Encoding only fails if the codec is misconfigured; surface as a
		// server error rather than silently dropping the session cookie.
		http.Error(w, "failed to encode session cookie", http.StatusInternalServerError)
		return err
	}
	// #nosec G124 -- Secure is enabled for HTTPS and for explicit upstream TLS termination deployments.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   g.sessionCookieSecure(r),
		MaxAge:   g.sessionMaxAge,
	})
	return nil
}

func sessionCookieMaxAgeSeconds(sessionTTL time.Duration) int {
	if sessionTTL <= 0 {
		sessionTTL = appconfig.DefaultSessionTTL
	}
	seconds := int(sessionTTL / time.Second)
	if sessionTTL%time.Second != 0 {
		seconds++
	}
	return seconds
}

func (g *Gateway) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- Secure mirrors setSessionCookie so local HTTP development can still clear sessions correctly.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   g.sessionCookieSecure(r),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (g *Gateway) sessionCookieSecure(r *http.Request) bool {
	return r.TLS != nil || g.Client.Config.ForceSecureCookies
}

func hasSessionCookie(r *http.Request) bool {
	if r == nil {
		return false
	}
	_, err := r.Cookie(SessionCookieName)
	return err == nil
}

// BuildBasicAuthorization returns a Basic Auth header value for the credentials.
func BuildBasicAuthorization(username, password string) string {
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + token
}

// internalUserPassword derives the Elasticsearch native-user password used by
// Kibana proxy sessions. It is stable for the same gateway secret and username
// so concurrent browser sessions for one user keep sharing valid credentials.
func (g *Gateway) internalUserPassword(username string) string {
	mac := hmac.New(sha256.New, g.passwordSecret)
	_, _ = mac.Write([]byte("elasticgateway internal user password\x00"))
	_, _ = mac.Write([]byte(strings.TrimSpace(username)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
