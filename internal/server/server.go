// Package server wires the HTTP routes, login flow, ingest API, and proxy.
package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/define42/elasticgateway/internal/authz"
	"github.com/define42/elasticgateway/internal/elastic"
	"github.com/define42/elasticgateway/internal/ingest"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
	"github.com/gorilla/securecookie"
)

// Session is the value carried inside the encrypted session cookie. It holds
// every per-request fact the gateway needs to authorize the user and proxy
// Kibana, so the gateway can scale horizontally without a shared session
// store: the cookie itself is the session. Expiry is enforced by
// gorilla/securecookie's MaxAge (default 24h) at decode time, so no timing
// fields are tracked here.
type Session struct {
	User       *authz.User
	Access     []authz.Access
	AuthHeader string
}

// SessionCookieName is the cookie that carries the gateway session token.
const SessionCookieName = "elasticgateway_session"

var (
	errIngestAuthRequired = errors.New("ingest authentication required")
	errIngestForbidden    = errors.New("ingest user is not allowed to write to this index")
)

// AuthenticateFunc validates credentials and returns the resolved LDAP access.
type AuthenticateFunc func(string, string) (*authz.User, []authz.Access, error)

// Gateway serves the login flow, ingest API, and Kibana reverse proxy.
type Gateway struct {
	Client          *elastic.Client
	Authenticate    AuthenticateFunc
	IngestAuthCache *ingest.AuthCache
	SecureCookie    *securecookie.SecureCookie
}

// LoginPageData is the template model for the login form.
type LoginPageData struct {
	Error    string
	Username string
}

// IngestResponse is returned to clients after a successful ingest request.
type IngestResponse struct {
	Result       string `json:"result"`
	WriteAlias   string `json:"write_alias"`
	DocumentID   string `json:"document_id"`
	Bootstrapped bool   `json:"bootstrapped"`
}

// ErrorResponse is the JSON error envelope used by the gateway.
type ErrorResponse struct {
	Error string `json:"error"`
}

// New constructs a gateway with the provided client and authenticator.
func New(client *elastic.Client, authenticate AuthenticateFunc) *Gateway {
	if authenticate == nil {
		authenticate = func(_, _ string) (*authz.User, []authz.Access, error) {
			return nil, nil, ldappkg.ErrInvalidCredentials
		}
	}

	return &Gateway{
		Client:          client,
		Authenticate:    authenticate,
		IngestAuthCache: ingest.NewAuthCache(),
		SecureCookie:    newSecureCookie(client.Config.SessionSecret),
	}
}

// newSecureCookie builds a securecookie codec. With no configured secret,
// keys are generated per process so cookies do not survive a restart.
func newSecureCookie(sessionSecret string) *securecookie.SecureCookie {
	sessionSecret = strings.TrimSpace(sessionSecret)
	if sessionSecret != "" {
		return securecookie.New(
			deriveSessionHashKey(sessionSecret),
			deriveSessionBlockKey(sessionSecret),
		).MaxAge(sessionCookieMaxAgeSeconds)
	}

	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)
	return securecookie.New(hashKey, blockKey).MaxAge(sessionCookieMaxAgeSeconds)
}

func deriveSessionHashKey(sessionSecret string) []byte {
	sum := sha512.Sum512([]byte("elasticgateway session hash\x00" + sessionSecret))
	return sum[:]
}

func deriveSessionBlockKey(sessionSecret string) []byte {
	sum := sha256.Sum256([]byte("elasticgateway session block\x00" + sessionSecret))
	return sum[:]
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

// Handler builds the HTTP mux for the gateway routes.
func (g *Gateway) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleRoot)
	mux.HandleFunc("/login", g.handleLogin)
	mux.HandleFunc("/logout", g.handleLogout)
	mux.HandleFunc("/kibana", g.HandleKibana)
	mux.HandleFunc("/kibana/", g.HandleKibana)
	mux.HandleFunc("/demo", g.handleDemo)
	mux.HandleFunc("/ingest", g.handleIngest)
	mux.HandleFunc("/ingest/", g.handleIngest)
	return mux
}

func (g *Gateway) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if sessionData, ok := g.currentSession(r); ok {
			http.Redirect(w, r, kibanaLandingPath(sessionData.Access), http.StatusSeeOther)
			return
		}
		g.RenderLoginPage(w, http.StatusOK, LoginPageData{})
	case http.MethodPost:
		g.handleLoginSubmit(w, r)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/logout" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if sessionData, ok := g.currentSession(r); ok && sessionData.User != nil {
		// Best-effort: drop this instance's LDAP basic-auth cache for the
		// logged-out user. With multiple gateways behind a load balancer,
		// peers still have their own caches until those entries expire.
		g.IngestAuthCache.ForgetUser(sessionData.User.Name)
	}

	g.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleKibana proxies authenticated requests to Kibana.
func (g *Gateway) HandleKibana(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/kibana" && !strings.HasPrefix(r.URL.Path, "/kibana/") {
		http.NotFound(w, r)
		return
	}

	if isKibanaLogoutPath(r.URL.Path) {
		g.handleKibanaLogout(w, r)
		return
	}

	sessionData, ok := g.currentSession(r)
	if !ok {
		g.clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := g.proxyKibana(w, r, sessionData); err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Kibana proxy failed: %v", err))
	}
}

func (g *Gateway) handleKibanaLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if sessionData, ok := g.currentSession(r); ok && sessionData.User != nil {
		g.IngestAuthCache.ForgetUser(sessionData.User.Name)
	}

	g.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func isKibanaLogoutPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	switch path {
	case "/kibana/auth/logout", "/kibana/logout", "/kibana/api/security/logout", "/kibana/security/logout":
		return true
	default:
		return strings.HasPrefix(path, "/kibana/s/") &&
			(strings.HasSuffix(path, "/auth/logout") ||
				strings.HasSuffix(path, "/logout") ||
				strings.HasSuffix(path, "/api/security/logout") ||
				strings.HasSuffix(path, "/security/logout"))
	}
}

func (g *Gateway) handleDemo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/demo" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	serveDemoPage(w)
}

func (g *Gateway) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		g.RenderLoginPage(w, http.StatusBadGateway, LoginPageData{Error: "failed to read login form"})
		return
	}

	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		g.RenderLoginPage(w, http.StatusUnauthorized, LoginPageData{
			Error:    "username and password are required",
			Username: username,
		})
		return
	}

	user, access, err := g.Authenticate(username, password)
	if err != nil {
		status, message := loginErrorResponse(err)
		g.RenderLoginPage(w, status, LoginPageData{
			Error:    message,
			Username: username,
		})
		return
	}

	internalPassword, err := generateInternalUserPassword()
	if err != nil {
		g.RenderLoginPage(w, http.StatusBadGateway, LoginPageData{
			Error:    "failed to allocate session credentials",
			Username: username,
		})
		return
	}

	if err := g.Client.ProvisionLoginUser(r.Context(), username, internalPassword, access); err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, elastic.ErrReservedNativeUser) {
			status = http.StatusForbidden
		}
		g.RenderLoginPage(w, status, LoginPageData{
			Error:    err.Error(),
			Username: username,
		})
		return
	}

	g.setSessionCookie(w, r, Session{
		User:       user,
		Access:     access,
		AuthHeader: BuildBasicAuthorization(username, internalPassword),
	})
	http.Redirect(w, r, kibanaLandingPath(access), http.StatusSeeOther)
}

func (g *Gateway) handleIngest(w http.ResponseWriter, r *http.Request) {
	indexName, err := ingest.ParsePath(r.URL.Path)
	if err != nil {
		writeIngestPathError(w, r, err)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	spaceName, err := g.authorizeIngestRequest(r, indexName)
	if err != nil {
		writeIngestAuthError(w, err)
		return
	}

	document, writeAlias, status, err := decodeIngestDocument(r, indexName)
	if err != nil {
		writeErrorJSON(w, status, err.Error())
		return
	}

	if err := g.Client.EnsureKibanaDataView(r.Context(), spaceName, indexName); err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Kibana setup failed: %v", err))
		return
	}

	bootstrapped, err := g.Client.EnsureWriteAlias(r.Context(), writeAlias)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Elasticsearch bootstrap failed: %v", err))
		return
	}

	indexed, err := g.Client.IndexDocument(r.Context(), writeAlias, document)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Elasticsearch ingest failed: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, IngestResponse{
		Result:       indexed.Result,
		WriteAlias:   writeAlias,
		DocumentID:   indexed.ID,
		Bootstrapped: bootstrapped,
	})
}

// RenderLoginPage writes the login page with the supplied status and model.
func (g *Gateway) RenderLoginPage(w http.ResponseWriter, status int, data LoginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := loginPageTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render login page", http.StatusInternalServerError)
	}
}

func loginErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, ldappkg.ErrInvalidCredentials), errors.Is(err, ldappkg.ErrUserNotFound):
		return http.StatusUnauthorized, "invalid username or password"
	case errors.Is(err, ldappkg.ErrUnauthorized):
		return http.StatusForbidden, "your LDAP account does not grant access to Kibana"
	default:
		return http.StatusBadGateway, fmt.Sprintf("LDAP authentication failed: %v", err)
	}
}

func (g *Gateway) authorizeIngestRequest(r *http.Request, indexName string) (string, error) {
	access, err := g.ingestAccess(r)
	if err != nil {
		return "", err
	}
	namespace, ok := authz.ResolveIngestWriteNamespace(access, indexName)
	if !ok {
		return "", errIngestForbidden
	}
	return namespace, nil
}

func (g *Gateway) ingestAccess(r *http.Request) ([]authz.Access, error) {
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		if sessionData, ok := g.currentSession(r); ok {
			return sessionData.Access, nil
		}
		return nil, errIngestAuthRequired
	}

	username, password, ok := r.BasicAuth()
	if !ok || strings.TrimSpace(username) == "" || password == "" {
		return nil, errIngestAuthRequired
	}

	_, access, _, err := g.IngestAuthCache.Resolve(ingest.AuthCacheKey(strings.TrimSpace(username), password), func() (string, []authz.Access, error) {
		return g.lookupIngestAccess(strings.TrimSpace(username), password)
	})
	if err != nil {
		return nil, err
	}
	return access, nil
}

func (g *Gateway) lookupIngestAccess(username, password string) (string, []authz.Access, error) {
	user, access, err := g.Authenticate(username, password)
	if err != nil {
		return "", nil, err
	}

	cachedUsername := username
	if user != nil && strings.TrimSpace(user.Name) != "" {
		cachedUsername = strings.TrimSpace(user.Name)
	}
	return cachedUsername, access, nil
}

func writeIngestPathError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ingest.ErrRouteNotFound) {
		http.NotFound(w, r)
		return
	}
	writeErrorJSON(w, http.StatusBadRequest, err.Error())
}

func writeIngestAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errIngestAuthRequired), errors.Is(err, ldappkg.ErrInvalidCredentials), errors.Is(err, ldappkg.ErrUserNotFound):
		writeIngestAuthRequired(w, "LDAP username and password are required for ingest")
	case errors.Is(err, ldappkg.ErrUnauthorized), errors.Is(err, errIngestForbidden):
		writeErrorJSON(w, http.StatusForbidden, "your LDAP account is not allowed to ingest into this index")
	default:
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("LDAP authentication failed: %v", err))
	}
}

func decodeIngestDocument(r *http.Request, indexName string) (map[string]any, string, int, error) {
	mediaType := strings.TrimSpace(r.Header.Get("Content-Type"))
	contentType, _, err := mimeParse(mediaType)
	if err != nil || contentType != "application/json" {
		return nil, "", http.StatusUnsupportedMediaType, errors.New("content type must be application/json")
	}

	document, err := ingest.DecodeJSONObject(r.Body)
	if err != nil {
		return nil, "", http.StatusBadRequest, err
	}

	eventTime, err := ingest.ParseEventTime(document)
	if err != nil {
		return nil, "", http.StatusBadRequest, err
	}

	writeAlias := ingest.BuildWriteAlias(indexName, eventTime)
	firstIndex := ingest.BuildFirstBackingIndex(writeAlias)
	if len(writeAlias) > ingest.MaxIndexNameBytes || len(firstIndex) > ingest.MaxIndexNameBytes {
		return nil, "", http.StatusBadRequest, errors.New("generated alias or backing index name exceeds Elasticsearch limits")
	}

	document["event_time"] = eventTime.UTC().Format(time.RFC3339)
	return document, writeAlias, 0, nil
}

func mimeParse(mediaType string) (string, map[string]string, error) {
	return mime.ParseMediaType(mediaType)
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
func (g *Gateway) setSessionCookie(w http.ResponseWriter, r *http.Request, s Session) {
	encoded, err := g.EncodeSessionCookieValue(s)
	if err != nil {
		// Encoding only fails if the codec is misconfigured; surface as a
		// server error rather than silently dropping the session cookie.
		http.Error(w, "failed to encode session cookie", http.StatusInternalServerError)
		return
	}
	// #nosec G124 -- Secure is intentionally enabled only for HTTPS so local HTTP development remains usable.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   sessionCookieMaxAgeSeconds,
	})
}

// sessionCookieMaxAgeSeconds is the shared browser-side and server-side
// session lifetime, so the browser drops the cookie when the gateway stops
// accepting it.
const sessionCookieMaxAgeSeconds = 86400

func (g *Gateway) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- Secure mirrors setSessionCookie so local HTTP development can still clear sessions correctly.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// BuildBasicAuthorization returns a Basic Auth header value for the credentials.
func BuildBasicAuthorization(username, password string) string {
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + token
}

// generateInternalUserPassword returns a random password used as the
// per-session Elasticsearch native-user password. The LDAP password is never
// stored in Elasticsearch; only this generated value is embedded in the
// encrypted session cookie's basic-auth header for the Kibana proxy.
func generateInternalUserPassword() (string, error) {
	b := make([]byte, 32)
	// io.ReadFull(rand.Reader, ...) returns errors normally, while rand.Read
	// fatals in Go 1.22+ — the former keeps the failure path testable.
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ForwardedProto reports the original request scheme for proxy headers.
func ForwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func kibanaLandingPath(access []authz.Access) string {
	effective := authz.NormalizeAccessByNamespace(access)
	if len(effective) == 0 || strings.TrimSpace(effective[0].Namespace) == "" {
		return "/kibana/app/home"
	}
	return "/kibana/s/" + url.PathEscape(effective[0].Namespace) + "/app/home"
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{Error: message})
}

func writeIngestAuthRequired(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="ElasticGateway ingest"`)
	writeErrorJSON(w, http.StatusUnauthorized, message)
}
