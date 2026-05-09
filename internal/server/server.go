// Package server wires the HTTP routes, login flow, ingest API, and proxy.
package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/define42/elasticgateway/internal/authz"
	appconfig "github.com/define42/elasticgateway/internal/config"
	"github.com/define42/elasticgateway/internal/elastic"
	"github.com/define42/elasticgateway/internal/ingest"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/hkdf"
)

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

const (
	// SessionCookieName is the cookie that carries the gateway session token.
	SessionCookieName              = "elasticgateway_session"
	gatewayBasePath                = "/elasticgateway"
	gatewayLoginPath               = gatewayBasePath + "/login"
	gatewayLogoutPath              = gatewayBasePath + "/logout"
	gatewayDemoPath                = gatewayBasePath + "/demo"
	gatewayIngestPath              = gatewayBasePath + "/ingest"
	gatewayHealthzPath             = gatewayBasePath + "/healthz"
	gatewayReadyzPath              = gatewayBasePath + "/readyz"
	invalidLoginCredentialsMessage = "invalid username or password"
	upstreamErrorMessage           = "upstream error, see logs"
	maxIngestRequestBodyBytes      = int64(512 * 1024 * 1024)
)

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
	Logger          *slog.Logger
	kibanaTarget    *url.URL
	kibanaTargetErr error
	passwordSecret  []byte
	sessionMaxAge   int
}

// LoginPageData is the template model for the login form.
type LoginPageData struct {
	Error    string
	Username string
	Next     string
}

// IngestResponse is returned to clients after a successful ingest request.
type IngestResponse struct {
	Result       string `json:"result"`
	WriteAlias   string `json:"write_alias"`
	DocumentID   string `json:"document_id"`
	Bootstrapped bool   `json:"bootstrapped"`
}

// BulkIngestResponse is returned after a successful bulk ingest request.
type BulkIngestResponse struct {
	Took                int                                 `json:"took,omitempty"`
	Errors              bool                                `json:"errors"`
	Documents           int                                 `json:"documents"`
	WriteAliases        []string                            `json:"write_aliases"`
	BootstrappedAliases []string                            `json:"bootstrapped_write_aliases,omitempty"`
	Items               []map[string]elastic.BulkItemResult `json:"items"`
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

	kibanaTarget, kibanaTargetErr := url.Parse(client.Config.KibanaURL)
	sessionMaxAge := sessionCookieMaxAgeSeconds(client.Config.SessionTTL)

	return &Gateway{
		Client:          client,
		Authenticate:    authenticate,
		IngestAuthCache: ingest.NewAuthCache(),
		SecureCookie:    newSecureCookie(client.Config.SessionSecret, sessionMaxAge),
		kibanaTarget:    kibanaTarget,
		kibanaTargetErr: kibanaTargetErr,
		passwordSecret:  newInternalPasswordSecret(client.Config.SessionSecret),
		sessionMaxAge:   sessionMaxAge,
	}
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

	keys := make([]byte, hashKeyBytes+blockKeyBytes)
	keyStream := hkdf.New(
		sha256.New,
		[]byte(sessionSecret),
		nil,
		[]byte("elasticgateway session cookie keys"),
	)
	if _, err := io.ReadFull(keyStream, keys); err != nil {
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

// Handler builds the HTTP mux for the gateway routes.
func (g *Gateway) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(gatewayHealthzPath, g.handleHealthz)
	mux.HandleFunc(gatewayReadyzPath, g.handleReadyz)
	mux.HandleFunc(gatewayLoginPath, g.handleLogin)
	mux.HandleFunc(gatewayLogoutPath, g.handleLogout)
	mux.HandleFunc(gatewayDemoPath, g.handleDemo)
	mux.HandleFunc(gatewayIngestPath, g.handleIngest)
	mux.HandleFunc(gatewayIngestPath+"/", g.handleIngest)
	mux.HandleFunc(gatewayBasePath, g.handleGatewayNotFound)
	mux.HandleFunc(gatewayBasePath+"/", g.handleGatewayNotFound)
	mux.HandleFunc("/", g.handleRoot)
	return mux
}

func (g *Gateway) handleRoot(w http.ResponseWriter, r *http.Request) {
	g.HandleKibana(w, r)
}

func (g *Gateway) handleGatewayNotFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != gatewayLoginPath {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		next := loginNextFromQuery(r)
		if _, ok := g.currentSession(r); ok {
			redirectToLocalPath(w, next, http.StatusSeeOther)
			return
		}
		if hasSessionCookie(r) {
			g.clearSessionCookie(w, r)
		}
		g.RenderLoginPage(w, http.StatusOK, LoginPageData{Next: next})
	case http.MethodPost:
		g.handleLoginSubmit(w, r)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != gatewayLogoutPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	sessionData, sessionOK := g.currentSession(r)
	if sessionOK && sessionData.User != nil {
		// Best-effort: drop this instance's LDAP basic-auth cache for the
		// logged-out user. With multiple gateways behind a load balancer,
		// peers still have their own caches until those entries expire.
		g.IngestAuthCache.ForgetUser(sessionData.User.Name)
	}
	g.logLogout(r, sessionData, sessionOK)

	g.clearSessionCookie(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleKibana proxies authenticated requests to Kibana.
func (g *Gateway) HandleKibana(w http.ResponseWriter, r *http.Request) {
	if isGatewayPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}

	if isKibanaLogoutPath(r.URL.Path) {
		g.handleKibanaLogout(w, r)
		return
	}

	sessionData, ok := g.currentSession(r)
	if !ok {
		if hasSessionCookie(r) {
			g.clearSessionCookie(w, r)
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			g.RenderLoginPage(w, http.StatusOK, LoginPageData{Next: loginNextForRequest(r)})
			return
		}
		writeErrorJSON(w, http.StatusUnauthorized, "gateway login required")
		return
	}

	if err := g.proxyKibana(w, r, sessionData); err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "kibana_proxy", err)
	}
}

func (g *Gateway) handleKibanaLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	sessionData, sessionOK := g.currentSession(r)
	if sessionOK && sessionData.User != nil {
		g.IngestAuthCache.ForgetUser(sessionData.User.Name)
	}
	g.logLogout(r, sessionData, sessionOK)

	g.clearSessionCookie(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func isKibanaLogoutPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	switch path {
	case "/auth/logout", "/logout", "/api/security/logout", "/security/logout":
		return true
	default:
		if !strings.HasPrefix(path, "/s/") {
			return false
		}
		spacePath := strings.TrimPrefix(path, "/s/")
		_, rest, ok := strings.Cut(spacePath, "/")
		if !ok {
			return false
		}
		return rest == "auth/logout" ||
			rest == "logout" ||
			rest == "api/security/logout" ||
			rest == "security/logout" ||
			strings.HasSuffix(rest, "/auth/logout") ||
			strings.HasSuffix(rest, "/logout") ||
			strings.HasSuffix(rest, "/api/security/logout") ||
			strings.HasSuffix(rest, "/security/logout")
	}
}

func isGatewayPath(path string) bool {
	return path == gatewayBasePath || strings.HasPrefix(path, gatewayBasePath+"/")
}

func loginNextForRequest(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	return sanitizeLoginNext(r.URL.RequestURI())
}

func loginNextFromQuery(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	return sanitizeLoginNext(r.URL.Query().Get("next"))
}

func sanitizeLoginNext(next string) string {
	next = strings.TrimSpace(next)
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") || hasControlCharacter(next) {
		return "/"
	}

	parsed, err := url.Parse(next)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Path == "" || isGatewayPath(parsed.Path) {
		return "/"
	}
	if parsed.Path[0] != '/' {
		return "/"
	}
	return parsed.RequestURI()
}

func redirectToLocalPath(w http.ResponseWriter, next string, status int) {
	w.Header().Set("Location", sanitizeLoginNext(next))
	w.WriteHeader(status)
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func hasSessionCookie(r *http.Request) bool {
	if r == nil {
		return false
	}
	_, err := r.Cookie(SessionCookieName)
	return err == nil
}

func gatewayIngestRequestPath(path string) string {
	if path == gatewayIngestPath {
		return "/ingest"
	}
	if strings.HasPrefix(path, gatewayIngestPath+"/") {
		return "/ingest" + strings.TrimPrefix(path, gatewayIngestPath)
	}
	return path
}

func (g *Gateway) handleDemo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != gatewayDemoPath {
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
		g.logLoginFailure(r, "", http.StatusBadRequest, "invalid_form", err)
		g.RenderLoginPage(w, http.StatusBadRequest, LoginPageData{Error: "failed to read login form", Next: "/"})
		return
	}

	next := sanitizeLoginNext(r.Form.Get("next"))
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		g.logLoginFailure(r, username, http.StatusUnauthorized, "missing_credentials", nil)
		g.renderLoginError(w, http.StatusUnauthorized, "username and password are required", username, next)
		return
	}

	user, access, err := g.Authenticate(username, password)
	if err != nil {
		status, message := loginErrorResponse(err)
		g.logLoginFailure(r, username, status, loginFailureReason(err), err)
		g.renderLoginError(w, status, message, username, next)
		return
	}

	internalPassword := g.internalUserPassword(username)

	if err := g.Client.ProvisionLoginUser(r.Context(), username, internalPassword, access); err != nil {
		status := http.StatusBadGateway
		message := "failed to prepare login session"
		if errors.Is(err, elastic.ErrReservedNativeUser) {
			status = http.StatusForbidden
			message = "this account cannot be used for gateway login"
		}
		g.logLoginFailure(r, username, status, provisionLoginFailureReason(err), err)
		g.renderLoginError(w, status, message, username, next)
		return
	}

	if err := g.setSessionCookie(w, r, Session{
		User:       user,
		Access:     access,
		AuthHeader: BuildBasicAuthorization(username, internalPassword),
	}); err != nil {
		g.logLoginFailure(r, username, http.StatusInternalServerError, "session_cookie_error", err)
		return
	}
	g.logLoginSuccess(r, username, user, access)
	redirectToLocalPath(w, next, http.StatusSeeOther)
}

func (g *Gateway) renderLoginError(w http.ResponseWriter, status int, message, username, next string) {
	g.RenderLoginPage(w, status, LoginPageData{
		Error:    message,
		Username: username,
		Next:     next,
	})
}

func (g *Gateway) handleIngest(w http.ResponseWriter, r *http.Request) {
	ingestPath := gatewayIngestRequestPath(r.URL.Path)
	if isBulkIngestPath(ingestPath) {
		g.handleBulkIngest(w, r, ingestPath)
		return
	}

	indexName, err := ingest.ParsePath(ingestPath)
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
		g.writeIngestAuthError(w, r, err)
		return
	}

	document, writeAlias, status, err := decodeIngestDocument(w, r, indexName)
	if err != nil {
		writeErrorJSON(w, status, err.Error())
		return
	}

	if err := g.Client.EnsureKibanaDataView(r.Context(), spaceName, indexName); err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "kibana_setup", err)
		return
	}

	bootstrapped, err := g.Client.EnsureWriteAlias(r.Context(), writeAlias)
	if err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "elasticsearch_bootstrap", err)
		return
	}

	indexed, err := g.Client.IndexDocument(r.Context(), writeAlias, document)
	if err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "elasticsearch_ingest", err)
		return
	}

	writeJSON(w, http.StatusCreated, IngestResponse{
		Result:       indexed.Result,
		WriteAlias:   writeAlias,
		DocumentID:   indexed.ID,
		Bootstrapped: bootstrapped,
	})
}

func (g *Gateway) handleBulkIngest(w http.ResponseWriter, r *http.Request, ingestPath string) {
	indexName, err := ingest.ParseBulkPath(ingestPath)
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
		g.writeIngestAuthError(w, r, err)
		return
	}

	documents, status, err := decodeBulkIngestDocuments(w, r, indexName)
	if err != nil {
		writeErrorJSON(w, status, err.Error())
		return
	}

	if err := g.Client.EnsureKibanaDataView(r.Context(), spaceName, indexName); err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "kibana_setup", err)
		return
	}

	aliases := bulkWriteAliases(documents)
	bootstrappedAliases := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		bootstrapped, err := g.Client.EnsureWriteAlias(r.Context(), alias)
		if err != nil {
			g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "elasticsearch_bootstrap", err)
			return
		}
		if bootstrapped {
			bootstrappedAliases = append(bootstrappedAliases, alias)
		}
	}

	indexed, err := g.Client.BulkIndexDocuments(r.Context(), documents)
	if err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "elasticsearch_bulk_ingest", err)
		return
	}

	writeJSON(w, http.StatusOK, BulkIngestResponse{
		Took:                indexed.Took,
		Errors:              indexed.Errors,
		Documents:           len(documents),
		WriteAliases:        aliases,
		BootstrappedAliases: bootstrappedAliases,
		Items:               indexed.Items,
	})
}

// RenderLoginPage writes the login page with the supplied status and model.
func (g *Gateway) RenderLoginPage(w http.ResponseWriter, status int, data LoginPageData) {
	var page bytes.Buffer
	if err := loginPageTemplate.Execute(&page, data); err != nil {
		http.Error(w, "failed to render login page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(page.Bytes())
}

func loginErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, ldappkg.ErrInvalidCredentials),
		errors.Is(err, ldappkg.ErrUserNotFound),
		errors.Is(err, ldappkg.ErrUnauthorized):
		return http.StatusUnauthorized, invalidLoginCredentialsMessage
	default:
		return http.StatusBadGateway, "LDAP authentication failed"
	}
}

func loginFailureReason(err error) string {
	switch {
	case errors.Is(err, ldappkg.ErrInvalidCredentials),
		errors.Is(err, ldappkg.ErrUserNotFound):
		return "invalid_credentials"
	case errors.Is(err, ldappkg.ErrUnauthorized):
		return "unauthorized"
	default:
		return "ldap_error"
	}
}

func provisionLoginFailureReason(err error) string {
	if errors.Is(err, elastic.ErrReservedNativeUser) {
		return "reserved_user"
	}
	return "provisioning_error"
}

func (g *Gateway) logLoginSuccess(r *http.Request, submittedUsername string, user *authz.User, access []authz.Access) {
	attrs := []any{
		slog.String("event", "user_login"),
		slog.String("username", loginLogUsername(submittedUsername, user)),
		slog.Int("http_status", http.StatusSeeOther),
		slog.Any("namespaces", accessNamespaces(access)),
	}
	attrs = append(attrs, g.requestLogAttrs(r)...)

	g.logger().InfoContext(r.Context(), "user login", attrs...)
}

func (g *Gateway) logLoginFailure(r *http.Request, username string, status int, reason string, err error) {
	attrs := []any{
		slog.String("event", "user_login_failed"),
		slog.String("username", strings.TrimSpace(username)),
		slog.Int("http_status", status),
		slog.String("reason", reason),
	}
	attrs = append(attrs, g.requestLogAttrs(r)...)
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}

	g.logger().WarnContext(r.Context(), "user login failed", attrs...)
}

func (g *Gateway) writeUpstreamErrorJSON(w http.ResponseWriter, r *http.Request, status int, operation string, err error) {
	g.logUpstreamFailure(r, status, operation, err)
	writeErrorJSON(w, status, upstreamErrorMessage)
}

func (g *Gateway) logUpstreamFailure(r *http.Request, status int, operation string, err error) {
	attrs := []any{
		slog.String("event", "upstream_request_failed"),
		slog.String("operation", operation),
		slog.Int("http_status", status),
		slog.String("client_error", upstreamErrorMessage),
	}
	if r != nil {
		attrs = append(attrs, g.requestLogAttrs(r)...)
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))

		var responseErr *elastic.ResponseError
		if errors.As(err, &responseErr) {
			attrs = append(attrs, slog.Group("upstream",
				slog.String("method", responseErr.Method),
				slog.String("path", responseErr.Path),
				slog.Int("status", responseErr.StatusCode),
				slog.String("body", responseErr.Body),
			))
		}
	}

	if r != nil {
		g.logger().WarnContext(r.Context(), "upstream request failed", attrs...)
		return
	}
	g.logger().Warn("upstream request failed", attrs...)
}

func (g *Gateway) logLogout(r *http.Request, sessionData Session, authenticated bool) {
	attrs := []any{
		slog.String("event", "user_logout"),
		slog.String("username", sessionLogUsername(sessionData)),
		slog.Bool("authenticated", authenticated),
		slog.Int("http_status", http.StatusSeeOther),
	}
	attrs = append(attrs, g.requestLogAttrs(r)...)

	g.logger().InfoContext(r.Context(), "user logout", attrs...)
}

func (g *Gateway) logger() *slog.Logger {
	if g == nil || g.Logger == nil {
		return slog.Default()
	}
	return g.Logger
}

func loginLogUsername(submittedUsername string, user *authz.User) string {
	if user != nil && strings.TrimSpace(user.Name) != "" {
		return strings.TrimSpace(user.Name)
	}
	return strings.TrimSpace(submittedUsername)
}

func sessionLogUsername(sessionData Session) string {
	if sessionData.User == nil {
		return ""
	}
	return strings.TrimSpace(sessionData.User.Name)
}

func accessNamespaces(access []authz.Access) []string {
	effective := authz.NormalizeAccessByNamespace(access)
	namespaces := make([]string, 0, len(effective))
	for _, item := range effective {
		namespace := strings.TrimSpace(item.Namespace)
		if namespace != "" {
			namespaces = append(namespaces, namespace)
		}
	}
	return namespaces
}

func (g *Gateway) requestLogAttrs(r *http.Request) []any {
	attrs := []any{
		slog.String("method", r.Method),
		slog.String("client_ip", g.clientIP(r)),
		slog.String("remote_addr", r.RemoteAddr),
	}
	if r.URL != nil {
		attrs = append(attrs, slog.String("path", r.URL.Path))
	}
	return attrs
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

func (g *Gateway) writeIngestAuthError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errIngestAuthRequired), errors.Is(err, ldappkg.ErrInvalidCredentials), errors.Is(err, ldappkg.ErrUserNotFound):
		writeIngestAuthRequired(w, "LDAP username and password are required for ingest")
	case errors.Is(err, ldappkg.ErrUnauthorized), errors.Is(err, errIngestForbidden):
		writeErrorJSON(w, http.StatusForbidden, "your LDAP account is not allowed to ingest into this index")
	default:
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "ldap_authentication", err)
	}
}

func isBulkIngestPath(path string) bool {
	return strings.HasSuffix(strings.TrimSuffix(path, "/"), "/_bulk")
}

func decodeIngestDocument(w http.ResponseWriter, r *http.Request, indexName string) (map[string]any, string, int, error) {
	return decodeIngestDocumentWithLimit(w, r, indexName, maxIngestRequestBodyBytes)
}

func decodeIngestDocumentWithLimit(w http.ResponseWriter, r *http.Request, indexName string, maxBodyBytes int64) (map[string]any, string, int, error) {
	mediaType := strings.TrimSpace(r.Header.Get("Content-Type"))
	contentType, _, err := mime.ParseMediaType(mediaType)
	if err != nil || contentType != "application/json" {
		return nil, "", http.StatusUnsupportedMediaType, errors.New("content type must be application/json")
	}

	body, err := limitedIngestBody(w, r, maxBodyBytes)
	if err != nil {
		return nil, "", http.StatusRequestEntityTooLarge, err
	}

	document, err := ingest.DecodeJSONObject(body)
	if err != nil {
		if isRequestBodyTooLarge(err) {
			return nil, "", http.StatusRequestEntityTooLarge, requestBodyTooLargeError(maxBodyBytes)
		}
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

func decodeBulkIngestDocuments(w http.ResponseWriter, r *http.Request, indexName string) ([]elastic.BulkIndexDocument, int, error) {
	return decodeBulkIngestDocumentsWithLimit(w, r, indexName, maxIngestRequestBodyBytes)
}

func decodeBulkIngestDocumentsWithLimit(w http.ResponseWriter, r *http.Request, indexName string, maxBodyBytes int64) ([]elastic.BulkIndexDocument, int, error) {
	mediaType := strings.TrimSpace(r.Header.Get("Content-Type"))
	contentType, _, err := mime.ParseMediaType(mediaType)
	if err != nil || contentType != "application/x-ndjson" {
		return nil, http.StatusUnsupportedMediaType, errors.New("content type must be application/x-ndjson")
	}

	body, err := limitedIngestBody(w, r, maxBodyBytes)
	if err != nil {
		return nil, http.StatusRequestEntityTooLarge, err
	}

	decoded, err := ingest.DecodeBulkNDJSON(body)
	if err != nil {
		if isRequestBodyTooLarge(err) {
			return nil, http.StatusRequestEntityTooLarge, requestBodyTooLargeError(maxBodyBytes)
		}
		return nil, http.StatusBadRequest, err
	}

	documents := make([]elastic.BulkIndexDocument, 0, len(decoded))
	for _, item := range decoded {
		writeAlias, err := normalizeIngestDocument(indexName, item.Document)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("bulk source line %d: %w", item.Line, err)
		}

		documents = append(documents, elastic.BulkIndexDocument{
			Action:   item.Action,
			Index:    writeAlias,
			Metadata: item.Metadata,
			Document: item.Document,
		})
	}
	return documents, 0, nil
}

func limitedIngestBody(w http.ResponseWriter, r *http.Request, maxBodyBytes int64) (io.Reader, error) {
	if r.ContentLength > maxBodyBytes {
		return nil, requestBodyTooLargeError(maxBodyBytes)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	return r.Body, nil
}

func isRequestBodyTooLarge(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

func requestBodyTooLargeError(maxBodyBytes int64) error {
	return fmt.Errorf("request body exceeds %s limit", byteLimitLabel(maxBodyBytes))
}

func byteLimitLabel(maxBodyBytes int64) string {
	const bytesPerMegabyte = 1024 * 1024
	if maxBodyBytes%bytesPerMegabyte == 0 {
		return fmt.Sprintf("%d MB", maxBodyBytes/bytesPerMegabyte)
	}
	return fmt.Sprintf("%d bytes", maxBodyBytes)
}

func normalizeIngestDocument(indexName string, document map[string]any) (string, error) {
	eventTime, err := ingest.ParseEventTime(document)
	if err != nil {
		return "", err
	}

	writeAlias := ingest.BuildWriteAlias(indexName, eventTime)
	firstIndex := ingest.BuildFirstBackingIndex(writeAlias)
	if len(writeAlias) > ingest.MaxIndexNameBytes || len(firstIndex) > ingest.MaxIndexNameBytes {
		return "", errors.New("generated alias or backing index name exceeds Elasticsearch limits")
	}

	document["event_time"] = eventTime.UTC().Format(time.RFC3339)
	return writeAlias, nil
}

func bulkWriteAliases(documents []elastic.BulkIndexDocument) []string {
	seen := make(map[string]struct{}, len(documents))
	for _, document := range documents {
		seen[document.Index] = struct{}{}
	}

	aliases := make([]string, 0, len(seen))
	for alias := range seen {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	return aliases
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

// ForwardedProto reports the direct request scheme for proxy headers.
func ForwardedProto(r *http.Request) string {
	return forwardedProto(r, false)
}

func forwardedProto(r *http.Request, forceSecure bool) string {
	if forceSecure {
		return "https"
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
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
