// Package server wires the HTTP routes, login flow, ingest API, and proxy.
package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	SessionCookieName                    = "elasticgateway_session"
	kibanaBasePath                       = "/kibana"
	invalidLoginCredentialsMessage       = "invalid username or password"
	maxIngestRequestBodyBytes      int64 = 512 * 1024 * 1024
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
	kibanaTarget    *url.URL
	kibanaTargetErr error
	sessionMaxAge   int
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
		sessionMaxAge:   sessionMaxAge,
	}
}

// newSecureCookie builds a securecookie codec. With no configured secret,
// keys are generated per process so cookies do not survive a restart.
func newSecureCookie(sessionSecret string, sessionMaxAge int) *securecookie.SecureCookie {
	sessionSecret = strings.TrimSpace(sessionSecret)
	if sessionSecret != "" {
		return securecookie.New(
			deriveSessionHashKey(sessionSecret),
			deriveSessionBlockKey(sessionSecret),
		).MaxAge(sessionMaxAge)
	}

	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)
	return securecookie.New(hashKey, blockKey).MaxAge(sessionMaxAge)
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
	mux.HandleFunc("/healthz", g.handleHealthz)
	mux.HandleFunc("/readyz", g.handleReadyz)
	mux.HandleFunc("/login", g.handleLogin)
	mux.HandleFunc("/logout", g.handleLogout)
	mux.HandleFunc(kibanaBasePath, g.HandleKibana)
	mux.HandleFunc(kibanaBasePath+"/", g.HandleKibana)
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
	if r.URL.Path != kibanaBasePath && !strings.HasPrefix(r.URL.Path, kibanaBasePath+"/") {
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
	case kibanaBasePath + "/auth/logout", kibanaBasePath + "/logout", kibanaBasePath + "/api/security/logout", kibanaBasePath + "/security/logout":
		return true
	default:
		return strings.HasPrefix(path, kibanaBasePath+"/s/") &&
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
		g.RenderLoginPage(w, http.StatusBadRequest, LoginPageData{Error: "failed to read login form"})
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
		message := "failed to prepare login session"
		if errors.Is(err, elastic.ErrReservedNativeUser) {
			status = http.StatusForbidden
			message = "this account cannot be used for gateway login"
		}
		log.Printf("failed to provision login user: %v", err)
		g.RenderLoginPage(w, status, LoginPageData{
			Error:    message,
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
	if isBulkIngestPath(r.URL.Path) {
		g.handleBulkIngest(w, r)
		return
	}

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

	document, writeAlias, status, err := decodeIngestDocument(w, r, indexName)
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

func (g *Gateway) handleBulkIngest(w http.ResponseWriter, r *http.Request) {
	indexName, err := ingest.ParseBulkPath(r.URL.Path)
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

	documents, status, err := decodeBulkIngestDocuments(w, r, indexName)
	if err != nil {
		writeErrorJSON(w, status, err.Error())
		return
	}

	if err := g.Client.EnsureKibanaDataView(r.Context(), spaceName, indexName); err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Kibana setup failed: %v", err))
		return
	}

	aliases := bulkWriteAliases(documents)
	bootstrappedAliases := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		bootstrapped, err := g.Client.EnsureWriteAlias(r.Context(), alias)
		if err != nil {
			writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Elasticsearch bootstrap failed: %v", err))
			return
		}
		if bootstrapped {
			bootstrappedAliases = append(bootstrappedAliases, alias)
		}
	}

	indexed, err := g.Client.BulkIndexDocuments(r.Context(), documents)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, fmt.Sprintf("Elasticsearch bulk ingest failed: %v", err))
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
		log.Printf("LDAP authentication failed: %v", err)
		return http.StatusBadGateway, "LDAP authentication failed"
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
func (g *Gateway) setSessionCookie(w http.ResponseWriter, r *http.Request, s Session) {
	encoded, err := g.EncodeSessionCookieValue(s)
	if err != nil {
		// Encoding only fails if the codec is misconfigured; surface as a
		// server error rather than silently dropping the session cookie.
		http.Error(w, "failed to encode session cookie", http.StatusInternalServerError)
		return
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

func kibanaLandingPath(access []authz.Access) string {
	effective := authz.NormalizeAccessByNamespace(access)
	if len(effective) == 0 || strings.TrimSpace(effective[0].Namespace) == "" {
		return kibanaBasePath + "/app/home"
	}
	return kibanaBasePath + "/s/" + url.PathEscape(effective[0].Namespace) + "/app/home"
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
