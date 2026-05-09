package server

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/define42/elasticgateway/internal/authz"
	"github.com/define42/elasticgateway/internal/elastic"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
)

const invalidLoginCredentialsMessage = "invalid username or password"

// LoginPageData is the template model for the login form.
type LoginPageData struct {
	Error    string
	Username string
	Next     string
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

func loginLogUsername(submittedUsername string, user *authz.User) string {
	if user != nil && strings.TrimSpace(user.Name) != "" {
		return strings.TrimSpace(user.Name)
	}
	return strings.TrimSpace(submittedUsername)
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
