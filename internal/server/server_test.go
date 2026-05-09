package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/define42/elasticgateway/internal/authz"
	appconfig "github.com/define42/elasticgateway/internal/config"
	elasticpkg "github.com/define42/elasticgateway/internal/elastic"
)

func TestSessionFormattingAndLoggingRedactsAuthHeader(t *testing.T) {
	authHeader := BuildBasicAuthorization("alice", "super-secret")
	sessionData := Session{
		User: &authz.User{Name: "alice"},
		Access: []authz.Access{
			{Group: "team1_user", Namespace: "team1", PullOnly: true},
		},
		AuthHeader: authHeader,
	}

	for _, formatted := range []string{
		sessionData.String(),
		fmt.Sprint(sessionData),
		fmt.Sprintf("%+v", sessionData),
		fmt.Sprintf("%#v", sessionData),
		fmt.Sprintf("%#v", &sessionData),
	} {
		if strings.Contains(formatted, authHeader) || strings.Contains(formatted, "super-secret") || strings.Contains(formatted, "Basic ") {
			t.Fatalf("session formatting leaked AuthHeader: %s", formatted)
		}
		if !strings.Contains(formatted, "<redacted>") {
			t.Fatalf("session formatting did not mark AuthHeader as redacted: %s", formatted)
		}
	}

	var output bytes.Buffer
	logger := testJSONLogger(&output)
	logger.Info("session", slog.Any("session", sessionData))

	logLine := output.String()
	if strings.Contains(logLine, authHeader) || strings.Contains(logLine, "super-secret") || strings.Contains(logLine, "Basic ") {
		t.Fatalf("session logging leaked AuthHeader: %s", logLine)
	}

	entry := onlyLogEntry(t, &output)
	loggedSession, ok := entry["session"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured session log value, got %#v", entry["session"])
	}
	if got := loggedSession["AuthHeader"]; got != "<redacted>" {
		t.Fatalf("expected redacted AuthHeader in session log, got %#v", got)
	}
}

func TestGatewayLogsLoginSuccessIgnoresSpoofedXForwardedForByDefault(t *testing.T) {
	var logOutput bytes.Buffer
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /_security/user/alice":
			http.NotFound(w, r)
		case "PUT /_security/role/gateway_team1_user":
			w.WriteHeader(http.StatusOK)
		case "PUT /_security/user/alice":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		ElasticsearchURL: elasticSearch.URL,
		HTTPClient:       elasticSearch.Client(),
	}), func(username, _ string) (*authz.User, []authz.Access, error) {
		return &authz.User{Name: username}, []authz.Access{
			{Group: "team1_user", Namespace: "team1", PullOnly: true},
		}, nil
	})
	gateway.Logger = testJSONLogger(&logOutput)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/login", strings.NewReader("username=alice&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.12")
	request.RemoteAddr = "198.51.100.22:54321"

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d: %s", recorder.Code, recorder.Body.String())
	}

	entry := onlyLogEntry(t, &logOutput)
	if entry["event"] != "user_login" || entry["msg"] != "user login" || entry["level"] != "INFO" {
		t.Fatalf("unexpected login log entry: %#v", entry)
	}
	if entry["username"] != "alice" || entry["client_ip"] != "198.51.100.22" || entry["http_status"] != float64(http.StatusSeeOther) {
		t.Fatalf("unexpected login log fields: %#v", entry)
	}
	namespaces, ok := entry["namespaces"].([]any)
	if !ok || len(namespaces) != 1 || namespaces[0] != "team1" {
		t.Fatalf("expected team1 namespace in login log, got %#v", entry["namespaces"])
	}
}

func TestGatewayLogsLoginSuccessUsesTrustedXForwardedFor(t *testing.T) {
	var logOutput bytes.Buffer
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /_security/user/alice":
			http.NotFound(w, r)
		case "PUT /_security/role/gateway_team1_user":
			w.WriteHeader(http.StatusOK)
		case "PUT /_security/user/alice":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		ElasticsearchURL: elasticSearch.URL,
		HTTPClient:       elasticSearch.Client(),
		TrustedProxies:   []netip.Prefix{mustTestPrefix(t, "10.0.0.0/8")},
	}), func(username, _ string) (*authz.User, []authz.Access, error) {
		return &authz.User{Name: username}, []authz.Access{
			{Group: "team1_user", Namespace: "team1", PullOnly: true},
		}, nil
	})
	gateway.Logger = testJSONLogger(&logOutput)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/login", strings.NewReader("username=alice&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Forwarded-For", "192.0.2.200, 203.0.113.7, 10.0.0.12")
	request.RemoteAddr = "10.0.0.13:54321"

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d: %s", recorder.Code, recorder.Body.String())
	}

	entry := onlyLogEntry(t, &logOutput)
	if entry["username"] != "alice" || entry["client_ip"] != "203.0.113.7" || entry["remote_addr"] != "10.0.0.13:54321" {
		t.Fatalf("unexpected login log fields: %#v", entry)
	}
}

func TestGatewayLogsLoginFailureIgnoresXForwardedForFromUntrustedPeer(t *testing.T) {
	var logOutput bytes.Buffer
	gateway := New(elasticpkg.NewClient(appconfig.Config{
		TrustedProxies: []netip.Prefix{mustTestPrefix(t, "10.0.0.0/8")},
	}), nil)
	gateway.Logger = testJSONLogger(&logOutput)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/login", strings.NewReader("username=alice&password=wrong"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Forwarded-For", "203.0.113.7")
	request.RemoteAddr = "198.51.100.22:54321"

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
	}

	entry := onlyLogEntry(t, &logOutput)
	if entry["client_ip"] != "198.51.100.22" || entry["remote_addr"] != "198.51.100.22:54321" {
		t.Fatalf("unexpected login-failure log fields: %#v", entry)
	}
}

func TestGatewayLogsLoginFailureAsJSON(t *testing.T) {
	var logOutput bytes.Buffer
	gateway := New(elasticpkg.NewClient(appconfig.Config{}), nil)
	gateway.Logger = testJSONLogger(&logOutput)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/login", strings.NewReader("username=alice&password=wrong"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
	}

	entry := onlyLogEntry(t, &logOutput)
	if entry["event"] != "user_login_failed" || entry["msg"] != "user login failed" || entry["level"] != "WARN" {
		t.Fatalf("unexpected login-failure log entry: %#v", entry)
	}
	if entry["username"] != "alice" || entry["reason"] != "invalid_credentials" || entry["http_status"] != float64(http.StatusUnauthorized) {
		t.Fatalf("unexpected login-failure log fields: %#v", entry)
	}
}

func TestGatewayLogsIngestAuthorizationDenialAsJSON(t *testing.T) {
	var logOutput bytes.Buffer
	gateway := New(elasticpkg.NewClient(appconfig.Config{
		TrustedProxies: []netip.Prefix{mustTestPrefix(t, "10.0.0.0/8")},
	}), func(username, _ string) (*authz.User, []authz.Access, error) {
		return &authz.User{Name: username}, []authz.Access{
			{Group: "team1_user", Namespace: "team1", PullOnly: true},
		}, nil
	})
	gateway.Logger = testJSONLogger(&logOutput)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.12")
	request.RemoteAddr = "10.0.0.13:54321"
	request.SetBasicAuth("alice", "secret")

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}

	assertIngestAuthorizationDenialLogEntry(t, &logOutput)
}

func assertIngestAuthorizationDenialLogEntry(t *testing.T, output *bytes.Buffer) {
	t.Helper()

	entry := onlyLogEntry(t, output)
	if entry["event"] != "ingest_authorization_denied" || entry["msg"] != "ingest authorization denied" || entry["level"] != "WARN" {
		t.Fatalf("unexpected ingest denial log entry: %#v", entry)
	}
	if entry["username"] != "alice" || entry["client_ip"] != "203.0.113.7" || entry["requested_index"] != "orders-demo" {
		t.Fatalf("unexpected ingest denial log fields: %#v", entry)
	}
	if entry["http_status"] != float64(http.StatusForbidden) || entry["reason"] != "forbidden_index" {
		t.Fatalf("unexpected ingest denial status/reason: %#v", entry)
	}

	assertIngestAuthorizationDenialAccessMap(t, entry)
}

func assertIngestAuthorizationDenialAccessMap(t *testing.T, entry map[string]any) {
	t.Helper()

	accessMap, ok := entry["access_map"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured access_map, got %#v", entry["access_map"])
	}
	teamAccess, ok := accessMap["team1"].(map[string]any)
	if !ok {
		t.Fatalf("expected team1 access map entry, got %#v", accessMap)
	}
	groups, ok := teamAccess["groups"].([]any)
	if !ok || len(groups) != 1 || groups[0] != "team1_user" {
		t.Fatalf("unexpected team1 access groups: %#v", teamAccess["groups"])
	}
	if teamAccess["mode"] != "user" || teamAccess["pull_only"] != true || teamAccess["delete_allowed"] != false {
		t.Fatalf("unexpected team1 access map entry: %#v", teamAccess)
	}
}

func TestGatewayLogsUpstreamFailureDetailsAndReturnsGenericError(t *testing.T) {
	var logOutput bytes.Buffer
	elasticSearch := httptest.NewServer(upstreamFailureDetailsHandler(t))
	defer elasticSearch.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		ElasticsearchURL: elasticSearch.URL,
		HTTPClient:       elasticSearch.Client(),
	}), func(username, _ string) (*authz.User, []authz.Access, error) {
		return &authz.User{Name: username}, []authz.Access{
			{Group: "orders_ingest", Namespace: "orders"},
		}, nil
	})
	gateway.Logger = testJSONLogger(&logOutput)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("alice", "secret")

	gateway.Handler().ServeHTTP(recorder, request)

	assertGenericUpstreamFailureResponse(t, recorder)
	assertUpstreamFailureLogEntry(t, &logOutput)
}

func upstreamFailureDetailsHandler(t *testing.T) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/orders-demo-20241230-rollover":
			w.WriteHeader(http.StatusOK)
		case "GET /_alias/orders-demo-20241230-rollover":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"orders-demo-20241230-rollover-000001":{"aliases":{"orders-demo-20241230-rollover":{"is_write_index":true}}}}`))
		case "PUT /orders-demo-20241230-rollover-000001/_settings":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "POST /orders-demo-20241230-rollover/_doc":
			http.Error(w, `{"error":"index failed","stack_trace":"secret stack"}`, http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}
}

func assertGenericUpstreamFailureResponse(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); !strings.Contains(body, upstreamErrorMessage) || strings.Contains(body, "secret stack") {
		t.Fatalf("expected generic client error without upstream details, got %q", body)
	}
}

func assertUpstreamFailureLogEntry(t *testing.T, output *bytes.Buffer) {
	t.Helper()

	entry := onlyLogEntry(t, output)
	if entry["event"] != "upstream_request_failed" || entry["operation"] != "elasticsearch_ingest" || entry["level"] != "WARN" {
		t.Fatalf("unexpected upstream failure log entry: %#v", entry)
	}
	if entry["client_error"] != upstreamErrorMessage || entry["http_status"] != float64(http.StatusBadGateway) {
		t.Fatalf("unexpected upstream failure log fields: %#v", entry)
	}
	upstream, ok := entry["upstream"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured upstream log fields, got %#v", entry["upstream"])
	}
	if upstream["method"] != http.MethodPost || upstream["path"] != "/orders-demo-20241230-rollover/_doc" || upstream["status"] != float64(http.StatusInternalServerError) {
		t.Fatalf("unexpected upstream log fields: %#v", upstream)
	}
	if body, ok := upstream["body"].(string); !ok || !strings.Contains(body, "secret stack") {
		t.Fatalf("expected raw upstream body in logs, got %#v", upstream["body"])
	}
}

func TestGatewayLogsLogoutAsJSON(t *testing.T) {
	var logOutput bytes.Buffer
	gateway := New(elasticpkg.NewClient(appconfig.Config{}), nil)
	gateway.Logger = testJSONLogger(&logOutput)

	encoded, err := gateway.EncodeSessionCookieValue(Session{User: &authz.User{Name: "alice"}})
	if err != nil {
		t.Fatalf("encode session cookie: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/logout", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: encoded})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d: %s", recorder.Code, recorder.Body.String())
	}

	entry := onlyLogEntry(t, &logOutput)
	if entry["event"] != "user_logout" || entry["msg"] != "user logout" || entry["level"] != "INFO" {
		t.Fatalf("unexpected logout log entry: %#v", entry)
	}
	if entry["username"] != "alice" || entry["authenticated"] != true || entry["http_status"] != float64(http.StatusSeeOther) {
		t.Fatalf("unexpected logout log fields: %#v", entry)
	}
}

func TestSessionCookieSecureHonorsForceSecureCookies(t *testing.T) {
	gateway := New(elasticpkg.NewClient(appconfig.Config{ForceSecureCookies: true}), nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/login", nil)

	if err := gateway.setSessionCookie(recorder, request, Session{User: &authz.User{Name: "alice"}}); err != nil {
		t.Fatalf("set session cookie: %v", err)
	}

	cookie := findTestCookie(t, recorder.Result().Cookies(), SessionCookieName)
	if !cookie.Secure {
		t.Fatalf("expected forced secure session cookie, got %#v", cookie)
	}
}

func TestSessionCookieMaxAgeHonorsSessionTTL(t *testing.T) {
	gateway := New(elasticpkg.NewClient(appconfig.Config{SessionTTL: 90 * time.Minute}), nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/login", nil)

	if err := gateway.setSessionCookie(recorder, request, Session{User: &authz.User{Name: "alice"}}); err != nil {
		t.Fatalf("set session cookie: %v", err)
	}

	cookie := findTestCookie(t, recorder.Result().Cookies(), SessionCookieName)
	if cookie.MaxAge != 5400 {
		t.Fatalf("expected browser cookie max age 5400 seconds, got %d", cookie.MaxAge)
	}

	maxAge := reflect.ValueOf(gateway.SecureCookie).Elem().FieldByName("maxAge").Int()
	if maxAge != 5400 {
		t.Fatalf("expected securecookie max age 5400 seconds, got %d", maxAge)
	}
}

func TestInternalUserPasswordDerivation(t *testing.T) {
	first := New(elasticpkg.NewClient(appconfig.Config{SessionSecret: "shared-secret-for-passwords"}), nil)
	second := New(elasticpkg.NewClient(appconfig.Config{SessionSecret: "shared-secret-for-passwords"}), nil)
	otherSecret := New(elasticpkg.NewClient(appconfig.Config{SessionSecret: "different-secret-for-passwords"}), nil)

	alicePassword := first.internalUserPassword("alice")
	if alicePassword == "" {
		t.Fatal("expected derived password")
	}
	if got := second.internalUserPassword("alice"); got != alicePassword {
		t.Fatalf("same secret and username should derive the same password: %q != %q", got, alicePassword)
	}
	if got := first.internalUserPassword(" alice "); got != alicePassword {
		t.Fatalf("submitted username should be trimmed before derivation: %q != %q", got, alicePassword)
	}
	if got := first.internalUserPassword("bob"); got == alicePassword {
		t.Fatal("different usernames should derive different passwords")
	}
	if got := otherSecret.internalUserPassword("alice"); got == alicePassword {
		t.Fatal("different session secrets should derive different passwords")
	}

	fallback := New(elasticpkg.NewClient(appconfig.Config{}), nil)
	if got, want := fallback.internalUserPassword("alice"), fallback.internalUserPassword("alice"); got != want {
		t.Fatalf("process fallback secret should be stable inside one gateway: %q != %q", got, want)
	}
}

func TestLoginUsesStableInternalPasswordForConcurrentSessions(t *testing.T) {
	gateway, userPasswords := newStablePasswordLoginGateway(t)

	var sessionPasswords []string
	for range 2 {
		sessionPasswords = append(sessionPasswords, loginSessionPassword(t, gateway))
	}

	if len(*userPasswords) != 2 || len(sessionPasswords) != 2 {
		t.Fatalf("expected two login passwords and session passwords, got %#v / %#v", *userPasswords, sessionPasswords)
	}
	if (*userPasswords)[0] != (*userPasswords)[1] {
		t.Fatalf("native-user password rotated across logins: %q != %q", (*userPasswords)[0], (*userPasswords)[1])
	}
	if sessionPasswords[0] != sessionPasswords[1] {
		t.Fatalf("session AuthHeader password changed across logins: %q != %q", sessionPasswords[0], sessionPasswords[1])
	}
	if sessionPasswords[0] != (*userPasswords)[0] {
		t.Fatalf("session password and native-user password diverged: %q != %q", sessionPasswords[0], (*userPasswords)[0])
	}
}

func TestClearSessionCookieSecureHonorsForceSecureCookies(t *testing.T) {
	gateway := New(elasticpkg.NewClient(appconfig.Config{ForceSecureCookies: true}), nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/logout", nil)

	gateway.clearSessionCookie(recorder, request)

	cookie := findTestCookie(t, recorder.Result().Cookies(), SessionCookieName)
	if !cookie.Secure {
		t.Fatalf("expected forced secure clear-session cookie, got %#v", cookie)
	}
}

func TestKibanaProxyForceSecureCookiesForwardsHTTPS(t *testing.T) {
	var forwardedProto string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer kibana.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		KibanaURL:          kibana.URL,
		ForceSecureCookies: true,
	}), nil)
	encoded, err := gateway.EncodeSessionCookieValue(Session{
		User:       &authz.User{Name: "alice"},
		AuthHeader: BuildBasicAuthorization("alice", "secret"),
	})
	if err != nil {
		t.Fatalf("encode session cookie: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: encoded})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if forwardedProto != "https" {
		t.Fatalf("expected forced X-Forwarded-Proto https, got %q", forwardedProto)
	}
}

func TestKibanaProxyIgnoresSpoofedXForwardedForByDefault(t *testing.T) {
	var forwardedFor string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedFor = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer kibana.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{KibanaURL: kibana.URL}), nil)
	encoded, err := gateway.EncodeSessionCookieValue(Session{
		User:       &authz.User{Name: "alice"},
		AuthHeader: BuildBasicAuthorization("alice", "secret"),
	})
	if err != nil {
		t.Fatalf("encode session cookie: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)
	request.Header.Set("X-Forwarded-For", "203.0.113.7")
	request.RemoteAddr = "198.51.100.22:54321"
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: encoded})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if forwardedFor != "198.51.100.22" {
		t.Fatalf("expected direct peer X-Forwarded-For, got %q", forwardedFor)
	}
}

func TestKibanaProxyForwardsSanitizedTrustedXForwardedFor(t *testing.T) {
	var forwardedFor string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedFor = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer kibana.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		KibanaURL:      kibana.URL,
		TrustedProxies: []netip.Prefix{mustTestPrefix(t, "10.0.0.0/8")},
	}), nil)
	encoded, err := gateway.EncodeSessionCookieValue(Session{
		User:       &authz.User{Name: "alice"},
		AuthHeader: BuildBasicAuthorization("alice", "secret"),
	})
	if err != nil {
		t.Fatalf("encode session cookie: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)
	request.Header.Set("X-Forwarded-For", "192.0.2.200, 203.0.113.7, 10.0.0.12")
	request.RemoteAddr = "10.0.0.13:54321"
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: encoded})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if forwardedFor != "203.0.113.7, 10.0.0.12, 10.0.0.13" {
		t.Fatalf("expected sanitized X-Forwarded-For chain, got %q", forwardedFor)
	}
}

func TestKibanaProxyUsesConstructedTargetURL(t *testing.T) {
	var proxied bool
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied = true
		w.WriteHeader(http.StatusOK)
	}))
	defer kibana.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{KibanaURL: kibana.URL}), nil)
	encoded, err := gateway.EncodeSessionCookieValue(Session{
		User:       &authz.User{Name: "alice"},
		AuthHeader: BuildBasicAuthorization("alice", "secret"),
	})
	if err != nil {
		t.Fatalf("encode session cookie: %v", err)
	}
	gateway.Client.Config.KibanaURL = "://bad"

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: encoded})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !proxied {
		t.Fatal("expected request to reach constructed Kibana target")
	}
}

func TestKibanaProxyTimesOutHungUpstream(t *testing.T) {
	kibana := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer kibana.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		KibanaURL: kibana.URL,
		HTTPClient: &http.Client{
			Timeout: 20 * time.Millisecond,
		},
	}), nil)
	encoded, err := gateway.EncodeSessionCookieValue(Session{
		User:       &authz.User{Name: "alice"},
		AuthHeader: BuildBasicAuthorization("alice", "secret"),
	})
	if err != nil {
		t.Fatalf("encode session cookie: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)
	ctx, cancel := context.WithTimeout(request.Context(), time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: encoded})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); !strings.Contains(body, upstreamErrorMessage) {
		t.Fatalf("expected generic upstream error, got %q", body)
	}
}

func TestRenderLoginPageTemplateFailureReturnsInternalServerError(t *testing.T) {
	originalTemplate := loginPageTemplate
	loginPageTemplate = template.Must(template.New("login").Parse(`{{.Missing.Value}}`))
	t.Cleanup(func() {
		loginPageTemplate = originalTemplate
	})

	gateway := New(elasticpkg.NewClient(appconfig.Config{}), nil)
	recorder := httptest.NewRecorder()

	gateway.RenderLoginPage(recorder, http.StatusTeapot, LoginPageData{})

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "failed to render login page") {
		t.Fatalf("expected render failure message, got %q", recorder.Body.String())
	}
}

func TestHealthAndReadyzProbeElasticsearchAndKibana(t *testing.T) {
	var calls []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "GET /", "GET /api/status":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected probe request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer upstream.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		ElasticsearchURL: upstream.URL,
		KibanaURL:        upstream.URL,
		HTTPClient:       upstream.Client(),
	}), nil)

	for _, path := range []string{"/elasticgateway/healthz", "/elasticgateway/readyz"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)

		gateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: expected status 200, got %d: %s", path, recorder.Code, recorder.Body.String())
		}
		var response probeResponse
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatalf("%s: decode probe response: %v", path, err)
		}
		if response.Checks["elasticsearch"].Status != "ok" || response.Checks["kibana"].Status != "ok" {
			t.Fatalf("%s: unexpected probe response: %#v", path, response)
		}
	}

	expected := []string{"GET /", "GET /api/status", "GET /", "GET /api/status"}
	if strings.Join(calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected probe calls: %#v", calls)
	}
}

func TestReadyzReturnsUnavailableWhenKibanaPingFails(t *testing.T) {
	var logOutput bytes.Buffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "GET /api/status":
			http.Error(w, "kibana unavailable", http.StatusServiceUnavailable)
		default:
			t.Fatalf("unexpected probe request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer upstream.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		ElasticsearchURL: upstream.URL,
		KibanaURL:        upstream.URL,
		HTTPClient:       upstream.Client(),
	}), nil)
	gateway.Logger = testJSONLogger(&logOutput)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/elasticgateway/readyz", nil)

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response probeResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode probe response: %v", err)
	}
	if response.Status != "not_ready" || response.Checks["kibana"].Status != "error" {
		t.Fatalf("unexpected probe response: %#v", response)
	}
	if response.Checks["kibana"].Error != upstreamErrorMessage {
		t.Fatalf("expected generic probe error, got %#v", response.Checks["kibana"])
	}

	entry := onlyLogEntry(t, &logOutput)
	if entry["event"] != "upstream_request_failed" || entry["operation"] != "kibana_probe" {
		t.Fatalf("unexpected probe failure log entry: %#v", entry)
	}
	upstreamFields, ok := entry["upstream"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured upstream probe fields, got %#v", entry["upstream"])
	}
	if body, ok := upstreamFields["body"].(string); !ok || !strings.Contains(body, "kibana unavailable") {
		t.Fatalf("expected raw probe body in logs, got %#v", upstreamFields["body"])
	}
}

func TestProbeRejectsUnexpectedPathsAndMethods(t *testing.T) {
	gateway := New(elasticpkg.NewClient(appconfig.Config{}), nil)

	tests := []struct {
		name   string
		method string
		path   string
		handle func(http.ResponseWriter, *http.Request)
		status int
		allow  string
	}{
		{
			name:   "healthz wrong path",
			method: http.MethodGet,
			path:   "/elasticgateway/healthz/extra",
			handle: gateway.handleHealthz,
			status: http.StatusNotFound,
		},
		{
			name:   "readyz wrong path",
			method: http.MethodGet,
			path:   "/elasticgateway/readyz/extra",
			handle: gateway.handleReadyz,
			status: http.StatusNotFound,
		},
		{
			name:   "probe wrong method",
			method: http.MethodPost,
			path:   "/elasticgateway/healthz",
			handle: gateway.handleHealthz,
			status: http.StatusMethodNotAllowed,
			allow:  http.MethodGet + ", " + http.MethodHead,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, nil)

			tt.handle(recorder, request)

			if recorder.Code != tt.status {
				t.Fatalf("expected status %d, got %d: %s", tt.status, recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Allow"); got != tt.allow {
				t.Fatalf("unexpected Allow header: got %q want %q", got, tt.allow)
			}
		})
	}
}

func TestProbeWithoutConfiguredClientReturnsUnavailable(t *testing.T) {
	var gateway *Gateway
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/elasticgateway/healthz", nil)

	gateway.handleProbe(recorder, request, "healthy", "unhealthy")

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response probeResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode probe response: %v", err)
	}
	if response.Status != "unhealthy" {
		t.Fatalf("unexpected probe status: %#v", response)
	}
	for name, check := range response.Checks {
		if check.Status != "error" || !strings.Contains(check.Error, "not configured") {
			t.Fatalf("unexpected %s check: %#v", name, check)
		}
	}
}

func TestHealthzReturnsUnavailableWhenElasticsearchFailsAndKibanaDisabled(t *testing.T) {
	var logOutput bytes.Buffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			t.Fatalf("unexpected probe request: %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, "elasticsearch unavailable", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		ElasticsearchURL: upstream.URL,
		HTTPClient:       upstream.Client(),
	}), nil)
	gateway.Logger = testJSONLogger(&logOutput)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/elasticgateway/healthz", nil)

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response probeResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode probe response: %v", err)
	}
	if response.Status != "unhealthy" {
		t.Fatalf("unexpected probe status: %#v", response)
	}
	if response.Checks["elasticsearch"].Status != "error" || response.Checks["elasticsearch"].Error != upstreamErrorMessage {
		t.Fatalf("unexpected Elasticsearch check: %#v", response.Checks["elasticsearch"])
	}
	if response.Checks["kibana"].Status != "disabled" {
		t.Fatalf("unexpected Kibana check: %#v", response.Checks["kibana"])
	}

	entry := onlyLogEntry(t, &logOutput)
	if entry["event"] != "upstream_request_failed" || entry["operation"] != "elasticsearch_probe" {
		t.Fatalf("unexpected probe failure log entry: %#v", entry)
	}
}

func TestForwardedForInfoHandlesMissingAndMalformedRemoteAddr(t *testing.T) {
	var gateway *Gateway

	if got := gateway.forwardedForInfo(nil); got.clientIP != "" || len(got.forwardedFor) != 0 {
		t.Fatalf("unexpected nil request forwarded info: %#v", got)
	}

	malformed := httptest.NewRequest(http.MethodGet, "/", nil)
	malformed.RemoteAddr = " unix socket "
	if got := gateway.forwardedForInfo(malformed); got.clientIP != "unix socket" || len(got.forwardedFor) != 0 {
		t.Fatalf("unexpected malformed remote forwarded info: %#v", got)
	}

	hostOnly := httptest.NewRequest(http.MethodGet, "/", nil)
	hostOnly.RemoteAddr = "203.0.113.7"
	if got := gateway.forwardedForInfo(hostOnly); got.clientIP != "203.0.113.7" || len(got.forwardedFor) != 0 {
		t.Fatalf("unexpected host-only remote forwarded info: %#v", got)
	}
}

func TestTrustedProxyWithoutUsableForwardedForFallsBackToRemotePeer(t *testing.T) {
	gateway := New(elasticpkg.NewClient(appconfig.Config{
		TrustedProxies: []netip.Prefix{mustTestPrefix(t, "10.0.0.0/8")},
	}), nil)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.12:54321"
	request.Header.Add("X-Forwarded-For", " , bad-ip ")

	info := gateway.forwardedForInfo(request)

	if info.clientIP != "10.0.0.12" || len(info.forwardedFor) != 0 {
		t.Fatalf("unexpected forwarded info: %#v", info)
	}
}

func TestDecodeIngestDocumentRejectsContentLengthOverLimit(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = maxIngestRequestBodyBytes + 1

	_, _, status, err := decodeIngestDocument(recorder, request, "orders-demo")

	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status 413, got %d", status)
	}
	if err == nil || !strings.Contains(err.Error(), "512 MB") {
		t.Fatalf("expected 512 MB limit error, got %v", err)
	}
}

func TestDecodeIngestDocumentsReturnRequestEntityTooLargeAfterReadingPastLimit(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		decode      func(http.ResponseWriter, *http.Request) (int, error)
	}{
		{
			name:        "single document",
			contentType: "application/json",
			body:        `{"event_time":"2024-12-30T10:11:12Z"}`,
			decode: func(w http.ResponseWriter, r *http.Request) (int, error) {
				_, _, status, err := decodeIngestDocumentWithLimit(w, r, "orders-demo", 8)
				return status, err
			},
		},
		{
			name:        "bulk",
			contentType: "application/x-ndjson",
			body:        "{\"index\":{}}\n{\"event_time\":\"2024-12-30T10:11:12Z\"}\n",
			decode: func(w http.ResponseWriter, r *http.Request) (int, error) {
				_, status, err := decodeBulkIngestDocumentsWithLimit(w, r, "orders-demo", 8)
				return status, err
			},
		},
		{
			name:        "bulk malformed line before limit",
			contentType: "application/x-ndjson",
			body:        "{bad}\n" + strings.Repeat("x", 32),
			decode: func(w http.ResponseWriter, r *http.Request) (int, error) {
				_, status, err := decodeBulkIngestDocumentsWithLimit(w, r, "orders-demo", 8)
				return status, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/elasticgateway/ingest/orders-demo", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", tt.contentType)
			request.ContentLength = -1

			status, err := tt.decode(recorder, request)

			if status != http.StatusRequestEntityTooLarge {
				t.Fatalf("expected status 413, got %d", status)
			}
			if err == nil || !strings.Contains(err.Error(), "8 bytes") {
				t.Fatalf("expected 8-byte limit error, got %v", err)
			}
		})
	}
}

func testJSONLogger(output *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		},
	}))
}

func onlyLogEntry(t *testing.T, output *bytes.Buffer) map[string]any {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected one JSON log line, got %q", output.String())
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("decode JSON log entry: %v\n%s", err, lines[0])
	}
	return entry
}

func mustTestPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()

	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatalf("parse test prefix %q: %v", value, err)
	}
	return prefix
}

func findTestCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q not found in %#v", name, cookies)
	return nil
}

func decodeTestJSONBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return body
}

func newStablePasswordLoginGateway(t *testing.T) (*Gateway, *[]string) {
	t.Helper()

	var userPasswords []string
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /_security/user/alice":
			http.NotFound(w, r)
		case "PUT /_security/role/gateway_team1_user":
			w.WriteHeader(http.StatusOK)
		case "PUT /_security/user/alice":
			body := decodeTestJSONBody(t, r)
			password, ok := body["password"].(string)
			if !ok || password == "" {
				t.Fatalf("expected native-user password, got %#v", body["password"])
			}
			userPasswords = append(userPasswords, password)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(elasticSearch.Close)

	gateway := New(elasticpkg.NewClient(appconfig.Config{
		ElasticsearchURL: elasticSearch.URL,
		HTTPClient:       elasticSearch.Client(),
		SessionSecret:    "shared-session-secret-for-login-passwords",
	}), func(username, _ string) (*authz.User, []authz.Access, error) {
		return &authz.User{Name: username}, []authz.Access{
			{Group: "team1_user", Namespace: "team1", PullOnly: true},
		}, nil
	})
	return gateway, &userPasswords
}

func loginSessionPassword(t *testing.T, gateway *Gateway) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/login", strings.NewReader("username=alice&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d: %s", recorder.Code, recorder.Body.String())
	}

	cookie := findTestCookie(t, recorder.Result().Cookies(), SessionCookieName)
	sessionData, err := gateway.decodeSessionCookieValue(cookie.Value)
	if err != nil {
		t.Fatalf("decode session cookie: %v", err)
	}
	username, password := decodeBasicAuthHeader(t, sessionData.AuthHeader)
	if username != "alice" {
		t.Fatalf("expected session Basic auth username alice, got %q", username)
	}
	return password
}

func decodeBasicAuthHeader(t *testing.T, header string) (string, string) {
	t.Helper()

	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		t.Fatalf("expected Basic auth header, got %q", header)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		t.Fatalf("decode Basic auth header: %v", err)
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		t.Fatalf("expected Basic auth username and password, got %q", decoded)
	}
	return parts[0], parts[1]
}
