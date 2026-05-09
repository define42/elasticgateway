package server

import (
	"bytes"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/define42/elasticgateway/internal/authz"
	appconfig "github.com/define42/elasticgateway/internal/config"
	elasticpkg "github.com/define42/elasticgateway/internal/elastic"
)

func TestGatewayLogsLoginSuccessAsJSON(t *testing.T) {
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
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.12")

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d: %s", recorder.Code, recorder.Body.String())
	}

	entry := onlyLogEntry(t, &logOutput)
	if entry["event"] != "user_login" || entry["msg"] != "user login" || entry["level"] != "INFO" {
		t.Fatalf("unexpected login log entry: %#v", entry)
	}
	if entry["username"] != "alice" || entry["client_ip"] != "203.0.113.7" || entry["http_status"] != float64(http.StatusSeeOther) {
		t.Fatalf("unexpected login log fields: %#v", entry)
	}
	namespaces, ok := entry["namespaces"].([]any)
	if !ok || len(namespaces) != 1 || namespaces[0] != "team1" {
		t.Fatalf("expected team1 namespace in login log, got %#v", entry["namespaces"])
	}
}

func TestGatewayLogsLoginFailureAsJSON(t *testing.T) {
	var logOutput bytes.Buffer
	gateway := New(elasticpkg.NewClient(appconfig.Config{}), nil)
	gateway.Logger = testJSONLogger(&logOutput)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=alice&password=wrong"))
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

func TestGatewayLogsLogoutAsJSON(t *testing.T) {
	var logOutput bytes.Buffer
	gateway := New(elasticpkg.NewClient(appconfig.Config{}), nil)
	gateway.Logger = testJSONLogger(&logOutput)

	encoded, err := gateway.EncodeSessionCookieValue(Session{User: &authz.User{Name: "alice"}})
	if err != nil {
		t.Fatalf("encode session cookie: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
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
	request := httptest.NewRequest(http.MethodPost, "/login", nil)

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
	request := httptest.NewRequest(http.MethodPost, "/login", nil)

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

func TestClearSessionCookieSecureHonorsForceSecureCookies(t *testing.T) {
	gateway := New(elasticpkg.NewClient(appconfig.Config{ForceSecureCookies: true}), nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/logout", nil)

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

	for _, path := range []string{"/healthz", "/readyz"} {
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
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)

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
}

func TestDecodeIngestDocumentRejectsContentLengthOverLimit(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
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
			request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(tt.body))
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
