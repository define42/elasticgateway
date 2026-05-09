// Package main contains gateway command and HTTP integration tests.
package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	authzpkg "github.com/define42/elasticgateway/internal/authz"
	appconfig "github.com/define42/elasticgateway/internal/config"
	elasticpkg "github.com/define42/elasticgateway/internal/elastic"
	ingestpkg "github.com/define42/elasticgateway/internal/ingest"
	serverpkg "github.com/define42/elasticgateway/internal/server"
)

func TestDefaultHTTPClient(t *testing.T) {
	t.Setenv("ELASTICSEARCH_SKIP_TLS_VERIFY", "true")
	client := appconfig.DefaultHTTPClient()
	if client.Timeout != 30*time.Second {
		t.Fatalf("unexpected timeout: %v", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected TLS client config with InsecureSkipVerify, got %#v", transport.TLSClientConfig)
	}
}

func TestLoadGatewayReadsSessionSecret(t *testing.T) {
	t.Setenv("SESSION_SECRET", "shared-session-secret-for-tests")

	cfg := appconfig.LoadGateway()
	if cfg.SessionSecret != "shared-session-secret-for-tests" {
		t.Fatalf("unexpected session secret: %q", cfg.SessionSecret)
	}
}

func TestLoadGatewayReadsForceSecureCookies(t *testing.T) {
	t.Setenv("FORCE_SECURE_COOKIES", "true")

	cfg := appconfig.LoadGateway()
	if !cfg.ForceSecureCookies {
		t.Fatal("expected FORCE_SECURE_COOKIES=true to enable forced secure cookies")
	}
}

func TestRunReturnsBootstrapFailures(t *testing.T) {
	t.Run("policy failure", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/_ilm/policy/"+elasticpkg.DefaultILMPolicyID {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			http.Error(w, `{"error":"policy lookup failed"}`, http.StatusInternalServerError)
		}))
		defer elasticSearch.Close()

		calledServe := false
		err := run(context.Background(), testConfig(elasticSearch), func(_ http.Handler) error {
			calledServe = true
			return nil
		})
		if err == nil {
			t.Fatal("expected bootstrap error")
		}
		if calledServe {
			t.Fatal("serve should not be called when policy bootstrap fails")
		}
	})

	t.Run("template failure", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method + " " + r.URL.Path {
			case "GET /_ilm/policy/" + elasticpkg.DefaultILMPolicyID:
				http.NotFound(w, r)
			case "PUT /_ilm/policy/" + elasticpkg.DefaultILMPolicyID:
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{}`)
			case "PUT /_index_template/" + elasticpkg.DefaultIndexTemplateName:
				http.Error(w, `{"error":"template failed"}`, http.StatusInternalServerError)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer elasticSearch.Close()

		calledServe := false
		err := run(context.Background(), testConfig(elasticSearch), func(_ http.Handler) error {
			calledServe = true
			return nil
		})
		if err == nil {
			t.Fatal("expected bootstrap error")
		}
		if calledServe {
			t.Fatal("serve should not be called when template bootstrap fails")
		}
	})
}

func TestGatewayRootAndDemoCoverage(t *testing.T) {
	gateway := testGatewayHandler(appconfig.Config{})
	rawGateway := newTestGateway(elasticpkg.NewClient(appconfig.Config{}), nil)

	t.Run("root head redirects", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodHead, "/", nil)
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("expected status 303, got %d", recorder.Code)
		}
	})

	t.Run("root wrong method", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", recorder.Code)
		}
		if got := recorder.Header().Get("Allow"); got != http.MethodGet+", "+http.MethodHead {
			t.Fatalf("unexpected Allow header: %q", got)
		}
	})

	t.Run("root not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/nope", nil)
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})

	t.Run("demo path not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/demo/nope", nil)
		rawGateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})

	t.Run("login path not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/login/nope", nil)
		rawGateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})
}

func TestGatewayLogoutCoverage(t *testing.T) {
	gateway := testGatewayHandler(appconfig.Config{})
	rawGateway := newTestGateway(elasticpkg.NewClient(appconfig.Config{}), nil)

	t.Run("logout wrong method", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/logout", nil)
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", recorder.Code)
		}
		if got := recorder.Header().Get("Allow"); got != http.MethodPost {
			t.Fatalf("unexpected Allow header: %q", got)
		}
	})

	t.Run("logout dangling cookie still redirects", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/logout", nil)
		request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: "dangling"})
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("expected status 303, got %d", recorder.Code)
		}
		if got := recorder.Header().Get("Location"); got != "/login" {
			t.Fatalf("unexpected redirect: %q", got)
		}
	})

	t.Run("logout path not found", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/logout/nope", nil)
		rawGateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})
}

func TestGatewayKibanaCoverage(t *testing.T) {
	t.Run("path not found", func(t *testing.T) {
		gateway := newTestGateway(elasticpkg.NewClient(appconfig.Config{}), nil)
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/kibana-nope", nil)
		gateway.HandleKibana(recorder, request)

		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", recorder.Code)
		}
	})

	t.Run("proxy error returns bad gateway", func(t *testing.T) {
		gateway := newTestGateway(elasticpkg.NewClient(appconfig.Config{KibanaURL: "://bad"}), nil)
		encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
			User:       &authzpkg.User{Name: "alice"},
			AuthHeader: serverpkg.BuildBasicAuthorization("alice", "secret"),
		})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/kibana", nil)
		request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})
		gateway.Handler().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestHandleLoginSubmitCoverage(t *testing.T) {
	t.Run("parse form failure", func(t *testing.T) {
		gateway := testGatewayHandler(appconfig.Config{})
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/login", io.NopCloser(errorReader{err: errors.New("read failed")}))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("expected status 502, got %d", recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "failed to read login form") {
			t.Fatalf("expected parse-form error page, got %q", recorder.Body.String())
		}
	})

	t.Run("password generation failure returns login error page", func(t *testing.T) {
		oldReader := cryptorand.Reader
		cryptorand.Reader = errorReader{err: errors.New("entropy unavailable")}
		defer func() {
			cryptorand.Reader = oldReader
		}()

		elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}))
		defer elasticSearch.Close()

		kibana := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.RequestURI())
		}))
		defer kibana.Close()

		gateway := testGatewayHandlerWithAuth(testConfigWithKibana(elasticSearch, kibana), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
			return &authzpkg.User{Name: username, Namespace: "team1"}, []authzpkg.Access{
				{Group: "team1_rw", Namespace: "team1"},
			}, nil
		})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		gateway.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), "failed to allocate session credentials") {
			t.Fatalf("expected password-generation failure page, got %q", recorder.Body.String())
		}
	})
}

func TestRenderLoginPageWriterFailure(_ *testing.T) {
	writer := &failingResponseWriter{header: make(http.Header)}
	newTestGateway(elasticpkg.NewClient(appconfig.Config{}), nil).RenderLoginPage(writer, http.StatusOK, serverpkg.LoginPageData{Username: "alice"})
}

func TestDecodeJSONObjectCoverage(t *testing.T) {
	if _, err := ingestpkg.DecodeJSONObject(strings.NewReader("")); err == nil || err.Error() != "request body must be a JSON object" {
		t.Fatalf("expected empty-body decode error, got %v", err)
	}

	if _, err := ingestpkg.DecodeJSONObject(strings.NewReader(`{} {}`)); err == nil || !strings.Contains(err.Error(), "single JSON object") {
		t.Fatalf("expected trailing-json decode error, got %v", err)
	}
}

//nolint:gocognit,funlen // Coverage subtests intentionally collect security helper edge cases.
func TestProvisionAndSecurityHelpersCoverage(t *testing.T) {
	t.Run("provision login user without access", func(t *testing.T) {
		client := elasticpkg.NewClient(appconfig.Config{})
		if err := client.ProvisionLoginUser(context.Background(), "alice", "secret", nil); err == nil {
			t.Fatal("expected missing-access error")
		}
	})

	t.Run("provision login user rejects invalid namespace", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/_security/user/alice" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			http.NotFound(w, r)
		}))
		defer elasticSearch.Close()

		client := elasticpkg.NewClient(testConfig(elasticSearch))
		err := client.ProvisionLoginUser(context.Background(), "alice", "secret", []authzpkg.Access{
			{Group: "bad_rw", Namespace: "bad.namespace"},
		})
		if err == nil || !strings.Contains(err.Error(), "cannot be mapped") {
			t.Fatalf("expected invalid namespace error, got %v", err)
		}
	})

	t.Run("ensure native user writable missing user info", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"other":{"reserved":false,"hidden":false}}`)
		}))
		defer elasticSearch.Close()

		client := elasticpkg.NewClient(testConfig(elasticSearch))
		if err := client.EnsureNativeUserWritable(context.Background(), "alice"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure native user writable hidden user", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"alice":{"reserved":false,"hidden":true}}`)
		}))
		defer elasticSearch.Close()

		client := elasticpkg.NewClient(testConfig(elasticSearch))
		err := client.EnsureNativeUserWritable(context.Background(), "alice")
		if !errors.Is(err, elasticpkg.ErrReservedNativeUser) {
			t.Fatalf("expected reserved/hidden error, got %v", err)
		}
	})

	t.Run("ensure security role failure", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"role failed"}`, http.StatusInternalServerError)
		}))
		defer elasticSearch.Close()

		client := elasticpkg.NewClient(testConfig(elasticSearch))
		if err := client.EnsureSecurityRole(context.Background(), "gateway_team1_rw", authzpkg.Access{Namespace: "team1"}); err == nil {
			t.Fatal("expected EnsureSecurityRole to fail")
		}
	})

	t.Run("upsert native user sends generated password", func(t *testing.T) {
		var body map[string]any
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		}))
		defer elasticSearch.Close()

		client := elasticpkg.NewClient(testConfig(elasticSearch))
		if err := client.UpsertNativeUser(context.Background(), "alice", "secret", []string{"gateway_team1_rw"}, []string{"team1_rw"}, []string{"team1"}); err != nil {
			t.Fatalf("UpsertNativeUser returned error: %v", err)
		}
		if got := body["password"]; got != "secret" {
			t.Fatalf("expected generated plaintext password, got %#v", got)
		}
	})
}

//nolint:gocognit,cyclop,funlen // Coverage subtests intentionally group related kibana client branches.
func TestTenantAndKibanaClientCoverage(t *testing.T) {
	t.Run("ensure space without kibana url is noop", func(t *testing.T) {
		client := elasticpkg.NewClient(appconfig.Config{})
		if err := client.EnsureSpace(context.Background(), "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure space cached skip", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}))
		defer elasticSearch.Close()

		cfg := testConfig(elasticSearch)
		cfg.KibanaURL = "http://kibana.example"
		client := elasticpkg.NewClient(cfg)
		client.EnsuredSpaces.Store("orders", true)

		if err := client.EnsureSpace(context.Background(), "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure kibana data view without kibana url is noop", func(t *testing.T) {
		client := elasticpkg.NewClient(appconfig.Config{})
		if err := client.EnsureKibanaDataView(context.Background(), "orders", "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure kibana data view cached skip", func(t *testing.T) {
		kibana := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}))
		defer kibana.Close()

		cfg := appconfig.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()}
		client := elasticpkg.NewClient(cfg)
		client.EnsuredSpaces.Store("orders", true)
		client.EnsuredDataViews.Store("orders/"+elasticpkg.BuildDataViewID("orders"), true)

		if err := client.EnsureKibanaDataView(context.Background(), "orders", "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("set kibana default index failure", func(t *testing.T) {
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"nope"}`, http.StatusInternalServerError)
		}))
		defer kibana.Close()

		client := elasticpkg.NewClient(appconfig.Config{
			KibanaURL:      kibana.URL,
			KibanaUsername: "admin",
			KibanaPassword: "secret",
			HTTPClient:     kibana.Client(),
		})
		err := client.SetKibanaDefaultDataView(context.Background(), "team1", elasticpkg.BuildDataViewID("team1"), true)
		if err == nil || !strings.Contains(err.Error(), `space "team1"`) {
			t.Fatalf("expected space-scoped default index error, got %v", err)
		}
	})

	t.Run("set kibana default index if missing skips existing default", func(t *testing.T) {
		var calls []string
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, r.Method+" "+r.URL.RequestURI())
			if r.Method != http.MethodGet || r.URL.RequestURI() != "/s/team1/api/data_views/default" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data_view_id":"gateway-index-pattern-team1"}`)
		}))
		defer kibana.Close()

		client := elasticpkg.NewClient(appconfig.Config{
			KibanaURL:      kibana.URL,
			KibanaUsername: "admin",
			KibanaPassword: "secret",
			HTTPClient:     kibana.Client(),
		})
		if err := client.SetKibanaDefaultDataViewIfMissing(context.Background(), "team1", elasticpkg.BuildDataViewID("team1-demo")); err != nil {
			t.Fatalf("SetKibanaDefaultDataViewIfMissing returned error: %v", err)
		}
		if !reflect.DeepEqual(calls, []string{"GET /s/team1/api/data_views/default"}) {
			t.Fatalf("unexpected default-index calls: %#v", calls)
		}
	})

	t.Run("set kibana default index if missing writes empty default", func(t *testing.T) {
		var calls []string
		var body map[string]any
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, r.Method+" "+r.URL.RequestURI())
			switch r.Method + " " + r.URL.RequestURI() {
			case "GET /s/team1/api/data_views/default":
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{}`)
			case "POST /s/team1/api/data_views/default":
				body = decodeRequestBody(t, r)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{}`)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			}
		}))
		defer kibana.Close()

		client := elasticpkg.NewClient(appconfig.Config{
			KibanaURL:      kibana.URL,
			KibanaUsername: "admin",
			KibanaPassword: "secret",
			HTTPClient:     kibana.Client(),
		})
		if err := client.SetKibanaDefaultDataViewIfMissing(context.Background(), "team1", elasticpkg.BuildDataViewID("team1-demo")); err != nil {
			t.Fatalf("SetKibanaDefaultDataViewIfMissing returned error: %v", err)
		}
		if !reflect.DeepEqual(calls, []string{
			"GET /s/team1/api/data_views/default",
			"POST /s/team1/api/data_views/default",
		}) {
			t.Fatalf("unexpected default-index calls: %#v", calls)
		}
		if got := body["data_view_id"]; got != elasticpkg.BuildDataViewID("team1-demo") {
			t.Fatalf("unexpected default-index body: %#v", body)
		}
	})

	t.Run("do kibana json uses basic auth and xsrf", func(t *testing.T) {
		var sawXSRF string
		var sawAuth string
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawXSRF = r.Header.Get("kbn-xsrf")
			sawAuth = r.Header.Get("Authorization")
			if r.URL.Path != "/api/test" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		}))
		defer kibana.Close()

		client := elasticpkg.NewClient(appconfig.Config{
			KibanaURL:      kibana.URL,
			KibanaUsername: "admin",
			KibanaPassword: "secret",
			HTTPClient:     kibana.Client(),
		})
		if err := client.DoKibanaJSON(context.Background(), http.MethodPost, "/api/test", map[string]any{"hello": "world"}, nil, []int{http.StatusOK}); err != nil {
			t.Fatalf("doKibanaJSON returned error: %v", err)
		}
		if sawXSRF != "true" {
			t.Fatalf("expected kbn-xsrf header, got %q", sawXSRF)
		}
		if !strings.HasPrefix(sawAuth, "Basic ") {
			t.Fatalf("expected basic auth header, got %q", sawAuth)
		}
	})

	t.Run("new kibana request adds base path and xsrf", func(t *testing.T) {
		client := elasticpkg.NewClient(appconfig.Config{
			KibanaURL:      "http://kibana.example",
			KibanaUsername: "admin",
			KibanaPassword: "secret",
		})
		req, err := client.NewKibanaRequest(context.Background(), http.MethodGet, "api/test", nil)
		if err != nil {
			t.Fatalf("newKibanaRequest returned error: %v", err)
		}
		if got := req.URL.String(); got != "http://kibana.example/api/test" {
			t.Fatalf("unexpected kibana url: %q", got)
		}
		if got := req.Header.Get("kbn-xsrf"); got != "true" {
			t.Fatalf("expected kbn-xsrf header, got %q", got)
		}
	})
}

func TestClientHelperCoverage(t *testing.T) {
	t.Run("alias exists returns response error on unexpected status", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"alias check failed"}`, http.StatusInternalServerError)
		}))
		defer elasticSearch.Close()

		client := elasticpkg.NewClient(testConfig(elasticSearch))
		_, err := client.AliasExists(context.Background(), "orders-20241230-rollover")
		if err == nil {
			t.Fatal("expected aliasExists to fail")
		}

		var responseErr *elasticpkg.ResponseError
		if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("expected response error with status 500, got %v", err)
		}
	})

	t.Run("do json with request returns marshal error", func(t *testing.T) {
		client := elasticpkg.NewClient(appconfig.Config{HTTPClient: http.DefaultClient})
		err := client.DoJSONWithRequest(context.Background(), http.MethodPost, "/broken", map[string]any{"bad": make(chan int)}, nil, []int{http.StatusOK}, func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
			t.Fatal("request builder should not be called when json marshal fails")
			return nil, nil
		})
		if err == nil {
			t.Fatal("expected marshal error")
		}
	})

	t.Run("do json with request returns builder error", func(t *testing.T) {
		client := elasticpkg.NewClient(appconfig.Config{HTTPClient: http.DefaultClient})
		wantErr := errors.New("build failed")
		err := client.DoJSONWithRequest(context.Background(), http.MethodGet, "/broken", nil, nil, []int{http.StatusOK}, func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
			return nil, wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected builder error, got %v", err)
		}
	})
}

func TestKibanaHelperCoverage(t *testing.T) {
	t.Run("kibana helper functions", func(t *testing.T) {
		if got := elasticpkg.KibanaAPIPath("/kibana"); got != "/kibana" {
			t.Fatalf("unexpected kibana path: %q", got)
		}
		if got := elasticpkg.KibanaAPIPath("/api/test"); got != "/api/test" {
			t.Fatalf("unexpected kibana path: %q", got)
		}
		if got := elasticpkg.KibanaAPIPath("api/test"); got != "/api/test" {
			t.Fatalf("unexpected kibana path: %q", got)
		}
	})
}

func TestDecodeAndSessionHelpersCoverage(t *testing.T) {
	t.Run("secure cookie max age matches browser cookie", func(t *testing.T) {
		gateway := newTestGateway(elasticpkg.NewClient(appconfig.Config{}), nil)
		maxAge := reflect.ValueOf(gateway.SecureCookie).Elem().FieldByName("maxAge").Int()
		if maxAge != 86400 {
			t.Fatalf("expected securecookie server-side max age to be 86400 seconds, got %d", maxAge)
		}
	})

	t.Run("forwarded proto handles https", func(t *testing.T) {
		if got := serverpkg.ForwardedProto(httptest.NewRequest(http.MethodGet, "http://example.com", nil)); got != "http" {
			t.Fatalf("expected http proto, got %q", got)
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.TLS = &tls.ConnectionState{}
		if got := serverpkg.ForwardedProto(req); got != "https" {
			t.Fatalf("expected https proto, got %q", got)
		}
	})
}

func TestAccessGroupNamesAndRetryableConflict(t *testing.T) {
	names := authzpkg.AccessGroupNames([]authzpkg.Access{
		{Group: "team1_rw"},
		{Group: ""},
		{Group: "team1_rw"},
		{Group: "team2_r"},
	})
	if !reflect.DeepEqual(names, []string{"team1_rw", "team2_r"}) {
		t.Fatalf("unexpected deduped group names: %#v", names)
	}

	if !elasticpkg.IsRetryableBootstrapConflict(&elasticpkg.ResponseError{StatusCode: http.StatusBadRequest, Body: `{"error":{"type":"resource_already_exists_exception"}}`}) {
		t.Fatal("expected 400 resource_already_exists_exception to be retryable")
	}
	if elasticpkg.IsRetryableBootstrapConflict(errors.New("plain error")) {
		t.Fatal("expected plain error not to be retryable")
	}
}

type failingResponseWriter struct {
	header http.Header
	status int
}

func (w *failingResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	if r.err == nil {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, r.err
}
