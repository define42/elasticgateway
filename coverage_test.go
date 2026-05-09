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
	serverpkg "github.com/define42/elasticgateway/internal/server"
)

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

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", recorder.Code)
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

func TestDecodeAndSessionHelpersCoverage(t *testing.T) {
	t.Run("secure cookie max age matches browser cookie", func(t *testing.T) {
		gateway := newTestGateway(elasticpkg.NewClient(appconfig.Config{}), nil)
		maxAge := reflect.ValueOf(gateway.SecureCookie).Elem().FieldByName("maxAge").Int()
		want := int64(appconfig.DefaultSessionTTL / time.Second)
		if maxAge != want {
			t.Fatalf("expected securecookie server-side max age to be %d seconds, got %d", want, maxAge)
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
