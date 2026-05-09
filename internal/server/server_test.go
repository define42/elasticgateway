package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/elasticgateway/internal/authz"
	appconfig "github.com/define42/elasticgateway/internal/config"
	elasticpkg "github.com/define42/elasticgateway/internal/elastic"
)

func TestSessionCookieSecureHonorsForceSecureCookies(t *testing.T) {
	gateway := New(elasticpkg.NewClient(appconfig.Config{ForceSecureCookies: true}), nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", nil)

	gateway.setSessionCookie(recorder, request, Session{User: &authz.User{Name: "alice"}})

	cookie := findTestCookie(t, recorder.Result().Cookies(), SessionCookieName)
	if !cookie.Secure {
		t.Fatalf("expected forced secure session cookie, got %#v", cookie)
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
