package server

import (
	"net/http"
	"net/http/httptest"
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
