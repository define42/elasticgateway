package elastic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/define42/elasticgateway/internal/config"
)

//nolint:gocognit,cyclop,funlen // Subtests group related Kibana client branches.
func TestTenantAndKibanaClientHelpers(t *testing.T) {
	t.Run("ensure space without kibana url is noop", func(t *testing.T) {
		client := NewClient(config.Config{})
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
		client := NewClient(cfg)
		client.EnsuredSpaces.Store("orders", true)

		if err := client.EnsureSpace(context.Background(), "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure kibana data view without kibana url is noop", func(t *testing.T) {
		client := NewClient(config.Config{})
		if err := client.EnsureKibanaDataView(context.Background(), "orders", "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("ensure kibana data view cached skip", func(t *testing.T) {
		kibana := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}))
		defer kibana.Close()

		cfg := config.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()}
		client := NewClient(cfg)
		client.EnsuredSpaces.Store("orders", true)
		client.EnsuredDataViews.Store("orders/"+BuildDataViewID("orders"), true)

		if err := client.EnsureKibanaDataView(context.Background(), "orders", "orders"); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("set kibana default index failure", func(t *testing.T) {
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"nope"}`, http.StatusInternalServerError)
		}))
		defer kibana.Close()

		client := NewClient(config.Config{
			KibanaURL:      kibana.URL,
			KibanaUsername: "admin",
			KibanaPassword: "secret",
			HTTPClient:     kibana.Client(),
		})
		err := client.SetKibanaDefaultDataView(context.Background(), "team1", BuildDataViewID("team1"), true)
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

		client := NewClient(config.Config{
			KibanaURL:      kibana.URL,
			KibanaUsername: "admin",
			KibanaPassword: "secret",
			HTTPClient:     kibana.Client(),
		})
		if err := client.SetKibanaDefaultDataViewIfMissing(context.Background(), "team1", BuildDataViewID("team1-demo")); err != nil {
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

		client := NewClient(config.Config{
			KibanaURL:      kibana.URL,
			KibanaUsername: "admin",
			KibanaPassword: "secret",
			HTTPClient:     kibana.Client(),
		})
		if err := client.SetKibanaDefaultDataViewIfMissing(context.Background(), "team1", BuildDataViewID("team1-demo")); err != nil {
			t.Fatalf("SetKibanaDefaultDataViewIfMissing returned error: %v", err)
		}
		if !reflect.DeepEqual(calls, []string{
			"GET /s/team1/api/data_views/default",
			"POST /s/team1/api/data_views/default",
		}) {
			t.Fatalf("unexpected default-index calls: %#v", calls)
		}
		if got := body["data_view_id"]; got != BuildDataViewID("team1-demo") {
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

		client := NewClient(config.Config{
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
		client := NewClient(config.Config{
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

func TestKibanaAPIPath(t *testing.T) {
	t.Parallel()

	if got := KibanaAPIPath("/kibana"); got != "/kibana" {
		t.Fatalf("unexpected kibana path: %q", got)
	}
	if got := KibanaAPIPath("/api/test"); got != "/api/test" {
		t.Fatalf("unexpected kibana path: %q", got)
	}
	if got := KibanaAPIPath("api/test"); got != "/api/test" {
		t.Fatalf("unexpected kibana path: %q", got)
	}
}

func TestKibanaAPIPathForSpaceBranches(t *testing.T) {
	t.Parallel()

	if got := KibanaAPIPathForSpace(" ", "api/test"); got != "/api/test" {
		t.Fatalf("blank space should not prefix path, got %q", got)
	}
	if got := KibanaAPIPathForSpace("team1", "/s/existing/api/test"); got != "/s/existing/api/test" {
		t.Fatalf("space-prefixed path should be preserved, got %q", got)
	}
	if got := KibanaAPIPathForSpace("team 1", "api/test"); got != "/s/team%201/api/test" {
		t.Fatalf("space should be escaped, got %q", got)
	}
}

//nolint:cyclop,funlen,gocognit // Subtests exercise related Kibana client error branches together.
func TestKibanaClientErrorBranches(t *testing.T) {
	t.Run("create missing space conflict confirm failure", func(t *testing.T) {
		var calls []string
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, r.Method+" "+r.URL.Path)
			switch r.Method + " " + r.URL.Path {
			case "POST /api/spaces/space":
				http.Error(w, `{"error":"conflict"}`, http.StatusConflict)
			case "GET /api/spaces/space/orders":
				http.Error(w, `{"error":"confirm failed"}`, http.StatusInternalServerError)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer kibana.Close()

		client := NewClient(config.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()})
		err := client.createMissingSpace(context.Background(), "orders", "/api/spaces/space/orders")
		if err == nil || !strings.Contains(err.Error(), "confirm Kibana space") {
			t.Fatalf("expected conflict confirmation error, got %v", err)
		}
		if !reflect.DeepEqual(calls, []string{"POST /api/spaces/space", "GET /api/spaces/space/orders"}) {
			t.Fatalf("unexpected calls: %#v", calls)
		}
	})

	t.Run("ensure data view lookup failure", func(t *testing.T) {
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/s/orders/api/data_views/data_view/"+BuildDataViewID("orders") {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			http.Error(w, `{"error":"lookup failed"}`, http.StatusInternalServerError)
		}))
		defer kibana.Close()

		client := NewClient(config.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()})
		err := client.ensureDataView(context.Background(), "orders", BuildDataViewID("orders"), "orders")
		if err == nil || !strings.Contains(err.Error(), "status=500") {
			t.Fatalf("expected lookup error, got %v", err)
		}
	})

	t.Run("ensure data view create failure", func(t *testing.T) {
		var calls []string
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, r.Method+" "+r.URL.Path)
			switch r.Method + " " + r.URL.Path {
			case "GET /s/orders/api/data_views/data_view/" + BuildDataViewID("orders"):
				http.NotFound(w, r)
			case "POST /s/orders/api/data_views/data_view":
				http.Error(w, `{"error":"create failed"}`, http.StatusInternalServerError)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer kibana.Close()

		client := NewClient(config.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()})
		err := client.ensureDataView(context.Background(), "orders", BuildDataViewID("orders"), "orders")
		if err == nil || !strings.Contains(err.Error(), "status=500") {
			t.Fatalf("expected create error, got %v", err)
		}
		if !reflect.DeepEqual(calls, []string{
			"GET /s/orders/api/data_views/data_view/" + BuildDataViewID("orders"),
			"POST /s/orders/api/data_views/data_view",
		}) {
			t.Fatalf("unexpected calls: %#v", calls)
		}
	})

	t.Run("default data view not found and failure", func(t *testing.T) {
		status := http.StatusNotFound
		kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"default failed"}`, status)
		}))
		defer kibana.Close()

		client := NewClient(config.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()})
		value, ok, err := client.KibanaDefaultDataView(context.Background(), "orders")
		if err != nil || ok || value != "" {
			t.Fatalf("404 should return missing default without error, value=%q ok=%v err=%v", value, ok, err)
		}

		status = http.StatusInternalServerError
		_, _, err = client.KibanaDefaultDataView(context.Background(), "orders")
		if err == nil || !strings.Contains(err.Error(), "get Kibana default data view") {
			t.Fatalf("expected default data view error, got %v", err)
		}
	})
}
