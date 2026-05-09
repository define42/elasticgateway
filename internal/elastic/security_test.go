package elastic

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/elasticgateway/internal/authz"
	"github.com/define42/elasticgateway/internal/config"
)

//nolint:gocognit,funlen // Subtests collect focused security client edge cases.
func TestProvisionAndSecurityHelpers(t *testing.T) {
	t.Run("provision login user without access", func(t *testing.T) {
		client := NewClient(config.Config{})
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

		client := NewClient(testConfig(elasticSearch))
		err := client.ProvisionLoginUser(context.Background(), "alice", "secret", []authz.Access{
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

		client := NewClient(testConfig(elasticSearch))
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

		client := NewClient(testConfig(elasticSearch))
		err := client.EnsureNativeUserWritable(context.Background(), "alice")
		if !errors.Is(err, ErrReservedNativeUser) {
			t.Fatalf("expected reserved/hidden error, got %v", err)
		}
	})

	t.Run("ensure security role failure", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"role failed"}`, http.StatusInternalServerError)
		}))
		defer elasticSearch.Close()

		client := NewClient(testConfig(elasticSearch))
		if err := client.EnsureSecurityRole(context.Background(), "gateway_team1_rw", authz.Access{Namespace: "team1"}); err == nil {
			t.Fatal("expected EnsureSecurityRole to fail")
		}
	})

	t.Run("upsert native user sends internal password", func(t *testing.T) {
		var body map[string]any
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		}))
		defer elasticSearch.Close()

		client := NewClient(testConfig(elasticSearch))
		if err := client.UpsertNativeUser(context.Background(), "alice", "secret", []string{"gateway_team1_rw"}, []string{"team1_rw"}, []string{"team1"}); err != nil {
			t.Fatalf("UpsertNativeUser returned error: %v", err)
		}
		if got := body["password"]; got != "secret" {
			t.Fatalf("expected internal plaintext password, got %#v", got)
		}
	})
}
