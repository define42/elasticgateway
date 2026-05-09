package elastic

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/define42/elasticgateway/internal/config"
)

func TestClientHelpers(t *testing.T) {
	t.Run("alias exists returns response error on unexpected status", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"alias check failed"}`, http.StatusInternalServerError)
		}))
		defer elasticSearch.Close()

		client := NewClient(testConfig(elasticSearch))
		_, err := client.AliasExists(context.Background(), "orders-20241230-rollover")
		if err == nil {
			t.Fatal("expected aliasExists to fail")
		}

		var responseErr *ResponseError
		if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("expected response error with status 500, got %v", err)
		}
	})

	t.Run("do json with request returns marshal error", func(t *testing.T) {
		client := NewClient(config.Config{HTTPClient: http.DefaultClient})
		err := client.DoJSONWithRequest(context.Background(), http.MethodPost, "/broken", map[string]any{"bad": make(chan int)}, nil, []int{http.StatusOK}, func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
			t.Fatal("request builder should not be called when json marshal fails")
			return nil, nil
		})
		if err == nil {
			t.Fatal("expected marshal error")
		}
	})

	t.Run("do json with request returns builder error", func(t *testing.T) {
		client := NewClient(config.Config{HTTPClient: http.DefaultClient})
		wantErr := errors.New("build failed")
		err := client.DoJSONWithRequest(context.Background(), http.MethodGet, "/broken", nil, nil, []int{http.StatusOK}, func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
			return nil, wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected builder error, got %v", err)
		}
	})
}
