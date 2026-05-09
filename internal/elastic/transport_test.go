package elastic

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/elasticgateway/internal/config"
)

func TestAliasExistsReturnsResponseErrorOnUnexpectedStatus(t *testing.T) {
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
}

func TestResponseErrorStringRedactsBodyWhileRetainingField(t *testing.T) {
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"request failed","stack_trace":"secret stack"}`, http.StatusInternalServerError)
	}))
	defer elasticSearch.Close()

	client := NewClient(testConfig(elasticSearch))
	err := client.DoJSON(context.Background(), http.MethodGet, "/broken", nil, nil, []int{http.StatusOK})
	if err == nil {
		t.Fatal("expected response error")
	}

	var responseErr *ResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected response error with status 500, got %v", err)
	}
	if !strings.Contains(responseErr.Body, "secret stack") {
		t.Fatalf("expected raw upstream body to be retained, got %q", responseErr.Body)
	}
	if strings.Contains(err.Error(), "secret stack") || strings.Contains(err.Error(), "body=") {
		t.Fatalf("response error string leaked upstream body: %q", err.Error())
	}
}

func TestDoJSONWithRequestReturnsMarshalError(t *testing.T) {
	client := NewClient(config.Config{HTTPClient: http.DefaultClient})
	err := client.DoJSONWithRequest(context.Background(), http.MethodPost, "/broken", map[string]any{"bad": make(chan int)}, nil, []int{http.StatusOK}, func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
		t.Fatal("request builder should not be called when json marshal fails")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestDoJSONWithRequestReturnsBuilderError(t *testing.T) {
	client := NewClient(config.Config{HTTPClient: http.DefaultClient})
	wantErr := errors.New("build failed")
	err := client.DoJSONWithRequest(context.Background(), http.MethodGet, "/broken", nil, nil, []int{http.StatusOK}, func(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected builder error, got %v", err)
	}
}

func TestNewClientAddsDefaultTimeoutToInjectedHTTPClient(t *testing.T) {
	input := &http.Client{}

	client := NewClient(config.Config{HTTPClient: input})

	if client.Config.HTTPClient == input {
		t.Fatal("expected no-timeout input client to be cloned")
	}
	if client.Config.HTTPClient.Timeout != config.DefaultHTTPClientTimeout {
		t.Fatalf("unexpected timeout: %v", client.Config.HTTPClient.Timeout)
	}
	if input.Timeout != 0 {
		t.Fatalf("input client was mutated: %v", input.Timeout)
	}
}
