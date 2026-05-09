package elastic

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestIsRetryableBootstrapConflict(t *testing.T) {
	t.Parallel()

	if !IsRetryableBootstrapConflict(&ResponseError{StatusCode: http.StatusBadRequest, Body: `{"error":{"type":"resource_already_exists_exception"}}`}) {
		t.Fatal("expected 400 resource_already_exists_exception to be retryable")
	}
	if IsRetryableBootstrapConflict(errors.New("plain error")) {
		t.Fatal("expected plain error not to be retryable")
	}
}

func TestEnsureWriteAliasReturnsBootstrapConflictWhenAliasStillMissing(t *testing.T) {
	t.Parallel()

	const alias = "orders-demo-20241230-rollover"
	const firstIndex = "orders-demo-20241230-rollover-000001"

	var calls []string
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/" + alias:
			w.WriteHeader(http.StatusNotFound)
		case "PUT /" + firstIndex:
			http.Error(w, `{"error":{"type":"resource_already_exists_exception"}}`, http.StatusConflict)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	client := NewClient(testConfig(elasticSearch))
	bootstrapped, err := client.EnsureWriteAlias(context.Background(), alias)
	if err == nil {
		t.Fatal("expected bootstrap conflict to fail when alias is still missing")
	}
	if bootstrapped {
		t.Fatal("failed conflict recovery should not report bootstrap")
	}
	if !strings.Contains(err.Error(), `bootstrap "`+alias+`"`) || !strings.Contains(err.Error(), "status=409") {
		t.Fatalf("expected bootstrap conflict context, got %v", err)
	}
	if _, cached := client.EnsuredAliasPolicies.Load(alias); cached {
		t.Fatal("failed conflict recovery must not cache alias policy")
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/" + alias,
		"PUT /" + firstIndex,
		"HEAD /_alias/" + alias,
	}) {
		t.Fatalf("unexpected conflict calls: %#v", calls)
	}
}

func TestEnsureWriteAliasReportsAliasRecheckFailureAfterBootstrapConflict(t *testing.T) {
	t.Parallel()

	const alias = "orders-demo-20241230-rollover"
	const firstIndex = "orders-demo-20241230-rollover-000001"

	var calls []string
	headCalls := 0
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/" + alias:
			headCalls++
			if headCalls == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			http.Error(w, `{"error":"alias recheck failed"}`, http.StatusInternalServerError)
		case "PUT /" + firstIndex:
			http.Error(w, `{"error":{"type":"resource_already_exists_exception"}}`, http.StatusConflict)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	client := NewClient(testConfig(elasticSearch))
	bootstrapped, err := client.EnsureWriteAlias(context.Background(), alias)
	if err == nil {
		t.Fatal("expected alias recheck failure after bootstrap conflict")
	}
	if bootstrapped {
		t.Fatal("failed recheck should not report bootstrap")
	}
	if !strings.Contains(err.Error(), `re-check alias "`+alias+`" after bootstrap conflict`) || !strings.Contains(err.Error(), "status=500") {
		t.Fatalf("expected alias recheck context, got %v", err)
	}
	if _, cached := client.EnsuredAliasPolicies.Load(alias); cached {
		t.Fatal("failed recheck must not cache alias policy")
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/" + alias,
		"PUT /" + firstIndex,
		"HEAD /_alias/" + alias,
	}) {
		t.Fatalf("unexpected recheck calls: %#v", calls)
	}
}

func TestEnsureWriteAliasReportsPolicyRepairFailureAfterBootstrapConflict(t *testing.T) {
	t.Parallel()

	const alias = "orders-demo-20241230-rollover"
	const firstIndex = "orders-demo-20241230-rollover-000001"

	var calls []string
	headCalls := 0
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/" + alias:
			headCalls++
			if headCalls == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "PUT /" + firstIndex:
			http.Error(w, `{"error":{"type":"resource_already_exists_exception"}}`, http.StatusConflict)
		case "GET /_alias/" + alias:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"`+firstIndex+`":{"aliases":{"`+alias+`":{"is_write_index":true}}}}`)
		case "PUT /" + firstIndex + "/_settings":
			http.Error(w, `{"error":"settings failed"}`, http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	client := NewClient(testConfig(elasticSearch))
	bootstrapped, err := client.EnsureWriteAlias(context.Background(), alias)
	if err == nil {
		t.Fatal("expected policy repair failure after bootstrap conflict")
	}
	if bootstrapped {
		t.Fatal("failed policy repair should not report bootstrap")
	}
	if !strings.Contains(err.Error(), `attach ILM policy to "`+firstIndex+`"`) || !strings.Contains(err.Error(), "status=500") {
		t.Fatalf("expected policy repair context, got %v", err)
	}
	if _, cached := client.EnsuredAliasPolicies.Load(alias); cached {
		t.Fatal("failed policy repair must not be cached")
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/" + alias,
		"PUT /" + firstIndex,
		"HEAD /_alias/" + alias,
		"GET /_alias/" + alias,
		"PUT /" + firstIndex + "/_settings",
	}) {
		t.Fatalf("unexpected policy repair calls: %#v", calls)
	}
}

//nolint:gocognit,funlen // Subtests keep the bulk request failure branches in one place.
func TestBulkIndexDocumentsErrorBranches(t *testing.T) {
	t.Run("action marshal error", func(t *testing.T) {
		client := newUnusedElasticClient(t)
		_, err := client.BulkIndexDocuments(context.Background(), []BulkIndexDocument{
			{Index: "orders", Metadata: map[string]any{"bad": make(chan int)}, Document: map[string]any{"event_time": "2024-12-30T10:11:12Z"}},
		})
		if err == nil {
			t.Fatal("expected action metadata marshal error")
		}
	})

	t.Run("document marshal error", func(t *testing.T) {
		client := newUnusedElasticClient(t)
		_, err := client.BulkIndexDocuments(context.Background(), []BulkIndexDocument{
			{Action: "create", Index: "orders", Document: map[string]any{"bad": make(chan int)}},
		})
		if err == nil {
			t.Fatal("expected document marshal error")
		}
	})

	t.Run("request build error", func(t *testing.T) {
		client := newUnusedElasticClient(t)
		client.Config.ElasticsearchURL = "://bad"

		_, err := client.BulkIndexDocuments(context.Background(), []BulkIndexDocument{
			{Index: "orders", Document: map[string]any{"event_time": "2024-12-30T10:11:12Z"}},
		})
		if err == nil {
			t.Fatal("expected request build error")
		}
	})

	t.Run("http client error", func(t *testing.T) {
		sentinel := errors.New("network failed")
		client := newUnusedElasticClient(t)
		client.Config.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, sentinel
		})}

		_, err := client.BulkIndexDocuments(context.Background(), []BulkIndexDocument{
			{Index: "orders", Document: map[string]any{"event_time": "2024-12-30T10:11:12Z"}},
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected HTTP client error, got %v", err)
		}
	})

	t.Run("non ok response keeps upstream body", func(t *testing.T) {
		var requestBody string
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			requestBody = string(body)
			http.Error(w, `{"error":"bulk failed"}`, http.StatusInternalServerError)
		}))
		defer elasticSearch.Close()

		client := NewClient(testConfig(elasticSearch))
		_, err := client.BulkIndexDocuments(context.Background(), []BulkIndexDocument{
			{Index: "orders", Document: map[string]any{"event_time": "2024-12-30T10:11:12Z"}},
		})
		var responseErr *ResponseError
		if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("expected response error, got %v", err)
		}
		if !strings.Contains(responseErr.Body, "bulk failed") {
			t.Fatalf("expected upstream body, got %q", responseErr.Body)
		}
		if !strings.Contains(requestBody, `{"index":{"_index":"orders"}}`) {
			t.Fatalf("expected default bulk index action, got %q", requestBody)
		}
	})

	t.Run("decode response error", func(t *testing.T) {
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{bad json"))
		}))
		defer elasticSearch.Close()

		client := NewClient(testConfig(elasticSearch))
		_, err := client.BulkIndexDocuments(context.Background(), []BulkIndexDocument{
			{Index: "orders", Document: map[string]any{"event_time": "2024-12-30T10:11:12Z"}},
		})
		if err == nil {
			t.Fatal("expected response decode error")
		}
	})
}

func TestWriteIndicesForAliasBranches(t *testing.T) {
	t.Run("single backing index without explicit write index", func(t *testing.T) {
		const alias = "orders-20241230-rollover"
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"orders-000001":{"aliases":{"`+alias+`":{}}}}`)
		}))
		defer elasticSearch.Close()

		client := NewClient(testConfig(elasticSearch))
		got, err := client.WriteIndicesForAlias(context.Background(), alias)
		if err != nil {
			t.Fatalf("WriteIndicesForAlias returned error: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"orders-000001"}) {
			t.Fatalf("unexpected write indices: %#v", got)
		}
	})

	t.Run("no matching backing indices", func(t *testing.T) {
		const alias = "orders-20241230-rollover"
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"orders-000001":{"aliases":{"other":{}}}}`)
		}))
		defer elasticSearch.Close()

		client := NewClient(testConfig(elasticSearch))
		_, err := client.WriteIndicesForAlias(context.Background(), alias)
		if err == nil || !strings.Contains(err.Error(), "no backing indices") {
			t.Fatalf("expected no backing indices error, got %v", err)
		}
	})

	t.Run("multiple backing indices without write index", func(t *testing.T) {
		const alias = "orders-20241230-rollover"
		elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"orders-000001":{"aliases":{"`+alias+`":{}}},"orders-000002":{"aliases":{"`+alias+`":{}}}}`)
		}))
		defer elasticSearch.Close()

		client := NewClient(testConfig(elasticSearch))
		_, err := client.WriteIndicesForAlias(context.Background(), alias)
		if err == nil || !strings.Contains(err.Error(), "no write index") {
			t.Fatalf("expected no write index error, got %v", err)
		}
	})
}

func TestEnsureWriteAliasPolicyUsesCache(t *testing.T) {
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request after alias policy cache hit: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	client := NewClient(testConfig(elasticSearch))
	client.EnsuredAliasPolicies.Store("orders-20241230-rollover", true)

	if err := client.EnsureWriteAliasPolicy(context.Background(), "orders-20241230-rollover"); err != nil {
		t.Fatalf("EnsureWriteAliasPolicy returned error: %v", err)
	}
}

func newUnusedElasticClient(t *testing.T) *Client {
	t.Helper()

	elasticSearch := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(elasticSearch.Close)
	return NewClient(testConfig(elasticSearch))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
