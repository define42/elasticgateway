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
