package ingest

import (
	"errors"
	"strings"
	"testing"

	"github.com/define42/elasticgateway/internal/authz"
)

func TestAuthCacheNilResolveFetchesAndClones(t *testing.T) {
	t.Parallel()

	var cache *AuthCache
	originalAccess := []authz.Access{{Group: "team1_rw", Namespace: "team1"}}

	username, access, cached, err := cache.Resolve("key", func() (string, []authz.Access, error) {
		return "alice", originalAccess, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if username != "alice" || cached {
		t.Fatalf("unexpected nil-cache result: username=%q cached=%v", username, cached)
	}

	access[0].Namespace = "mutated"
	if originalAccess[0].Namespace != "team1" {
		t.Fatalf("nil-cache Resolve did not clone access: %#v", originalAccess)
	}
}

func TestAuthCacheResolveUsesInflightResult(t *testing.T) {
	t.Parallel()

	cache := NewAuthCache()
	key := "inflight-success"
	done := make(chan struct{})
	call := &authCacheCall{
		done: done,
		entry: authCacheEntry{
			Username: "alice",
			Access:   []authz.Access{{Group: "team1_rw", Namespace: "team1"}},
		},
	}
	cache.mu.Lock()
	cache.inflight[key] = call
	close(done)
	cache.mu.Unlock()

	username, access, cached, err := cache.Resolve(key, func() (string, []authz.Access, error) {
		t.Fatal("fetch should not run while an in-flight lookup exists")
		return "", nil, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if username != "alice" || cached || len(access) != 1 || access[0].Namespace != "team1" {
		t.Fatalf("unexpected in-flight result: username=%q cached=%v access=%#v", username, cached, access)
	}
}

func TestAuthCacheResolveReturnsInflightError(t *testing.T) {
	t.Parallel()

	cache := NewAuthCache()
	key := "inflight-error"
	sentinel := errors.New("lookup failed")
	done := make(chan struct{})
	call := &authCacheCall{done: done, err: sentinel}
	cache.mu.Lock()
	cache.inflight[key] = call
	close(done)
	cache.mu.Unlock()

	_, _, _, err := cache.Resolve(key, func() (string, []authz.Access, error) {
		t.Fatal("fetch should not run while an in-flight lookup exists")
		return "", nil, nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected in-flight error, got %v", err)
	}
}

func TestAuthCacheCurrentTimeHandlesNilCache(t *testing.T) {
	t.Parallel()

	var cache *AuthCache
	if cache.currentTime().IsZero() {
		t.Fatal("expected nil cache currentTime to return current time")
	}
}

func TestDecodeBulkNDJSONDrainsAfterMalformedActionLine(t *testing.T) {
	t.Parallel()

	trailingErr := errors.New("trailing read failed")
	_, err := DecodeBulkNDJSON(&malformedLineThenErrorReader{err: trailingErr})

	if !errors.Is(err, trailingErr) {
		t.Fatalf("expected trailing read error to be surfaced, got %v", err)
	}
	if !strings.Contains(err.Error(), "bulk action line 1") {
		t.Fatalf("expected malformed action context, got %v", err)
	}
}

func TestDecodeBulkNDJSONPreservesMalformedActionLineErrorAfterDrain(t *testing.T) {
	t.Parallel()

	body := strings.NewReader("{bad}\n" +
		"{\"index\":{}}\n" +
		"{\"event_time\":\"2024-12-30T10:11:12Z\"}\n")

	_, err := DecodeBulkNDJSON(body)

	if err == nil || !strings.Contains(err.Error(), "bulk action line 1: invalid action JSON") {
		t.Fatalf("expected malformed action error, got %v", err)
	}
}

func TestDecodeBulkNDJSONRejectsMalformedBodies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "empty body",
			body: "",
			want: "bulk body must contain at least one action/source pair",
		},
		{
			name: "blank only body",
			body: "\n \n\t\n",
			want: "bulk body must contain at least one action/source pair",
		},
		{
			name: "action without source",
			body: "{\"index\":{}}\n\n",
			want: "bulk action line 1 has no source document",
		},
		{
			name: "unsupported action",
			body: "{\"delete\":{}}\n{\"event_time\":\"2024-12-30T10:11:12Z\"}\n",
			want: `bulk action line 1: unsupported action "delete"; only index and create are supported`,
		},
		{
			name: "multiple actions",
			body: "{\"index\":{},\"create\":{}}\n{\"event_time\":\"2024-12-30T10:11:12Z\"}\n",
			want: "bulk action line 1: action must contain exactly one operation",
		},
		{
			name: "invalid action metadata",
			body: "{\"index\":\"not metadata\"}\n{\"event_time\":\"2024-12-30T10:11:12Z\"}\n",
			want: "bulk action line 1: invalid action metadata",
		},
		{
			name: "invalid source json",
			body: "{\"index\":{}}\n{bad}\n",
			want: "bulk source line 2: invalid source JSON",
		},
		{
			name: "null source document",
			body: "{\"index\":{}}\nnull\n",
			want: "bulk source line 2: source document must be a JSON object",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeBulkNDJSON(strings.NewReader(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestDecodeBulkNDJSONDrainsAfterMalformedSourceLine(t *testing.T) {
	t.Parallel()

	trailingErr := errors.New("trailing read failed")
	_, err := DecodeBulkNDJSON(&malformedSourceThenErrorReader{err: trailingErr})

	if !errors.Is(err, trailingErr) {
		t.Fatalf("expected trailing read error to be surfaced, got %v", err)
	}
	if !strings.Contains(err.Error(), "bulk source line 2") {
		t.Fatalf("expected malformed source context, got %v", err)
	}
}

func TestDecodeJSONObjectRejectsEmptyAndTrailingInput(t *testing.T) {
	t.Parallel()

	if _, err := DecodeJSONObject(strings.NewReader("")); err == nil || err.Error() != "request body must be a JSON object" {
		t.Fatalf("expected empty-body decode error, got %v", err)
	}

	if _, err := DecodeJSONObject(strings.NewReader(`{} {}`)); err == nil || !strings.Contains(err.Error(), "single JSON object") {
		t.Fatalf("expected trailing-json decode error, got %v", err)
	}
}

func TestParsePathValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr string
	}{
		{name: "valid", path: "/ingest/orders-demo/", want: "orders-demo"},
		{name: "wrong route", path: "/other/orders-demo", wantErr: ErrRouteNotFound.Error()},
		{name: "empty index", path: "/ingest/", wantErr: "path must be /ingest/<index>/"},
		{name: "nested path", path: "/ingest/orders/demo", wantErr: "path must be /ingest/<index>/"},
		{name: "invalid index", path: "/ingest/Orders", wantErr: "index name must start"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParsePath(tt.path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ParsePath returned error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("ParsePath returned %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestParseBulkPathValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr string
	}{
		{name: "valid", path: "/ingest/orders-demo/_bulk/", want: "orders-demo"},
		{name: "wrong route", path: "/other/orders-demo/_bulk", wantErr: ErrRouteNotFound.Error()},
		{name: "missing bulk suffix", path: "/ingest/orders-demo", wantErr: ErrRouteNotFound.Error()},
		{name: "empty index", path: "/ingest//_bulk", wantErr: "path must be /ingest/<index>/_bulk"},
		{name: "nested path", path: "/ingest/orders/demo/_bulk", wantErr: "path must be /ingest/<index>/_bulk"},
		{name: "invalid index", path: "/ingest/Orders/_bulk", wantErr: "index name must start"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseBulkPath(tt.path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseBulkPath returned error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("ParseBulkPath returned %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

type malformedLineThenErrorReader struct {
	read bool
	err  error
}

func (r *malformedLineThenErrorReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, r.err
	}
	r.read = true
	return copy(p, "{bad}\n"), nil
}

type malformedSourceThenErrorReader struct {
	read bool
	err  error
}

func (r *malformedSourceThenErrorReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, r.err
	}
	r.read = true
	return copy(p, "{\"index\":{}}\n{bad}\n"), nil
}
