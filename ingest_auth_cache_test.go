package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authzpkg "github.com/define42/elasticgateway/internal/authz"
	elasticpkg "github.com/define42/elasticgateway/internal/elastic"
	ingestpkg "github.com/define42/elasticgateway/internal/ingest"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
	serverpkg "github.com/define42/elasticgateway/internal/server"
)

//nolint:cyclop // Cache behavior test keeps the hit, miss, and expiry assertions together.
func TestIngestAuthCacheCachesSuccessfulLookups(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 8, 12, 0, 0, 0, time.UTC)
	cache := ingestpkg.NewAuthCache()
	cache.SetNow(func() time.Time { return now })

	lookups := 0
	key := ingestpkg.AuthCacheKey("ingestuser", "dogood")

	username, access, cached, err := cache.Resolve(key, func() (string, []authzpkg.Access, error) {
		lookups++
		return "ingestuser", []authzpkg.Access{{Group: "team10_rw", Namespace: "team10"}}, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if cached {
		t.Fatal("expected first lookup to miss cache")
	}
	if username != "ingestuser" || len(access) != 1 || access[0].Namespace != "team10" {
		t.Fatalf("unexpected cached access result: username=%q access=%+v", username, access)
	}

	access[0].Namespace = "mutated"
	now = now.Add(30 * time.Second)

	username, access, cached, err = cache.Resolve(key, func() (string, []authzpkg.Access, error) {
		lookups++
		return "wrong", nil, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error on cached lookup: %v", err)
	}
	if !cached {
		t.Fatal("expected second lookup to hit cache")
	}
	if username != "ingestuser" || len(access) != 1 || access[0].Namespace != "team10" {
		t.Fatalf("unexpected cached access result after mutation: username=%q access=%+v", username, access)
	}
	if lookups != 1 {
		t.Fatalf("expected one LDAP lookup, got %d", lookups)
	}

	stats := cache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Expired != 0 || stats.Entries != 1 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}
}

func TestIngestAuthCacheExpiresEntries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 8, 12, 0, 0, 0, time.UTC)
	cache := ingestpkg.NewAuthCache()
	cache.SetNow(func() time.Time { return now })

	lookups := 0
	key := ingestpkg.AuthCacheKey("ingestuser", "dogood")

	if _, _, _, err := cache.Resolve(key, func() (string, []authzpkg.Access, error) {
		lookups++
		return "ingestuser", []authzpkg.Access{{Group: "team10_rw", Namespace: "team10"}}, nil
	}); err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	now = now.Add(ingestpkg.CacheTTL + time.Second)

	_, _, cached, err := cache.Resolve(key, func() (string, []authzpkg.Access, error) {
		lookups++
		return "ingestuser", []authzpkg.Access{{Group: "team10_rw", Namespace: "team10"}}, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error after expiry: %v", err)
	}
	if cached {
		t.Fatal("expected expired entry to miss cache")
	}
	if lookups != 2 {
		t.Fatalf("expected two LDAP lookups after expiry, got %d", lookups)
	}

	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 2 || stats.Expired != 1 || stats.Entries != 1 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}
}

//nolint:gocognit // Concurrent cache miss test keeps goroutine coordination visible.
func TestIngestAuthCacheDeduplicatesConcurrentMisses(t *testing.T) {
	t.Parallel()

	cache := ingestpkg.NewAuthCache()
	key := ingestpkg.AuthCacheKey("ingestuser", "dogood")

	var lookups atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	const goroutines = 8
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			username, access, _, err := cache.Resolve(key, func() (string, []authzpkg.Access, error) {
				if lookups.Add(1) == 1 {
					started <- struct{}{}
				}
				<-release
				return "ingestuser", []authzpkg.Access{{Group: "team10_rw", Namespace: "team10"}}, nil
			})
			if err != nil {
				errCh <- err
				return
			}
			if username != "ingestuser" || len(access) != 1 || access[0].Namespace != "team10" {
				errCh <- io.ErrUnexpectedEOF
			}
		}()
	}

	<-started
	close(release)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent Resolve returned error: %v", err)
		}
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("expected one in-flight LDAP lookup, got %d", got)
	}

	stats := cache.Stats()
	if stats.Misses != 1 || stats.Entries != 1 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}
}

//nolint:cyclop,funlen // Cache integration test keeps first-hit repair and second-hit cache behavior together.
func TestGatewayIngestBasicAuthUsesLDAPCache(t *testing.T) {
	t.Parallel()

	var calls []string
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/team10-hello-20241230-rollover":
			w.WriteHeader(http.StatusOK)
		case "GET /_alias/team10-hello-20241230-rollover":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"team10-hello-20241230-rollover-000001":{"aliases":{"team10-hello-20241230-rollover":{"is_write_index":true}}}}`)
		case "PUT /team10-hello-20241230-rollover-000001/_settings":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "POST /team10-hello-20241230-rollover/_doc":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"cached-doc"}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	var authCalls atomic.Int32
	gateway := newTestGateway(elasticpkg.NewClient(testConfig(elasticSearch)), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		authCalls.Add(1)
		return &authzpkg.User{Name: username, Namespace: "team10"}, []authzpkg.Access{
			{Group: "team10_rw", Namespace: "team10"},
		}, nil
	})

	handler := gateway.Handler()
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/elasticgateway/ingest/team10-hello", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"cached"}`))
		request.Header.Set("Content-Type", "application/json")
		request.SetBasicAuth("ingestuser", "dogood")

		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusCreated {
			t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
		}

		var response serverpkg.IngestResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if response.WriteAlias != "team10-hello-20241230-rollover" {
			t.Fatalf("unexpected write alias: %#v", response)
		}
	}

	if got := authCalls.Load(); got != 1 {
		t.Fatalf("expected one LDAP auth call, got %d", got)
	}
	if len(calls) != 6 {
		t.Fatalf("expected first write to repair policy and both writes to index, got %#v", calls)
	}

	stats := gateway.IngestAuthCache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Expired != 0 || stats.Entries != 1 {
		t.Fatalf("unexpected gateway cache stats: %+v", stats)
	}
}

func TestIngestAuthCacheForgetUserEvictsEntries(t *testing.T) {
	t.Parallel()

	cache := ingestpkg.NewAuthCache()

	resolve := func(username, password, namespace string) {
		key := ingestpkg.AuthCacheKey(username, password)
		if _, _, _, err := cache.Resolve(key, func() (string, []authzpkg.Access, error) {
			return username, []authzpkg.Access{{Group: namespace + "_rw", Namespace: namespace}}, nil
		}); err != nil {
			t.Fatalf("Resolve(%q): %v", username, err)
		}
	}

	resolve("alice", "p1", "team10")
	resolve("alice", "p2", "team10")
	resolve("bob", "p1", "team20")

	if got := cache.Stats().Entries; got != 3 {
		t.Fatalf("expected 3 entries before forget, got %d", got)
	}

	cache.ForgetUser("alice")

	stats := cache.Stats()
	if stats.Entries != 1 {
		t.Fatalf("expected 1 entry after forgetting alice, got %d", stats.Entries)
	}

	_, _, cached, err := cache.Resolve(ingestpkg.AuthCacheKey("bob", "p1"), func() (string, []authzpkg.Access, error) {
		t.Fatal("bob's entry should still be cached")
		return "", nil, nil
	})
	if err != nil || !cached {
		t.Fatalf("bob's entry was evicted (cached=%v err=%v)", cached, err)
	}
}

func TestGatewayLogoutEvictsIngestAuthCache(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfig(elasticSearch)), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return &authzpkg.User{Name: username}, []authzpkg.Access{{Group: "team10_rw", Namespace: "team10"}}, nil
	})

	if _, _, _, err := gateway.IngestAuthCache.Resolve(ingestpkg.AuthCacheKey("ingestuser", "dogood"), func() (string, []authzpkg.Access, error) {
		return "ingestuser", []authzpkg.Access{{Group: "team10_rw", Namespace: "team10"}}, nil
	}); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "ingestuser"},
		AuthHeader: serverpkg.BuildBasicAuthorization("ingestuser", "dogood"),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/elasticgateway/logout", nil)
	request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected logout redirect, got %d", recorder.Code)
	}
	if got := gateway.IngestAuthCache.Stats().Entries; got != 0 {
		t.Fatalf("expected ingest auth cache entries to be cleared after logout, got %d", got)
	}
}

func TestGatewayIngestBasicAuthDoesNotCacheAuthenticationErrors(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	var authCalls atomic.Int32
	gateway := newTestGateway(elasticpkg.NewClient(testConfig(elasticSearch)), func(_, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		authCalls.Add(1)
		return nil, nil, ldappkg.ErrInvalidCredentials
	})

	handler := gateway.Handler()
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/elasticgateway/ingest/team10-hello", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"cached"}`))
		request.Header.Set("Content-Type", "application/json")
		request.SetBasicAuth("ingestuser", "wrong")

		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
		}
	}

	if got := authCalls.Load(); got != 2 {
		t.Fatalf("expected failed LDAP auth to be retried twice, got %d", got)
	}

	stats := gateway.IngestAuthCache.Stats()
	if stats.Hits != 0 || stats.Misses != 2 || stats.Expired != 0 || stats.Entries != 0 {
		t.Fatalf("unexpected gateway cache stats after failures: %+v", stats)
	}
}
