package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appconfig "github.com/define42/elasticgateway/internal/config"
	elasticpkg "github.com/define42/elasticgateway/internal/elastic"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
	serverpkg "github.com/define42/elasticgateway/internal/server"
)

const testDefaultPassword = "Cedar7!FluxOrbit29"

//nolint:gocognit,cyclop,funlen // Docker-backed integration scenario verifies the full LDAP ingest path.
func TestLDAPIngestUserCanIngestTeam10(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker-backed LDAP integration test in short mode")
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, stopLDAP := startDockerGlauth(ctx, t)
	defer stopLDAP()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	var mu sync.Mutex
	var elasticSearchCalls []string
	var indexedDocument map[string]any
	aliasChecks := 0
	indexedDocuments := 0

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		elasticSearchCalls = append(elasticSearchCalls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch r.Method + " " + r.URL.Path {
		case "GET /_ilm/policy/" + elasticpkg.DefaultILMPolicyID:
			http.NotFound(w, r)
		case "PUT /_ilm/policy/" + elasticpkg.DefaultILMPolicyID:
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "PUT /_index_template/" + elasticpkg.DefaultIndexTemplateName:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "HEAD /_alias/team10-hello-20241230-rollover":
			if aliasChecks == 0 {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			aliasChecks++
		case "PUT /team10-hello-20241230-rollover-000001":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "GET /_alias/team10-hello-20241230-rollover":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"team10-hello-20241230-rollover-000001":{"aliases":{"team10-hello-20241230-rollover":{"is_write_index":true}}}}`)
		case "PUT /team10-hello-20241230-rollover-000001/_settings":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "POST /team10-hello-20241230-rollover/_doc":
			indexedDocument = decodeRequestBody(t, r)
			indexedDocuments++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"ldap-team10-doc"}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	var kibanaCalls []string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		kibanaCalls = append(kibanaCalls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()

		if got := r.Header.Get("kbn-xsrf"); got != "true" {
			t.Fatalf("expected kbn-xsrf header, got %q", got)
		}

		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /api/spaces/space/team10":
			http.NotFound(w, r)
		case "POST /api/spaces/space":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "GET /s/team10/api/data_views/data_view/gateway-index-pattern-team10-hello":
			http.NotFound(w, r)
		case "POST /s/team10/api/data_views/data_view":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "GET /s/team10/api/data_views/default":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"data_view_id":"gateway-index-pattern-team10"}`)
		default:
			t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer kibana.Close()

	cfg := appconfig.Config{
		ElasticsearchURL:      elasticSearch.URL,
		ElasticsearchUsername: "elastic",
		ElasticsearchPassword: testDefaultPassword,
		KibanaURL:             kibana.URL,
		KibanaUsername:        "admin",
		KibanaPassword:        testDefaultPassword,
		ListenAddr:            ":0",
		Shards:                1,
		Replicas:              1,
		HTTPClient:            &http.Client{Timeout: 10 * time.Second},
	}

	baseURL, gateway, stopGateway := startIntegrationGateway(ctx, t, cfg)
	defer stopGateway()

	responses := make([]serverpkg.IngestResponse, 0, 2)
	messages := []string{"ldap ingest integration", "ldap ingest cached"}
	for _, message := range messages {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/ingest/team10-hello", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"`+message+`"}`))
		if err != nil {
			t.Fatalf("build ingest request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("ingestuser", "dogood")

		resp, err := cfg.HTTPClient.Do(req)
		if err != nil {
			t.Fatalf("send ingest request: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read ingest response: %v", err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		var response serverpkg.IngestResponse
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("decode ingest response: %v", err)
		}
		responses = append(responses, response)
	}

	if responses[0].WriteAlias != "team10-hello-20241230-rollover" || responses[1].WriteAlias != "team10-hello-20241230-rollover" {
		t.Fatalf("unexpected write aliases: %#v", responses)
	}
	if responses[0].DocumentID != "ldap-team10-doc" || responses[0].Result != "created" || !responses[0].Bootstrapped {
		t.Fatalf("unexpected first ingest response: %#v", responses[0])
	}
	if responses[1].DocumentID != "ldap-team10-doc" || responses[1].Result != "created" || responses[1].Bootstrapped {
		t.Fatalf("unexpected second ingest response: %#v", responses[1])
	}

	if got := indexedDocument["message"]; got != "ldap ingest cached" {
		t.Fatalf("unexpected indexed message: %#v", indexedDocument)
	}
	if got := indexedDocument["event_time"]; got != "2024-12-30T10:11:12Z" {
		t.Fatalf("unexpected indexed event_time: %#v", indexedDocument)
	}
	if aliasChecks != 2 {
		t.Fatalf("expected two alias checks, got %d", aliasChecks)
	}
	if indexedDocuments != 2 {
		t.Fatalf("expected two indexed documents, got %d", indexedDocuments)
	}

	if !containsCall(elasticSearchCalls, "POST /team10-hello-20241230-rollover/_doc") {
		t.Fatalf("expected document ingest call, got %#v", elasticSearchCalls)
	}
	if !containsCall(kibanaCalls, "POST /s/team10/api/data_views/data_view") {
		t.Fatalf("expected Kibana data view creation, got %#v", kibanaCalls)
	}
	if len(kibanaCalls) != 5 {
		t.Fatalf("expected space-scoped Kibana setup only once, got %#v", kibanaCalls)
	}

	stats := gateway.IngestAuthCache.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Expired != 0 || stats.Entries != 1 {
		t.Fatalf("unexpected ingest auth cache stats: %+v", stats)
	}
}

//nolint:funlen // Docker-backed integration scenario setup is intentionally explicit.
func TestLDAPJohndoeCannotIngestTeam10(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker-backed LDAP integration test in short mode")
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, stopLDAP := startDockerGlauth(ctx, t)
	defer stopLDAP()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	var mu sync.Mutex
	var elasticSearchCalls []string

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		elasticSearchCalls = append(elasticSearchCalls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch r.Method + " " + r.URL.Path {
		case "GET /_ilm/policy/" + elasticpkg.DefaultILMPolicyID:
			http.NotFound(w, r)
		case "PUT /_ilm/policy/" + elasticpkg.DefaultILMPolicyID:
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "PUT /_index_template/" + elasticpkg.DefaultIndexTemplateName:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	kibana := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.RequestURI())
	}))
	defer kibana.Close()

	cfg := appconfig.Config{
		ElasticsearchURL:      elasticSearch.URL,
		ElasticsearchUsername: "elastic",
		ElasticsearchPassword: testDefaultPassword,
		KibanaURL:             kibana.URL,
		KibanaUsername:        "admin",
		KibanaPassword:        testDefaultPassword,
		ListenAddr:            ":0",
		Shards:                1,
		Replicas:              1,
		HTTPClient:            &http.Client{Timeout: 10 * time.Second},
	}

	baseURL, _, stopGateway := startIntegrationGateway(ctx, t, cfg)
	defer stopGateway()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/ingest/team10-hello", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"should be forbidden"}`))
	if err != nil {
		t.Fatalf("build ingest request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("johndoe", "dogood")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("send ingest request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read ingest response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", resp.StatusCode, string(body))
	}

	var response serverpkg.ErrorResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if response.Error != "your LDAP account is not allowed to ingest into this index" {
		t.Fatalf("unexpected error response: %#v", response)
	}

	if len(elasticSearchCalls) != 3 {
		t.Fatalf("expected only startup bootstrap calls, got %#v", elasticSearchCalls)
	}
	if containsCall(elasticSearchCalls, "POST /team10-hello-20241230-rollover/_doc") {
		t.Fatalf("document indexing should not happen for read-only LDAP user: %#v", elasticSearchCalls)
	}
}

func TestLDAPAuthenticateAccessErrorScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker-backed LDAP integration test in short mode")
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, stopLDAP := startDockerGlauth(ctx, t)
	defer stopLDAP()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	t.Run("invalid credentials", func(t *testing.T) {
		user, access, err := ldappkg.New(appconfig.LoadLDAP()).AuthenticateAccess("johndoe", "wrongpass")
		if !errors.Is(err, ldappkg.ErrInvalidCredentials) {
			t.Fatalf("expected invalid credentials error, got user=%+v access=%+v err=%v", user, access, err)
		}
	})

	t.Run("unauthorized groups", func(t *testing.T) {
		user, access, err := ldappkg.New(appconfig.LoadLDAP()).AuthenticateAccess("serviceuser", "mysecret")
		if !errors.Is(err, ldappkg.ErrUnauthorized) {
			t.Fatalf("expected unauthorized error, got user=%+v access=%+v err=%v", user, access, err)
		}
	})
}

func requireDocker(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	cmd := exec.Command("docker", "info")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("docker is not available: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

func startDockerGlauth(ctx context.Context, t *testing.T) (string, func()) {
	t.Helper()

	cfgPath := repoPath(t, "testldap", "default-config.cfg")
	certPath := repoPath(t, "testldap", "cert.pem")
	keyPath := repoPath(t, "testldap", "key.pem")
	containerName := fmt.Sprintf("elasticgateway-ldap-test-%d", time.Now().UnixNano())

	runArgs := []string{
		"run", "--detach", "--rm",
		"--publish", "127.0.0.1::389",
		"--name", containerName,
		"--env", "GLAUTH_CONFIG=/app/config/config.cfg",
		"--volume", cfgPath + ":/app/config/config.cfg:ro",
		"--volume", certPath + ":/app/config/cert.pem:ro",
		"--volume", keyPath + ":/app/config/key.pem:ro",
		"glauth/glauth:latest",
	}
	if out, err := exec.CommandContext(ctx, "docker", runArgs...).CombinedOutput(); err != nil {
		t.Fatalf("start glauth container: %v\n%s", err, string(out))
	}

	cleanup := func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = exec.CommandContext(stopCtx, "docker", "rm", "-f", containerName).CombinedOutput()
	}

	t.Cleanup(cleanup)

	port, err := dockerMappedPort(ctx, containerName, "389/tcp")
	if err != nil {
		t.Fatalf("resolve glauth mapped port: %v", err)
	}

	ldapURL := "ldaps://127.0.0.1:" + port
	waitForLDAPReady(ctx, t, ldapURL)
	return ldapURL, cleanup
}

func dockerMappedPort(ctx context.Context, containerName, containerPort string) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, "docker", "port", containerName, containerPort).CombinedOutput()
		if err == nil {
			mapping := strings.TrimSpace(string(out))
			if mapping != "" {
				hostPort := mapping[strings.LastIndex(mapping, ":")+1:]
				if hostPort != "" {
					return hostPort, nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("timed out waiting for docker port mapping for %s", containerName)
}

func waitForLDAPReady(ctx context.Context, t *testing.T, ldapURL string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cfg := appconfig.LDAPConfig{
			URL:             ldapURL,
			BaseDN:          "dc=glauth,dc=com",
			UserFilter:      "(mail=%s)",
			GroupAttribute:  "memberOf",
			GroupNamePrefix: "team",
			UserMailDomain:  "@example.com",
			StartTLS:        false,
			SkipTLSVerify:   true,
		}
		_, _, err := ldappkg.New(cfg).AuthenticateAccess("ingestuser", "dogood")
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("LDAP did not become ready: %v", ctx.Err())
		case <-time.After(1 * time.Second):
		}
	}
	t.Fatalf("LDAP did not become ready in time")
}

func startIntegrationGateway(ctx context.Context, t *testing.T, cfg appconfig.Config) (string, *serverpkg.Gateway, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for gateway: %v", err)
	}

	baseURL := "http://" + listener.Addr().String()
	client := elasticpkg.NewClient(cfg)
	if err := client.EnsureILMPolicy(ctx, elasticpkg.DefaultILMPolicyID, 100000000); err != nil {
		t.Fatalf("bootstrap ILM policy: %v", err)
	}
	if err := client.EnsureIndexTemplate(ctx, elasticpkg.DefaultIndexTemplateName); err != nil {
		t.Fatalf("bootstrap index template: %v", err)
	}
	gateway := newTestGateway(client, ldappkg.New(appconfig.LoadLDAP()).AuthenticateAccess)
	runCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)

	go func() {
		srv := &http.Server{
			Handler:           gateway.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
		}

		go func() {
			<-runCtx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
		}()

		err := srv.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	waitForGatewayReady(ctx, t, cfg.HTTPClient, baseURL)

	cleanup := func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("gateway exited with error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for gateway shutdown")
		}
	}

	return baseURL, gateway, cleanup
}

func waitForGatewayReady(ctx context.Context, t *testing.T, client *http.Client, baseURL string) {
	t.Helper()

	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/login", nil)
		if err != nil {
			t.Fatalf("build readiness request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("gateway did not become ready in time")
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func repoPath(t *testing.T, elems ...string) string {
	t.Helper()

	path := filepath.Join(elems...)
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve path %q: %v", path, err)
	}
	return abs
}
