package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	authzpkg "github.com/define42/opensearchgateway/internal/authz"
	appconfig "github.com/define42/opensearchgateway/internal/config"
	elasticpkg "github.com/define42/opensearchgateway/internal/elastic"
	ldappkg "github.com/define42/opensearchgateway/internal/ldap"
	serverpkg "github.com/define42/opensearchgateway/internal/server"
)

//nolint:gocognit,funlen // Bootstrap test keeps policy/template request assertions together.
func TestRunBootstrapsBeforeServe(t *testing.T) {
	t.Parallel()

	var calls []string
	var policyBody map[string]any
	var templateBody map[string]any

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /_ilm/policy/" + elasticpkg.DefaultILMPolicyID:
			calls = append(calls, "policy")
			http.NotFound(w, r)
		case "PUT /_ilm/policy/" + elasticpkg.DefaultILMPolicyID:
			calls = append(calls, "policy-put")
			policyBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusOK)
		case "PUT /_index_template/" + elasticpkg.DefaultIndexTemplateName:
			calls = append(calls, "template")
			templateBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected bootstrap request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	sentinel := errors.New("stop serve")
	err := run(context.Background(), testConfig(elasticSearch), func(handler http.Handler) error {
		if handler == nil {
			t.Fatal("expected handler to be constructed")
		}
		if !reflect.DeepEqual(calls, []string{"policy", "policy-put", "template"}) {
			t.Fatalf("unexpected bootstrap order: %#v", calls)
		}

		template := nestedMap(t, templateBody["template"])
		settings := nestedMap(t, template["settings"])
		if got := settings["index.lifecycle.name"]; got != elasticpkg.DefaultILMPolicyID {
			t.Fatalf("unexpected template policy id: %#v", got)
		}

		mappings := nestedMap(t, template["mappings"])
		properties := nestedMap(t, mappings["properties"])
		eventTime := nestedMap(t, properties["event_time"])
		if got := eventTime["type"]; got != "date" {
			t.Fatalf("expected event_time mapping to be date, got %#v", got)
		}

		patterns, ok := templateBody["index_patterns"].([]any)
		if !ok || len(patterns) != 1 || patterns[0] != "*-*-rollover-*" {
			t.Fatalf("unexpected index_patterns: %#v", templateBody["index_patterns"])
		}
		if got := templateBody["priority"]; got != float64(2000) {
			t.Fatalf("unexpected template priority: %#v", got)
		}

		policy := nestedMap(t, policyBody["policy"])
		phases := nestedMap(t, policy["phases"])
		hot := nestedMap(t, phases["hot"])
		actions := nestedMap(t, hot["actions"])
		rollover := nestedMap(t, actions["rollover"])
		if got := rollover["max_docs"]; got != float64(100000000) {
			t.Fatalf("unexpected rollover max docs: %#v", policyBody)
		}

		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

func TestEnsureILMPolicySkipsWhenExistingMatches(t *testing.T) {
	t.Parallel()

	var calls []string
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/_ilm/policy/"+elasticpkg.DefaultILMPolicyID {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]elasticpkg.ILMPolicyResponse{
			elasticpkg.DefaultILMPolicyID: {
				Policy: elasticpkg.BuildILMPolicy(100000000),
			},
		})
	}))
	defer elasticSearch.Close()

	client := elasticpkg.NewClient(testConfig(elasticSearch))
	if err := client.EnsureILMPolicy(context.Background(), elasticpkg.DefaultILMPolicyID, 100000000); err != nil {
		t.Fatalf("EnsureILMPolicy returned error: %v", err)
	}

	if !reflect.DeepEqual(calls, []string{"GET /_ilm/policy/" + elasticpkg.DefaultILMPolicyID}) {
		t.Fatalf("unexpected request sequence: %#v", calls)
	}
}

func TestEnsureILMPolicyUpdatesWhenExistingDiffers(t *testing.T) {
	t.Parallel()

	var calls []string
	var updateBody map[string]any

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())

		switch len(calls) {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/_ilm/policy/"+elasticpkg.DefaultILMPolicyID {
				t.Fatalf("unexpected first request: %s %s", r.Method, r.URL.RequestURI())
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]elasticpkg.ILMPolicyResponse{
				elasticpkg.DefaultILMPolicyID: {
					Policy: elasticpkg.BuildILMPolicy(10),
				},
			})
		case 2:
			expectedPath := "/_ilm/policy/" + elasticpkg.DefaultILMPolicyID
			if r.Method != http.MethodPut || r.URL.RequestURI() != expectedPath {
				t.Fatalf("unexpected second request: %s %s", r.Method, r.URL.RequestURI())
			}
			updateBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer elasticSearch.Close()

	client := elasticpkg.NewClient(testConfig(elasticSearch))
	if err := client.EnsureILMPolicy(context.Background(), elasticpkg.DefaultILMPolicyID, 100000000); err != nil {
		t.Fatalf("EnsureILMPolicy returned error: %v", err)
	}

	if !reflect.DeepEqual(calls, []string{
		"GET /_ilm/policy/" + elasticpkg.DefaultILMPolicyID,
		"PUT /_ilm/policy/" + elasticpkg.DefaultILMPolicyID,
	}) {
		t.Fatalf("unexpected request sequence: %#v", calls)
	}

	policy := nestedMap(t, updateBody["policy"])
	phases := nestedMap(t, policy["phases"])
	hot := nestedMap(t, phases["hot"])
	actions := nestedMap(t, hot["actions"])
	rollover := nestedMap(t, actions["rollover"])
	if got := rollover["max_docs"]; got != float64(100000000) {
		t.Fatalf("unexpected updated policy body: %#v", updateBody)
	}
}

func TestEnsureSpaceCreatesWhenMissing(t *testing.T) {
	t.Parallel()

	var calls []string
	var createBody map[string]any

	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch len(calls) {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/api/spaces/space/orders" {
				t.Fatalf("unexpected first request: %s %s", r.Method, r.URL.Path)
			}
			http.NotFound(w, r)
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/api/spaces/space" {
				t.Fatalf("unexpected second request: %s %s", r.Method, r.URL.Path)
			}
			createBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer kibana.Close()

	cfg := appconfig.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()}

	client := elasticpkg.NewClient(cfg)
	if err := client.EnsureSpace(context.Background(), "orders"); err != nil {
		t.Fatalf("EnsureSpace returned error: %v", err)
	}

	if !reflect.DeepEqual(calls, []string{
		"GET /api/spaces/space/orders",
		"POST /api/spaces/space",
	}) {
		t.Fatalf("unexpected request sequence: %#v", calls)
	}
	if got := createBody["description"]; got != "Gateway space for orders" {
		t.Fatalf("unexpected space description: %#v", got)
	}
	if got := createBody["id"]; got != "orders" {
		t.Fatalf("unexpected space id: %#v", got)
	}
}

func TestEnsureSpaceSkipsWhenExisting(t *testing.T) {
	t.Parallel()

	var calls []string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/api/spaces/space/orders" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"orders","name":"orders"}`)
	}))
	defer kibana.Close()

	cfg := appconfig.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()}

	client := elasticpkg.NewClient(cfg)
	if err := client.EnsureSpace(context.Background(), "orders"); err != nil {
		t.Fatalf("EnsureSpace returned error: %v", err)
	}

	if !reflect.DeepEqual(calls, []string{"GET /api/spaces/space/orders"}) {
		t.Fatalf("unexpected request sequence: %#v", calls)
	}
}

func TestEnsureSpaceReturnsErrorOnFailure(t *testing.T) {
	t.Parallel()

	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/spaces/space/orders" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, `{"error":"space lookup failed"}`, http.StatusInternalServerError)
	}))
	defer kibana.Close()

	cfg := appconfig.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()}

	client := elasticpkg.NewClient(cfg)
	if err := client.EnsureSpace(context.Background(), "orders"); err == nil {
		t.Fatal("expected EnsureSpace to fail")
	}
}

//nolint:funlen // End-to-end data-view setup keeps request assertions together.
func TestEnsureKibanaDataViewCreatesExpectedPatternWithoutOverwritingDefault(t *testing.T) {
	t.Parallel()

	var requestBody map[string]any
	var defaultIndexGets int
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("kbn-xsrf"); got != "true" {
			t.Fatalf("expected kbn-xsrf header, got %q", got)
		}
		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /api/spaces/space/team10":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"id":"team10","name":"team10"}`)
		case "GET /s/team10/api/data_views/data_view/gateway-index-pattern-team10-hello":
			http.NotFound(w, r)
		case "POST /s/team10/api/data_views/data_view":
			requestBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "GET /s/team10/api/data_views/default":
			defaultIndexGets++
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"data_view_id":"gateway-index-pattern-team10"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer kibana.Close()

	client := elasticpkg.NewClient(appconfig.Config{KibanaURL: kibana.URL, HTTPClient: kibana.Client()})

	if err := client.EnsureKibanaDataView(context.Background(), "team10", "team10-hello"); err != nil {
		t.Fatalf("EnsureKibanaDataView returned error: %v", err)
	}

	dataView := nestedMap(t, requestBody["data_view"])
	if got := dataView["title"]; got != "team10-hello-*" {
		t.Fatalf("unexpected data view title: %#v", got)
	}
	if got := dataView["timeFieldName"]; got != "event_time" {
		t.Fatalf("unexpected time field: %#v", got)
	}
	if defaultIndexGets != 1 {
		t.Fatalf("expected one default-index lookup, got %d", defaultIndexGets)
	}
	if _, ok := client.EnsuredDataViews.Load("team10/" + elasticpkg.BuildDataViewID("team10-hello")); !ok {
		t.Fatal("expected ensured data-view cache to contain team10-hello")
	}
}

//nolint:funlen // End-to-end ingest flow keeps Elasticsearch and Kibana assertions together.
func TestGatewayIngestEnsuresKibanaDataView(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var calls []string
	appendCall := func(call string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call)
	}

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/orders-demo-20241230-rollover":
			appendCall("alias-head")
			w.WriteHeader(http.StatusOK)
		case "GET /_alias/orders-demo-20241230-rollover":
			appendCall("alias-get")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"orders-demo-20241230-rollover-000001":{"aliases":{"orders-demo-20241230-rollover":{"is_write_index":true}}}}`)
		case "PUT /orders-demo-20241230-rollover-000001/_settings":
			appendCall("policy-attach")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "POST /orders-demo-20241230-rollover/_doc":
			appendCall("doc-post")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"dash-view"}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /api/spaces/space/orders":
			appendCall("space-get")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"id":"orders","name":"orders"}`)
		case "GET /s/orders/api/data_views/data_view/gateway-index-pattern-orders-demo":
			appendCall("data-view-get")
			http.NotFound(w, r)
		case "POST /s/orders/api/data_views/data_view":
			appendCall("data-view-post")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "GET /s/orders/api/data_views/default":
			appendCall("default-index-get")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"data_view_id":"gateway-index-pattern-orders"}`)
		default:
			t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer kibana.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfigWithKibana(elasticSearch, kibana)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{
		"space-get",
		"data-view-get",
		"data-view-post",
		"default-index-get",
		"alias-head",
		"alias-get",
		"policy-attach",
		"doc-post",
	}) {
		t.Fatalf("unexpected request order: %#v", calls)
	}
}

func TestGatewayRootRedirectsToLogin(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(appconfig.Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login, got %q", got)
	}
}

func TestGatewayLoginServesLoginForm(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(appconfig.Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("expected HTML content type, got %q", got)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "<form") || !strings.Contains(body, "Username") || !strings.Contains(body, "Password") {
		t.Fatalf("expected login form content, got %q", body)
	}
}

func TestGatewayLoginRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(appconfig.Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/login", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodGet+", "+http.MethodPost {
		t.Fatalf("expected Allow header for login, got %q", got)
	}
}

func TestGatewayDemoServesDemoForm(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(appconfig.Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/demo", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("expected HTML content type, got %q", got)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "<form") || !strings.Contains(body, "Index Name") || !strings.Contains(body, "JSON Payload") {
		t.Fatalf("expected demo form content, got %q", body)
	}
	if !strings.Contains(body, "LDAP Username") || !strings.Contains(body, "LDAP Password") {
		t.Fatalf("expected demo page to include LDAP credential fields, got %q", body)
	}
	if !strings.Contains(body, "/ingest/") {
		t.Fatalf("expected demo page to reference ingest endpoint, got %q", body)
	}
}

func TestGatewayDemoRejectsNonGet(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(appconfig.Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/demo", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("expected Allow header %q, got %q", http.MethodGet, got)
	}
}

func TestGatewayIngestBasePathReturnsNotFound(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(appconfig.Config{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", recorder.Code)
	}
}

func TestGatewayAuthenticatedLoginRedirectsToKibana(t *testing.T) {
	t.Parallel()

	gateway := newTestGateway(elasticpkg.NewClient(appconfig.Config{}), nil)
	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "alice"},
		AuthHeader: serverpkg.BuildBasicAuthorization("alice", "secret"),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/kibana/app/home" {
		t.Fatalf("expected redirect to Kibana home, got %q", got)
	}
}

func TestGatewayLoginInvalidCredentialsReturnsUnauthorized(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	gateway := testGatewayHandlerWithAuth(testConfig(elasticSearch), func(_, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return nil, nil, ldappkg.ErrInvalidCredentials
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=wrong"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Header().Get("Set-Cookie"), serverpkg.SessionCookieName+"=") {
		t.Fatalf("did not expect session cookie on failed login")
	}
}

func TestGatewayLoginUnauthorizedGroupsReturnsForbidden(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	gateway := testGatewayHandlerWithAuth(testConfig(elasticSearch), func(_, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return nil, nil, ldappkg.ErrUnauthorized
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayLoginLDAPFailureReturnsBadGateway(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	gateway := testGatewayHandlerWithAuth(testConfig(elasticSearch), func(_, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return nil, nil, errors.New("ldap server unavailable")
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayLoginReservedInternalUserReturnsForbidden(t *testing.T) {
	t.Parallel()

	var elasticSearchCalls []string
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elasticSearchCalls = append(elasticSearchCalls, r.Method+" "+r.URL.Path)

		if r.Method != http.MethodGet || r.URL.Path != "/_security/user/testuser" {
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"testuser":{"reserved":true}}`)
	}))
	defer elasticSearch.Close()

	kibana := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.Path)
	}))
	defer kibana.Close()

	gateway := testGatewayHandlerWithAuth(testConfigWithKibana(elasticSearch, kibana), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return &authzpkg.User{Name: username, Namespace: "team1", PullOnly: false, DeleteAllowed: true}, []authzpkg.Access{
			{Group: "team1_rwd", Namespace: "team1", PullOnly: false, DeleteAllowed: true},
		}, nil
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(elasticSearchCalls, []string{
		"GET /_security/user/testuser",
	}) {
		t.Fatalf("unexpected Elasticsearch sequence: %#v", elasticSearchCalls)
	}
}

//nolint:gocognit,cyclop,funlen // Login provisioning scenario validates the complete request sequence.
func TestGatewayLoginSuccessProvisionsUserAndSession(t *testing.T) {
	t.Parallel()

	var elasticSearchCalls []string
	var roleBody map[string]any
	var spaceBody map[string]any
	var userBody map[string]any

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elasticSearchCalls = append(elasticSearchCalls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "GET /_security/user/testuser":
			http.NotFound(w, r)
		case "PUT /_security/user/testuser":
			userBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	var kibanaCalls []string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kibanaCalls = append(kibanaCalls, r.Method+" "+r.URL.RequestURI())

		if got := r.Header.Get("kbn-xsrf"); got != "true" {
			t.Fatalf("expected kbn-xsrf header, got %q", got)
		}
		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /api/spaces/space/team1":
			http.NotFound(w, r)
		case "POST /api/spaces/space":
			spaceBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "PUT /api/security/role/gateway_team1_rwd":
			roleBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusNoContent)
		case "GET /s/team1/api/data_views/data_view/gateway-index-pattern-team1":
			http.NotFound(w, r)
		case "POST /s/team1/api/data_views/data_view":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "POST /s/team1/api/data_views/default":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer kibana.Close()

	gateway := testGatewayHandlerWithAuth(testConfigWithKibana(elasticSearch, kibana), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return &authzpkg.User{Name: username, Namespace: "team1", PullOnly: false, DeleteAllowed: true}, []authzpkg.Access{
			{Group: "team1_rwd", Namespace: "team1", PullOnly: false, DeleteAllowed: true},
		}, nil
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/kibana/s/team1/app/home" {
		t.Fatalf("expected redirect to Kibana home, got %q", got)
	}
	if !strings.Contains(recorder.Header().Get("Set-Cookie"), serverpkg.SessionCookieName+"=") {
		t.Fatalf("expected session cookie, got %q", recorder.Header().Get("Set-Cookie"))
	}

	if !reflect.DeepEqual(elasticSearchCalls, []string{
		"GET /_security/user/testuser",
		"PUT /_security/user/testuser",
	}) {
		t.Fatalf("unexpected Elasticsearch sequence: %#v", elasticSearchCalls)
	}
	if !reflect.DeepEqual(kibanaCalls, []string{
		"GET /api/spaces/space/team1",
		"POST /api/spaces/space",
		"PUT /api/security/role/gateway_team1_rwd",
		"GET /s/team1/api/data_views/data_view/gateway-index-pattern-team1",
		"POST /s/team1/api/data_views/data_view",
		"POST /s/team1/api/data_views/default",
	}) {
		t.Fatalf("unexpected Kibana sequence: %#v", kibanaCalls)
	}

	elasticsearchRole := nestedMap(t, roleBody["elasticsearch"])
	indexPermissions, ok := elasticsearchRole["indices"].([]any)
	if !ok || len(indexPermissions) != 1 {
		t.Fatalf("expected one index privilege block, got %#v", roleBody)
	}
	indexPermission := nestedMap(t, indexPermissions[0])
	if got := indexPermission["names"]; !reflect.DeepEqual(got, []any{"team1-*"}) {
		t.Fatalf("unexpected index patterns: %#v", got)
	}
	if got := indexPermission["privileges"]; !reflect.DeepEqual(got, []any{"read", "write", "delete", "create_index", "view_index_metadata"}) {
		t.Fatalf("unexpected index privileges: %#v", got)
	}
	kibanaPrivileges, ok := roleBody["kibana"].([]any)
	if !ok || len(kibanaPrivileges) != 1 {
		t.Fatalf("expected Kibana privileges, got %#v", roleBody)
	}
	kibanaPrivilege := nestedMap(t, kibanaPrivileges[0])
	if got := kibanaPrivilege["base"]; !reflect.DeepEqual(got, []any{"all"}) {
		t.Fatalf("unexpected Kibana base privileges: %#v", got)
	}
	if got := kibanaPrivilege["spaces"]; !reflect.DeepEqual(got, []any{"team1"}) {
		t.Fatalf("unexpected Kibana spaces: %#v", got)
	}
	if got := spaceBody["description"]; got != "Gateway space for team1" {
		t.Fatalf("unexpected space description: %#v", got)
	}
	if got := userBody["password"]; got == "" {
		t.Fatalf("expected plaintext generated Elasticsearch password, got %#v", got)
	}
	if got := userBody["roles"]; !reflect.DeepEqual(got, []any{"gateway_team1_rwd"}) {
		t.Fatalf("unexpected Elasticsearch roles: %#v", got)
	}
	metadata := nestedMap(t, userBody["metadata"])
	if got := metadata["managed_by"]; got != "elasticgateway" {
		t.Fatalf("unexpected managed_by metadata: %#v", got)
	}
}

//nolint:cyclop,funlen // Multi-namespace login scenario verifies provisioning across namespaces.
func TestGatewayLoginMultiNamespaceRedirectsToKibanaHome(t *testing.T) {
	t.Parallel()

	var userBody map[string]any
	var elasticSearchCalls []string
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elasticSearchCalls = append(elasticSearchCalls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "GET /_security/user/testuser":
			http.NotFound(w, r)
		case "PUT /_security/user/testuser":
			userBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	var kibanaCalls []string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kibanaCalls = append(kibanaCalls, r.Method+" "+r.URL.RequestURI())

		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /api/spaces/space/team1",
			"GET /api/spaces/space/team10",
			"GET /api/spaces/space/team2":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "PUT /api/security/role/gateway_team1_rwd",
			"PUT /api/security/role/gateway_team10_r",
			"PUT /api/security/role/gateway_team2_rw":
			w.WriteHeader(http.StatusNoContent)
		case "GET /s/team1/api/data_views/data_view/gateway-index-pattern-team1",
			"GET /s/team10/api/data_views/data_view/gateway-index-pattern-team10",
			"GET /s/team2/api/data_views/data_view/gateway-index-pattern-team2":
			http.NotFound(w, r)
		case "POST /s/team1/api/data_views/data_view",
			"POST /s/team10/api/data_views/data_view",
			"POST /s/team2/api/data_views/data_view",
			"POST /s/team1/api/data_views/default",
			"POST /s/team10/api/data_views/default",
			"POST /s/team2/api/data_views/default":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer kibana.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfigWithKibana(elasticSearch, kibana)), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return &authzpkg.User{Name: username, Namespace: "team1", PullOnly: false, DeleteAllowed: true}, []authzpkg.Access{
			{Group: "team10_r", Namespace: "team10", PullOnly: true},
			{Group: "team1_rwd", Namespace: "team1", PullOnly: false, DeleteAllowed: true},
			{Group: "team2_rw", Namespace: "team2", PullOnly: false},
		}, nil
	})

	loginRecorder := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=testuser&password=dogood"))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	gateway.Handler().ServeHTTP(loginRecorder, loginRequest)

	if loginRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected login status 303, got %d: %s", loginRecorder.Code, loginRecorder.Body.String())
	}
	if got := loginRecorder.Header().Get("Location"); got != "/kibana/s/team1/app/home" {
		t.Fatalf("expected redirect to Kibana home, got %q", got)
	}
	cookies := loginRecorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected login to set a session cookie")
	}
	if got := userBody["roles"]; !reflect.DeepEqual(got, []any{"gateway_team10_r", "gateway_team1_rwd", "gateway_team2_rw"}) {
		t.Fatalf("unexpected Elasticsearch roles: %#v", got)
	}
	metadata := nestedMap(t, userBody["metadata"])
	if got := metadata["namespaces"]; !reflect.DeepEqual(got, []any{"team1", "team10", "team2"}) {
		t.Fatalf("unexpected namespace metadata: %#v", got)
	}
	if !reflect.DeepEqual(elasticSearchCalls, []string{
		"GET /_security/user/testuser",
		"PUT /_security/user/testuser",
	}) {
		t.Fatalf("unexpected Elasticsearch calls: %#v", elasticSearchCalls)
	}
	if len(kibanaCalls) != 15 {
		t.Fatalf("expected spaces, roles, data views, and defaults for three namespaces, got %#v", kibanaCalls)
	}
}

//nolint:gocognit // Table-driven role mode assertions intentionally cover every access shape.
func TestRoleRequestForAccessModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		access      authzpkg.Access
		wantAllowed []string
		wantBase    []string
		wantFeature map[string][]string
	}{
		{name: "read", access: authzpkg.Access{Namespace: "team1", PullOnly: true}, wantAllowed: []string{"read", "view_index_metadata"}, wantBase: []string{"read"}, wantFeature: map[string][]string{}},
		{name: "read edit", access: authzpkg.Access{Namespace: "team1", PullOnly: true, DashboardEdit: true}, wantAllowed: []string{"read", "view_index_metadata"}, wantBase: []string{}, wantFeature: map[string][]string{
			"dashboard_v2": {"all"},
			"discover_v2":  {"read"},
			"visualize_v2": {"all"},
		}},
		{name: "read delete", access: authzpkg.Access{Namespace: "team1", PullOnly: true, DeleteAllowed: true}, wantAllowed: []string{"read", "delete", "view_index_metadata"}, wantBase: []string{"all"}, wantFeature: map[string][]string{}},
		{name: "read write", access: authzpkg.Access{Namespace: "team1", PullOnly: false}, wantAllowed: []string{"read", "write", "create_index", "view_index_metadata"}, wantBase: []string{"all"}, wantFeature: map[string][]string{}},
		{name: "read write delete", access: authzpkg.Access{Namespace: "team1", PullOnly: false, DeleteAllowed: true}, wantAllowed: []string{"read", "write", "delete", "create_index", "view_index_metadata"}, wantBase: []string{"all"}, wantFeature: map[string][]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := elasticpkg.RoleRequestForAccess(tt.access)
			if got := role.Elasticsearch.Indices[0].Privileges; !reflect.DeepEqual(got, tt.wantAllowed) {
				t.Fatalf("unexpected index privileges: %#v", got)
			}
			if got := role.Elasticsearch.Indices[0].Names; !reflect.DeepEqual(got, []string{"team1-*"}) {
				t.Fatalf("unexpected index names: %#v", got)
			}
			if got := role.Kibana[0].Base; !reflect.DeepEqual(got, tt.wantBase) {
				t.Fatalf("unexpected Kibana base privileges: %#v", got)
			}
			if got := role.Kibana[0].Feature; !reflect.DeepEqual(got, tt.wantFeature) {
				t.Fatalf("unexpected Kibana feature privileges: %#v", got)
			}
			if got := role.Kibana[0].Spaces; !reflect.DeepEqual(got, []string{"team1"}) {
				t.Fatalf("unexpected Kibana spaces: %#v", got)
			}
		})
	}
}

func TestNormalizeAccessByNamespaceCombinesPermissions(t *testing.T) {
	t.Parallel()

	result := authzpkg.NormalizeAccessByNamespace([]authzpkg.Access{
		{Group: "team1_rw", Namespace: "team1", PullOnly: false},
		{Group: "team1_rd", Namespace: "team1", PullOnly: true, DeleteAllowed: true},
		{Group: "team2_r", Namespace: "team2", PullOnly: true},
		{Group: "team2_re", Namespace: "team2", PullOnly: true, DashboardEdit: true},
	})

	if len(result) != 2 {
		t.Fatalf("expected two namespaces, got %#v", result)
	}
	if got := authzpkg.RoleModeForAccess(result[0]); got != "rwd" {
		t.Fatalf("expected team1 to combine to rwd, got %q", got)
	}
	if got := authzpkg.RoleModeForAccess(result[1]); got != "re" {
		t.Fatalf("expected team2 to become re, got %q", got)
	}
}

func TestGatewayKibanaRequiresLogin(t *testing.T) {
	t.Parallel()

	gateway := testGatewayHandler(appconfig.Config{KibanaURL: "http://kibana.example"})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login, got %q", got)
	}
}

func TestGatewayKibanaProxyForwardsSessionBasicAuth(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	var upstreamAuth string
	var upstreamPath string
	var upstreamQuery string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
		upstreamPath = r.URL.Path
		upstreamQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "proxied kibana")
	}))
	defer kibana.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfigWithKibana(elasticSearch, kibana)), nil)
	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "testuser"},
		AuthHeader: serverpkg.BuildBasicAuthorization("testuser", "dogood"),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home?foo=bar", nil)
	request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if upstreamAuth != serverpkg.BuildBasicAuthorization("testuser", "dogood") {
		t.Fatalf("unexpected Authorization header: %q", upstreamAuth)
	}
	if upstreamPath != "/app/home" || upstreamQuery != "foo=bar" {
		t.Fatalf("unexpected upstream request: path=%q query=%q", upstreamPath, upstreamQuery)
	}
	if body := recorder.Body.String(); body != "proxied kibana" {
		t.Fatalf("unexpected proxy body: %q", body)
	}
}

func TestGatewayKibanaProxyForwardsMultiNamespaceSession(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "proxied kibana")
	}))
	defer kibana.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfigWithKibana(elasticSearch, kibana)), nil)
	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "testuser"},
		AuthHeader: serverpkg.BuildBasicAuthorization("testuser", "dogood"),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)
	request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayKibanaProxyForwardsQuery(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	var upstreamQueries []string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamQueries = append(upstreamQueries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "proxied kibana")
	}))
	defer kibana.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfigWithKibana(elasticSearch, kibana)), nil)
	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "testuser"},
		AuthHeader: serverpkg.BuildBasicAuthorization("testuser", "dogood"),
	})
	cookie := &http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt}

	firstRecorder := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodGet, "/kibana/app/home?foo=team10", nil)
	firstRequest.AddCookie(cookie)
	gateway.Handler().ServeHTTP(firstRecorder, firstRequest)
	if firstRecorder.Code != http.StatusOK {
		t.Fatalf("expected first status 200, got %d: %s", firstRecorder.Code, firstRecorder.Body.String())
	}

	if !reflect.DeepEqual(upstreamQueries, []string{"foo=team10"}) {
		t.Fatalf("expected query to pass through, got %#v", upstreamQueries)
	}
}

func TestGatewayKibanaProxyLeavesEmptyIndexPatternFindResultsUntouched(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	const upstreamBody = `{"page":1,"per_page":10000,"total":0,"saved_objects":[]}`
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/saved_objects/_find" {
			t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	defer kibana.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfigWithKibana(elasticSearch, kibana)), nil)
	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "testuser"},
		AuthHeader: serverpkg.BuildBasicAuthorization("testuser", "dogood"),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/api/saved_objects/_find?fields=title&per_page=10000&type=index-pattern", nil)
	request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := strings.TrimSpace(recorder.Body.String()); body != upstreamBody {
		t.Fatalf("expected upstream body to pass through, got %s", body)
	}
}

func TestGatewayKibanaProxyLeavesNonEmptyIndexPatternFindResultsUntouched(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	const upstreamBody = `{"page":1,"per_page":10000,"total":1,"saved_objects":[{"id":"upstream-pattern","type":"index-pattern","attributes":{"title":"custom-*","timeFieldName":"event_time"}}]}`
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	defer kibana.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfigWithKibana(elasticSearch, kibana)), nil)
	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "testuser"},
		AuthHeader: serverpkg.BuildBasicAuthorization("testuser", "dogood"),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/api/saved_objects/_find?fields=title&per_page=10000&type=index-pattern", nil)
	request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := strings.TrimSpace(recorder.Body.String()); body != upstreamBody {
		t.Fatalf("expected upstream body to pass through, got %s", body)
	}
}

func TestGatewayLogoutClearsSession(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	kibana := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Kibana request after logout: %s %s", r.Method, r.URL.Path)
	}))
	defer kibana.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfigWithKibana(elasticSearch, kibana)), nil)
	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "testuser"},
		AuthHeader: serverpkg.BuildBasicAuthorization("testuser", "dogood"),
	})

	logoutRecorder := httptest.NewRecorder()
	logoutRequest := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutRequest.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

	gateway.Handler().ServeHTTP(logoutRecorder, logoutRequest)

	if logoutRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected logout redirect, got %d", logoutRecorder.Code)
	}

	// With stateless cookies the gateway can no longer revoke an issued
	// cookie server-side; the strongest property the logout response can
	// guarantee is that the browser's copy is cleared.
	clearedCookie := findCookie(logoutRecorder.Result().Cookies(), serverpkg.SessionCookieName)
	if clearedCookie == nil {
		t.Fatal("expected logout response to set a clearing session cookie")
	}
	if clearedCookie.Value != "" || clearedCookie.MaxAge >= 0 {
		t.Fatalf("expected clearing cookie (empty value, negative MaxAge), got value=%q MaxAge=%d", clearedCookie.Value, clearedCookie.MaxAge)
	}

	kibanaRecorder := httptest.NewRecorder()
	kibanaRequest := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)
	gateway.Handler().ServeHTTP(kibanaRecorder, kibanaRequest)

	if kibanaRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303 after logout, got %d", kibanaRecorder.Code)
	}
	if got := kibanaRecorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login after logout, got %q", got)
	}
}

func TestGatewayKibanaLogoutClearsGatewaySession(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	kibana := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("Kibana logout should be handled by gateway, got upstream request: %s %s", r.Method, r.URL.Path)
	}))
	defer kibana.Close()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "auth logout get", method: http.MethodGet, path: "/kibana/auth/logout?nextUrl=%2Fkibana%2Fapp%2Fhome"},
		{name: "auth logout post", method: http.MethodPost, path: "/kibana/auth/logout"},
		{name: "legacy logout", method: http.MethodGet, path: "/kibana/logout"},
		{name: "api security logout", method: http.MethodPost, path: "/kibana/api/security/logout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway := newTestGateway(elasticpkg.NewClient(testConfigWithKibana(elasticSearch, kibana)), nil)
			encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
				User:       &authzpkg.User{Name: "testuser"},
				AuthHeader: serverpkg.BuildBasicAuthorization("testuser", "dogood"),
			})

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, nil)
			request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

			gateway.Handler().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusSeeOther {
				t.Fatalf("expected logout redirect, got %d: %s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Location"); got != "/login" {
				t.Fatalf("expected redirect to /login, got %q", got)
			}
			clearedCookie := findCookie(recorder.Result().Cookies(), serverpkg.SessionCookieName)
			if clearedCookie == nil {
				t.Fatal("expected logout response to clear gateway session cookie")
			}
			if clearedCookie.Value != "" || clearedCookie.MaxAge >= 0 {
				t.Fatalf("expected clearing cookie, got value=%q MaxAge=%d", clearedCookie.Value, clearedCookie.MaxAge)
			}
		})
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestGatewayInvalidSessionRedirectsToLogin(t *testing.T) {
	t.Parallel()

	gateway := newTestGateway(elasticpkg.NewClient(appconfig.Config{KibanaURL: "http://kibana.example"}), nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/kibana/app/home", nil)
	request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: "expired"})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login, got %q", got)
	}
}

func TestGatewayIngestRequiresAuthentication(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")

	testGatewayHandler(testConfig(elasticSearch)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("WWW-Authenticate"); got != `Basic realm="ElasticGateway ingest"` {
		t.Fatalf("unexpected WWW-Authenticate header: %q", got)
	}
}

func TestGatewayIngestRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("writer", "wrong")

	testGatewayHandlerWithAuth(testConfig(elasticSearch), func(_, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return nil, nil, ldappkg.ErrInvalidCredentials
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayIngestRejectsReadOnlyAccess(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/team10-hello", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("johndoe", "dogood")

	testGatewayHandlerWithAuth(testConfig(elasticSearch), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return &authzpkg.User{Name: username, Namespace: "team10", PullOnly: true}, []authzpkg.Access{
			{Group: "team10_r", Namespace: "team10", PullOnly: true},
		}, nil
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayIngestRejectsWrongNamespace(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("writer", "secret")

	testGatewayHandlerWithAuth(testConfig(elasticSearch), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return &authzpkg.User{Name: username, Namespace: "team1"}, []authzpkg.Access{
			{Group: "team1_rw", Namespace: "team1"},
		}, nil
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayIngestRejectsBareNamespace(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/team10", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("writer", "secret")

	testGatewayHandlerWithAuth(testConfig(elasticSearch), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return &authzpkg.User{Name: username, Namespace: "team10"}, []authzpkg.Access{
			{Group: "team10_rw", Namespace: "team10"},
		}, nil
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestGatewayIngestUsesAuthenticatedSessionAccess(t *testing.T) {
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
			_, _ = io.WriteString(w, `{"result":"created","_id":"session-doc"}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	gateway := newTestGateway(elasticpkg.NewClient(testConfig(elasticSearch)), func(_, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		t.Fatalf("session-backed ingest should not call LDAP authenticate")
		return nil, nil, nil
	})
	encoded, expiresAt := mustEncodeSessionCookieFromData(t, gateway, serverpkg.Session{
		User:       &authzpkg.User{Name: "ingestuser", Namespace: "team10"},
		Access:     []authzpkg.Access{{Group: "team10_rw", Namespace: "team10"}},
		AuthHeader: serverpkg.BuildBasicAuthorization("ingestuser", "dogood"),
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/team10-hello", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: serverpkg.SessionCookieName, Value: encoded, Expires: expiresAt})

	gateway.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/team10-hello-20241230-rollover",
		"GET /_alias/team10-hello-20241230-rollover",
		"PUT /team10-hello-20241230-rollover-000001/_settings",
		"POST /team10-hello-20241230-rollover/_doc",
	}) {
		t.Fatalf("unexpected Elasticsearch sequence: %#v", calls)
	}
}

//nolint:cyclop,funlen // Ingest bootstrap scenario keeps alias, policy, and indexing assertions together.
func TestGatewayIngestBootstrapsAndIndexes(t *testing.T) {
	t.Parallel()

	var calls []string
	var createBody map[string]any
	var indexBody map[string]any

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/orders-demo-20241230-rollover":
			calls = append(calls, "head")
			w.WriteHeader(http.StatusNotFound)
		case "PUT /orders-demo-20241230-rollover-000001":
			calls = append(calls, "create")
			createBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "POST /orders-demo-20241230-rollover/_doc":
			calls = append(calls, "index")
			indexBody = decodeRequestBody(t, r)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"abc123"}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo/", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello","count":1}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfig(elasticSearch)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{"head", "create", "index"}) {
		t.Fatalf("unexpected Elasticsearch sequence: %#v", calls)
	}

	aliases := nestedMap(t, createBody["aliases"])
	aliasConfig := nestedMap(t, aliases["orders-demo-20241230-rollover"])
	if got := aliasConfig["is_write_index"]; got != true {
		t.Fatalf("expected write alias to be marked as write index, got %#v", got)
	}

	settings := nestedMap(t, createBody["settings"])
	if got := settings["index.lifecycle.rollover_alias"]; got != "orders-demo-20241230-rollover" {
		t.Fatalf("unexpected rollover alias setting: %#v", got)
	}
	if got := settings["index.lifecycle.name"]; got != elasticpkg.DefaultILMPolicyID {
		t.Fatalf("unexpected policy setting: %#v", got)
	}
	if got := indexBody["event_time"]; got != "2024-12-30T10:11:12Z" {
		t.Fatalf("unexpected normalized event_time: %#v", got)
	}
	if got := indexBody["count"]; got != float64(1) {
		t.Fatalf("expected arbitrary fields to be preserved, got %#v", got)
	}

	var response serverpkg.IngestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Result != "created" || response.DocumentID != "abc123" || response.WriteAlias != "orders-demo-20241230-rollover" || !response.Bootstrapped {
		t.Fatalf("unexpected gateway response: %#v", response)
	}
}

func TestGatewayRepeatWriteSkipsBootstrap(t *testing.T) {
	t.Parallel()

	var calls []string

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/orders-demo-20241230-rollover":
			calls = append(calls, "head")
			w.WriteHeader(http.StatusOK)
		case "GET /_alias/orders-demo-20241230-rollover":
			calls = append(calls, "alias")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"orders-demo-20241230-rollover-000001":{"aliases":{"orders-demo-20241230-rollover":{"is_write_index":true}}}}`)
		case "PUT /orders-demo-20241230-rollover-000001/_settings":
			calls = append(calls, "attach")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case "POST /orders-demo-20241230-rollover/_doc":
			calls = append(calls, "index")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"steady"}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfig(elasticSearch)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{"head", "alias", "attach", "index"}) {
		t.Fatalf("unexpected Elasticsearch sequence: %#v", calls)
	}

	var response serverpkg.IngestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Bootstrapped {
		t.Fatalf("expected repeat write to skip bootstrap, got %#v", response)
	}
	if response.WriteAlias != "orders-demo-20241230-rollover" {
		t.Fatalf("unexpected alias: %#v", response)
	}
}

func TestEnsureWriteAliasRepairsExistingAliasPolicy(t *testing.T) {
	t.Parallel()

	var calls []string
	var attachBody map[string]any
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/orders-demo-20241230-rollover":
			w.WriteHeader(http.StatusOK)
		case "GET /_alias/orders-demo-20241230-rollover":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"orders-demo-20241230-rollover-000001":{"aliases":{"orders-demo-20241230-rollover":{"is_write_index":true}}}}`)
		case "PUT /orders-demo-20241230-rollover-000001/_settings":
			attachBody = decodeRequestBody(t, r)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	bootstrapped, err := elasticpkg.NewClient(testConfig(elasticSearch)).EnsureWriteAlias(context.Background(), "orders-demo-20241230-rollover")
	if err != nil {
		t.Fatalf("EnsureWriteAlias returned error: %v", err)
	}
	if bootstrapped {
		t.Fatal("existing alias should not report bootstrap")
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/orders-demo-20241230-rollover",
		"GET /_alias/orders-demo-20241230-rollover",
		"PUT /orders-demo-20241230-rollover-000001/_settings",
	}) {
		t.Fatalf("unexpected repair calls: %#v", calls)
	}
	indexSettings := nestedMap(t, attachBody["index"])
	lifecycle := nestedMap(t, indexSettings["lifecycle"])
	if got := lifecycle["name"]; got != elasticpkg.DefaultILMPolicyID {
		t.Fatalf("unexpected attached policy id: %#v", got)
	}
	if got := lifecycle["rollover_alias"]; got != "orders-demo-20241230-rollover" {
		t.Fatalf("unexpected attached rollover alias: %#v", got)
	}
}

func TestEnsureWriteAliasRejectsFailedILMSettingsResponse(t *testing.T) {
	t.Parallel()

	var calls []string
	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch r.Method + " " + r.URL.Path {
		case "HEAD /_alias/orders-demo-20241230-rollover":
			w.WriteHeader(http.StatusOK)
		case "GET /_alias/orders-demo-20241230-rollover":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"orders-demo-20241230-rollover-000001":{"aliases":{"orders-demo-20241230-rollover":{"is_write_index":true}}}}`)
		case "PUT /orders-demo-20241230-rollover-000001/_settings":
			http.Error(w, `{"error":"settings failed"}`, http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	client := elasticpkg.NewClient(testConfig(elasticSearch))
	bootstrapped, err := client.EnsureWriteAlias(context.Background(), "orders-demo-20241230-rollover")
	if err == nil {
		t.Fatal("expected EnsureWriteAlias to reject failed ILM settings response")
	}
	if bootstrapped {
		t.Fatal("failed repair should not report bootstrap")
	}
	if !strings.Contains(err.Error(), "orders-demo-20241230-rollover-000001") {
		t.Fatalf("expected failed index in error, got %v", err)
	}
	if _, cached := client.EnsuredAliasPolicies.Load("orders-demo-20241230-rollover"); cached {
		t.Fatal("failed policy repair must not be cached")
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/orders-demo-20241230-rollover",
		"GET /_alias/orders-demo-20241230-rollover",
		"PUT /orders-demo-20241230-rollover-000001/_settings",
	}) {
		t.Fatalf("unexpected repair calls: %#v", calls)
	}
}

func TestGatewayValidationErrors(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch call for validation error case: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	longNamespace := strings.Repeat("a", 240)
	longIndexName := longNamespace + "-x"
	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "invalid json", method: http.MethodPost, path: "/ingest/orders-demo", contentType: "application/json", body: `{"event_time":`, wantStatus: http.StatusBadRequest},
		{name: "non object body", method: http.MethodPost, path: "/ingest/orders-demo", contentType: "application/json", body: `[]`, wantStatus: http.StatusBadRequest},
		{name: "missing event_time", method: http.MethodPost, path: "/ingest/orders-demo", contentType: "application/json", body: `{"message":"hello"}`, wantStatus: http.StatusBadRequest},
		{name: "non string event_time", method: http.MethodPost, path: "/ingest/orders-demo", contentType: "application/json", body: `{"event_time":123}`, wantStatus: http.StatusBadRequest},
		{name: "non utc event_time", method: http.MethodPost, path: "/ingest/orders-demo", contentType: "application/json", body: `{"event_time":"2024-12-30T10:11:12+02:00"}`, wantStatus: http.StatusBadRequest},
		{name: "invalid index", method: http.MethodPost, path: "/ingest/Orders", contentType: "application/json", body: `{"event_time":"2024-12-30T10:11:12Z"}`, wantStatus: http.StatusBadRequest},
		{name: "extra path segments", method: http.MethodPost, path: "/ingest/orders/extra", contentType: "application/json", body: `{"event_time":"2024-12-30T10:11:12Z"}`, wantStatus: http.StatusBadRequest},
		{name: "wrong content type", method: http.MethodPost, path: "/ingest/orders-demo", contentType: "text/plain", body: `{"event_time":"2024-12-30T10:11:12Z"}`, wantStatus: http.StatusUnsupportedMediaType},
		{name: "wrong method", method: http.MethodGet, path: "/ingest/orders-demo", contentType: "application/json", body: ``, wantStatus: http.StatusMethodNotAllowed},
		{name: "name too long", method: http.MethodPost, path: "/ingest/" + longIndexName, contentType: "application/json", body: `{"event_time":"2024-12-30T10:11:12Z"}`, wantStatus: http.StatusBadRequest},
	}

	gateway := testGatewayHandlerWithAuth(testConfig(elasticSearch), func(username, _ string) (*authzpkg.User, []authzpkg.Access, error) {
		return &authzpkg.User{Name: username, Namespace: "orders"}, []authzpkg.Access{
			{Group: "orders_rw", Namespace: "orders"},
			{Group: longNamespace + "_rw", Namespace: longNamespace},
		}, nil
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.contentType != "" {
				request.Header.Set("Content-Type", tt.contentType)
			}
			addTestIngestBasicAuth(request)

			gateway.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tt.wantStatus, recorder.Code, recorder.Body.String())
			}
			if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
				t.Fatalf("expected JSON error response, got %q", contentType)
			}
		})
	}
}

//nolint:funlen // Error-mapping cases are kept together for consistent gateway assertions.
func TestGatewayElasticsearchFailuresReturnBadGateway(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantCalls []string
	}{
		{
			name: "alias head failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead || r.URL.Path != "/_alias/orders-demo-20241230-rollover" {
					t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
				}
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			wantCalls: []string{"HEAD /_alias/orders-demo-20241230-rollover"},
		},
		{
			name: "bootstrap put failure",
			handler: sequenceHandler(t,
				responseSpec{method: http.MethodHead, path: "/_alias/orders-demo-20241230-rollover", status: http.StatusNotFound},
				responseSpec{method: http.MethodPut, path: "/orders-demo-20241230-rollover-000001", status: http.StatusInternalServerError, body: `{"error":"create failed"}`},
			),
			wantCalls: []string{
				"HEAD /_alias/orders-demo-20241230-rollover",
				"PUT /orders-demo-20241230-rollover-000001",
			},
		},
		{
			name: "document post failure",
			handler: sequenceHandler(t,
				responseSpec{method: http.MethodHead, path: "/_alias/orders-demo-20241230-rollover", status: http.StatusOK},
				responseSpec{method: http.MethodGet, path: "/_alias/orders-demo-20241230-rollover", status: http.StatusOK, body: `{"orders-demo-20241230-rollover-000001":{"aliases":{"orders-demo-20241230-rollover":{"is_write_index":true}}}}`},
				responseSpec{method: http.MethodPut, path: "/orders-demo-20241230-rollover-000001/_settings", status: http.StatusOK, body: `{}`},
				responseSpec{method: http.MethodPost, path: "/orders-demo-20241230-rollover/_doc", status: http.StatusInternalServerError, body: `{"error":"index failed"}`},
			),
			wantCalls: []string{
				"HEAD /_alias/orders-demo-20241230-rollover",
				"GET /_alias/orders-demo-20241230-rollover",
				"PUT /orders-demo-20241230-rollover-000001/_settings",
				"POST /orders-demo-20241230-rollover/_doc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				tt.handler.ServeHTTP(w, r)
			}))
			defer elasticSearch.Close()

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z"}`))
			request.Header.Set("Content-Type", "application/json")
			addTestIngestBasicAuth(request)

			testGatewayHandler(testConfig(elasticSearch)).ServeHTTP(recorder, request)

			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Fatalf("unexpected Elasticsearch sequence: %#v", calls)
			}
		})
	}
}

func TestGatewaySpaceFailureReturnsBadGateway(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	var kibanaCalls []string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kibanaCalls = append(kibanaCalls, r.Method+" "+r.URL.RequestURI())
		if r.Method != http.MethodGet || r.URL.RequestURI() != "/api/spaces/space/orders" {
			t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.RequestURI())
		}
		http.Error(w, `{"error":"space lookup failed"}`, http.StatusInternalServerError)
	}))
	defer kibana.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfigWithKibana(elasticSearch, kibana)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(kibanaCalls, []string{
		"GET /api/spaces/space/orders",
	}) {
		t.Fatalf("unexpected Kibana sequence: %#v", kibanaCalls)
	}
}

func TestGatewayDataViewFailureReturnsBadGateway(t *testing.T) {
	t.Parallel()

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected Elasticsearch request: %s %s", r.Method, r.URL.Path)
	}))
	defer elasticSearch.Close()

	var kibanaCalls []string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kibanaCalls = append(kibanaCalls, r.Method+" "+r.URL.RequestURI())

		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /api/spaces/space/orders":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"id":"orders"}`)
		case "GET /s/orders/api/data_views/data_view/gateway-index-pattern-orders-demo":
			http.NotFound(w, r)
		case "POST /s/orders/api/data_views/data_view":
			http.Error(w, `{"error":"data view create failed"}`, http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected Kibana request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer kibana.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfigWithKibana(elasticSearch, kibana)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(kibanaCalls, []string{
		"GET /api/spaces/space/orders",
		"GET /s/orders/api/data_views/data_view/gateway-index-pattern-orders-demo",
		"POST /s/orders/api/data_views/data_view",
	}) {
		t.Fatalf("unexpected Kibana sequence: %#v", kibanaCalls)
	}
}

//nolint:gocognit,cyclop,funlen // Conflict retry scenario needs sequential request assertions.
func TestGatewayBootstrapConflictRetriesAliasCheck(t *testing.T) {
	t.Parallel()

	var calls []string

	elasticSearch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch len(calls) {
		case 1:
			if r.Method != http.MethodHead || r.URL.Path != "/_alias/orders-demo-20241230-rollover" {
				t.Fatalf("unexpected first request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNotFound)
		case 2:
			if r.Method != http.MethodPut || r.URL.Path != "/orders-demo-20241230-rollover-000001" {
				t.Fatalf("unexpected second request: %s %s", r.Method, r.URL.Path)
			}
			http.Error(w, `{"error":{"type":"resource_already_exists_exception"}}`, http.StatusConflict)
		case 3:
			if r.Method != http.MethodHead || r.URL.Path != "/_alias/orders-demo-20241230-rollover" {
				t.Fatalf("unexpected third request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		case 4:
			if r.Method != http.MethodGet || r.URL.Path != "/_alias/orders-demo-20241230-rollover" {
				t.Fatalf("unexpected fourth request: %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"orders-demo-20241230-rollover-000001":{"aliases":{"orders-demo-20241230-rollover":{"is_write_index":true}}}}`)
		case 5:
			if r.Method != http.MethodPut || r.URL.Path != "/orders-demo-20241230-rollover-000001/_settings" {
				t.Fatalf("unexpected fifth request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case 6:
			if r.Method != http.MethodPost || r.URL.Path != "/orders-demo-20241230-rollover/_doc" {
				t.Fatalf("unexpected sixth request: %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"result":"created","_id":"after-race"}`)
		default:
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer elasticSearch.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/ingest/orders-demo", strings.NewReader(`{"event_time":"2024-12-30T10:11:12Z","message":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	addTestIngestBasicAuth(request)

	testGatewayHandler(testConfig(elasticSearch)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !reflect.DeepEqual(calls, []string{
		"HEAD /_alias/orders-demo-20241230-rollover",
		"PUT /orders-demo-20241230-rollover-000001",
		"HEAD /_alias/orders-demo-20241230-rollover",
		"GET /_alias/orders-demo-20241230-rollover",
		"PUT /orders-demo-20241230-rollover-000001/_settings",
		"POST /orders-demo-20241230-rollover/_doc",
	}) {
		t.Fatalf("unexpected Elasticsearch sequence: %#v", calls)
	}

	var response serverpkg.IngestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Bootstrapped {
		t.Fatalf("expected race winner to be another writer, got %#v", response)
	}
	if response.DocumentID != "after-race" {
		t.Fatalf("unexpected response after conflict retry: %#v", response)
	}
}

type responseSpec struct {
	method string
	path   string
	status int
	body   string
}

func sequenceHandler(t *testing.T, responses ...responseSpec) http.HandlerFunc {
	t.Helper()

	var index int
	return func(w http.ResponseWriter, r *http.Request) {
		if index >= len(responses) {
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.Path)
		}

		response := responses[index]
		index++

		if r.Method != response.method || r.URL.Path != response.path {
			t.Fatalf("unexpected request %d: got %s %s, want %s %s", index, r.Method, r.URL.Path, response.method, response.path)
		}
		w.WriteHeader(response.status)
		if response.body != "" {
			_, _ = io.WriteString(w, response.body)
		}
	}
}

func testConfig(server *httptest.Server) appconfig.Config {
	return appconfig.Config{
		ElasticsearchURL:      server.URL,
		ElasticsearchUsername: "elastic",
		ElasticsearchPassword: "Admin123!",
		KibanaUsername:        "elastic",
		KibanaPassword:        "Admin123!",
		ListenAddr:            ":0",
		Shards:                2,
		Replicas:              2,
		HTTPClient:            server.Client(),
	}
}

func testConfigWithKibana(elasticSearch, kibana *httptest.Server) appconfig.Config {
	cfg := testConfig(elasticSearch)
	cfg.KibanaURL = kibana.URL
	cfg.HTTPClient = elasticSearch.Client()
	return cfg
}

func testGatewayHandler(cfg appconfig.Config) http.Handler {
	return testGatewayHandlerWithAuth(cfg, defaultTestLDAPAuthenticator)
}

func testGatewayHandlerWithAuth(cfg appconfig.Config, authenticate serverpkg.AuthenticateFunc) http.Handler {
	return newTestGateway(elasticpkg.NewClient(cfg), authenticate).Handler()
}

func newTestGateway(client *elasticpkg.Client, authenticate serverpkg.AuthenticateFunc) *serverpkg.Gateway {
	if authenticate == nil {
		authenticate = defaultTestLDAPAuthenticator
	}
	return serverpkg.New(client, authenticate)
}

func defaultTestLDAPAuthenticator(username, password string) (*authzpkg.User, []authzpkg.Access, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, nil, ldappkg.ErrInvalidCredentials
	}

	return &authzpkg.User{Name: username, Namespace: "orders"}, []authzpkg.Access{
		{Group: "orders_rw", Namespace: "orders"},
		{Group: "team1_rw", Namespace: "team1"},
		{Group: "team10_rw", Namespace: "team10"},
	}, nil
}

func addTestIngestBasicAuth(request *http.Request) {
	request.SetBasicAuth("writer", "secret")
}

func mustEncodeSessionCookieFromData(tb testing.TB, g *serverpkg.Gateway, data serverpkg.Session) (string, time.Time) {
	tb.Helper()
	encoded, err := g.EncodeSessionCookieValue(data)
	if err != nil {
		tb.Fatalf("encode session cookie: %v", err)
	}
	return encoded, time.Now().Add(time.Hour)
}

func decodeRequestBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()

	if r.Body == nil {
		return nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode request body %q: %v", string(body), err)
	}
	return payload
}

func nestedMap(t *testing.T, value any) map[string]any {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %#v", value)
	}
	return object
}
