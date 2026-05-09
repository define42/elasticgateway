package elastic

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/define42/elasticgateway/internal/config"
)

func testConfig(server *httptest.Server) config.Config {
	return config.Config{
		ElasticsearchURL:      server.URL,
		ElasticsearchUsername: "elastic",
		ElasticsearchPassword: "Admin123!",
		KibanaUsername:        "elastic",
		KibanaPassword:        "Admin123!",
		ListenAddr:            ":0",
		Shards:                1,
		Replicas:              1,
		HTTPClient:            server.Client(),
	}
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
