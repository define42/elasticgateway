package config

import (
	"net/http"
	"testing"
	"time"
)

func TestDefaultHTTPClient(t *testing.T) {
	t.Setenv("ELASTICSEARCH_SKIP_TLS_VERIFY", "true")

	client := DefaultHTTPClient()
	if client.Timeout != 30*time.Second {
		t.Fatalf("unexpected timeout: %v", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected TLS client config with InsecureSkipVerify, got %#v", transport.TLSClientConfig)
	}
}

func TestLoadGatewayReadsSessionSecret(t *testing.T) {
	t.Setenv("SESSION_SECRET", "shared-session-secret-for-tests")

	cfg := LoadGateway()
	if cfg.SessionSecret != "shared-session-secret-for-tests" {
		t.Fatalf("unexpected session secret: %q", cfg.SessionSecret)
	}
}

func TestLoadGatewayReadsSessionTTL(t *testing.T) {
	t.Run("duration", func(t *testing.T) {
		t.Setenv("SESSION_TTL", "2h30m")

		cfg := LoadGateway()
		if cfg.SessionTTL != 150*time.Minute {
			t.Fatalf("unexpected session ttl: %v", cfg.SessionTTL)
		}
	})

	t.Run("seconds", func(t *testing.T) {
		t.Setenv("SESSION_TTL", "3600")

		cfg := LoadGateway()
		if cfg.SessionTTL != time.Hour {
			t.Fatalf("unexpected session ttl: %v", cfg.SessionTTL)
		}
	})
}

func TestLoadGatewayReadsForceSecureCookies(t *testing.T) {
	t.Setenv("FORCE_SECURE_COOKIES", "true")

	cfg := LoadGateway()
	if !cfg.ForceSecureCookies {
		t.Fatal("expected FORCE_SECURE_COOKIES=true to enable forced secure cookies")
	}
}
