package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

	cfg, err := LoadGateway()
	if err != nil {
		t.Fatalf("LoadGateway: %v", err)
	}
	if cfg.SessionSecret != "shared-session-secret-for-tests" {
		t.Fatalf("unexpected session secret: %q", cfg.SessionSecret)
	}
}

func TestLoadGatewayReadsSessionTTL(t *testing.T) {
	t.Run("duration", func(t *testing.T) {
		t.Setenv("SESSION_TTL", "2h30m")

		cfg, err := LoadGateway()
		if err != nil {
			t.Fatalf("LoadGateway: %v", err)
		}
		if cfg.SessionTTL != 150*time.Minute {
			t.Fatalf("unexpected session ttl: %v", cfg.SessionTTL)
		}
	})

	t.Run("seconds", func(t *testing.T) {
		t.Setenv("SESSION_TTL", "3600")

		cfg, err := LoadGateway()
		if err != nil {
			t.Fatalf("LoadGateway: %v", err)
		}
		if cfg.SessionTTL != time.Hour {
			t.Fatalf("unexpected session ttl: %v", cfg.SessionTTL)
		}
	})
}

func TestLoadGatewayReadsForceSecureCookies(t *testing.T) {
	t.Setenv("FORCE_SECURE_COOKIES", "true")

	cfg, err := LoadGateway()
	if err != nil {
		t.Fatalf("LoadGateway: %v", err)
	}
	if !cfg.ForceSecureCookies {
		t.Fatal("expected FORCE_SECURE_COOKIES=true to enable forced secure cookies")
	}
}

func TestLoadGatewayTrustedProxiesDefaultDisabled(t *testing.T) {
	cfg, err := LoadGateway()
	if err != nil {
		t.Fatalf("LoadGateway: %v", err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Fatalf("expected no trusted proxies by default, got %#v", cfg.TrustedProxies)
	}
}

func TestLoadGatewayReadsTrustedProxies(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.10 2001:db8::/32")

	cfg, err := LoadGateway()
	if err != nil {
		t.Fatalf("LoadGateway: %v", err)
	}

	got := make([]string, 0, len(cfg.TrustedProxies))
	for _, prefix := range cfg.TrustedProxies {
		got = append(got, prefix.String())
	}
	want := []string{"10.0.0.0/8", "192.0.2.10/32", "2001:db8::/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected trusted proxies: got %#v want %#v", got, want)
	}
}

func TestLoadGatewayInvalidTrustedProxiesReturnsError(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, nope")

	_, err := LoadGateway()
	if err == nil {
		t.Fatal("expected invalid TRUSTED_PROXIES error")
	}
	if !strings.Contains(err.Error(), "TRUSTED_PROXIES") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("expected useful TRUSTED_PROXIES error, got %v", err)
	}
}

func TestLoadGatewayUsesPEMRootCA(t *testing.T) {
	t.Setenv("ROOT_CA", writeRootCAPEMFile(t))

	cfg, err := LoadGateway()
	if err != nil {
		t.Fatalf("LoadGateway: %v", err)
	}

	transport, ok := cfg.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", cfg.HTTPClient.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatalf("expected TLS root CA pool, got %#v", transport.TLSClientConfig)
	}
}

func TestLoadGatewayUsesDERRootCA(t *testing.T) {
	t.Setenv("ROOT_CA", writeRootCADERFile(t))

	cfg, err := LoadGateway()
	if err != nil {
		t.Fatalf("LoadGateway: %v", err)
	}

	transport, ok := cfg.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", cfg.HTTPClient.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatalf("expected TLS root CA pool, got %#v", transport.TLSClientConfig)
	}
}

func TestLoadGatewayInvalidRootCAReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root-ca.txt")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write invalid root CA: %v", err)
	}
	t.Setenv("ROOT_CA", path)

	_, err := LoadGateway()
	if err == nil {
		t.Fatal("expected invalid ROOT_CA error")
	}
	if !strings.Contains(err.Error(), "ROOT_CA") || !strings.Contains(err.Error(), path) {
		t.Fatalf("expected useful ROOT_CA error, got %v", err)
	}
}

func TestLoadGatewaySkipTLSVerifyWinsOverRootCA(t *testing.T) {
	t.Setenv("ELASTICSEARCH_SKIP_TLS_VERIFY", "true")
	t.Setenv("ROOT_CA", filepath.Join(t.TempDir(), "missing-ca.pem"))

	cfg, err := LoadGateway()
	if err != nil {
		t.Fatalf("LoadGateway should not read ROOT_CA when skip verify is enabled: %v", err)
	}

	transport, ok := cfg.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", cfg.HTTPClient.Transport)
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected InsecureSkipVerify, got %#v", transport.TLSClientConfig)
	}
}

func TestLoadLDAPDefaultGroupPrefix(t *testing.T) {
	original, ok := os.LookupEnv("LDAP_GROUP_PREFIX")
	if err := os.Unsetenv("LDAP_GROUP_PREFIX"); err != nil {
		t.Fatalf("unset LDAP_GROUP_PREFIX: %v", err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv("LDAP_GROUP_PREFIX", original)
			return
		}
		_ = os.Unsetenv("LDAP_GROUP_PREFIX")
	})

	cfg := LoadLDAP()
	if cfg.GroupNamePrefix != "app_elk_" {
		t.Fatalf("unexpected default LDAP group prefix: %q", cfg.GroupNamePrefix)
	}
}

func TestLoadLDAPAllowsEmptyGroupPrefix(t *testing.T) {
	t.Setenv("LDAP_GROUP_PREFIX", "")

	cfg := LoadLDAP()
	if cfg.GroupNamePrefix != "" {
		t.Fatalf("expected empty LDAP group prefix, got %q", cfg.GroupNamePrefix)
	}
}

func TestLoadLDAPReadsRootCA(t *testing.T) {
	t.Setenv("ROOT_CA", "/mounted/root-ca.pem")

	cfg := LoadLDAP()
	if cfg.RootCAPath != "/mounted/root-ca.pem" {
		t.Fatalf("unexpected LDAP root CA path: %q", cfg.RootCAPath)
	}
}

func writeRootCAPEMFile(t *testing.T) string {
	t.Helper()

	der := testRootCADER(t)
	return writeTestFile(t, "root-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeRootCADERFile(t *testing.T) string {
	t.Helper()

	return writeTestFile(t, "root-ca.der", testRootCADER(t))
}

func testRootCADER(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func writeTestFile(t *testing.T, name string, contents []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}
