package ldap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/elasticgateway/internal/config"
	goldap "github.com/go-ldap/ldap/v3"
)

func TestUserSearchFilterEscapesMailValue(t *testing.T) {
	t.Parallel()

	auth := New(config.LDAPConfig{
		UserFilter: "(&(objectClass=person)(mail=%s))",
	})
	mail := `bad*)(|(mail=*))@example.com`

	got := auth.userSearchFilter(mail)
	want := "(&(objectClass=person)(mail=" + goldap.EscapeFilter(mail) + "))"
	if got != want {
		t.Fatalf("user search filter = %q, want %q", got, want)
	}
	if strings.Contains(got, `*)(|`) {
		t.Fatalf("user search filter contains unescaped LDAP filter operators: %q", got)
	}
}

func TestLDAPTLSConfigUsesRootCA(t *testing.T) {
	tlsConfig, err := ldapTLSConfig(config.LDAPConfig{
		URL:        "ldaps://ldap.example.com:636",
		RootCAPath: writeRootCAPEMFile(t),
	})
	if err != nil {
		t.Fatalf("ldapTLSConfig: %v", err)
	}

	if tlsConfig.InsecureSkipVerify {
		t.Fatal("expected LDAP TLS verification to remain enabled")
	}
	if tlsConfig.RootCAs == nil {
		t.Fatalf("expected LDAP TLS root CA pool, got %#v", tlsConfig)
	}
}

func TestLDAPTLSConfigSetsServerName(t *testing.T) {
	tlsConfig, err := ldapTLSConfig(config.LDAPConfig{
		URL: "ldap://ldap.example.com:389",
	})
	if err != nil {
		t.Fatalf("ldapTLSConfig: %v", err)
	}

	if tlsConfig.ServerName != "ldap.example.com" {
		t.Fatalf("unexpected LDAP TLS server name: %q", tlsConfig.ServerName)
	}
}

func TestLDAPTLSConfigSkipVerifyWinsOverRootCA(t *testing.T) {
	tlsConfig, err := ldapTLSConfig(config.LDAPConfig{
		URL:           "ldaps://ldap.example.com:636",
		SkipTLSVerify: true,
		RootCAPath:    filepath.Join(t.TempDir(), "missing-ca.pem"),
	})
	if err != nil {
		t.Fatalf("ldapTLSConfig should not read ROOT_CA when skip verify is enabled: %v", err)
	}

	if !tlsConfig.InsecureSkipVerify {
		t.Fatalf("expected InsecureSkipVerify, got %#v", tlsConfig)
	}
	if tlsConfig.RootCAs != nil {
		t.Fatalf("expected no root CA pool when skip verify is enabled, got %#v", tlsConfig.RootCAs)
	}
}

func writeRootCAPEMFile(t *testing.T) string {
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

	path := filepath.Join(t.TempDir(), "root-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write root CA: %v", err)
	}
	return path
}
