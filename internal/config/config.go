// Package config loads environment-backed gateway and LDAP configuration.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	// DefaultListenAddr is the gateway bind address used when LISTEN_ADDR is unset.
	DefaultListenAddr = ":8080"
	// DefaultElasticsearchURL is the default Elasticsearch endpoint.
	DefaultElasticsearchURL = "https://localhost:9200"
	// DefaultKibanaURL is the default Kibana endpoint.
	DefaultKibanaURL = "http://localhost:5601"
	// DefaultUsername is the default upstream admin username.
	DefaultUsername = "elastic"
	// DefaultSessionTTL is the default gateway session lifetime.
	DefaultSessionTTL = 24 * time.Hour
)

// Config contains runtime settings for Elasticsearch, Kibana, and HTTP serving.
type Config struct {
	ElasticsearchURL      string
	ElasticsearchUsername string
	ElasticsearchPassword string
	KibanaURL             string
	KibanaUsername        string
	KibanaPassword        string
	SessionSecret         string
	SessionTTL            time.Duration
	ForceSecureCookies    bool
	TrustedProxies        []netip.Prefix
	ListenAddr            string
	Shards                int
	Replicas              int
	HTTPClient            *http.Client
}

// LDAPConfig contains runtime settings for the gateway's LDAP client.
type LDAPConfig struct {
	URL             string
	BaseDN          string
	UserFilter      string
	GroupAttribute  string
	GroupNamePrefix string
	UserMailDomain  string
	StartTLS        bool
	SkipTLSVerify   bool
	RootCAPath      string
}

// DefaultHTTPClient builds the default upstream HTTP client for the gateway.
func DefaultHTTPClient() *http.Client {
	client, err := defaultHTTPClient()
	if err != nil {
		return &http.Client{
			Timeout:   30 * time.Second,
			Transport: errorRoundTripper{err: err},
		}
	}
	return client
}

func defaultHTTPClient() (*http.Client, error) {
	transport := &http.Transport{}
	if getEnvBool("ELASTICSEARCH_SKIP_TLS_VERIFY", false) {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit local-dev opt-in for self-signed Elasticsearch
	} else if rootCAPath := getEnv("ROOT_CA", ""); rootCAPath != "" {
		rootCAs, err := RootCAPool(rootCAPath)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}, nil
}

// LoadGateway loads gateway configuration from the environment.
func LoadGateway() (Config, error) {
	defaultPassword := getEnv("ELASTIC_PASSWORD", "")
	httpClient, err := defaultHTTPClient()
	if err != nil {
		return Config{}, err
	}
	trustedProxies, err := parseTrustedProxies(getEnv("TRUSTED_PROXIES", ""))
	if err != nil {
		return Config{}, err
	}

	return Config{
		ElasticsearchURL:      getEnv("ELASTICSEARCH_URL", DefaultElasticsearchURL),
		ElasticsearchUsername: getEnv("ELASTICSEARCH_USERNAME", DefaultUsername),
		ElasticsearchPassword: getEnv("ELASTICSEARCH_PASSWORD", defaultPassword),
		KibanaURL:             getEnv("KIBANA_URL", DefaultKibanaURL),
		KibanaUsername:        getEnv("KIBANA_USERNAME", getEnv("ELASTICSEARCH_USERNAME", DefaultUsername)),
		KibanaPassword:        getEnv("KIBANA_PASSWORD", getEnv("ELASTICSEARCH_PASSWORD", defaultPassword)),
		SessionSecret:         getEnv("SESSION_SECRET", ""),
		SessionTTL:            getEnvDuration("SESSION_TTL", DefaultSessionTTL),
		ForceSecureCookies:    getEnvBool("FORCE_SECURE_COOKIES", false),
		TrustedProxies:        trustedProxies,
		ListenAddr:            getEnv("LISTEN_ADDR", DefaultListenAddr),
		Shards:                1,
		Replicas:              1,
		HTTPClient:            httpClient,
	}, nil
}

// LoadLDAP loads LDAP configuration from the environment.
func LoadLDAP() LDAPConfig {
	return LDAPConfig{
		URL:             getEnv("LDAP_URL", "ldaps://ldap:389"),
		BaseDN:          getEnv("LDAP_BASE_DN", "dc=glauth,dc=com"),
		UserFilter:      getEnv("LDAP_USER_FILTER", "(mail=%s)"),
		GroupAttribute:  getEnv("LDAP_GROUP_ATTRIBUTE", "memberOf"),
		GroupNamePrefix: getEnv("LDAP_GROUP_PREFIX", "team"),
		UserMailDomain:  getEnv("LDAP_USER_DOMAIN", "@example.com"),
		StartTLS:        getEnvBool("LDAP_STARTTLS", false),
		SkipTLSVerify:   getEnvBool("LDAP_SKIP_TLS_VERIFY", true),
		RootCAPath:      getEnv("ROOT_CA", ""),
	}
}

// RootCAPool loads a PEM or DER root CA file into a certificate pool.
func RootCAPool(path string) (*x509.CertPool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}

	certBytes, err := readRootCAFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ROOT_CA %q: %w", path, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if pool.AppendCertsFromPEM(certBytes) {
		return pool, nil
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ROOT_CA %q as PEM or DER certificate: %w", path, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("parse ROOT_CA %q as PEM or DER certificate: no certificates found", path)
	}
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool, nil
}

func readRootCAFile(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(cleanPath))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = root.Close()
	}()

	return root.ReadFile(filepath.Base(cleanPath))
}

type errorRoundTripper struct {
	err error
}

func (t errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}

func getEnv(key, def string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		value = strings.ToLower(strings.TrimSpace(value))
		return value == "1" || value == "true" || value == "yes"
	}
	return def
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	if value, ok := os.LookupEnv(key); ok {
		value = strings.TrimSpace(value)
		duration, err := time.ParseDuration(value)
		if err == nil && duration > 0 {
			return duration
		}
		seconds, err := strconv.Atoi(value)
		if err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return def
}

func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	prefixes := make([]netip.Prefix, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		if prefix, err := netip.ParsePrefix(field); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(field); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q: expected CIDR or IP address", field)
	}
	return prefixes, nil
}
