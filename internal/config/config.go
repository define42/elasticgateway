// Package config loads environment-backed gateway and LDAP configuration.
package config

import (
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// DefaultListenAddr is the gateway bind address used when LISTEN_ADDR is unset.
	DefaultListenAddr = ":8080"
	// DefaultElasticsearchURL is the default Elasticsearch endpoint.
	DefaultElasticsearchURL = "https://localhost:9200"
	// DefaultKibanaURL is the default Kibana endpoint.
	DefaultKibanaURL = "http://localhost:5601"
	// DefaultKibanaBasePath is the proxied Kibana base path.
	DefaultKibanaBasePath = "/kibana"
	// DefaultUsername is the default upstream admin username.
	DefaultUsername = "elastic"
)

// Config contains runtime settings for Elasticsearch, Kibana, and HTTP serving.
type Config struct {
	ElasticsearchURL      string
	ElasticsearchUsername string
	ElasticsearchPassword string
	KibanaURL             string
	KibanaUsername        string
	KibanaPassword        string
	KibanaBasePath        string
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
}

// DefaultHTTPClient builds the default upstream HTTP client for the gateway.
func DefaultHTTPClient() *http.Client {
	transport := &http.Transport{}
	if getEnvBool("ELASTICSEARCH_SKIP_TLS_VERIFY", false) {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit local-dev opt-in for self-signed Elasticsearch
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// LoadGateway loads gateway configuration from the environment.
func LoadGateway() Config {
	defaultPassword := getEnv("ELASTIC_PASSWORD", "")

	return Config{
		ElasticsearchURL:      getEnv("ELASTICSEARCH_URL", DefaultElasticsearchURL),
		ElasticsearchUsername: getEnv("ELASTICSEARCH_USERNAME", DefaultUsername),
		ElasticsearchPassword: getEnv("ELASTICSEARCH_PASSWORD", defaultPassword),
		KibanaURL:             getEnv("KIBANA_URL", DefaultKibanaURL),
		KibanaUsername:        getEnv("KIBANA_USERNAME", getEnv("ELASTICSEARCH_USERNAME", DefaultUsername)),
		KibanaPassword:        getEnv("KIBANA_PASSWORD", getEnv("ELASTICSEARCH_PASSWORD", defaultPassword)),
		KibanaBasePath:        normalizeBasePath(getEnv("KIBANA_BASE_PATH", DefaultKibanaBasePath)),
		ListenAddr:            getEnv("LISTEN_ADDR", DefaultListenAddr),
		Shards:                1,
		Replicas:              1,
		HTTPClient:            DefaultHTTPClient(),
	}
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
	}
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

func normalizeBasePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return ""
	}
	path = "/" + strings.Trim(path, "/")
	return path
}
