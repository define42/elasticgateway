// Package server wires the HTTP routes, login flow, ingest API, and proxy.
package server

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/define42/elasticgateway/internal/authz"
	"github.com/define42/elasticgateway/internal/elastic"
	"github.com/define42/elasticgateway/internal/ingest"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
	"github.com/gorilla/securecookie"
)

const (
	gatewayBasePath    = "/elasticgateway"
	gatewayLoginPath   = gatewayBasePath + "/login"
	gatewayLogoutPath  = gatewayBasePath + "/logout"
	gatewayDemoPath    = gatewayBasePath + "/demo"
	gatewayIngestPath  = gatewayBasePath + "/ingest"
	gatewayHealthzPath = gatewayBasePath + "/healthz"
	gatewayReadyzPath  = gatewayBasePath + "/readyz"
)

// AuthenticateFunc validates credentials and returns the resolved LDAP access.
type AuthenticateFunc func(string, string) (*authz.User, []authz.Access, error)

// Gateway serves the login flow, ingest API, and Kibana reverse proxy.
type Gateway struct {
	Client          *elastic.Client
	Authenticate    AuthenticateFunc
	IngestAuthCache *ingest.AuthCache
	SecureCookie    *securecookie.SecureCookie
	Logger          *slog.Logger
	kibanaTarget    *url.URL
	kibanaTargetErr error
	passwordSecret  []byte
	sessionMaxAge   int
}

// New constructs a gateway with the provided client and authenticator.
func New(client *elastic.Client, authenticate AuthenticateFunc) *Gateway {
	if authenticate == nil {
		authenticate = func(_, _ string) (*authz.User, []authz.Access, error) {
			return nil, nil, ldappkg.ErrInvalidCredentials
		}
	}

	kibanaTarget, kibanaTargetErr := url.Parse(client.Config.KibanaURL)
	sessionMaxAge := sessionCookieMaxAgeSeconds(client.Config.SessionTTL)

	return &Gateway{
		Client:          client,
		Authenticate:    authenticate,
		IngestAuthCache: ingest.NewAuthCache(),
		SecureCookie:    newSecureCookie(client.Config.SessionSecret, sessionMaxAge),
		kibanaTarget:    kibanaTarget,
		kibanaTargetErr: kibanaTargetErr,
		passwordSecret:  newInternalPasswordSecret(client.Config.SessionSecret),
		sessionMaxAge:   sessionMaxAge,
	}
}

// Handler builds the HTTP mux for the gateway routes.
func (g *Gateway) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(gatewayHealthzPath, g.handleHealthz)
	mux.HandleFunc(gatewayReadyzPath, g.handleReadyz)
	mux.HandleFunc(gatewayLoginPath, g.handleLogin)
	mux.HandleFunc(gatewayLogoutPath, g.handleLogout)
	mux.HandleFunc(gatewayDemoPath, g.handleDemo)
	mux.HandleFunc(gatewayIngestPath, g.handleIngest)
	mux.HandleFunc(gatewayIngestPath+"/", g.handleIngest)
	mux.HandleFunc(gatewayBasePath, g.handleGatewayNotFound)
	mux.HandleFunc(gatewayBasePath+"/", g.handleGatewayNotFound)
	mux.HandleFunc("/", g.handleRoot)
	return mux
}

func (g *Gateway) handleRoot(w http.ResponseWriter, r *http.Request) {
	g.HandleKibana(w, r)
}

func (g *Gateway) handleGatewayNotFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (g *Gateway) handleDemo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != gatewayDemoPath {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	serveDemoPage(w)
}

// HandleKibana proxies authenticated requests to Kibana.
func (g *Gateway) HandleKibana(w http.ResponseWriter, r *http.Request) {
	if isGatewayPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}

	if isKibanaLogoutPath(r.URL.Path) {
		g.handleKibanaLogout(w, r)
		return
	}

	sessionData, ok := g.currentSession(r)
	if !ok {
		if hasSessionCookie(r) {
			g.clearSessionCookie(w, r)
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			g.RenderLoginPage(w, http.StatusOK, LoginPageData{Next: loginNextForRequest(r)})
			return
		}
		writeErrorJSON(w, http.StatusUnauthorized, "gateway login required")
		return
	}

	if err := g.proxyKibana(w, r, sessionData); err != nil {
		g.writeUpstreamErrorJSON(w, r, http.StatusBadGateway, "kibana_proxy", err)
	}
}
