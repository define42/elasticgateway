package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
)

func (g *Gateway) proxyKibana(w http.ResponseWriter, r *http.Request, sessionData Session) error {
	if g.kibanaTargetErr != nil {
		return fmt.Errorf("invalid Kibana URL: %w", g.kibanaTargetErr)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(g.kibanaTarget)
			pr.Out.URL.Path = kibanaUpstreamPath(pr.Out.URL.Path)
			pr.Out.URL.RawPath = ""
			if forwardedFor := g.trustedForwardedFor(pr.In); len(forwardedFor) > 0 {
				pr.Out.Header.Set("X-Forwarded-For", strings.Join(forwardedFor, ", "))
			}
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", sessionData.AuthHeader)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", forwardedProto(pr.In, g.Client.Config.ForceSecureCookies))
			pr.Out.Header.Set("X-Forwarded-Prefix", kibanaBasePath)
		},
		ErrorHandler: func(proxyWriter http.ResponseWriter, _ *http.Request, proxyErr error) {
			writeErrorJSON(proxyWriter, http.StatusBadGateway, fmt.Sprintf("Kibana proxy failed: %v", proxyErr))
		},
	}

	proxy.ServeHTTP(w, r)
	return nil
}

func kibanaUpstreamPath(path string) string {
	if path == kibanaBasePath {
		return "/"
	}
	if strings.HasPrefix(path, kibanaBasePath+"/") {
		return strings.TrimPrefix(path, kibanaBasePath)
	}
	return path
}
