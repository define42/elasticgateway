package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func (g *Gateway) proxyKibana(w http.ResponseWriter, r *http.Request, sessionData Session) error {
	target, err := url.Parse(g.Client.Config.KibanaURL)
	if err != nil {
		return fmt.Errorf("invalid Kibana URL: %w", err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = kibanaUpstreamPath(pr.Out.URL.Path)
			pr.Out.URL.RawPath = ""
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", sessionData.AuthHeader)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", ForwardedProto(pr.In))
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
