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
			pr.Out.URL.Path = kibanaUpstreamPath(pr.Out.URL.Path, g.Client.Config.KibanaBasePath)
			pr.Out.URL.RawPath = ""
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", sessionData.AuthHeader)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", ForwardedProto(pr.In))
			if strings.TrimSpace(g.Client.Config.KibanaBasePath) != "" {
				pr.Out.Header.Set("X-Forwarded-Prefix", g.Client.Config.KibanaBasePath)
			}
		},
		ErrorHandler: func(proxyWriter http.ResponseWriter, _ *http.Request, proxyErr error) {
			writeErrorJSON(proxyWriter, http.StatusBadGateway, fmt.Sprintf("Kibana proxy failed: %v", proxyErr))
		},
	}

	proxy.ServeHTTP(w, r)
	return nil
}

func kibanaUpstreamPath(path, basePath string) string {
	basePath = strings.TrimRight(strings.TrimSpace(basePath), "/")
	if basePath == "" || basePath == "/" {
		return path
	}
	if path == basePath {
		return "/"
	}
	if strings.HasPrefix(path, basePath+"/") {
		return strings.TrimPrefix(path, basePath)
	}
	return path
}
