package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/define42/elasticgateway/internal/authz"
)

func (g *Gateway) proxyKibana(w http.ResponseWriter, r *http.Request, sessionData Session) error {
	if g.kibanaTargetErr != nil {
		return fmt.Errorf("invalid Kibana URL: %w", g.kibanaTargetErr)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(g.kibanaTarget)
			pr.Out.URL.RawPath = ""
			if forwardedFor := g.trustedForwardedFor(pr.In); len(forwardedFor) > 0 {
				pr.Out.Header.Set("X-Forwarded-For", strings.Join(forwardedFor, ", "))
			}
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", sessionData.AuthHeader)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", forwardedProto(pr.In, g.Client.Config.ForceSecureCookies))
		},
		ModifyResponse: func(response *http.Response) error {
			if response.StatusCode == http.StatusNotFound && isKibanaUserProfilePath(response.Request.URL.Path) {
				return writeKibanaUserProfileFallback(response, sessionData)
			}
			return nil
		},
		ErrorHandler: func(proxyWriter http.ResponseWriter, proxyRequest *http.Request, proxyErr error) {
			g.writeUpstreamErrorJSON(proxyWriter, proxyRequest, http.StatusBadGateway, "kibana_proxy", proxyErr)
		},
	}

	proxy.ServeHTTP(w, r)
	return nil
}

func isKibanaUserProfilePath(path string) bool {
	if path == "/internal/security/user_profile" {
		return true
	}
	if !strings.HasPrefix(path, "/s/") {
		return false
	}

	spacePath := strings.TrimPrefix(path, "/s/")
	_, rest, ok := strings.Cut(spacePath, "/")
	return ok && rest == "internal/security/user_profile"
}

func writeKibanaUserProfileFallback(response *http.Response, sessionData Session) error {
	username := sessionLogUsername(sessionData)
	if username == "" {
		username = "elasticgateway"
	}
	roles := kibanaProfileRoles(sessionData.Access)

	payload, err := json.Marshal(map[string]any{
		"uid":     "elasticgateway-" + username,
		"enabled": true,
		"data":    map[string]any{},
		"user": map[string]any{
			"username":   username,
			"roles":      roles,
			"realm_name": "default_native",
			"authentication_provider": map[string]string{
				"type": "http",
				"name": "__http__",
			},
		},
		"labels": map[string]any{},
	})
	if err != nil {
		return err
	}

	_ = response.Body.Close()
	response.StatusCode = http.StatusOK
	response.Status = "200 OK"
	response.Body = io.NopCloser(bytes.NewReader(payload))
	response.ContentLength = int64(len(payload))
	response.Header.Set("Content-Type", "application/json; charset=utf-8")
	response.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	response.Header.Del("Content-Encoding")
	response.Header.Del("Etag")
	return nil
}

func kibanaProfileRoles(access []authz.Access) []string {
	effective := authz.NormalizeAccessByNamespace(access)
	roles := make([]string, 0, len(effective))
	for _, item := range effective {
		roles = append(roles, authz.BuildGatewayRoleName(item.Namespace, authz.RoleModeForAccess(item)))
	}
	return roles
}
