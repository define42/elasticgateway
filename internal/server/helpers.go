package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/define42/elasticgateway/internal/authz"
	"github.com/define42/elasticgateway/internal/elastic"
)

const upstreamErrorMessage = "upstream error, see logs"

// ErrorResponse is the JSON error envelope used by the gateway.
type ErrorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{Error: message})
}

// ForwardedProto reports the direct request scheme for proxy headers.
func ForwardedProto(r *http.Request) string {
	return forwardedProto(r, false)
}

func forwardedProto(r *http.Request, forceSecure bool) string {
	if forceSecure {
		return "https"
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func isGatewayPath(path string) bool {
	return path == gatewayBasePath || strings.HasPrefix(path, gatewayBasePath+"/")
}

func accessNamespaces(access []authz.Access) []string {
	effective := authz.NormalizeAccessByNamespace(access)
	namespaces := make([]string, 0, len(effective))
	for _, item := range effective {
		namespace := strings.TrimSpace(item.Namespace)
		if namespace != "" {
			namespaces = append(namespaces, namespace)
		}
	}
	return namespaces
}

func accessLogMap(access []authz.Access) map[string]any {
	effective := authz.NormalizeAccessByNamespace(access)
	groupsByNamespace := accessGroupsByNamespace(access)
	accessMap := make(map[string]any, len(effective))
	for _, item := range effective {
		namespace := strings.TrimSpace(item.Namespace)
		if namespace == "" {
			continue
		}
		accessMap[namespace] = map[string]any{
			"groups":         groupsByNamespace[namespace],
			"mode":           authz.RoleModeForAccess(item),
			"pull_only":      item.PullOnly,
			"delete_allowed": item.DeleteAllowed,
		}
	}
	return accessMap
}

func accessGroupsByNamespace(access []authz.Access) map[string][]string {
	seenByNamespace := make(map[string]map[string]struct{})
	for _, item := range access {
		namespace := strings.TrimSpace(item.Namespace)
		group := strings.TrimSpace(item.Group)
		if namespace == "" || group == "" {
			continue
		}
		if seenByNamespace[namespace] == nil {
			seenByNamespace[namespace] = make(map[string]struct{})
		}
		seenByNamespace[namespace][group] = struct{}{}
	}

	groupsByNamespace := make(map[string][]string, len(seenByNamespace))
	for namespace, seen := range seenByNamespace {
		groups := make([]string, 0, len(seen))
		for group := range seen {
			groups = append(groups, group)
		}
		sort.Strings(groups)
		groupsByNamespace[namespace] = groups
	}
	return groupsByNamespace
}

func (g *Gateway) requestLogAttrs(r *http.Request) []any {
	attrs := []any{
		slog.String("method", r.Method),
		slog.String("client_ip", g.clientIP(r)),
		slog.String("remote_addr", r.RemoteAddr),
	}
	if r.URL != nil {
		attrs = append(attrs, slog.String("path", r.URL.Path))
	}
	return attrs
}

func (g *Gateway) logger() *slog.Logger {
	if g == nil || g.Logger == nil {
		return slog.Default()
	}
	return g.Logger
}

func (g *Gateway) writeUpstreamErrorJSON(w http.ResponseWriter, r *http.Request, status int, operation string, err error) {
	g.logUpstreamFailure(r, status, operation, err)
	writeErrorJSON(w, status, upstreamErrorMessage)
}

func (g *Gateway) logUpstreamFailure(r *http.Request, status int, operation string, err error) {
	attrs := []any{
		slog.String("event", "upstream_request_failed"),
		slog.String("operation", operation),
		slog.Int("http_status", status),
		slog.String("client_error", upstreamErrorMessage),
	}
	if r != nil {
		attrs = append(attrs, g.requestLogAttrs(r)...)
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))

		var responseErr *elastic.ResponseError
		if errors.As(err, &responseErr) {
			attrs = append(attrs, slog.Group("upstream",
				slog.String("method", responseErr.Method),
				slog.String("path", responseErr.Path),
				slog.Int("status", responseErr.StatusCode),
				slog.String("body", responseErr.Body),
			))
		}
	}

	if r != nil {
		g.logger().WarnContext(r.Context(), "upstream request failed", attrs...)
		return
	}
	g.logger().Warn("upstream request failed", attrs...)
}
