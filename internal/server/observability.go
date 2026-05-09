package server

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const probeTimeout = 2 * time.Second

type probeResponse struct {
	Status string                `json:"status"`
	Checks map[string]probeCheck `json:"checks"`
}

type probeCheck struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func (g *Gateway) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/healthz" {
		http.NotFound(w, r)
		return
	}
	g.handleProbe(w, r, "healthy", "unhealthy")
}

func (g *Gateway) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/readyz" {
		http.NotFound(w, r)
		return
	}
	g.handleProbe(w, r, "ready", "not_ready")
}

func (g *Gateway) handleProbe(w http.ResponseWriter, r *http.Request, okStatus, failedStatus string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()

	checks, ok := g.probeChecks(ctx)
	status := http.StatusOK
	responseStatus := okStatus
	if !ok {
		status = http.StatusServiceUnavailable
		responseStatus = failedStatus
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, probeResponse{
		Status: responseStatus,
		Checks: checks,
	})
}

func (g *Gateway) probeChecks(ctx context.Context) (map[string]probeCheck, bool) {
	checks := map[string]probeCheck{
		"elasticsearch": {Status: "ok"},
		"kibana":        {Status: "ok"},
	}
	ok := true

	if g == nil || g.Client == nil {
		checks["elasticsearch"] = probeCheck{Status: "error", Error: "gateway client is not configured"}
		checks["kibana"] = probeCheck{Status: "error", Error: "gateway client is not configured"}
		return checks, false
	}

	if err := g.Client.PingElasticsearch(ctx); err != nil {
		checks["elasticsearch"] = probeCheck{Status: "error", Error: err.Error()}
		ok = false
	}

	if strings.TrimSpace(g.Client.Config.KibanaURL) == "" {
		checks["kibana"] = probeCheck{Status: "disabled"}
		return checks, ok
	}
	if err := g.Client.PingKibana(ctx); err != nil {
		checks["kibana"] = probeCheck{Status: "error", Error: err.Error()}
		ok = false
	}

	return checks, ok
}
