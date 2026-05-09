package elastic

import (
	"context"
	"net/http"
	"strings"
)

// PingElasticsearch checks that Elasticsearch is reachable with the configured credentials.
func (c *Client) PingElasticsearch(ctx context.Context) error {
	return c.DoJSON(ctx, http.MethodGet, "/", nil, nil, []int{http.StatusOK})
}

// PingKibana checks that Kibana is reachable with the configured credentials.
func (c *Client) PingKibana(ctx context.Context) error {
	if strings.TrimSpace(c.Config.KibanaURL) == "" {
		return nil
	}
	return c.DoKibanaJSON(ctx, http.MethodGet, "/api/status", nil, nil, []int{http.StatusOK})
}
