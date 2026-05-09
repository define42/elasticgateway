package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
)

// DoJSON issues an Elasticsearch request against the primary cluster endpoint.
func (c *Client) DoJSON(ctx context.Context, method, path string, body any, out any, okStatuses []int) error {
	return c.DoJSONWithRequest(ctx, method, path, body, out, okStatuses, c.NewRequest)
}

// DoKibanaJSON issues a request against Kibana without a space prefix.
func (c *Client) DoKibanaJSON(ctx context.Context, method, path string, body any, out any, okStatuses []int) error {
	return c.DoJSONWithRequest(ctx, method, path, body, out, okStatuses, c.NewKibanaRequest)
}

// DoKibanaJSONInSpace issues a Kibana request with an explicit space.
func (c *Client) DoKibanaJSONInSpace(ctx context.Context, spaceName, method, path string, body any, out any, okStatuses []int) error {
	return c.DoJSONWithRequest(ctx, method, path, body, out, okStatuses, func(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
		return c.NewKibanaRequestForSpace(ctx, spaceName, method, path, body)
	})
}

// DoJSONWithRequest sends a JSON request using the provided request builder.
func (c *Client) DoJSONWithRequest(ctx context.Context, method, path string, body any, out any, okStatuses []int, buildRequest func(context.Context, string, string, io.Reader) (*http.Request, error)) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}

	req, err := buildRequest(ctx, method, path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.Config.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if !slices.Contains(okStatuses, resp.StatusCode) {
		b, _ := io.ReadAll(resp.Body)
		return &ResponseError{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(b)),
		}
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// NewRequest creates an Elasticsearch API request using the primary base URL.
func (c *Client) NewRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	return c.NewRequestForBase(ctx, c.Config.ElasticsearchURL, method, path, body, c.Config.ElasticsearchUsername, c.Config.ElasticsearchPassword, nil)
}

// NewKibanaRequest creates a Kibana API request outside a space.
func (c *Client) NewKibanaRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	headers := map[string]string{
		"kbn-xsrf": "true",
	}
	return c.NewRequestForBase(ctx, c.Config.KibanaURL, method, KibanaAPIPath(path), body, c.Config.KibanaUsername, c.Config.KibanaPassword, headers)
}

// NewKibanaRequestForSpace creates a Kibana API request for spaceName.
func (c *Client) NewKibanaRequestForSpace(ctx context.Context, spaceName, method, path string, body io.Reader) (*http.Request, error) {
	headers := map[string]string{
		"kbn-xsrf": "true",
	}
	return c.NewRequestForBase(ctx, c.Config.KibanaURL, method, KibanaAPIPathForSpace(spaceName, path), body, c.Config.KibanaUsername, c.Config.KibanaPassword, headers)
}

// NewRequestForBase builds an authenticated request against baseURL.
func (c *Client) NewRequestForBase(ctx context.Context, baseURL, method, path string, body io.Reader, username, password string, headers map[string]string) (*http.Request, error) {
	base := strings.TrimRight(baseURL, "/")
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return nil, err
	}

	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req, nil
}
