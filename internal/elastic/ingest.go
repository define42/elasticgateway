package elastic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/define42/elasticgateway/internal/ingest"
)

// EnsureWriteAlias creates the first backing index and policy wiring when needed.
func (c *Client) EnsureWriteAlias(ctx context.Context, alias string) (bool, error) {
	exists, err := c.AliasExists(ctx, alias)
	if err != nil {
		return false, fmt.Errorf("check alias %q: %w", alias, err)
	}
	if exists {
		if err := c.EnsureWriteAliasPolicy(ctx, alias); err != nil {
			return false, err
		}
		return false, nil
	}

	firstIndex := ingest.BuildFirstBackingIndex(alias)
	if err := c.BootstrapDateStream(ctx, firstIndex, alias); err != nil {
		return c.handleBootstrapDateStreamError(ctx, alias, err)
	}

	c.EnsuredAliasPolicies.Store(alias, true)
	return true, nil
}

func (c *Client) handleBootstrapDateStreamError(ctx context.Context, alias string, err error) (bool, error) {
	if !IsRetryableBootstrapConflict(err) {
		return false, fmt.Errorf("bootstrap %q: %w", alias, err)
	}

	exists, recheckErr := c.AliasExists(ctx, alias)
	if recheckErr != nil {
		return false, fmt.Errorf("re-check alias %q after bootstrap conflict: %w", alias, recheckErr)
	}
	if exists {
		if err := c.EnsureWriteAliasPolicy(ctx, alias); err != nil {
			return false, err
		}
		return false, nil
	}
	return false, fmt.Errorf("bootstrap %q: %w", alias, err)
}

// IndexDocument indexes document through the provided rollover alias.
func (c *Client) IndexDocument(ctx context.Context, alias string, document map[string]any) (IndexDocumentResponse, error) {
	path := "/" + url.PathEscape(alias) + "/_doc"

	var response IndexDocumentResponse
	if err := c.DoJSON(ctx, http.MethodPost, path, document, &response, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return IndexDocumentResponse{}, err
	}
	return response, nil
}

// BootstrapDateStream creates the first backing index and marks alias writable.
func (c *Client) BootstrapDateStream(ctx context.Context, indexName, alias string) error {
	body := map[string]any{
		"aliases": map[string]any{
			alias: map[string]any{
				"is_write_index": true,
			},
		},
		"settings": map[string]any{
			"index.lifecycle.name":           DefaultILMPolicyID,
			"index.lifecycle.rollover_alias": alias,
		},
	}

	return c.DoJSON(ctx, http.MethodPut, "/"+url.PathEscape(indexName), body, nil, []int{http.StatusOK, http.StatusCreated})
}

// EnsureWriteAliasPolicy repairs lifecycle settings for an already-existing write alias.
func (c *Client) EnsureWriteAliasPolicy(ctx context.Context, alias string) error {
	if _, ok := c.EnsuredAliasPolicies.Load(alias); ok {
		return nil
	}

	writeIndices, err := c.WriteIndicesForAlias(ctx, alias)
	if err != nil {
		return fmt.Errorf("resolve write indices for alias %q: %w", alias, err)
	}
	for _, indexName := range writeIndices {
		if err := c.AttachILMPolicy(ctx, indexName, alias, DefaultILMPolicyID); err != nil {
			return fmt.Errorf("attach ILM policy to %q: %w", indexName, err)
		}
	}

	c.EnsuredAliasPolicies.Store(alias, true)
	return nil
}

// WriteIndicesForAlias returns the concrete write backing indices for alias.
func (c *Client) WriteIndicesForAlias(ctx context.Context, alias string) ([]string, error) {
	var response AliasResponse
	path := "/_alias/" + url.PathEscape(alias)
	if err := c.DoJSON(ctx, http.MethodGet, path, nil, &response, []int{http.StatusOK}); err != nil {
		return nil, err
	}

	backingIndices := make([]string, 0, len(response))
	writeIndices := make([]string, 0, 1)
	for indexName, indexInfo := range response {
		aliasInfo, ok := indexInfo.Aliases[alias]
		if !ok {
			continue
		}

		backingIndices = append(backingIndices, indexName)
		if aliasInfo.IsWriteIndex != nil && *aliasInfo.IsWriteIndex {
			writeIndices = append(writeIndices, indexName)
		}
	}

	sort.Strings(backingIndices)
	sort.Strings(writeIndices)
	if len(writeIndices) > 0 {
		return writeIndices, nil
	}
	if len(backingIndices) == 1 {
		return backingIndices, nil
	}
	if len(backingIndices) == 0 {
		return nil, fmt.Errorf("alias %q has no backing indices", alias)
	}
	return nil, fmt.Errorf("alias %q has no write index", alias)
}

// AttachILMPolicy attaches policyID and alias lifecycle settings to indexName.
func (c *Client) AttachILMPolicy(ctx context.Context, indexName, alias, policyID string) error {
	body := map[string]any{
		"index": map[string]any{
			"lifecycle": map[string]any{
				"name":           policyID,
				"rollover_alias": alias,
			},
		},
	}

	path := "/" + url.PathEscape(indexName) + "/_settings"
	return c.DoJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK})
}

// AliasExists checks whether alias currently exists in Elasticsearch.
func (c *Client) AliasExists(ctx context.Context, alias string) (bool, error) {
	path := "/_alias/" + url.PathEscape(alias)
	req, err := c.NewRequest(ctx, http.MethodHead, path, nil)
	if err != nil {
		return false, err
	}

	resp, err := c.Config.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		b, _ := io.ReadAll(resp.Body)
		return false, &ResponseError{
			Method:     http.MethodHead,
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(b)),
		}
	}
}

// IsRetryableBootstrapConflict reports whether err is a retryable create conflict.
func IsRetryableBootstrapConflict(err error) bool {
	var responseErr *ResponseError
	if !errors.As(err, &responseErr) {
		return false
	}
	if responseErr.StatusCode != http.StatusBadRequest && responseErr.StatusCode != http.StatusConflict {
		return false
	}

	body := responseErr.Body
	return strings.Contains(body, "resource_already_exists_exception") || strings.Contains(body, "already exists")
}

// IsNotFoundResponse reports whether err is an upstream HTTP 404 response.
func IsNotFoundResponse(err error) bool {
	var responseErr *ResponseError
	return errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusNotFound
}
