package elastic

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// EnsureSpace creates spaceName if it does not already exist.
func (c *Client) EnsureSpace(ctx context.Context, spaceName string) error {
	if c.Config.KibanaURL == "" {
		return nil
	}

	if _, ok := c.EnsuredSpaces.Load(spaceName); ok {
		return nil
	}

	path := "/api/spaces/space/" + url.PathEscape(spaceName)
	if err := c.ensureSpaceExists(ctx, spaceName, path); err != nil {
		return err
	}

	c.EnsuredSpaces.Store(spaceName, true)
	return nil
}

func (c *Client) ensureSpaceExists(ctx context.Context, spaceName, path string) error {
	err := c.DoKibanaJSON(ctx, http.MethodGet, path, nil, nil, []int{http.StatusOK})
	if err == nil {
		return nil
	}
	if !IsNotFoundResponse(err) {
		return err
	}

	return c.createMissingSpace(ctx, spaceName, path)
}

func (c *Client) createMissingSpace(ctx context.Context, spaceName, path string) error {
	body := SpaceRequest{
		ID:               spaceName,
		Name:             spaceName,
		Description:      fmt.Sprintf("Gateway space for %s", spaceName),
		DisabledFeatures: []string{},
	}
	err := c.DoKibanaJSON(ctx, http.MethodPost, "/api/spaces/space", body, nil, []int{http.StatusOK, http.StatusCreated})
	if err == nil {
		return nil
	}
	if !IsConflictResponse(err) {
		return err
	}
	if err := c.DoKibanaJSON(ctx, http.MethodGet, path, nil, nil, []int{http.StatusOK}); err != nil {
		return fmt.Errorf("confirm Kibana space %q after create conflict: %w", spaceName, err)
	}
	return nil
}

// EnsureKibanaDataView ensures indexName's data view inside spaceName.
func (c *Client) EnsureKibanaDataView(ctx context.Context, spaceName, indexName string) error {
	if c.Config.KibanaURL == "" {
		return nil
	}

	if err := c.EnsureSpace(ctx, spaceName); err != nil {
		return err
	}

	dataViewID := BuildDataViewID(indexName)
	cacheKey := BuildDataViewCacheKey(spaceName, indexName)
	if _, ok := c.EnsuredDataViews.Load(cacheKey); ok {
		return nil
	}

	if err := c.ensureDataView(ctx, spaceName, dataViewID, indexName); err != nil {
		return err
	}
	if err := c.ensureKibanaDefaultDataView(ctx, spaceName, indexName, dataViewID); err != nil {
		return err
	}

	c.EnsuredDataViews.Store(cacheKey, indexName)
	return nil
}

func (c *Client) ensureDataView(ctx context.Context, spaceName, dataViewID, indexName string) error {
	path := "/api/data_views/data_view/" + url.PathEscape(dataViewID)
	err := c.DoKibanaJSONInSpace(ctx, spaceName, http.MethodGet, path, nil, nil, []int{http.StatusOK})
	if err == nil {
		return nil
	}
	if !IsNotFoundResponse(err) {
		return err
	}

	body := KibanaDataViewRequest{
		DataView: KibanaDataView{
			ID:            dataViewID,
			Name:          BuildDataViewPattern(indexName),
			Title:         BuildDataViewPattern(indexName),
			TimeFieldName: "event_time",
		},
		Override: true,
	}
	return c.DoKibanaJSONInSpace(ctx, spaceName, http.MethodPost, "/api/data_views/data_view", body, nil, []int{http.StatusOK, http.StatusCreated})
}

func (c *Client) ensureKibanaDefaultDataView(ctx context.Context, spaceName, indexName, dataViewID string) error {
	if spaceName == indexName {
		return c.SetKibanaDefaultDataView(ctx, spaceName, dataViewID, true)
	}
	return c.SetKibanaDefaultDataViewIfMissing(ctx, spaceName, dataViewID)
}

// SetKibanaDefaultDataViewIfMissing sets the space default only when no default exists.
func (c *Client) SetKibanaDefaultDataViewIfMissing(ctx context.Context, spaceName, dataViewID string) error {
	if _, ok, err := c.KibanaDefaultDataView(ctx, spaceName); err != nil {
		return err
	} else if ok {
		return nil
	}
	return c.SetKibanaDefaultDataView(ctx, spaceName, dataViewID, false)
}

// KibanaDefaultDataView returns the current space default data-view id, if set.
func (c *Client) KibanaDefaultDataView(ctx context.Context, spaceName string) (string, bool, error) {
	var response KibanaDefaultDataViewResponse
	err := c.DoKibanaJSONInSpace(ctx, spaceName, http.MethodGet, "/api/data_views/default", nil, &response, []int{http.StatusOK})
	if err != nil {
		if IsNotFoundResponse(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get Kibana default data view for space %q: %w", spaceName, err)
	}

	value := strings.TrimSpace(response.DataViewID)
	return value, value != "", nil
}

// SetKibanaDefaultDataView sets the default data view inside spaceName.
func (c *Client) SetKibanaDefaultDataView(ctx context.Context, spaceName, dataViewID string, force bool) error {
	body := KibanaDefaultDataViewRequest{
		DataViewID: dataViewID,
		Force:      force,
	}
	if err := c.DoKibanaJSONInSpace(ctx, spaceName, http.MethodPost, "/api/data_views/default", body, nil, []int{http.StatusOK}); err != nil {
		return fmt.Errorf("set Kibana default data view for space %q: %w", spaceName, err)
	}
	return nil
}

// BuildDataViewID returns the deterministic Kibana data-view id for indexName.
func BuildDataViewID(indexName string) string {
	return "gateway-index-pattern-" + indexName
}

// BuildDataViewCacheKey returns the space-scoped cache key for indexName.
func BuildDataViewCacheKey(spaceName, indexName string) string {
	return spaceName + "/" + BuildDataViewID(indexName)
}

// BuildDataViewPattern returns the wildcard pattern used by a space data view.
func BuildDataViewPattern(indexName string) string {
	return indexName + "-*"
}

// KibanaAPIPath ensures path is rooted for direct Kibana API calls.
func KibanaAPIPath(path string) string {
	return "/" + strings.TrimLeft(path, "/")
}

// KibanaAPIPathForSpace ensures an API path targets a Kibana space.
func KibanaAPIPathForSpace(spaceName, path string) string {
	path = KibanaAPIPath(path)
	if strings.TrimSpace(spaceName) == "" {
		return path
	}
	if strings.HasPrefix(path, "/s/") {
		return path
	}
	return "/s/" + url.PathEscape(spaceName) + path
}
