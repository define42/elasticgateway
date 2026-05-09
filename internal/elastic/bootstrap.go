package elastic

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
)

// EnsureILMPolicy creates or updates the shared rollover ILM policy.
func (c *Client) EnsureILMPolicy(ctx context.Context, policyID string, maxDocs int) error {
	path := "/_ilm/policy/" + url.PathEscape(policyID)
	desired := ILMPolicyRequest{
		Policy: BuildILMPolicy(maxDocs),
	}

	var existing map[string]ILMPolicyResponse
	err := c.DoJSON(ctx, http.MethodGet, path, nil, &existing, []int{http.StatusOK})
	if err != nil {
		if IsNotFoundResponse(err) {
			return c.DoJSON(ctx, http.MethodPut, path, desired, nil, []int{http.StatusOK, http.StatusCreated})
		}
		return err
	}

	if current, ok := existing[policyID]; ok && reflect.DeepEqual(current.Policy, desired.Policy) {
		return nil
	}

	return c.DoJSON(ctx, http.MethodPut, path, desired, nil, []int{http.StatusOK, http.StatusCreated})
}

// EnsureIndexTemplate upserts the shared rollover index template.
func (c *Client) EnsureIndexTemplate(ctx context.Context, templateName string) error {
	body := map[string]any{
		"index_patterns": []string{"*-*-rollover-*"},
		"priority":       2000,
		"template": map[string]any{
			"settings": map[string]any{
				"index.number_of_shards":   c.Config.Shards,
				"index.number_of_replicas": c.Config.Replicas,
				"index.lifecycle.name":     DefaultILMPolicyID,
			},
			"mappings": map[string]any{
				"properties": map[string]any{
					"event_time": map[string]any{
						"type": "date",
					},
				},
			},
		},
	}

	return c.DoJSON(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(templateName), body, nil, []int{http.StatusOK, http.StatusCreated})
}

// BuildILMPolicy returns the rollover policy used for gateway-managed aliases.
func BuildILMPolicy(maxDocs int) ILMPolicy {
	return ILMPolicy{
		Phases: map[string]ILMPhase{
			"hot": {
				Actions: map[string]ILMRolloverAction{
					"rollover": {
						MaxDocs: maxDocs,
					},
				},
			},
		},
	}
}
