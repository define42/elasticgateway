// Package elastic contains the gateway's Elasticsearch and Kibana clients.
package elastic

import (
	"errors"
	"fmt"
	"sync"

	"github.com/define42/elasticgateway/internal/config"
)

const (
	// DefaultILMPolicyID is the gateway-managed rollover policy identifier.
	DefaultILMPolicyID = "generic-rollover-100m"
	// DefaultIndexTemplateName is the shared rollover template name.
	DefaultIndexTemplateName = "gateway-rollover-template"
)

// ErrReservedNativeUser reports a native user that cannot be overwritten.
var ErrReservedNativeUser = errors.New("elasticsearch native user is reserved or built-in")

// ErrReservedInternalUser is kept as a compatibility alias for older callers.
var ErrReservedInternalUser = ErrReservedNativeUser

// Client wraps Elasticsearch and Kibana HTTP interactions for the gateway.
type Client struct {
	Config               config.Config
	EnsuredSpaces        sync.Map
	EnsuredDataViews     sync.Map
	EnsuredAliasPolicies sync.Map
}

// ResponseError reports a non-success HTTP response from an upstream API.
type ResponseError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

// Error formats the upstream failure response.
func (e *ResponseError) Error() string {
	return fmt.Sprintf("%s %s failed: status=%d", e.Method, e.Path, e.StatusCode)
}

// IndexDocumentResponse captures the Elasticsearch index API response fields used by the gateway.
type IndexDocumentResponse struct {
	ID     string `json:"_id"`
	Result string `json:"result"`
}

// BulkIndexDocument is one document to send through Elasticsearch _bulk.
type BulkIndexDocument struct {
	Action   string
	Index    string
	Metadata map[string]any
	Document map[string]any
}

// BulkIndexResponse captures the Elasticsearch bulk API response.
type BulkIndexResponse struct {
	Took   int                         `json:"took,omitempty"`
	Errors bool                        `json:"errors"`
	Items  []map[string]BulkItemResult `json:"items"`
}

// BulkItemResult captures the subset of each bulk item returned to callers.
type BulkItemResult struct {
	Index  string `json:"_index,omitempty"`
	ID     string `json:"_id,omitempty"`
	Result string `json:"result,omitempty"`
	Status int    `json:"status,omitempty"`
	Error  any    `json:"error,omitempty"`
}

// AliasResponse captures the Elasticsearch alias lookup payload by backing index.
type AliasResponse map[string]AliasIndexInfo

// AliasIndexInfo captures the aliases attached to a single backing index.
type AliasIndexInfo struct {
	Aliases map[string]AliasInfo `json:"aliases"`
}

// AliasInfo captures alias metadata needed to identify writable backing indices.
type AliasInfo struct {
	IsWriteIndex *bool `json:"is_write_index,omitempty"`
}

// SpaceRequest creates a Kibana space.
type SpaceRequest struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	DisabledFeatures []string `json:"disabledFeatures"`
}

// KibanaDataViewRequest creates or updates a Kibana data view.
type KibanaDataViewRequest struct {
	DataView KibanaDataView `json:"data_view"`
	Override bool           `json:"override,omitempty"`
}

// KibanaDataView holds the data-view fields managed by the gateway.
type KibanaDataView struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	Title         string `json:"title"`
	TimeFieldName string `json:"timeFieldName"`
}

// KibanaDefaultDataViewRequest writes a space default data-view id.
type KibanaDefaultDataViewRequest struct {
	DataViewID string `json:"data_view_id"`
	Force      bool   `json:"force,omitempty"`
}

// KibanaDefaultDataViewResponse reads the current space default data-view id.
type KibanaDefaultDataViewResponse struct {
	DataViewID string `json:"data_view_id"`
}

// KibanaRoleRequest describes an Elastic role with Elasticsearch and Kibana privileges.
type KibanaRoleRequest struct {
	Description   string                   `json:"description,omitempty"`
	Elasticsearch ElasticsearchRoleRequest `json:"elasticsearch"`
	Kibana        []KibanaSpacePrivilege   `json:"kibana"`
	Metadata      map[string]any           `json:"metadata,omitempty"`
}

// ElasticsearchRoleRequest describes index and cluster privileges.
type ElasticsearchRoleRequest struct {
	Cluster  []string                      `json:"cluster"`
	Indices  []ElasticsearchIndexPrivilege `json:"indices"`
	Metadata map[string]any                `json:"metadata,omitempty"`
}

// ElasticsearchIndexPrivilege grants index-level permissions to a role.
type ElasticsearchIndexPrivilege struct {
	Names                  []string `json:"names"`
	Privileges             []string `json:"privileges"`
	AllowRestrictedIndices bool     `json:"allow_restricted_indices"`
}

// KibanaSpacePrivilege grants Kibana privileges inside spaces.
type KibanaSpacePrivilege struct {
	Base    []string            `json:"base"`
	Feature map[string][]string `json:"feature"`
	Spaces  []string            `json:"spaces"`
}

// NativeUserRequest describes the payload for an Elasticsearch native user.
type NativeUserRequest struct {
	Password string         `json:"password"`
	Roles    []string       `json:"roles"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Enabled  bool           `json:"enabled"`
}

// NativeUserInfo is the subset of native-user metadata the gateway needs.
type NativeUserInfo struct {
	Metadata map[string]any `json:"metadata,omitempty"`
	Reserved bool           `json:"reserved,omitempty"`
	Hidden   bool           `json:"hidden,omitempty"`
	Enabled  bool           `json:"enabled,omitempty"`
}

// ILMPolicyRequest wraps an ILM policy payload.
type ILMPolicyRequest struct {
	Policy ILMPolicy `json:"policy"`
}

// ILMPolicyResponse is the Elasticsearch ILM policy response used for upserts.
type ILMPolicyResponse struct {
	Policy ILMPolicy `json:"policy"`
}

// ILMPolicy describes an index lifecycle management policy.
type ILMPolicy struct {
	Phases map[string]ILMPhase `json:"phases"`
}

// ILMPhase describes a lifecycle phase.
type ILMPhase struct {
	Actions map[string]ILMRolloverAction `json:"actions"`
}

// ILMRolloverAction configures rollover thresholds for an ILM policy.
type ILMRolloverAction struct {
	MaxDocs int `json:"max_docs,omitempty"`
}

// NewClient constructs a client for Elasticsearch and Kibana APIs.
func NewClient(cfg config.Config) *Client {
	cfg = normalizeConfig(cfg)
	return &Client{Config: cfg}
}

func normalizeConfig(cfg config.Config) config.Config {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = config.DefaultHTTPClient()
	}
	return cfg
}
