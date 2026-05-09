package elastic

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/define42/opensearchgateway/internal/authz"
)

var reservedNativeUsers = map[string]struct{}{
	"elastic":                {},
	"kibana":                 {},
	"kibana_system":          {},
	"logstash_system":        {},
	"beats_system":           {},
	"apm_system":             {},
	"remote_monitoring_user": {},
	"anonymous":              {},
}

// ProvisionLoginUser ensures roles, spaces, data views, and the native user.
//
// internalUserPassword is the password to set on the Elasticsearch native user
// for username. It is NOT the caller's LDAP password: the gateway mints a fresh
// random value per login so the LDAP credential never reaches Elasticsearch.
func (c *Client) ProvisionLoginUser(ctx context.Context, username, internalUserPassword string, access []authz.Access) error {
	effective := authz.NormalizeAccessByNamespace(access)
	if len(effective) == 0 {
		return fmt.Errorf("no LDAP namespaces available for %s", username)
	}

	if err := c.EnsureNativeUserWritable(ctx, username); err != nil {
		return err
	}

	roleNames := make([]string, 0, len(effective))
	namespaces := make([]string, 0, len(effective))
	for _, item := range effective {
		if !authz.ValidNamespace(item.Namespace) {
			return fmt.Errorf("LDAP namespace %q cannot be mapped to Elasticsearch resources", item.Namespace)
		}

		if err := c.EnsureSpace(ctx, item.Namespace); err != nil {
			return err
		}

		roleName := authz.BuildGatewayRoleName(item.Namespace, authz.RoleModeForAccess(item))
		if err := c.EnsureSecurityRole(ctx, roleName, item); err != nil {
			return err
		}
		if err := c.EnsureKibanaDataView(ctx, item.Namespace, item.Namespace); err != nil {
			return err
		}

		roleNames = append(roleNames, roleName)
		namespaces = append(namespaces, item.Namespace)
	}

	sort.Strings(roleNames)
	sort.Strings(namespaces)

	return c.UpsertNativeUser(ctx, username, internalUserPassword, roleNames, authz.AccessGroupNames(access), namespaces)
}

// EnsureSecurityRole upserts the Elastic role used for a namespace access mode.
func (c *Client) EnsureSecurityRole(ctx context.Context, roleName string, access authz.Access) error {
	body := RoleRequestForAccess(access)
	if c.Config.KibanaURL != "" {
		path := "/api/security/role/" + url.PathEscape(roleName)
		if err := c.DoKibanaJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK, http.StatusNoContent}); err != nil {
			return fmt.Errorf("ensure security role %q: %w", roleName, err)
		}
		return nil
	}

	path := "/_security/role/" + url.PathEscape(roleName)
	if err := c.DoJSON(ctx, http.MethodPut, path, body.Elasticsearch, nil, []int{http.StatusOK}); err != nil {
		return fmt.Errorf("ensure security role %q: %w", roleName, err)
	}
	return nil
}

// RoleRequestForAccess converts namespace access into an Elastic role payload.
func RoleRequestForAccess(access authz.Access) KibanaRoleRequest {
	mode := authz.RoleModeForAccess(access)
	kibanaBase, kibanaFeature := kibanaPrivilegesForMode(mode)

	return KibanaRoleRequest{
		Description: fmt.Sprintf("Gateway role for namespace %s (%s)", access.Namespace, mode),
		Elasticsearch: ElasticsearchRoleRequest{
			Cluster: []string{},
			Indices: []ElasticsearchIndexPrivilege{
				{
					Names:                  []string{BuildDataViewPattern(access.Namespace)},
					Privileges:             authz.AllowedActionsForAccess(mode),
					AllowRestrictedIndices: false,
				},
			},
		},
		Kibana: []KibanaSpacePrivilege{
			{
				Base:    kibanaBase,
				Feature: kibanaFeature,
				Spaces:  []string{access.Namespace},
			},
		},
		Metadata: map[string]any{
			"managed_by": "elasticgateway",
			"namespace":  access.Namespace,
			"mode":       mode,
		},
	}
}

func kibanaPrivilegesForMode(mode string) ([]string, map[string][]string) {
	switch mode {
	case "r":
		return []string{"read"}, map[string][]string{}
	case "re":
		return []string{}, map[string][]string{
			"dashboard_v2": {"all"},
			"discover_v2":  {"read"},
			"visualize_v2": {"all"},
		}
	case "rw", "rd", "rwd":
		return []string{"all"}, map[string][]string{}
	default:
		return []string{"read"}, map[string][]string{}
	}
}

// UpsertNativeUser creates or replaces an Elasticsearch native user.
func (c *Client) UpsertNativeUser(ctx context.Context, username, internalUserPassword string, roleNames, backendRoles, namespaces []string) error {
	body := NativeUserRequest{
		Password: internalUserPassword,
		Roles:    roleNames,
		Enabled:  true,
		Metadata: map[string]any{
			"backend_roles": backendRoles,
			"namespaces":    namespaces,
			"managed_by":    "elasticgateway",
		},
	}

	path := "/_security/user/" + url.PathEscape(username)
	if err := c.DoJSON(ctx, http.MethodPut, path, body, nil, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return fmt.Errorf("upsert Elasticsearch user %q: %w", username, err)
	}
	return nil
}

// EnsureNativeUserWritable rejects built-in or reserved native users.
func (c *Client) EnsureNativeUserWritable(ctx context.Context, username string) error {
	username = strings.TrimSpace(username)
	if _, reserved := reservedNativeUsers[username]; reserved {
		return fmt.Errorf("%w: %s", ErrReservedNativeUser, username)
	}

	path := "/_security/user/" + url.PathEscape(username)

	var response map[string]NativeUserInfo
	err := c.DoJSON(ctx, http.MethodGet, path, nil, &response, []int{http.StatusOK})
	if err != nil {
		if IsNotFoundResponse(err) {
			return nil
		}
		return err
	}

	info, ok := response[username]
	if !ok {
		return nil
	}
	if info.Reserved || info.Hidden || metadataBool(info.Metadata, "_reserved") || metadataBool(info.Metadata, "reserved") || metadataBool(info.Metadata, "hidden") {
		return fmt.Errorf("%w: %s", ErrReservedNativeUser, username)
	}
	return nil
}

func metadataBool(metadata map[string]any, key string) bool {
	value, ok := metadata[key]
	if !ok {
		return false
	}
	asBool, ok := value.(bool)
	return ok && asBool
}
