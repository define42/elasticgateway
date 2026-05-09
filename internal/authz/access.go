// Package authz defines shared namespace access semantics for the gateway.
package authz

import (
	"regexp"
	"sort"
	"strings"
)

// namespacePattern restricts namespaces to characters that cannot collide
// with the "<namespace>-<index>" ingest path separator. A "-" inside the
// namespace would let multiple namespaces prefix-match the same index name.
var namespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_]*$`)

// ValidNamespace reports whether ns is allowed as a gateway namespace.
func ValidNamespace(ns string) bool {
	return namespacePattern.MatchString(ns)
}

// User describes the most permissive namespace access selected for a person.
type User struct {
	Name          string
	Group         string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

// Access describes namespace permissions derived from one LDAP group.
type Access struct {
	Group         string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

// MorePermissive reports whether a grants more access than b.
func MorePermissive(a, b *User) bool {
	if a.DeleteAllowed != b.DeleteAllowed {
		return a.DeleteAllowed
	}
	if a.PullOnly != b.PullOnly {
		return !a.PullOnly
	}
	return false
}

// NormalizeAccessByNamespace merges duplicate namespaces to the strongest access.
func NormalizeAccessByNamespace(access []Access) []Access {
	combined := make(map[string]Access)

	for _, item := range access {
		existing, ok := combined[item.Namespace]
		if !ok {
			combined[item.Namespace] = item
			continue
		}

		existing.PullOnly = existing.PullOnly && item.PullOnly
		existing.DeleteAllowed = existing.DeleteAllowed || item.DeleteAllowed
		if existing.Group == "" {
			existing.Group = item.Group
		}
		combined[item.Namespace] = existing
	}

	namespaces := make([]string, 0, len(combined))
	for namespace := range combined {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	result := make([]Access, 0, len(namespaces))
	for _, namespace := range namespaces {
		result = append(result, combined[namespace])
	}
	return result
}

// AccessGroupNames returns sorted distinct LDAP group names from access.
func AccessGroupNames(access []Access) []string {
	seen := make(map[string]struct{})
	groups := make([]string, 0, len(access))
	for _, item := range access {
		if item.Group == "" {
			continue
		}
		if _, ok := seen[item.Group]; ok {
			continue
		}
		seen[item.Group] = struct{}{}
		groups = append(groups, item.Group)
	}
	sort.Strings(groups)
	return groups
}

// CloneAccess returns a shallow copy of access.
func CloneAccess(access []Access) []Access {
	if len(access) == 0 {
		return nil
	}

	cloned := make([]Access, len(access))
	copy(cloned, access)
	return cloned
}

// ResolveIngestWriteNamespace returns the namespace that permits writing indexName.
func ResolveIngestWriteNamespace(access []Access, indexName string) (string, bool) {
	bestNamespace := ""
	for _, item := range NormalizeAccessByNamespace(access) {
		if item.PullOnly || item.Namespace == "" {
			continue
		}

		prefix := item.Namespace + "-"
		if !strings.HasPrefix(indexName, prefix) || len(indexName) == len(prefix) {
			continue
		}

		if len(item.Namespace) > len(bestNamespace) {
			bestNamespace = item.Namespace
		}
	}

	if bestNamespace == "" {
		return "", false
	}
	return bestNamespace, true
}

// RoleModeForAccess converts access into the gateway's role suffix.
func RoleModeForAccess(access Access) string {
	switch {
	case !access.PullOnly && access.DeleteAllowed:
		return "rwd"
	case !access.PullOnly:
		return "rw"
	default:
		return "r"
	}
}

// BuildGatewayRoleName builds the deterministic security role name.
func BuildGatewayRoleName(namespace, mode string) string {
	return "gateway_" + namespace + "_" + mode
}

// AllowedActionsForAccess maps a role mode to Elasticsearch index privileges.
func AllowedActionsForAccess(mode string) []string {
	switch mode {
	case "rwd":
		return []string{"read", "write", "delete", "create_index", "view_index_metadata"}
	case "rw":
		return []string{"read", "write", "create_index", "view_index_metadata"}
	default:
		return []string{"read", "view_index_metadata"}
	}
}
