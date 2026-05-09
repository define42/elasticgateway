// Package ldap authenticates gateway users and maps LDAP groups to namespaces.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/define42/elasticgateway/internal/authz"
	"github.com/define42/elasticgateway/internal/config"
	goldap "github.com/go-ldap/ldap/v3"
)

var (
	// ErrInvalidCredentials reports an LDAP bind failure caused by bad credentials.
	ErrInvalidCredentials = errors.New("ldap invalid credentials")
	// ErrUserNotFound reports an authenticated LDAP user missing from search results.
	ErrUserNotFound = errors.New("ldap user not found")
	// ErrUnauthorized reports a valid LDAP user without matching gateway groups.
	ErrUnauthorized = errors.New("ldap user has no authorized groups")
)

// Authenticator authenticates users against LDAP using the configured server.
type Authenticator struct {
	cfg config.LDAPConfig
}

// New returns an LDAP authenticator backed by cfg.
func New(cfg config.LDAPConfig) *Authenticator {
	return &Authenticator{cfg: cfg}
}

// AuthenticateAccess validates the credentials and resolves namespace access.
func (a *Authenticator) AuthenticateAccess(username, password string) (*authz.User, []authz.Access, error) {
	conn, err := Dial(a.cfg)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	mail := a.mailForUsername(username)
	if err := conn.Bind(mail, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, fmt.Errorf("ldap bind failed: %w", err)
	}

	entry, err := a.lookupEntry(conn, mail)
	if err != nil {
		return nil, nil, err
	}

	groups := entry.GetAttributeValues(a.cfg.GroupAttribute)
	access, user := AccessFromGroups(username, groups, a.cfg.GroupNamePrefix)
	if user == nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnauthorized, username)
	}

	return user, access, nil
}

func (a *Authenticator) mailForUsername(username string) string {
	if strings.Contains(username, "@") || a.cfg.UserMailDomain == "" {
		return username
	}

	domain := a.cfg.UserMailDomain
	if !strings.HasPrefix(domain, "@") {
		domain = "@" + domain
	}
	return username + domain
}

func (a *Authenticator) lookupEntry(conn *goldap.Conn, mail string) (*goldap.Entry, error) {
	searchReq := goldap.NewSearchRequest(
		a.cfg.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases, 1, 0, false,
		a.userSearchFilter(mail),
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, mail)
	}
	return sr.Entries[0], nil
}

func (a *Authenticator) userSearchFilter(mail string) string {
	return fmt.Sprintf(a.cfg.UserFilter, goldap.EscapeFilter(mail))
}

// Dial opens an LDAP connection according to cfg.
func Dial(cfg config.LDAPConfig) (*goldap.Conn, error) {
	tlsConfig, err := ldapTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	conn, err := goldap.DialURL(cfg.URL, goldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}

	if cfg.StartTLS && strings.HasPrefix(cfg.URL, "ldap://") {
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func ldapTLSConfig(cfg config.LDAPConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify} // #nosec G402 -- explicit LDAP local-dev opt-in.
	if cfg.SkipTLSVerify {
		return tlsConfig, nil
	}

	rootCAs, err := config.RootCAPool(cfg.RootCAPath)
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = rootCAs
	tlsConfig.ServerName = ldapServerName(cfg.URL)
	return tlsConfig, nil
}

func ldapServerName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// AccessFromGroups converts LDAP group DNs into gateway access entries.
func AccessFromGroups(username string, groups []string, prefix string) ([]authz.Access, *authz.User) {
	var selected *authz.User
	var access []authz.Access

	for _, g := range groups {
		groupName := GroupNameFromDN(g)
		permissionGroup := groupName
		if prefix != "" {
			if !strings.HasPrefix(groupName, prefix) {
				continue
			}
			permissionGroup = strings.TrimPrefix(groupName, prefix)
		}

		ns, pullOnly, deleteAllowed, ok := PermissionsFromGroup(permissionGroup)
		if !ok {
			continue
		}
		if !authz.ValidNamespace(ns) {
			continue
		}

		access = append(access, authz.Access{
			Group:         groupName,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		})

		candidate := &authz.User{
			Name:          username,
			Group:         groupName,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		}

		if selected == nil || authz.MorePermissive(candidate, selected) {
			selected = candidate
		}
	}

	return access, selected
}

// GroupNameFromDN extracts the leading CN or OU value from a group DN.
func GroupNameFromDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return dn
	}

	first := strings.TrimSpace(parts[0])
	firstLower := strings.ToLower(first)

	switch {
	case strings.HasPrefix(firstLower, "cn="):
		return first[3:]
	case strings.HasPrefix(firstLower, "ou="):
		return first[3:]
	default:
		return dn
	}
}

// PermissionsFromGroup parses namespace access suffixes like _user, _ingest, and _admin.
func PermissionsFromGroup(group string) (namespace string, pullOnly bool, deleteAllowed bool, ok bool) {
	switch {
	case strings.HasSuffix(group, "_admin"):
		ns := strings.TrimSuffix(group, "_admin")
		return ns, false, true, true
	case strings.HasSuffix(group, "_ingest"):
		ns := strings.TrimSuffix(group, "_ingest")
		return ns, false, false, true
	case strings.HasSuffix(group, "_user"):
		ns := strings.TrimSuffix(group, "_user")
		return ns, true, false, true
	default:
		return "", false, false, false
	}
}
