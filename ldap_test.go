package main

import (
	"errors"
	"net"
	"testing"
	"time"

	authzpkg "github.com/define42/elasticgateway/internal/authz"
	appconfig "github.com/define42/elasticgateway/internal/config"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
)

//nolint:funlen // Table-driven LDAP permission cases are easier to audit in one table.
func TestPermissionsFromGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		group         string
		wantNamespace string
		wantPullOnly  bool
		wantDelete    bool
		wantOK        bool
	}{
		{
			name:          "rwd group parses full access",
			group:         "team10_rwd",
			wantNamespace: "team10",
			wantPullOnly:  false,
			wantDelete:    true,
			wantOK:        true,
		},
		{
			name:          "rd group is rejected",
			group:         "team10_rd",
			wantNamespace: "",
			wantPullOnly:  false,
			wantDelete:    false,
			wantOK:        false,
		},
		{
			name:          "rw group parses read write access",
			group:         "team10_rw",
			wantNamespace: "team10",
			wantPullOnly:  false,
			wantDelete:    false,
			wantOK:        true,
		},
		{
			name:          "re group is rejected",
			group:         "team10_re",
			wantNamespace: "",
			wantPullOnly:  false,
			wantDelete:    false,
			wantOK:        false,
		},
		{
			name:          "r group parses read-only access",
			group:         "team10_r",
			wantNamespace: "team10",
			wantPullOnly:  true,
			wantDelete:    false,
			wantOK:        true,
		},
		{
			name:          "invalid suffix is rejected",
			group:         "team10_admin",
			wantNamespace: "",
			wantPullOnly:  false,
			wantDelete:    false,
			wantOK:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotNamespace, gotPullOnly, gotDelete, gotOK := ldappkg.PermissionsFromGroup(tt.group)
			if gotNamespace != tt.wantNamespace || gotPullOnly != tt.wantPullOnly || gotDelete != tt.wantDelete || gotOK != tt.wantOK {
				t.Fatalf(
					"ldappkg.PermissionsFromGroup(%q) = (%q, %t, %t, %t), want (%q, %t, %t, %t)",
					tt.group,
					gotNamespace,
					gotPullOnly,
					gotDelete,
					gotOK,
					tt.wantNamespace,
					tt.wantPullOnly,
					tt.wantDelete,
					tt.wantOK,
				)
			}
		})
	}
}

func TestGroupNameFromDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dn   string
		want string
	}{
		{name: "cn prefix", dn: "cn=team10_rw,ou=groups,dc=glauth,dc=com", want: "team10_rw"},
		{name: "ou prefix", dn: "ou=team10_r,dc=glauth,dc=com", want: "team10_r"},
		{name: "plain value", dn: "team10_rwd", want: "team10_rwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ldappkg.GroupNameFromDN(tt.dn); got != tt.want {
				t.Fatalf("ldappkg.GroupNameFromDN(%q) = %q, want %q", tt.dn, got, tt.want)
			}
		})
	}
}

func TestAccessFromGroupsFiltersPrefixAndSelectsMostPermissive(t *testing.T) {
	t.Parallel()

	groups := []string{
		"cn=team10_r,ou=groups,dc=glauth,dc=com",
		"ou=team10_rw,dc=glauth,dc=com",
		"cn=other_rw,ou=groups,dc=glauth,dc=com",
	}

	access, user := ldappkg.AccessFromGroups("johndoe", groups, "team")
	if user == nil {
		t.Fatal("expected selected user")
	}
	if user.Namespace != "team10" || user.PullOnly || user.DeleteAllowed {
		t.Fatalf("unexpected selected user permissions: %+v", user)
	}
	if len(access) != 2 {
		t.Fatalf("expected two team-prefixed access entries, got %+v", access)
	}
}

func TestAccessFromGroupsRejectsReadEditSuffix(t *testing.T) {
	t.Parallel()

	access, user := ldappkg.AccessFromGroups("reader", []string{
		"cn=team10_r,ou=groups,dc=glauth,dc=com",
		"cn=team10_re,ou=groups,dc=glauth,dc=com",
	}, "team")
	if user == nil {
		t.Fatal("expected selected user")
	}
	if user.Namespace != "team10" || !user.PullOnly || user.DeleteAllowed {
		t.Fatalf("unexpected selected user permissions: %+v", user)
	}
	if len(access) != 1 {
		t.Fatalf("expected only the _r access entry, got %+v", access)
	}
}

func TestAccessFromGroupsDropsHyphenedNamespace(t *testing.T) {
	t.Parallel()

	groups := []string{
		"cn=team10_rw,ou=groups,dc=glauth,dc=com",
		"cn=team10-special_rw,ou=groups,dc=glauth,dc=com",
	}

	access, user := ldappkg.AccessFromGroups("johndoe", groups, "team")
	if user == nil || user.Namespace != "team10" {
		t.Fatalf("expected selected user in team10, got %+v", user)
	}
	if len(access) != 1 || access[0].Namespace != "team10" {
		t.Fatalf("hyphened namespace must be dropped; got access=%+v", access)
	}
}

func TestDialLDAPStartTLSFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			close(accepted)
			time.Sleep(100 * time.Millisecond)
			_ = conn.Close()
		}
	}()

	_, err = ldappkg.Dial(appconfig.LDAPConfig{
		URL:            "ldap://" + listener.Addr().String(),
		StartTLS:       true,
		SkipTLSVerify:  true,
		UserMailDomain: "@example.com",
	})
	if err == nil {
		t.Fatal("expected StartTLS failure")
	}
	<-accepted
}

func TestLDAPAuthenticateAccessUnauthorizedErrorHelpers(t *testing.T) {
	if !errors.Is(ldappkg.ErrInvalidCredentials, ldappkg.ErrInvalidCredentials) {
		t.Fatal("expected invalid credentials sentinel to match itself")
	}
	if !errors.Is(ldappkg.ErrUnauthorized, ldappkg.ErrUnauthorized) {
		t.Fatal("expected unauthorized sentinel to match itself")
	}
}

func TestMorePermissive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    *authzpkg.User
		b    *authzpkg.User
		want bool
	}{
		{
			name: "full access outranks write-only access",
			a:    &authzpkg.User{Name: "a", Namespace: "team10", PullOnly: false, DeleteAllowed: true},
			b:    &authzpkg.User{Name: "b", Namespace: "team10", PullOnly: false, DeleteAllowed: false},
			want: true,
		},
		{
			name: "write access outranks read-only access when delete is equal",
			a:    &authzpkg.User{Name: "a", Namespace: "team10", PullOnly: false, DeleteAllowed: false},
			b:    &authzpkg.User{Name: "b", Namespace: "team10", PullOnly: true, DeleteAllowed: false},
			want: true,
		},
		{
			name: "full access outranks read-only access",
			a:    &authzpkg.User{Name: "a", Namespace: "team10", PullOnly: false, DeleteAllowed: true},
			b:    &authzpkg.User{Name: "b", Namespace: "team10", PullOnly: true, DeleteAllowed: false},
			want: true,
		},
		{
			name: "less permissive user does not outrank more permissive user",
			a:    &authzpkg.User{Name: "a", Namespace: "team10", PullOnly: true, DeleteAllowed: false},
			b:    &authzpkg.User{Name: "b", Namespace: "team10", PullOnly: false, DeleteAllowed: true},
			want: false,
		},
		{
			name: "equal permissions are not more permissive",
			a:    &authzpkg.User{Name: "a", Namespace: "team10", PullOnly: false, DeleteAllowed: false},
			b:    &authzpkg.User{Name: "b", Namespace: "team10", PullOnly: false, DeleteAllowed: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := authzpkg.MorePermissive(tt.a, tt.b); got != tt.want {
				t.Fatalf("authzpkg.MorePermissive(%+v, %+v) = %t, want %t", *tt.a, *tt.b, got, tt.want)
			}
		})
	}
}
