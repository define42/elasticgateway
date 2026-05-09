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
			name:          "admin group parses full access",
			group:         "team10_admin",
			wantNamespace: "team10",
			wantPullOnly:  false,
			wantDelete:    true,
			wantOK:        true,
		},
		{
			name:          "rwd group is rejected",
			group:         "team10_rwd",
			wantNamespace: "",
			wantPullOnly:  false,
			wantDelete:    false,
			wantOK:        false,
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
			name:          "rw group is rejected",
			group:         "team10_rw",
			wantNamespace: "",
			wantPullOnly:  false,
			wantDelete:    false,
			wantOK:        false,
		},
		{
			name:          "ingest group parses read write access",
			group:         "team10_ingest",
			wantNamespace: "team10",
			wantPullOnly:  false,
			wantDelete:    false,
			wantOK:        true,
		},
		{
			name:          "r group is rejected",
			group:         "team10_r",
			wantNamespace: "",
			wantPullOnly:  false,
			wantDelete:    false,
			wantOK:        false,
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
			name:          "user group parses read-only access",
			group:         "team10_user",
			wantNamespace: "team10",
			wantPullOnly:  true,
			wantDelete:    false,
			wantOK:        true,
		},
		{
			name:          "invalid suffix is rejected",
			group:         "team10_operator",
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
		{name: "cn prefix", dn: "cn=team10_ingest,ou=groups,dc=glauth,dc=com", want: "team10_ingest"},
		{name: "ou prefix", dn: "ou=team10_user,dc=glauth,dc=com", want: "team10_user"},
		{name: "plain value", dn: "team10_admin", want: "team10_admin"},
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

func TestAccessFromGroupsStripsPrefixAndSelectsMostPermissive(t *testing.T) {
	t.Parallel()

	groups := []string{
		"cn=app_elk_team10_user,ou=groups,dc=glauth,dc=com",
		"ou=app_elk_team10_ingest,dc=glauth,dc=com",
		"cn=other_ingest,ou=groups,dc=glauth,dc=com",
		"cn=app_elk_team10,ou=groups,dc=glauth,dc=com",
	}

	access, user := ldappkg.AccessFromGroups("johndoe", groups, "app_elk_")
	if user == nil {
		t.Fatal("expected selected user")
	}
	if user.Group != "app_elk_team10_ingest" || user.Namespace != "team10" || user.PullOnly || user.DeleteAllowed {
		t.Fatalf("unexpected selected user permissions: %+v", user)
	}
	if len(access) != 2 {
		t.Fatalf("expected two valid app_elk-prefixed access entries, got %+v", access)
	}
	if access[0].Group != "app_elk_team10_user" || access[0].Namespace != "team10" || !access[0].PullOnly || access[0].DeleteAllowed {
		t.Fatalf("unexpected user access entry: %+v", access[0])
	}
	if access[1].Group != "app_elk_team10_ingest" || access[1].Namespace != "team10" || access[1].PullOnly || access[1].DeleteAllowed {
		t.Fatalf("unexpected ingest access entry: %+v", access[1])
	}
}

func TestAccessFromGroupsEmptyPrefixKeepsUnprefixedParsing(t *testing.T) {
	t.Parallel()

	access, user := ldappkg.AccessFromGroups("johndoe", []string{
		"cn=team10_user,ou=groups,dc=glauth,dc=com",
		"cn=team10,ou=groups,dc=glauth,dc=com",
	}, "")
	if user == nil {
		t.Fatal("expected selected user")
	}
	if user.Group != "team10_user" || user.Namespace != "team10" || !user.PullOnly || user.DeleteAllowed {
		t.Fatalf("unexpected selected user permissions: %+v", user)
	}
	if len(access) != 1 || access[0].Group != "team10_user" || access[0].Namespace != "team10" {
		t.Fatalf("expected only the unprefixed _user access entry, got %+v", access)
	}
}

func TestAccessFromGroupsRejectsReadEditSuffix(t *testing.T) {
	t.Parallel()

	access, user := ldappkg.AccessFromGroups("reader", []string{
		"cn=app_elk_team10_user,ou=groups,dc=glauth,dc=com",
		"cn=app_elk_team10_re,ou=groups,dc=glauth,dc=com",
	}, "app_elk_")
	if user == nil {
		t.Fatal("expected selected user")
	}
	if user.Namespace != "team10" || !user.PullOnly || user.DeleteAllowed {
		t.Fatalf("unexpected selected user permissions: %+v", user)
	}
	if len(access) != 1 {
		t.Fatalf("expected only the _user access entry, got %+v", access)
	}
}

func TestAccessFromGroupsDropsHyphenedNamespace(t *testing.T) {
	t.Parallel()

	groups := []string{
		"cn=app_elk_team10_ingest,ou=groups,dc=glauth,dc=com",
		"cn=app_elk_team10-special_ingest,ou=groups,dc=glauth,dc=com",
	}

	access, user := ldappkg.AccessFromGroups("johndoe", groups, "app_elk_")
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
			name: "admin access outranks write-only access",
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
			name: "admin access outranks read-only access",
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
