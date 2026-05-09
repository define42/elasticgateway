package ldap

import (
	"strings"
	"testing"

	"github.com/define42/opensearchgateway/internal/config"
	goldap "github.com/go-ldap/ldap/v3"
)

func TestUserSearchFilterEscapesMailValue(t *testing.T) {
	t.Parallel()

	auth := New(config.LDAPConfig{
		UserFilter: "(&(objectClass=person)(mail=%s))",
	})
	mail := `bad*)(|(mail=*))@example.com`

	got := auth.userSearchFilter(mail)
	want := "(&(objectClass=person)(mail=" + goldap.EscapeFilter(mail) + "))"
	if got != want {
		t.Fatalf("user search filter = %q, want %q", got, want)
	}
	if strings.Contains(got, `*)(|`) {
		t.Fatalf("user search filter contains unescaped LDAP filter operators: %q", got)
	}
}
