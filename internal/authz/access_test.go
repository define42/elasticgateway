package authz

import "testing"

func TestResolveIngestWriteNamespace(t *testing.T) {
	t.Parallel()

	for _, tt := range resolveIngestWriteNamespaceCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := ResolveIngestWriteNamespace(tt.access, tt.indexName)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("ResolveIngestWriteNamespace() = %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

type resolveIngestWriteNamespaceCase struct {
	name      string
	access    []Access
	indexName string
	want      string
	wantOK    bool
}

func resolveIngestWriteNamespaceCases() []resolveIngestWriteNamespaceCase {
	return []resolveIngestWriteNamespaceCase{
		{
			name:      "write access allows prefixed index",
			access:    []Access{{Group: "team10_rw", Namespace: "team10"}},
			indexName: "team10-hello",
			want:      "team10",
			wantOK:    true,
		},
		{
			name:      "bare namespace is not an ingest index",
			access:    []Access{{Group: "team10_rw", Namespace: "team10"}},
			indexName: "team10",
		},
		{
			name:      "empty suffix is not allowed",
			access:    []Access{{Group: "team10_rw", Namespace: "team10"}},
			indexName: "team10-",
		},
		{
			name:      "different namespace prefix is not allowed",
			access:    []Access{{Group: "team10_rw", Namespace: "team10"}},
			indexName: "team100-hello",
		},
		{
			name:      "read only access is not write access",
			access:    []Access{{Group: "team10_r", Namespace: "team10", PullOnly: true}},
			indexName: "team10-hello",
		},
		{
			name:      "dashboard access is not write access",
			access:    []Access{{Group: "team10_re", Namespace: "team10", PullOnly: true, DashboardEdit: true}},
			indexName: "team10-hello",
		},
		{
			name: "non-overlapping namespaces resolve only their own indices",
			access: []Access{
				{Group: "team_rw", Namespace: "team"},
				{Group: "team10_rw", Namespace: "team10"},
			},
			indexName: "team10-foo",
			want:      "team10",
			wantOK:    true,
		},
	}
}
