package commandcoverage

import (
	"strings"
	"testing"
)

const semanticRoutePrefix = "proofkit.command_coverage.source_oracle.v1."

// SemanticRoute binds a Go test body to a command-coverage semantic oracle row.
func SemanticRoute(t testing.TB, marker string) {
	t.Helper()
	if !strings.HasPrefix(marker, semanticRoutePrefix) || len(marker) != len(semanticRoutePrefix)+78 {
		t.Fatalf("invalid command coverage semantic route marker %q", marker)
	}
	for _, character := range strings.TrimPrefix(marker, semanticRoutePrefix) {
		if character < '0' || character > '9' {
			t.Fatalf("invalid command coverage semantic route marker %q", marker)
		}
	}
}
