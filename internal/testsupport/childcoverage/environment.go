// Package childcoverage isolates coverage output from subprocess test protocols.
package childcoverage

import (
	"strings"
	"testing"
)

// Environment preserves the explicit caller environment, replacing only the
// inherited coverage destination with a directory owned by this test. Nil does
// not import the ambient environment.
func Environment(t testing.TB, base []string) []string {
	t.Helper()
	result := make([]string, 0, len(base)+1)
	for _, value := range base {
		key, _, _ := strings.Cut(value, "=")
		if key != "GOCOVERDIR" {
			result = append(result, value)
		}
	}
	return append(result, "GOCOVERDIR="+t.TempDir())
}
