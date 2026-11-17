package projectstructure_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/app"
)

func TestPreparedInputProducersPreserveCLIStdinTransport(t *testing.T) {
	for _, item := range []struct{ route, diagnostic string }{
		{"scaffold-project-structure", "project structure scaffold input must be an object"},
		{"gradual-adoption-bootstrap", "proofkit gradual adoption bootstrap input must be an object"},
	} {
		t.Run(item.route, func(t *testing.T) {
			stdin := strings.NewReader("null")
			var stdout, stderr bytes.Buffer
			code := app.Run(context.Background(), []string{item.route, "--input", "-"}, stdin, &stdout, &stderr)
			if code != 1 || stdout.Len() != 0 || stderr.String() != item.diagnostic+"\n" || stdin.Len() != 0 {
				t.Fatalf("stdin did not reach native admission: exit=%d stdout=%q stderr=%q unread=%d", code, stdout.String(), stderr.String(), stdin.Len())
			}
		})
	}
}
