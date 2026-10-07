package selectivegateevidence

import (
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestCommandKeyRoundTripPreservesCommandDelimiters(t *testing.T) {
	path := "src/check.go"
	for _, command := range []string{"go test ./...", "\x00", "go\x00test", "\x00go\x00test\x00"} {
		for _, source := range []*string{nil, &path} {
			key := commandKey{ID: "command.one", Command: command, SourcePath: source}
			if actual := parseKey(keyString(key)); !reflect.DeepEqual(actual, key) {
				t.Fatalf("key round trip: got %#v, want %#v", actual, key)
			}
		}
	}
}

func TestCommandKeyBoundaryComponentsRejectDelimiters(t *testing.T) {
	for _, id := range []string{"command\x00one", "\x00command"} {
		if _, err := admit.RuleID(id, "command identity"); err == nil {
			t.Fatal("admitted identifier contains a key delimiter")
		}
	}
	for _, path := range []string{"src/check\x00.go", "src/\x00check.go", ""} {
		if _, err := admit.SafeRepoRelativePath(path, "command source path"); err == nil {
			t.Fatal("admitted source path is empty or contains a key delimiter")
		}
	}
}

func TestUnplannedRouteDiagnosticPreservesCommandDelimiters(t *testing.T) {
	input := validProjectionInput()
	route := input["commandRoutes"].([]any)[0].(map[string]any)
	route["command"] = "go\x00test"
	route["sourcePath"] = "src/route.go"
	_, err := ProjectObligationDecision(input)
	want := "selective evidence obligation projection route does not match a planned command: " + route["commandId"].(string) + " :: go\x00test :: src/route.go"
	if err == nil || err.Error() != want {
		t.Fatalf("route diagnostic: got %v, want %q", err, want)
	}
}
