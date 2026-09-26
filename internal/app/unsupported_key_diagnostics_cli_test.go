package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestKnownKeysNativeCLIDiagnostics(t *testing.T) {
	binary := buildTestBinary(t)
	const publicRouteID = "synthetic.batch20.public-route"
	const publicRef = "docs/specs/synthetic-batch20/requirements.v2.json"
	input := func() map[string]any {
		return map[string]any{
			"schemaVersion": 1,
			"routeId":       publicRouteID,
			"goal":          "validate_requirement_source",
			"mode":          "observe",
			"availableInputs": []any{map[string]any{
				"kind": "requirement_source", "ref": publicRef,
			}},
		}
	}
	run := func(t *testing.T, record map[string]any, wantStderr string) string {
		t.Helper()
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), binary, "agent-route", "--input", "-")
		command.Stdin = bytes.NewReader(encoded)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err = command.Run()
		if wantStderr == "" {
			if err != nil || stderr.Len() != 0 {
				t.Fatalf("positive CLI failed: err=%v stderr=%q", err, stderr.String())
			}
			var report map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("positive CLI did not emit JSON: %v", err)
			}
			if report["state"] != "routed" || report["selectedRouteFamily"] != "requirement_source" || report["reportId"] != publicRouteID || !strings.Contains(stdout.String(), publicRef) {
				t.Fatalf("positive CLI lost public route context: %s", stdout.String())
			}
		} else {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || stdout.Len() != 0 || stderr.String() != wantStderr {
				t.Fatalf("CLI rejection: err=%v stdout=%q stderr=%q, want exit 1, empty stdout and %q", err, stdout.String(), stderr.String(), wantStderr)
			}
		}
		return stdout.String()
	}

	positive := run(t, input(), "")
	for _, stage := range []struct {
		name    string
		context string
	}{
		{"root", "agent route input"},
		{"nested", "agent route availableInputs[0]"},
	} {
		for index, keys := range [][]string{
			{"synthetic-batch20-opaque-alpha"},
			{"synthetic-batch20-opaque-omega"},
			{"synthetic-batch20-opaque-alpha", "synthetic-batch20-opaque-omega"},
			{"synthetic-batch20-opaque-omega", "synthetic-batch20-opaque-alpha"},
			{"synthetic-batch20-renamed-z", "synthetic-batch20-renamed-a"},
		} {
			t.Run(fmt.Sprintf("%s/rename_%d", stage.name, index), func(t *testing.T) {
				record := input()
				target := record
				if stage.name == "nested" {
					target = record["availableInputs"].([]any)[0].(map[string]any)
				}
				for _, key := range keys {
					target[key] = map[string]any{"payload": "synthetic-batch20-ignored-value"}
				}
				want := fmt.Sprintf("%s has unsupported field(s): %d\n", stage.context, len(keys))
				run(t, record, want)
				for _, key := range keys {
					delete(target, key)
				}
				if got := run(t, record, ""); got != positive {
					t.Fatal("removing only unknown keys did not restore the exact positive report")
				}
			})
		}
	}
}
