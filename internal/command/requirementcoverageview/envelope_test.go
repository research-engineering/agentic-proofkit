package requirementcoverageview

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestCoverageEnvelopePreservesAdmittedLauncherArgv(t *testing.T) {
	for _, test := range []struct {
		name       string
		profile    string
		executable string
		prefix     []any
	}{
		{name: "default", prefix: []any{"agentic-proofkit"}},
		{name: "path", profile: cliexec.ProfilePath, prefix: []any{"agentic-proofkit"}},
		{name: "npm offline", profile: cliexec.ProfileNPMOffline, prefix: []any{"npm", "exec", "--offline", "--", "agentic-proofkit"}},
		{name: "python structural path", profile: cliexec.ProfilePythonModule, executable: "/opt/task-validation/bin/python", prefix: []any{"/opt/task-validation/bin/python", "-m", "agentic_proofkit"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			renderer, err := cliexec.AdmitLauncherProfile(test.profile, test.executable)
			if err != nil {
				t.Fatal(err)
			}
			input := validCoverageInput(t)
			inventoryEntry(input)["requirementRefs"] = []any{"REQ-PROOFKIT-COVERAGE-001", "REQ-UNKNOWN-001"}
			raw, code, err := BuildJSON(input, Options{AgentEnvelope: true, Renderer: renderer})
			if err != nil || code != 1 {
				t.Fatalf("envelope exit=%d err=%v, want failed coverage report", code, err)
			}
			wire, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]any
			if err := json.Unmarshal(wire, &envelope); err != nil {
				t.Fatal(err)
			}
			commands := envelope["commands"].([]any)
			if len(commands) != 1 {
				t.Fatalf("commands=%#v, want one rerun command", commands)
			}
			command := commands[0].(map[string]any)
			want := append(test.prefix, "requirement-coverage-view", "--input", "<coverage-input.json>")
			if !reflect.DeepEqual(command["argv"], want) {
				t.Fatalf("argv=%#v, want %#v", command["argv"], want)
			}
		})
	}
}
