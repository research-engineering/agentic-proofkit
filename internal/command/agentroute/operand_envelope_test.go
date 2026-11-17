package agentroute

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestFullRouteEnvelopePreservesWireOperands(t *testing.T) {
	profiles := []struct{ name, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""},
		{cliexec.ProfilePythonModule, "/opt/task-validation/bin/python"},
	}
	paths := []struct{ name, prefix, root string }{
		{"task_names", "inputs/task-", "."},
		{"risk_names", "inputs/risk-", "."},
		{"long_inputs", strings.Repeat("segment/", 70) + "task-", "."},
		{"distinct_long_repo_root", "inputs/task-", strings.Repeat("checkout/", 70) + "risk-root"},
	}
	if len(routeSpecs) == 0 {
		t.Fatal("ready route corpus is empty")
	}
	for _, profile := range profiles {
		renderer, err := cliexec.AdmitLauncherProfile(profile.name, profile.python)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			for _, goal := range slices.Sorted(maps.Keys(routeSpecs)) {
				t.Run(profile.name+"/"+path.name+"/"+goal, func(t *testing.T) {
					input := structuralRouteInput(goal, true)
					refs := map[string]string{}
					for _, raw := range input["availableInputs"].([]any) {
						ref := raw.(map[string]any)
						kind := ref["kind"].(string)
						value := path.prefix + kind + ".json"
						if strings.HasSuffix(kind, "_repo_root") {
							value = path.root
						}
						ref["ref"], refs[kind] = value, value
						if path.name == "long_inputs" && value != "." && len(value) <= 512 {
							t.Fatal("long input does not cross the scalar truncation boundary")
						}
					}
					// Ownership comes from the declarative route spec, never from
					// reparsing a generated argv or a display command.
					wantCommands := map[string]int{}
					wantContexts := map[string]bool{}
					for _, command := range routeSpecs[goal].NextCommands {
						args := append([]string{command.Command}, command.ExtraArgs...)
						for _, operand := range command.ArgInputs {
							value, ok := refs[operand.InputKind]
							if !ok {
								t.Fatalf("ready corpus lacks %s", operand.InputKind)
							}
							if value == refs[command.InputKind] {
								t.Fatal("non-input operand must differ from the input path")
							}
							args = append(args, operand.Flag, value)
							wantContexts[value] = true
						}
						if command.InputKind != "" {
							value, ok := refs[command.InputKind]
							if !ok {
								t.Fatalf("ready corpus lacks %s", command.InputKind)
							}
							args = append(args, "--input", value)
							wantContexts[value] = true
						}
						wantCommands[wireCommandKey(t, command.Command, renderer.Argv(args...))]++
					}
					if len(wantCommands) == 0 || len(wantContexts) == 0 {
						t.Fatal("ready goal did not exercise commands and caller-owned paths")
					}
					for _, entrypoint := range []string{"default_full", "explicit_full"} {
						t.Run(entrypoint, func(t *testing.T) {
							var envelope map[string]any
							var code int
							var err error
							if entrypoint == "default_full" {
								envelope, code, err = BuildEnvelopeWithRenderer(input, renderer)
							} else {
								envelope, code, err = BuildEnvelopeModeWithRenderer(input, renderer, EnvelopeModeFull)
							}
							if err != nil || code != 0 {
								t.Fatalf("ready public route: exit=%d err=%v", code, err)
							}
							wire := routeEnvelopeWire(t, envelope)
							if wire["sourceReport"].(map[string]any)["state"] != "passed" {
								t.Fatal("ready corpus did not reach a passed route source projection")
							}
							commands := wire["commands"].([]any)
							if len(commands) != len(routeSpecs[goal].NextCommands) || len(wire["omitted"].([]any)) != 0 {
								t.Fatalf("ready commands were omitted: commands=%d want=%d omitted=%v", len(commands), len(routeSpecs[goal].NextCommands), wire["omitted"])
							}
							remaining := maps.Clone(wantCommands)
							for _, raw := range commands {
								command := raw.(map[string]any)
								argv := []string{}
								for _, raw := range command["argv"].([]any) {
									value, ok := raw.(string)
									if !ok {
										t.Fatal("argv operand is not a JSON-wire string")
									}
									argv = append(argv, value)
								}
								if profile.name == cliexec.ProfilePythonModule && (len(argv) == 0 || argv[0] != "/opt/task-validation/bin/python") {
									t.Fatal("sealed Python launcher was redacted or replaced")
								}
								key := wireCommandKey(t, command["proofkitRoute"].(string), argv)
								if remaining[key] == 0 {
									t.Fatalf("unexpected, duplicate, or altered wire argv: %q", argv)
								}
								remaining[key]--
							}
							for _, count := range remaining {
								if count != 0 {
									t.Fatal("a declared ready command disappeared")
								}
							}
							contexts := maps.Clone(wantContexts)
							for _, raw := range wire["contextRefs"].([]any) {
								ref := raw.(map[string]any)
								if ref["role"] != "caller_owned_input" {
									continue
								}
								value, ok := ref["path"].(string)
								if !ok || !contexts[value] || ref["selector"] != value {
									t.Fatalf("caller-owned path/selector changed, duplicated, or invented: %#v", ref)
								}
								delete(contexts, value)
							}
							if len(contexts) != 0 {
								t.Fatalf("caller-owned context paths were omitted: %v", slices.Sorted(maps.Keys(contexts)))
							}
						})
					}
				})
			}
		}
	}
}

func wireCommandKey(t *testing.T, route string, argv []string) string {
	t.Helper()
	encoded, err := json.Marshal(argv)
	if err != nil {
		t.Fatal(err)
	}
	return route + "\x00" + string(encoded)
}

func routeEnvelopeWire(t *testing.T, envelope map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	return wire
}
