package selectivegateplan

import (
	"strings"
	"testing"
)

func TestOutputRelationsPreserveNativeSuccessfulAndFailedPlans(t *testing.T) {
	for _, kind := range []string{"minimal", "covered", "uncovered", "preexisting", "scan-collision", "fallback-collision"} {
		t.Run(kind, func(t *testing.T) {
			input := relationPlanInput(kind)
			output, exitCode, err := Build(input)
			if err != nil {
				t.Fatal(err)
			}
			want := "fail_closed"
			if kind == "minimal" || kind == "covered" {
				want = "ok"
			}
			if output["planState"] != want || (exitCode == 0) != (want == "ok") {
				t.Fatalf("native state=%v exit=%d, want %s", output["planState"], exitCode, want)
			}
			projection, err := AdmitEvidencePlan(jsonRoundTrip(t, output))
			if err != nil || projection.PlanState != want {
				t.Fatalf("native wire output not closed: %v %v", projection.PlanState, err)
			}
		})
	}
}

func TestOutputRelationsRejectIndependentContradictions(t *testing.T) {
	tests := []struct {
		name   string
		cause  string
		mutate func(map[string]any)
	}{
		{"state-without-failure", "planState contradicts", func(p map[string]any) { p["planState"] = "fail_closed" }},
		{"success-with-failure", "planState contradicts", func(p map[string]any) { p["failures"] = []any{"Rejected fact."} }},
		{"scan-missing", "scan obligation", func(p map[string]any) {
			var kept []any
			for _, raw := range p["requiredCommands"].([]any) {
				if raw.(map[string]any)["id"] != "secret-scan" {
					kept = append(kept, raw)
				}
			}
			p["requiredCommands"] = kept
		}},
		{"scan-command", "scan obligation", func(p map[string]any) {
			p["scanObligation"].(map[string]any)["command"] = "agentic-proofkit secret-scan --input artifacts/other.json"
		}},
		{"scan-ownership", "scan obligation", func(p map[string]any) {
			for _, raw := range p["requiredCommands"].([]any) {
				item := raw.(map[string]any)
				if item["id"] == "secret-scan" {
					item["commandOwnership"] = "caller_owned_external"
				}
			}
		}},
		{"scan-source", "scan obligation", func(p map[string]any) {
			for _, raw := range p["requiredCommands"].([]any) {
				item := raw.(map[string]any)
				if item["id"] == "secret-scan" {
					item["sourcePath"] = "other.json"
				}
			}
		}},
		{"fallback-command", "fallback is missing", func(p map[string]any) {
			p["fallbackCoverage"].([]any)[0].(map[string]any)["command"].(map[string]any)["command"] = "npm run other"
		}},
		{"fallback-source", "fallback is missing", func(p map[string]any) {
			p["fallbackCoverage"].([]any)[0].(map[string]any)["command"].(map[string]any)["sourcePath"] = "other.json"
		}},
		{"fallback-ownership", "fallback is missing", func(p map[string]any) {
			p["fallbackCoverage"].([]any)[0].(map[string]any)["command"].(map[string]any)["commandOwnership"] = "caller_owned_external"
		}},
		{"uncovered-success", "successful state contains uncovered", func(p map[string]any) {
			p["fallbackCoverage"] = []any{}
			edge := p["unknownEdges"].([]any)[0].(map[string]any)
			edge["coverageState"] = "uncovered"
			edge["fallbackCommandIds"] = []any{}
		}},
		{"edge-state", "fallback relation", func(p map[string]any) { p["unknownEdges"].([]any)[0].(map[string]any)["coverageState"] = "uncovered" }},
		{"edge-ids", "fallback relation", func(p map[string]any) {
			p["unknownEdges"].([]any)[0].(map[string]any)["fallbackCommandIds"] = []any{"other.fallback"}
		}},
		{"edge-class", "fallback relation", func(p map[string]any) {
			p["unknownEdges"].([]any)[0].(map[string]any)["edgeClass"] = "generated_source"
		}},
		{"duplicate-command", "command keys must be unique", func(p map[string]any) {
			p["requiredCommands"] = append(p["requiredCommands"].([]any), p["requiredCommands"].([]any)[0])
		}},
		{"duplicate-fallback", "fallback command ids must be unique", func(p map[string]any) {
			p["fallbackCoverage"] = append(p["fallbackCoverage"].([]any), p["fallbackCoverage"].([]any)[0])
		}},
		{"duplicate-edge", "edge ids must be unique", func(p map[string]any) {
			p["unknownEdges"] = append(p["unknownEdges"].([]any), p["unknownEdges"].([]any)[0])
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, code, err := Build(relationPlanInput("covered"))
			if err != nil || code != 0 {
				t.Fatalf("control build: %d %v", code, err)
			}
			wire := jsonRoundTrip(t, output)
			if _, err := AdmitEvidencePlan(wire); err != nil {
				t.Fatalf("control admission: %v", err)
			}
			test.mutate(wire)
			if _, err := AdmitEvidencePlan(wire); err == nil || !strings.Contains(err.Error(), test.cause) {
				t.Fatalf("contradiction not rejected by %q: %v", test.cause, err)
			}
		})
	}
}

func relationPlanInput(kind string) map[string]any {
	input := validPlanInput()
	if kind == "covered" || kind == "fallback-collision" || kind == "uncovered" {
		input["unknownEdges"] = []any{unknownEdgeInput("edge.dynamic", "dynamic_or_unknown")}
	}
	if kind == "covered" || kind == "fallback-collision" {
		input["fallbackCoverage"] = []any{map[string]any{"command": planCommand("full.workspace", "npm run check", "full_workspace"), "edgeClasses": []any{"dynamic_or_unknown"}, "reason": "Full workspace checks this edge."}}
	}
	if kind == "preexisting" {
		input["preexistingFailures"] = []any{"Prior obligation failed."}
	}
	if kind == "scan-collision" {
		input["baseCommands"] = []any{planCommand("secret-scan", "agentic-proofkit secret-scan --input artifacts/secret-scan.json", "other_reason")}
	}
	if kind == "fallback-collision" {
		input["baseCommands"] = []any{planCommand("full.workspace", "npm run check", "other_reason")}
	}
	return input
}
