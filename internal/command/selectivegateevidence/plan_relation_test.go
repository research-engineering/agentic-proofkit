package selectivegateevidence

import "testing"

func TestEvidenceRejectsContradictoryPlansInBothEvidenceClasses(t *testing.T) {
	for _, class := range []string{"advisory", "merge_satisfying"} {
		for _, contradiction := range []string{"scan", "uncovered", "fallback-command"} {
			t.Run(class+"/"+contradiction, func(t *testing.T) {
				input := validEvidenceInput()
				input["evidenceClass"] = class
				control, err := Build(input)
				if err != nil || control.ExitCode != 0 || control.Report.State != "passed" {
					t.Fatalf("control: %#v %v", control, err)
				}
				plan := evidencePlan(input)
				switch contradiction {
				case "scan":
					plan["scanObligation"].(map[string]any)["commandId"] = "missing.scan"
				case "uncovered":
					edge := unknownEdgeRecord("dynamic_or_unknown", "uncovered")
					edge["fallbackCommandIds"] = []any{}
					plan["unknownEdges"] = []any{edge}
				case "fallback-command":
					fallback := plannedCommand()
					fallback["command"] = "go test ./other"
					plan["unknownEdges"] = []any{unknownEdgeRecord("dynamic_or_unknown", "covered_by_declared_fallback")}
					plan["fallbackCoverage"] = []any{map[string]any{"command": fallback, "edgeClasses": []any{"dynamic_or_unknown"}, "reason": "Synthetic edge coverage."}}
				}
				if result, err := Build(input); err == nil {
					t.Fatalf("contradictory plan was admitted: %#v", result)
				}
			})
		}
	}
}
