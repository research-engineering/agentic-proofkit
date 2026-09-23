package selectivegateplan

import "testing"

func TestScanOwnershipSurvivesNativeCommandCoalescing(t *testing.T) {
	for _, position := range []string{"before", "after", "fallback"} {
		t.Run(position, func(t *testing.T) {
			input := validPlanInput()
			duplicate := planCommand("secret-scan", "agentic-proofkit secret-scan --input artifacts/secret-scan.json", "secret_scan")
			switch position {
			case "before":
				input["baseCommands"] = []any{duplicate}
			case "after":
				input["packageCommands"] = []any{duplicate}
			case "fallback":
				input["unknownEdges"] = []any{unknownEdgeInput("edge.dynamic", "dynamic_or_unknown")}
				input["fallbackCoverage"] = []any{map[string]any{"command": duplicate, "edgeClasses": []any{"dynamic_or_unknown"}, "reason": "Caller-selected fallback reuses the scan command."}}
			}
			output, code, err := Build(input)
			if err != nil || code != 0 {
				t.Fatalf("native duplicate control: %d %v", code, err)
			}
			projection, err := AdmitEvidencePlan(jsonRoundTrip(t, output))
			if err != nil {
				t.Fatalf("coalescing erased a native scan owner: %v", err)
			}
			count := 0
			for _, command := range projection.RequiredCommands {
				if command["id"] == "secret-scan" {
					count++
					if command["commandOwnership"] != "proofkit_secret_scan" {
						t.Fatalf("wrong coalesced owner: %v", command)
					}
				}
			}
			if count != 1 {
				t.Fatalf("coalescing duplicated the scan obligation: %d", count)
			}
		})
	}
}
