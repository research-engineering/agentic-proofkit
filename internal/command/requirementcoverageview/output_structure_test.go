package requirementcoverageview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func coverageStructureCases(t *testing.T) map[string]map[string]any {
	t.Helper()
	outputs := map[string]map[string]any{}
	for _, mode := range []string{"structured", "compact"} {
		for _, outcome := range []string{"passed", "missing-inventory", "failed-inventory", "unmapped-test"} {
			input := validCoverageInput(t).(map[string]any)
			if mode == "compact" {
				input["requirementProofBinding"] = nil
				input["compactProofContract"] = validCompactCoverageContract()
				input["localEnvironmentPolicy"] = map[string]any{"authority": "caller_provided", "localEnvironmentClasses": []any{"local-go"}}
				inventoryEntry(input)["witnessRefs"] = []any{}
			}
			switch outcome {
			case "missing-inventory":
				input["testEvidenceInventory"] = nil
			case "failed-inventory":
				inventoryEntry(input)["qualityFindings"] = []any{map[string]any{
					"class": "implementation_mirror", "evidenceRefs": []any{"test.coverage.semantic"},
					"findingId": "finding.coverage.implementation-mirror", "nonClaims": []any{"Caller-owned finding does not prove execution."},
					"ownerReviewState": "confirmed", "severity": "failure",
				}}
			case "unmapped-test":
				for _, field := range []string{"commandRefs", "ownerInvariantRefs", "requirementRefs", "witnessRefs"} {
					inventoryEntry(input)[field] = []any{}
				}
			}
			view, exitCode, err := BuildJSON(input, Options{})
			if err != nil {
				t.Fatalf("%s/%s: %v", mode, outcome, err)
			}
			if (exitCode == 0) != (outcome == "passed") {
				t.Fatalf("%s/%s: unexpected exit %d", mode, outcome, exitCode)
			}
			outputs[mode+"/"+outcome] = view.(map[string]any)
		}
	}
	outputs["owner-invariant"] = coverageRecordWithOwnerInvariant(t)
	return outputs
}

func TestCoverageOutputStructureConservesWholeReports(t *testing.T) {
	for name, output := range coverageStructureCases(t) {
		t.Run(name, func(t *testing.T) {
			if err := OutputShape().CheckGenerated(output, name); err != nil {
				t.Fatal(err)
			}
			encoded, err := stablejson.Marshal(output)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := OutputShape().Admit(wire, name)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []any{output, wire, snapshot} {
				admitted, err := AdmitOutput(value)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := stablejson.Marshal(admitted)
				if err != nil || !bytes.Equal(encoded, actual) {
					t.Fatalf("whole output changed during re-admission: %v", err)
				}
			}
			snapshot.(map[string]any)["requirementCoverage"].([]any)[0].(map[string]any)["invariant"] = "Detached edit"
			actual, err := stablejson.Marshal(wire)
			if err != nil || !bytes.Equal(encoded, actual) {
				t.Fatal("structural snapshot aliases caller rows")
			}
		})
	}
}

type coverageStructureMutation struct {
	name   string
	mutate func(map[string]any)
}

func coverageStructureMutations() []coverageStructureMutation {
	row := func(record map[string]any) map[string]any {
		return record["requirementCoverage"].([]any)[0].(map[string]any)
	}
	return []coverageStructureMutation{
		{"unknown-root", func(r map[string]any) { r["undeclared"] = true }},
		{"missing-root", func(r map[string]any) { delete(r, "testInventoryId") }},
		{"wrong-version", func(r map[string]any) { r["schemaVersion"] = json.Number("3") }},
		{"wrong-mode", func(r map[string]any) { r["proofMode"] = "compact" }},
		{"null-row-array", func(r map[string]any) { r["commandCoverage"] = nil }},
		{"missing-row", func(r map[string]any) { delete(row(r), "sharedPremises") }},
		{"unknown-row", func(r map[string]any) { row(r)["undeclared"] = false }},
		{"wrong-scalar", func(r map[string]any) { row(r)["invariant"] = true }},
		{"null-item", func(r map[string]any) { row(r)["nonClaims"] = []any{nil} }},
		{"negative-count", func(r map[string]any) { row(r)["scenarioCount"] = json.Number("-1") }},
		{"unknown-state", func(r map[string]any) { row(r)["coverageState"] = "proven_correct" }},
		{"missing-scenario", func(r map[string]any) { delete(row(r)["scenarios"].([]any)[0].(map[string]any), "witnessKind") }},
		{"missing-test", func(r map[string]any) {
			delete(row(r)["tests"].([]any)[0].(map[string]any), "supersessionDeclarationRef")
		}},
		{"invalid-basis", func(r map[string]any) { r["coverageBasis"].(map[string]any)["ownerIds"] = []any{} }},
		{"unknown-guidance", func(r map[string]any) { r["guidanceSummary"].(map[string]any)["approval"] = true }},
	}
}

func TestCoverageOutputStructureRejectsIsolatedStructuralCorruption(t *testing.T) {
	base := coverageStructureCases(t)["structured/passed"]
	for _, mutation := range coverageStructureMutations() {
		t.Run(mutation.name, func(t *testing.T) {
			record := cloneCoverageJSONValue(base).(map[string]any)
			mutation.mutate(record)
			if err := OutputShape().CheckGenerated(record, "coverage"); err == nil {
				t.Fatal("structural corruption admitted")
			}
			if _, err := AdmitOutput(record); err == nil {
				t.Fatal("native re-admission accepted structural corruption")
			}
		})
	}
	for _, count := range []any{json.Number("1.0"), json.Number("1e0"), json.Number("01"), float64(1)} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			record := cloneCoverageJSONValue(base).(map[string]any)
			record["requirementCoverageCount"] = count
			if err := OutputShape().CheckGenerated(record, "coverage"); err == nil {
				t.Fatal("noncanonical numeric carrier admitted")
			}
		})
	}
}

func TestCoverageOutputStructureDoesNotReplaceSemanticReplay(t *testing.T) {
	record := coverageStructureCases(t)["structured/passed"]
	row := record["requirementCoverage"].([]any)[0].(map[string]any)
	row["commandIds"] = []any{"proofkit.unrelated.command"}
	if err := OutputShape().CheckGenerated(record, "coverage"); err != nil {
		t.Fatal("semantic-only control must remain structurally valid", err)
	}
	if _, err := AdmitOutput(record); err == nil {
		t.Fatal("structural validity replaced native relation replay")
	}
}
