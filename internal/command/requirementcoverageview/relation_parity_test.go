package requirementcoverageview

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func cloneRelationValue(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func relationParityInput(t *testing.T, mode string) map[string]any {
	t.Helper()
	raw := validCoverageInput(t).(map[string]any)
	group := coverageSourceGroup(raw["requirementSource"].(map[string]any))
	member := group["members"].([]any)[0]
	proof := raw["requirementProofBinding"].(map[string]any)
	requirement := proof["requirements"].([]any)[0]
	binding := proof["bindings"].([]any)[0]
	command := proof["witnessCommands"].([]any)[0]
	entry := inventoryEntry(raw)
	members, requirements, bindings, commands, entries, invariants := []any{}, []any{}, []any{}, []any{}, []any{}, []any{}
	for i := 1; i <= 3; i++ {
		reqID := fmt.Sprintf("REQ-PROOFKIT-COVERAGE-%03d", i)
		cmdID := fmt.Sprintf("command.%d", i)
		invID := fmt.Sprintf("invariant.%d", i)
		m := cloneRelationValue(t, member)
		m["requirementId"] = reqID
		r := cloneRelationValue(t, requirement)
		r["requirementId"] = reqID
		b := cloneRelationValue(t, binding)
		b["requirementId"] = reqID
		b["scenarioId"] = fmt.Sprintf("scenario.%d", i)
		b["commandIds"] = []any{cmdID}
		c := cloneRelationValue(t, command)
		c["commandId"] = cmdID
		e := cloneRelationValue(t, entry)
		e["testId"] = fmt.Sprintf("test.%d", i)
		e["falsifier"].(map[string]any)["falsifierId"] = fmt.Sprintf("falsifier.%d", i)
		e["falsifier"].(map[string]any)["negativeCaseId"] = fmt.Sprintf("case.%d", i)
		e["requirementRefs"] = []any{reqID}
		e["ownerInvariantRefs"] = []any{invID}
		e["commandRefs"] = []any{cmdID}
		if mode == "dense" || mode == "mixed-negative" || mode == "owner-scope" || mode == "compact" {
			e["requirementRefs"] = []any{"REQ-PROOFKIT-COVERAGE-001", "REQ-PROOFKIT-COVERAGE-002", "REQ-PROOFKIT-COVERAGE-003"}
			e["ownerInvariantRefs"] = []any{"invariant.1", "invariant.2", "invariant.3"}
			e["commandRefs"] = []any{"command.1", "command.2", "command.3"}
		}
		if mode == "no-match" {
			e["requirementRefs"] = []any{}
			e["ownerInvariantRefs"] = []any{}
			e["commandRefs"] = []any{}
		}
		if mode == "mixed-negative" && i == 2 {
			e["requirementRefs"] = append(e["requirementRefs"].([]any), "REQ-UNKNOWN")
			e["ownerInvariantRefs"] = append(e["ownerInvariantRefs"].([]any), "invariant.unknown")
			e["commandRefs"] = append(e["commandRefs"].([]any), "command.unknown")
			e["witnessRefs"] = []any{"witness.unknown"}
			e["ownerId"] = "owner.outside"
			e["oracle"] = nil
		}
		owner := "proofkit.coverage"
		if mode == "owner-scope" && i == 3 {
			owner = "owner.outside"
			m["fields"].(map[string]any)["ownerId"] = owner
			r["ownerId"] = owner
		}
		members = append(members, m)
		requirements = append(requirements, r)
		bindings = append(bindings, b)
		commands = append(commands, c)
		// Reverse raw inventory order: admission, not fixture order, owns TestID order.
		entries = append([]any{e}, entries...)
		invariants = append(invariants, map[string]any{"ownerInvariantId": invID, "ownerId": owner, "sourcePath": "docs/invariants.md", "summary": "Relation mapping preserves inventory entries.", "nonClaims": []any{}})
	}
	group["members"] = members
	proof["requirements"] = requirements
	proof["bindings"] = bindings
	proof["witnessCommands"] = commands
	raw["testEvidenceInventory"].(map[string]any)["entries"] = entries
	raw["coverageUniverse"].(map[string]any)["commandRefs"] = []any{}
	raw["ownerInvariantRegistry"] = map[string]any{"schemaVersion": json.Number("1"), "registryId": "registry.relations", "invariants": invariants, "nonClaims": []any{"Registry does not execute tests."}}
	if mode == "missing" {
		raw["testEvidenceInventory"] = nil
	}
	if mode == "failed" {
		entries[0].(map[string]any)["oracle"] = nil
	}
	if mode == "compact" {
		compactBindings := [][]any{}
		for i := 1; i <= 3; i++ {
			binding := compactCoverageBinding(fmt.Sprintf("proofkit.coverage::scenario.%d", i))
			binding[0] = fmt.Sprintf("REQ-PROOFKIT-COVERAGE-%03d", i)
			compactBindings = append(compactBindings, binding)
		}
		compactBindings = append(compactBindings, compactCoverageBinding("proofkit.coverage::scenario.extra"))
		raw["compactProofContract"] = validCompactCoverageContract(compactBindings...)
		raw["requirementProofBinding"] = nil
		raw["localEnvironmentPolicy"] = map[string]any{"authority": "caller_provided", "localEnvironmentClasses": []any{"local-go"}}
		raw["coverageUniverse"].(map[string]any)["commandRefs"] = []any{"command.1", "command.2", "command.3"}
		for _, entry := range entries {
			entry.(map[string]any)["witnessRefs"] = []any{}
		}
	}
	return raw
}

func TestCoverageRelationFullOutputParity(t *testing.T) {
	// Captured from the unindexed base-83eddaf owner with its current renderer.
	// JSON, Markdown and exit codes match the earlier base-27fcb8e observations.
	// HTML was re-captured when the shared stylesheet began hiding unmatched
	// card groups; only that stylesheet rule changed the rendered bytes.
	// "compact" was re-captured when compact Markdown/HTML began rendering
	// declared witness routes; its JSON and exit-code projection is unchanged.
	wants := map[string]string{
		"sparse":         "f6e52d12b5bf07fe84b20cfe02791631815dbb79255fe40da9cba0f95cbfd6f1",
		"dense":          "ece6842d9bf9ee589c6d4b353ee8b5f2c761a46f91e9f18b4b232378b6ca397f",
		"no-match":       "e1199178877df52b4634abd873e76a6a8a3db289703951d3175fd3b3e53b0c34",
		"missing":        "2da12f764a429da0b08cd38550c9e401e7715cc4bfcf7af1ddb550c8499c2cf3",
		"failed":         "d0483811de43b06f2a5ff4f1582f60f05e9bbc15ad706ee4ba3c403c64d353ad",
		"mixed-negative": "7ac30c89c9d7570d6a4f4dc30bf57ee2667e282e54c931edd0f42bfcd81798bd",
		"owner-scope":    "87d6075e17f0e33c0966ca32022de5896dbc52b487142ae2f77ce693c8c8fceb",
		"compact":        "07fb069aca5f40990960ed9a674d39526ac15a406fd50e332bb5a27642315ca2",
	}
	for _, name := range []string{"sparse", "dense", "no-match", "missing", "failed", "mixed-negative", "owner-scope", "compact"} {
		t.Run(name, func(t *testing.T) {
			raw := relationParityInput(t, name)
			before, _ := json.Marshal(raw)
			view, code, err := BuildJSON(raw, Options{})
			if err != nil {
				t.Fatal(err)
			}
			markdown, markdownCode, err := BuildMarkdown(raw)
			if err != nil {
				t.Fatal(err)
			}
			html, htmlCode, err := BuildHTML(raw)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(raw)
			if string(before) != string(after) {
				t.Fatal("Build mutated caller input")
			}
			if code != markdownCode || code != htmlCode {
				t.Fatal("rendered exit code mismatch")
			}
			positive := name == "sparse" || name == "dense" || name == "compact"
			if positive && code != 0 {
				t.Fatalf("positive fixture failed: %#v", view.(map[string]any)["failures"])
			}
			if !positive && code != 1 {
				t.Fatalf("negative fixture passed: %#v", view)
			}
			if name == "dense" || name == "compact" {
				for _, key := range []string{"requirementCoverage", "ownerInvariantCoverage", "commandCoverage"} {
					for _, row := range view.(map[string]any)[key].([]any) {
						if !reflect.DeepEqual(row.(map[string]any)["testIds"], []any{"test.1", "test.2", "test.3"}) {
							t.Fatalf("lost many-to-many mapping: %#v", row)
						}
					}
				}
			}
			encoded, err := json.Marshal([]any{view, code, markdown, html})
			if err != nil {
				t.Fatal(err)
			}
			got := fmt.Sprintf("%x", sha256.Sum256(encoded))
			if got != wants[name] {
				t.Fatalf("full output digest = %s", got)
			}
		})
	}
}

func queryScopedRelationInput(t *testing.T) map[string]any {
	t.Helper()
	raw := relationParityInput(t, "owner-scope")
	raw["coverageUniverse"].(map[string]any)["commandRefs"] = []any{"command.declared"}
	entries := raw["testEvidenceInventory"].(map[string]any)["entries"].([]any)
	for _, value := range entries {
		entry := value.(map[string]any)
		switch entry["testId"] {
		case "test.3":
			entry["ownerId"] = "owner.outside"
			entry["requirementRefs"] = []any{"REQ-PROOFKIT-COVERAGE-003", "REQ-UNKNOWN"}
			entry["ownerInvariantRefs"] = []any{"invariant.3", "invariant.unknown"}
			entry["commandRefs"] = []any{"command.3", "command.unknown"}
		case "test.2":
			entry["ownerId"] = "owner.outside"
			entry["requirementRefs"] = append(entry["requirementRefs"].([]any), "REQ-UNKNOWN")
			entry["ownerInvariantRefs"] = append(entry["ownerInvariantRefs"].([]any), "invariant.unknown")
			entry["commandRefs"] = append(entry["commandRefs"].([]any), "command.declared", "command.unknown")
		}
	}
	return raw
}

func TestCoverageUnqueriedInventoryDiagnostics(t *testing.T) {
	raw := queryScopedRelationInput(t)
	before, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	view, code, err := BuildJSON(raw, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Fatalf("unknown inventory refs returned code %d", code)
	}
	output := view.(map[string]any)
	for _, id := range []string{"test.2", "test.3"} {
		for _, failure := range []string{
			"inventory_entry_owner_outside_scope:" + id + ":owner.outside",
			"unknown_requirement_ref:" + id + ":REQ-PROOFKIT-COVERAGE-003",
			"unknown_requirement_ref:" + id + ":REQ-UNKNOWN",
			"unknown_owner_invariant_ref:" + id + ":invariant.3",
			"unknown_owner_invariant_ref:" + id + ":invariant.unknown",
			"unknown_command_or_witness_ref:" + id + ":command.3",
			"unknown_command_or_witness_ref:" + id + ":command.unknown",
		} {
			if !containsString(anyStrings(output["failures"].([]any)), failure) {
				t.Errorf("lost full-inventory diagnostic %s", failure)
			}
		}
	}
	unmapped := output["unmappedTests"].([]any)
	if len(unmapped) != 1 || unmapped[0].(map[string]any)["testId"] != "test.3" {
		t.Fatalf("unmapped tests = %#v, want test.3", unmapped)
	}
	for key, want := range map[string][]any{
		"requirementRefs":    {"REQ-PROOFKIT-COVERAGE-003", "REQ-UNKNOWN"},
		"ownerInvariantRefs": {"invariant.3", "invariant.unknown"},
		"commandRefs":        {"command.3", "command.unknown"},
	} {
		if got := unmapped[0].(map[string]any)[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("unmapped %s = %#v, want %#v", key, got, want)
		}
	}
	for _, key := range []string{"requirementCoverage", "ownerInvariantCoverage", "commandCoverage"} {
		for _, value := range output[key].([]any) {
			row := value.(map[string]any)
			want := []any{"test.1", "test.2"}
			if row["commandId"] == "command.declared" {
				want = []any{"test.2"}
			}
			if !reflect.DeepEqual(row["testIds"], want) {
				t.Errorf("%s lost queried matches: %#v", key, row)
			}
		}
	}
	after, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Build mutated caller input")
	}
}
