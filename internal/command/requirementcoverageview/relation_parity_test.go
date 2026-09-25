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
	// Captured from the complete base-27fcb8e JSON, Markdown and HTML outputs.
	wants := map[string]string{
		"sparse":         "bbb8301eaa6f8a1eef7bf6e9014a4d8eb244aa5df18ec95fa5bf21047c008539",
		"dense":          "5fe303636801fc4e4c0f4c3f113f2ebf84bf57f777e11ed317d9ac89fa3bbfa2",
		"no-match":       "97077764446c771cf0494d256c758a1bda48fc07dc39402fcebf577908d24e77",
		"missing":        "2d5d66e50045f08fd8888cf78e6749c587ec5515e16f9b7339acd9cf45f05acc",
		"failed":         "7572ca52ca5b4c1e82823ffb853a4399076972fa7a8f694cbf8476beb2cf0f6f",
		"mixed-negative": "dd38c68762abd29858570b4c556baac3cebc838ccec644e5558c32e39feef549",
		"owner-scope":    "e32f8d52b4cef0ce43b88c1fdc802be8b4d644331f294932e557994bf2dcb7a1",
		"compact":        "236880dbe5473ebadfd255007b791d232815c54dce24db216dfa5c5bdf56a739",
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
