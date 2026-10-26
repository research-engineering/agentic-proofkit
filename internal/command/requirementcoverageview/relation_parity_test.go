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
	// The same eight inputs retain the JSON, exit and Markdown observations
	// independently captured from main 3d760a1. Full-output hashes additionally
	// bind the admitted HTML changes: styles, display controls, table wrapping
	// a textual report-state badge and hierarchy navigation. Visual-only updates
	// must retain protectedWants.
	protectedWants := map[string]string{
		"sparse":         "8c538adccaf293c5aa4ab392f6f2d581d34a6874cf195b1f009fe72ca2d0c173",
		"dense":          "2bde9e9fa38f4de2f581462886a7aec9c74ebf9839144294432ac4dae02868f5",
		"no-match":       "707dde2b594ff01302feefdbc9ebf46043c87cf8b5e499e5e211ac87027a2190",
		"missing":        "926e3602a4a7656b73c723c1045127421adefb25e015738ba4479f81b5550a9c",
		"failed":         "644cf6224c0f6582dc1c30ca1e50adc121a802fae5325aa82bdc40ea4edfa691",
		"mixed-negative": "168f76dc99b4e372130daa4dafe38b3a71807bd3cee3ef01aeea6001498ace53",
		"owner-scope":    "b44ce994f05b5a86a6692dbeb77244c79fbf07a499d2dbe9f611c8a3a97c5632",
		"compact":        "c0a6930a61e5068f698064da83b26b5eb38fef0c985fc00729527cad8649e7da",
	}
	wants := map[string]string{
		"sparse":         "fb67d62ee1a1db60d099ea8843d0834a791bb63680ad7e8e59e8682512c16449",
		"dense":          "0a28706ede56f47692a9829eca8b109dae356c3adbe6f7f7ce3c14a1749551f4",
		"no-match":       "f5185d667d94c72ccfff30ca972d563922a22a3e3334691f6417e1a1ac4c86af",
		"missing":        "beaf20909664943199c239fba06e39206e5b39743cda76f7ed9860d13be50ff1",
		"failed":         "8acdaa9b6938b5518e4d5bef3ff3970138616acdad5a28af94184607c3d43f36",
		"mixed-negative": "68a8f19fa1645cbd0a3e1c704ae24077657a4ff9e5f71d8cebba8cac1ac5dc1f",
		"owner-scope":    "97e2ea8b16f56405dc489ab79f52e5ebf90f6b1f8903ce770e2b422afe13ba1c",
		"compact":        "0e266dc7d77f17f16befa17e78a57217e0e0ae0307a6b1e1b5380f5a9620d236",
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
			if got := relationObservationDigest(t, []any{view, code, markdown}); got != protectedWants[name] {
				t.Fatalf("protected JSON/exit/Markdown digest = %s", got)
			}
			got := relationObservationDigest(t, []any{view, code, markdown, html})
			if got != wants[name] {
				t.Fatalf("full output digest = %s", got)
			}
		})
	}
}

func relationObservationDigest(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
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
