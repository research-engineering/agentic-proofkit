package requirementcoverageview

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
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
	// The same eight inputs retain the JSON, exit and human observations
	// independently captured from main 3d760a1, except the unsupported selector
	// absence sentence removed from baseline 5459a33. Full-output hashes also
	// bind the admitted HTML changes: styles, display controls, table wrapping
	// a textual report-state badge, hierarchy navigation and filter value sets.
	// HTML representation updates must retain protectedWants.
	protectedWants := map[string]string{
		"sparse":         "41ece738e6c5deb55588190878ff0ac7055ea61f2e09f9beede556908fb696ad",
		"dense":          "ba318512d3954a1de0c944fa7f16338b0fa368596817facd04b9d6ed5ec173e2",
		"no-match":       "469f58a23bf746277f57295ec012e3e0b2dcdf050cd08a2fd9d80c592c086cad",
		"missing":        "a1408a780c70744b4312b73522405fc702f3c60fec6b17ba29bd374da891bf04",
		"failed":         "b1f18a6b7765f7d2d170aee7435a0824abf1381e4698f1d1d3b023ecf06f130c",
		"mixed-negative": "40c12bc4e4ca6a93ceb48d748cb1269e176e964e34e4186e6adc8e97a8da5234",
		"owner-scope":    "bd1f5d2c8aa6ec3fcb56b784c8d1df8cedba529775ac943dede87c0afc4559fb",
		"compact":        "c0a6930a61e5068f698064da83b26b5eb38fef0c985fc00729527cad8649e7da",
	}
	frameWants := map[string]string{
		"sparse":         "8d7eb48bff901ae02ab71148223e4fa8ad2c89367bd2284e6b846b9241cc861f",
		"dense":          "92de20e9455f119e94590d78339af458448ffeac1aef9c9d8c5d9bf5c8246202",
		"no-match":       "05acfc194a84f84fdee65d83fd040e48258d04ab7919954cba7f5a8fcf6f7ef3",
		"missing":        "f7a1d0e44c8de29259154662930ea457bca1fdae4983fd30f2a0a6b0e3cff9cf",
		"failed":         "9d877950800287bb2106905fad839a6b0854ca51cee9890facb66c48427f4778",
		"mixed-negative": "068745bdb5a5b3f225df66360c0e80f03c822aa755a898f2dd080788f4c4e3c3",
		"owner-scope":    "ebdd5437d0c232e52b31a663e4719352dcfb4b168c0d2c0f49d7532ea747be05",
		"compact":        "caaa62d48fff5f267268d1848dabecc7312443e0c0bf3e2b503923ee839b7f86",
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
			// Bind the shared script to its owner independently of the coverage HTML frame.
			beforeScript, scriptAndTail, starts := strings.Cut(html, "<script>")
			script, tail, ends := strings.Cut(scriptAndTail, "</script>")
			sum := sha256.Sum256([]byte(script))
			if !starts || !ends || "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'" != browserdoc.ScriptHashSource() {
				t.Fatal("coverage HTML did not embed the exact shared browser script")
			}
			frame := beforeScript + "<script></script>" + tail
			if got := relationObservationDigest(t, []any{view, code, markdown, frame}); got != frameWants[name] {
				t.Fatalf("coverage output frame digest = %s", got)
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
