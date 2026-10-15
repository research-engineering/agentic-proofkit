package migrationplan

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func migrationWire(t *testing.T, value any) any {
	t.Helper()
	data, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := admission.DecodeJSON(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// structuralAdmission applies the projected shape and its published grammar refinement.
func structuralAdmission(wire any) error {
	if _, err := InputShape().Admit(wire, "migration plan structure"); err != nil {
		return err
	}
	for _, raw := range wire.(map[string]any)["retainedOwners"].([]any) {
		if _, err := TrimmedRuleIDBoundShape().Admit(raw, "retained owner bound"); err != nil {
			return err
		}
	}
	return nil
}

func blockedMigrationInput() map[string]any {
	input := validMigrationPlanInput()
	input["sourceProofOwners"] = append(input["sourceProofOwners"].([]any), map[string]any{
		"ownerId": "kept.owner", "ownerKind": "local_test", "path": "tests/kept.go", "retirementPolicy": "retain",
	})
	input["retainedOwners"] = []any{"ghost.owner", "old.owner"}
	input["parityEvidenceRefs"] = append(input["parityEvidenceRefs"].([]any), map[string]any{
		"evidenceId": "proofkit.parity.ghost", "evidenceRef": "artifacts/ghost.json", "nonClaim": "Ghost parity.",
		"sourceOwnerId": "ghost.source", "targetId": "ghost.target",
	})
	input["retirementCandidates"] = append(input["retirementCandidates"].([]any),
		map[string]any{"ownerId": "kept.owner", "reason": "Retained owner.", "removalRef": "tests/kept.go"},
		map[string]any{"ownerId": "unknown.owner", "reason": "Unknown owner.", "removalRef": "docs/unknown.json"})
	input["followUpCommands"] = []any{}
	return input
}

func TestOutputStructureCoversReadyAndBlockedPlans(t *testing.T) {
	ready := validMigrationPlanInput()
	readyWithoutCandidates := validMigrationPlanInput()
	readyWithoutCandidates["retirementCandidates"] = []any{}
	readyWithoutCandidates["parityEvidenceRefs"] = []any{}
	readyWithoutCandidates["followUpCommands"] = []any{}
	readyWithoutCandidates["nonClaims"] = []any{migrationNonClaims[0]}
	seenReasons := map[string]bool{}
	for _, row := range []struct {
		name  string
		input map[string]any
		state string
		code  int
	}{
		{"ready", ready, planStateReady, 0}, {"ready-empty", readyWithoutCandidates, planStateReady, 0},
		{"blocked", blockedMigrationInput(), planStateBlocked, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			output, code, err := Build(migrationWire(t, row.input))
			if err != nil || code != row.code || output["planState"] != row.state {
				t.Fatalf("native state changed: code=%d err=%v state=%v", code, err, output["planState"])
			}
			if err := OutputShape().CheckGenerated(output, "migration plan"); err != nil {
				t.Fatal(err)
			}
			wire := migrationWire(t, output).(map[string]any)
			if _, err := OutputShape().Admit(wire, "migration plan wire"); err != nil {
				t.Fatal(err)
			}
			for _, claim := range migrationNonClaims {
				if !slices.Contains(wire["nonClaims"].([]any), any(claim)) {
					t.Fatalf("builtin nonClaim omitted: %s", claim)
				}
			}
			for _, raw := range wire["blockers"].([]any) {
				seenReasons[raw.(map[string]any)["reason"].(string)] = true
			}
			for _, key := range slices.Sorted(maps.Keys(wire)) {
				missing := maps.Clone(wire)
				delete(missing, key)
				if _, err := OutputShape().Admit(missing, "migration plan"); err == nil {
					t.Fatalf("missing %s admitted", key)
				}
			}
			foreign := maps.Clone(wire)
			foreign["foreign"] = true
			if _, err := OutputShape().Admit(foreign, "migration plan"); err == nil {
				t.Fatal("foreign root field admitted")
			}
			swapped := maps.Clone(wire)
			swapped["planState"] = map[string]string{planStateReady: planStateBlocked, planStateBlocked: planStateReady}[row.state]
			if _, err := OutputShape().Admit(swapped, "migration plan"); err == nil {
				t.Fatal("plan state became independent of blockers")
			}
		})
	}
	for _, rule := range blockerRules {
		if !seenReasons[rule.reason] {
			t.Fatalf("blocker branch is unreachable by the fixture corpus: %s", rule.reason)
		}
	}
}

func TestOutputStructureBindsNativeVocabularies(t *testing.T) {
	schema := OutputStructure()
	branches := schema["oneOf"].([]any)
	if len(branches) != 2 || len(schema) != 2 {
		t.Fatalf("plan sum changed: %v", slices.Sorted(maps.Keys(schema)))
	}
	for _, raw := range branches {
		branch := raw.(map[string]any)
		claims := branch["properties"].(map[string]any)["nonClaims"].(map[string]any)
		if len(claims["allOf"].([]any)) != len(migrationNonClaims) || claims["minItems"] != len(migrationNonClaims) {
			t.Fatal("builtin nonClaims refinement drifted")
		}
		phases := branch["properties"].(map[string]any)["phases"].(map[string]any)["prefixItems"].([]any)
		for index, phase := range phaseOrder {
			if phases[index].(map[string]any)["properties"].(map[string]any)["phase"].(map[string]any)["const"] != phase {
				t.Fatalf("phase order drifted at %d", index)
			}
		}
	}
	input := InputStructure()
	retained := input["properties"].(map[string]any)["retainedOwners"].(map[string]any)["items"].(map[string]any)
	if !reflect.DeepEqual(retained["allOf"], []any{map[string]any{"pattern": TrimmedRuleIDBoundShape().JSONSchema()["pattern"]}}) {
		t.Fatal("retained owner bound refinement drifted")
	}
	plain := InputShape().JSONSchema()
	delete(retained, "allOf")
	delete(input, "description")
	if !reflect.DeepEqual(input, plain) {
		t.Fatal("published input structure is not the native shape projection")
	}
}

func TestInputStructureAgreesWithNativeAdmission(t *testing.T) {
	type mutation struct {
		name   string
		mutate func(map[string]any)
		// nativeOnly marks semantic predicates the structure names but cannot express.
		accepted, nativeOnly bool
	}
	at := func(input map[string]any, field string, index int) map[string]any {
		return input[field].([]any)[index].(map[string]any)
	}
	set := func(field string, value any) func(map[string]any) {
		return func(input map[string]any) { input[field] = value }
	}
	setItem := func(field, key string, value any) func(map[string]any) {
		return func(input map[string]any) { at(input, field, 0)[key] = value }
	}
	cases := []mutation{
		{name: "valid", mutate: func(map[string]any) {}, accepted: true},
		{name: "foreign root", mutate: set("foreign", true)},
		{name: "version two", mutate: set("schemaVersion", json.Number("2"))},
		{name: "version decimal", mutate: set("schemaVersion", json.Number("1.0"))},
		{name: "version text", mutate: set("schemaVersion", "1")},
		{name: "migration id grammar", mutate: set("migrationId", "1bad")},
		{name: "migration id padded", mutate: set("migrationId", " proofkit.migration")},
		{name: "migration id 256", mutate: set("migrationId", "a"+strings.Repeat("b", 255)), accepted: true},
		{name: "migration id 257", mutate: set("migrationId", "a"+strings.Repeat("b", 256))},
		{name: "migration id timestamp", mutate: set("migrationId", "proofkit.2026-01-01"), nativeOnly: true},
		{name: "empty owners", mutate: set("sourceProofOwners", []any{})},
		{name: "empty targets", mutate: set("targetProofkitRefs", []any{})},
		{name: "empty optional records", mutate: func(input map[string]any) {
			for _, field := range []string{"parityEvidenceRefs", "retirementCandidates", "retainedOwners", "followUpCommands", "nonClaims"} {
				input[field] = []any{}
			}
		}, accepted: true},
		{name: "owner kind", mutate: setItem("sourceProofOwners", "ownerKind", "foreign")},
		{name: "owner kind other", mutate: setItem("sourceProofOwners", "ownerKind", "other"), accepted: true},
		{name: "retirement policy", mutate: setItem("sourceProofOwners", "retirementPolicy", "Retain")},
		{name: "owner foreign", mutate: setItem("sourceProofOwners", "foreign", true)},
		{name: "owner path blank", mutate: setItem("sourceProofOwners", "path", " \u2003")},
		{name: "owner path padded", mutate: setItem("sourceProofOwners", "path", " docs/old.json\t"), accepted: true},
		{name: "owner path escape", mutate: setItem("sourceProofOwners", "path", "../old.json"), nativeOnly: true},
		{name: "target kind", mutate: setItem("targetProofkitRefs", "targetKind", "proofkit_receipt")},
		{name: "target id null", mutate: setItem("targetProofkitRefs", "targetId", nil)},
		{name: "parity nonClaim number", mutate: setItem("parityEvidenceRefs", "nonClaim", json.Number("1"))},
		{name: "candidate reason secret", mutate: setItem("retirementCandidates", "reason", "Authorization: Bearer abcdefghijklmnop"), nativeOnly: true},
		{name: "command owner", mutate: setItem("followUpCommands", "owner", "proofkit")},
		{name: "command phase", mutate: setItem("followUpCommands", "phase", "rollout")},
		{name: "command shell control", mutate: setItem("followUpCommands", "command", "go test ./... && curl example.test"), nativeOnly: true},
		{name: "duplicate commands", mutate: func(input map[string]any) {
			input["followUpCommands"] = append(input["followUpCommands"].([]any), maps.Clone(at(input, "followUpCommands", 0)))
		}, nativeOnly: true},
		{name: "retained padded", mutate: set("retainedOwners", []any{" \u00a0old.owner\t"}), accepted: true},
		{name: "retained 256 core", mutate: set("retainedOwners", []any{" a" + strings.Repeat("b", 255) + " "}), accepted: true},
		{name: "retained 257 core", mutate: set("retainedOwners", []any{" a" + strings.Repeat("b", 256) + " "})},
		{name: "retained duplicate", mutate: set("retainedOwners", []any{"old.owner", " old.owner"}), nativeOnly: true},
		{name: "retained grammar", mutate: set("retainedOwners", []any{"old owner"})},
		{name: "nonClaims blank", mutate: set("nonClaims", []any{"  "})},
		{name: "nonClaims null", mutate: set("nonClaims", nil)},
	}
	for _, key := range inputKeys {
		cases = append(cases, mutation{name: "missing " + key, mutate: func(input map[string]any) { delete(input, key) }})
	}
	for field, keys := range map[string][]string{
		"sourceProofOwners": sourceOwnerKeys, "targetProofkitRefs": targetRefKeys, "parityEvidenceRefs": parityEvidenceKeys,
		"retirementCandidates": retirementCandidateKeys, "followUpCommands": followUpCommandKeys,
	} {
		for _, key := range keys {
			cases = append(cases, mutation{name: field + " missing " + key, mutate: func(input map[string]any) { delete(at(input, field, 0), key) }})
		}
		cases = append(cases, mutation{name: field + " item null", mutate: func(input map[string]any) { input[field].([]any)[0] = nil }})
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validMigrationPlanInput()
			item.mutate(input)
			wire := migrationWire(t, input)
			_, nativeErr := admitInput(wire)
			structuralErr := structuralAdmission(wire)
			if (nativeErr == nil) != item.accepted {
				t.Fatalf("native admission=%v want accepted=%v", nativeErr, item.accepted)
			}
			if item.nativeOnly {
				if structuralErr != nil {
					t.Fatalf("structure refused a native-only predicate: %v", structuralErr)
				}
				return
			}
			if (structuralErr == nil) != item.accepted {
				t.Fatalf("structure=%v native=%v", structuralErr, nativeErr)
			}
		})
	}
}
