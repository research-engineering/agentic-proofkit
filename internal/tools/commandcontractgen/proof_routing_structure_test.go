package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/obligationdecision"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/selectivegateevidence"
	"github.com/research-engineering/agentic-proofkit/internal/command/selectivegateplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

func TestProofRoutingStructuresBindOwnersAndRejectRehashedDrift(t *testing.T) {
	rows := []struct {
		command, direction, version string
		projections                 []func() map[string]any
	}{
		{"requirement-bindings", "output", "1", []func() map[string]any{requirementbinding.ReportOutputStructure}},
		{"evidence-graph", "output", "1", []func() map[string]any{requirementbinding.EvidenceGraphOutputStructure}},
		{"proof-slice", "output", "1", []func() map[string]any{requirementbinding.ProofSliceOutputStructure}},
		{"requirement-proof-resolver", "output", "2", []func() map[string]any{compactproofcontract.ResolverOutputStructure}},
		{"witness-plan", "input", "1", []func() map[string]any{witnessplan.DirectInputStructure, witnessplan.ProjectedInputStructure}},
		{"witness-plan", "output", "1", []func() map[string]any{witnessplan.OutputStructure}},
		{"witness-scheduler-plan", "input", "1", []func() map[string]any{witnessschedulerplan.InputStructure}},
		{"witness-scheduler-plan", "output", "1", []func() map[string]any{witnessschedulerplan.OutputStructure}},
		{"selective-gate-plan", "input", "1", []func() map[string]any{selectivegateplan.InputStructure}},
		{"selective-gate-plan", "output", "1", []func() map[string]any{selectivegateplan.EnvelopeStructure, agentenvelope.InvalidInputStructure, selectivegateplan.OutputStructure}},
		{"selective-gate-evidence", "input", "1", []func() map[string]any{selectivegateevidence.InputStructure}},
		{"selective-gate-evidence", "output", "1", []func() map[string]any{selectivegateevidence.EnvelopeStructure, agentenvelope.InvalidInputStructure, selectivegateevidence.OutputStructure}},
		{"selective-gate-obligation-decision-input", "input", "1", []func() map[string]any{selectivegateevidence.ProjectionInputStructure}},
		{"selective-gate-obligation-decision-input", "output", "1", []func() map[string]any{obligationdecision.InputStructure}},
		{"obligation-decision", "input", "1", []func() map[string]any{obligationdecision.InputStructure}},
		{"obligation-decision", "output", "1", []func() map[string]any{obligationdecision.EnvelopeStructure, agentenvelope.InvalidInputStructure, obligationdecision.OutputStructure}},
	}
	for _, row := range rows {
		prefix := "proofkit." + row.command + "." + row.direction + ".v" + row.version
		t.Run(prefix, func(t *testing.T) {
			owner, ok := nativeStructureOwner(prefix + ".json-schema")
			if !ok || owner.direction != row.direction || !slices.Equal(owner.commands, []string{row.command}) || !slices.Equal(owner.predecessors, []string{prefix + ".root-shape"}) {
				t.Fatal("missing or incorrect exact direction owner")
			}
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
			if len(variants) != len(row.projections) {
				t.Fatal("variant partition differs")
			}
			for i, projection := range row.projections {
				actual := variants[i].(map[string]any)["schema"]
				if !reflect.DeepEqual(actual, projection()) {
					t.Fatal("registered schema differs from owner")
				}
				before, err := canonicalJSON(projection())
				if err != nil {
					t.Fatal(err)
				}
				restore := mutateStructureContainers(actual.(map[string]any))
				after, err := canonicalJSON(projection())
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("schema aliases returned mutable containers")
				}
				restore()
			}
			version, err := owner.contractVersion(definition)
			if err != nil || version != json.Number(row.version) {
				t.Fatalf("version=%s err=%v", version, err)
			}
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err != nil {
				t.Fatal(err)
			}
			variants[0].(map[string]any)["schema"].(map[string]any)["additionalProperties"] = true
			delete(definition, "canonicalDigest")
			encoded, err := canonicalJSON(definition)
			if err != nil {
				t.Fatal(err)
			}
			definition["canonicalDigest"] = sha256Digest(encoded)
			if _, err := admitDefinitions(map[string]any{"contractDefinitions": []any{definition}}); err == nil {
				t.Fatal("rehashed caller structure was admitted")
			}
		})
	}
}

func TestOptionalInputVersionPreservesRequiredFieldPartition(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.witness-plan.input.v1.json-schema")
	if !ok {
		t.Fatal("missing owner")
	}
	definition, err := owner.definition()
	if err != nil {
		t.Fatal(err)
	}
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	for i, expected := range [][]any{{"commands", "vocabulary"}, {"projection", "requirementProofBinding", "schemaVersion", "vocabulary"}} {
		if !reflect.DeepEqual(variants[i].(map[string]any)["requiredFields"], expected) {
			t.Fatalf("variant %d invented or omitted required fields", i)
		}
	}
	for _, mutate := range []func(*nativeStructure){
		func(o *nativeStructure) { o.optionalInputVersion = false },
		func(o *nativeStructure) { o.direction = "output" },
		func(o *nativeStructure) { o.wireVersion = "1" },
		func(o *nativeStructure) { o.outOfBandVersion = "1" },
	} {
		bad := owner
		mutate(&bad)
		if _, err := bad.definition(); err == nil {
			t.Fatal("invalid optional-version policy passed")
		}
	}
	for _, mutation := range []func(map[string]any){
		func(s map[string]any) { delete(s["properties"].(map[string]any), "schemaVersion") },
		func(s map[string]any) {
			s["properties"].(map[string]any)["schemaVersion"] = map[string]any{"type": "integer", "const": json.Number("2")}
		},
	} {
		copy := cloneRecord(definition)
		value, err := canonicalJSON(copy)
		if err != nil {
			t.Fatal(err)
		}
		var bad map[string]any
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.UseNumber()
		if err := decoder.Decode(&bad); err != nil {
			t.Fatal(err)
		}
		schema := bad["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)["schema"].(map[string]any)
		mutation(schema)
		if _, err := owner.contractVersion(bad); err == nil {
			t.Fatal("missing or inconsistent optional version accepted")
		}
	}
}
