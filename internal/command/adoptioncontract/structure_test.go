package adoptioncontract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/pilotadmission"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

type structureInputVariant struct {
	id      string
	schema  map[string]any
	options []Options
}

// The variant partition is independent of the generator registry: it is
// derived from ValidateOptions and the delegation switch in Build.
func structureInputVariants() []structureInputVariant {
	variants := []structureInputVariant{
		{"adoption", AdoptionInputStructure(), []Options{{Mode: "adoption"}}},
		{"bootstrap", BootstrapInputStructure(), []Options{{Mode: "bootstrap"}, {Mode: "bootstrap", AgentEnvelope: true}, {Mode: "bootstrap", MaterializationManifest: true}}},
	}
	for mask := range 8 {
		guidance := gradualadoption.GuidanceOptions{}
		if mask&1 != 0 {
			guidance.GuidanceMode = "observe"
		}
		if mask&2 != 0 {
			guidance.CheckedScope = "none"
		}
		if mask&4 != 0 {
			guidance.CheckedScope, guidance.TouchedRuleIDs = "touched", []string{"proofkit.test.rule"}
			if mask&2 == 0 {
				guidance.CheckedScope = ""
			}
		}
		variants = append(variants, structureInputVariant{fmt.Sprintf("guidance-%03b", mask), GuidanceInputStructure(mask&1 != 0, mask&2 != 0, mask&4 != 0), []Options{
			{Mode: "guidance", Guidance: guidance}, {Mode: "guidance", Guidance: guidance, AgentEnvelope: true},
		}})
	}
	return append(variants,
		structureInputVariant{"pilot-all", PilotInputStructure("all"), []Options{{Mode: "pilot", Pilot: "all"}}},
		structureInputVariant{"pilot-first", PilotInputStructure("first"), []Options{{Mode: "pilot", Pilot: "first"}, {Mode: "pilot"}}},
		structureInputVariant{"pilot-stack-diverse", PilotInputStructure("stack-diverse"), []Options{{Mode: "pilot", Pilot: "stack-diverse"}}},
		structureInputVariant{"workflow", WorkflowInputStructure(), []Options{{Mode: "workflow"}, {Mode: "workflow", AgentEnvelope: true}}},
	)
}

func refused(output any, err error) bool {
	if err != nil {
		return true
	}
	record, ok := output.(map[string]any)
	return ok && record["envelopeId"] == "proofkit.agent-envelope.invalid-input"
}

func at(input map[string]any, path ...string) map[string]any {
	current := input
	for _, key := range path {
		current = current[key].(map[string]any)
	}
	return current
}

func structureAggregateCorpus() map[string]func(map[string]any) {
	corpus := map[string]func(map[string]any){
		"valid":                  func(map[string]any) {},
		"root-foreign":           func(input map[string]any) { input["foreign"] = true },
		"root-header":            func(input map[string]any) { input["schema"] = "proofkit.adoption-contract-envelope.v1" },
		"envelope-id":            func(input map[string]any) { input["envelopeId"] = "bad id" },
		"envelope-id-limit":      func(input map[string]any) { input["envelopeId"] = strings.Repeat("A", 256) },
		"envelope-id-bound":      func(input map[string]any) { input["envelopeId"] = strings.Repeat("A", 257) },
		"envelope-id-missing":    func(input map[string]any) { delete(input, "envelopeId") },
		"claims-empty":           func(input map[string]any) { input["nonClaims"] = []any{} },
		"claims-missing":         func(input map[string]any) { delete(input, "nonClaims") },
		"claims-duplicate":       func(input map[string]any) { input["nonClaims"] = []any{"same", "same"} },
		"claims-blank":           func(input map[string]any) { input["nonClaims"] = []any{"\t"} },
		"claims-unsorted":        func(input map[string]any) { input["nonClaims"] = []any{"zulu", "alpha"} },
		"workflow-foreign":       func(input map[string]any) { at(input, "workflow")["foreign"] = map[string]any{} },
		"workflow-header":        func(input map[string]any) { at(input, "workflow")["schema"] = "proofkit.adoption-workflow.v2" },
		"workflow-child-type":    func(input map[string]any) { at(input, "workflow")["workflow"] = []any{} },
		"workflow-child-empty":   func(input map[string]any) { at(input, "workflow")["workflow"] = map[string]any{} },
		"workflow-child-blocked": func(input map[string]any) { at(input, "workflow", "workflow")["inputRefs"] = []any{} },
		"workflow-scenario":      func(input map[string]any) { at(input, "workflow", "workflow")["scenario"] = "unknown_scenario" },
		"gradual-foreign":        func(input map[string]any) { at(input, "gradual")["foreign"] = map[string]any{} },
		"gradual-header":         func(input map[string]any) { at(input, "gradual")["schema"] = "proofkit.gradual-adoption-profile.v2" },
		"gradual-input-type":     func(input map[string]any) { at(input, "gradual")["input"] = "x" },
		"gradual-input-empty":    func(input map[string]any) { at(input, "gradual")["input"] = map[string]any{} },
		"gradual-input-id":       func(input map[string]any) { at(input, "gradual", "input")["adoptionId"] = "bad id" },
		"gradual-input-failed": func(input map[string]any) {
			at(input, "gradual", "input", "budget")["profileLines"] = json.Number("99")
		},
		"gradual-bootstrap-type": func(input map[string]any) { at(input, "gradual")["bootstrap"] = nil },
		"gradual-bootstrap-open": func(input map[string]any) { at(input, "gradual")["bootstrap"] = map[string]any{"foreign": true} },
		"gradual-guidance-type":  func(input map[string]any) { at(input, "gradual")["guidance"] = []any{} },
		"gradual-guidance-open":  func(input map[string]any) { at(input, "gradual")["guidance"] = map[string]any{"foreign": true} },
		"guidance-mode-absent":   func(input map[string]any) { delete(at(input, "gradual", "guidance"), "defaultMode") },
		"guidance-mode-foreign":  func(input map[string]any) { at(input, "gradual", "guidance")["defaultMode"] = 7 },
		"guidance-scope-absent":  func(input map[string]any) { delete(at(input, "gradual", "guidance", "scopeEvidence"), "checkedScope") },
		"guidance-ids-absent": func(input map[string]any) {
			delete(at(input, "gradual", "guidance", "scopeEvidence"), "touchedRuleIds")
		},
		"pilot-foreign":        func(input map[string]any) { at(input, "pilot")["foreign"] = map[string]any{} },
		"pilot-header":         func(input map[string]any) { at(input, "pilot")["schema"] = "proofkit.pilot-admission.v1" },
		"pilot-input-type":     func(input map[string]any) { at(input, "pilot")["input"] = 1 },
		"pilot-input-empty":    func(input map[string]any) { at(input, "pilot")["input"] = map[string]any{} },
		"pilot-stack-empty":    func(input map[string]any) { at(input, "pilot")["stackDiverseInput"] = map[string]any{} },
		"pilot-input-rollback": func(input map[string]any) { at(input, "pilot", "input", "rollback")["foreign"] = true },
		"pilot-stack-failed":   func(input map[string]any) { at(input, "pilot", "stackDiverseInput")["pilotMode"] = "blocking" },
		"pilot-input-failed":   func(input map[string]any) { at(input, "pilot", "input")["rolloutClaim"] = true },
		"pilot-input-demo-ref": func(input map[string]any) {
			at(input, "pilot", "input")["impactDemos"] = []any{map[string]any{"demoId": "bad id"}}
		},
	}
	for _, field := range []string{"workflow", "gradual", "pilot"} {
		corpus["missing-"+field] = func(input map[string]any) { delete(input, field) }
		corpus["type-"+field] = func(input map[string]any) { input[field] = []any{} }
	}
	return corpus
}

func TestAggregateInputVariantsAgreeWithEveryDelegatedAdmission(t *testing.T) {
	for _, variant := range structureInputVariants() {
		for name, mutate := range structureAggregateCorpus() {
			input := validAggregateEnvelope()
			mutate(input)
			structural := schemacheck.Validate(variant.schema, input)
			for _, options := range variant.options {
				output, _, err := Build(input, options)
				if (structural == nil) == refused(output, err) {
					t.Fatalf("%s/%s/%+v: structure=%v native=%v", variant.id, name, options, structural, err)
				}
			}
		}
	}
}

func TestAggregateInputVariantsArePairwiseDistinguishedByDelegation(t *testing.T) {
	// Each selected child path is admitted only by its own mode.
	cases := map[string]string{
		"workflow-child-empty": "workflow", "gradual-input-empty": "adoption bootstrap guidance-000 guidance-001 guidance-010 guidance-011 guidance-100 guidance-101 guidance-110 guidance-111",
		"pilot-input-empty": "pilot-all pilot-first", "pilot-stack-empty": "pilot-all pilot-stack-diverse",
	}
	for name, refusing := range cases {
		input := validAggregateEnvelope()
		structureAggregateCorpus()[name](input)
		for _, variant := range structureInputVariants() {
			want := strings.Contains(" "+refusing+" ", " "+variant.id+" ")
			if got := schemacheck.Validate(variant.schema, input) != nil; got != want {
				t.Fatalf("%s/%s refused=%t want %t", name, variant.id, got, want)
			}
		}
	}
}

func aggregateOutputStructure(options Options) map[string]any {
	switch {
	case options.Mode == "adoption":
		return gradualadoption.OutputStructure()
	case options.Mode == "bootstrap" && options.AgentEnvelope:
		return AgentOutputStructure("bootstrap")
	case options.Mode == "bootstrap" && options.MaterializationManifest:
		return gradualadoption.BootstrapMaterializationStructure()
	case options.Mode == "bootstrap":
		return gradualadoption.BootstrapOutputStructure()
	case options.Mode == "guidance" && options.AgentEnvelope:
		return AgentOutputStructure("guidance")
	case options.Mode == "guidance":
		return gradualadoption.GuidanceOutputStructure()
	case options.Mode == "pilot" && options.Pilot == "all":
		return pilotadmission.AllOutputStructure()
	case options.Mode == "pilot":
		return pilotadmission.ReportStructure()
	case options.Mode == "workflow" && options.AgentEnvelope:
		return AgentOutputStructure("workflow")
	default:
		return adoptionworkflow.OutputStructure()
	}
}

func TestAggregateOutputVariantsAcceptEveryEmittedCarrier(t *testing.T) {
	exits := map[string]map[int]bool{}
	for _, variant := range structureInputVariants() {
		for name, mutate := range structureAggregateCorpus() {
			input := validAggregateEnvelope()
			mutate(input)
			for _, options := range variant.options {
				output, code, err := Build(input, options)
				if err != nil {
					continue
				}
				key := fmt.Sprintf("%s/%t/%t/%s", options.Mode, options.AgentEnvelope, options.MaterializationManifest, options.Pilot)
				if exits[key] == nil {
					exits[key] = map[int]bool{}
				}
				exits[key][code] = true
				if err := schemacheck.Validate(aggregateOutputStructure(options), output); err != nil {
					t.Fatalf("%s/%s/%s: %v", variant.id, name, key, err)
				}
			}
		}
	}
	for key, codes := range exits {
		if !codes[0] || !codes[1] {
			t.Fatalf("%s did not reach both exit outcomes: %v", key, codes)
		}
	}
	if len(exits) != 12 {
		t.Fatalf("output option cases=%d want the 12 closed flag conditions", len(exits))
	}
}

func TestAggregateAgentSumsAreExclusive(t *testing.T) {
	for _, mode := range []string{"bootstrap", "guidance", "workflow"} {
		schema := AgentOutputStructure(mode)
		alternatives := schema["oneOf"].([]any)
		if len(alternatives) != 2 {
			t.Fatalf("%s agent sum lost an alternative", mode)
		}
		input := validAggregateEnvelope()
		output, _, err := Build(input, Options{Mode: mode, AgentEnvelope: true})
		repair, _, repairErr := Build(map[string]any{"schema": aggregateEnvelopeSchema}, Options{Mode: mode, AgentEnvelope: true})
		if err != nil || repairErr == nil || repair != nil {
			t.Fatal("aggregate admission errors must stay errors for the CLI repair writer")
		}
		delete(at(input, "gradual", "input"), "budget")
		delete(at(input, "workflow", "workflow"), "scenario")
		childRepair, _, childErr := Build(input, Options{Mode: mode, AgentEnvelope: true})
		if childErr != nil || !refused(childRepair, nil) {
			t.Fatalf("%s child refusal did not become a repair envelope: %v", mode, childErr)
		}
		for index, value := range []any{output, childRepair} {
			if schemacheck.Validate(alternatives[index].(map[string]any), value) != nil || schemacheck.Validate(alternatives[1-index].(map[string]any), value) == nil {
				t.Fatalf("%s value %d is not matched by exactly its own alternative", mode, index)
			}
		}
	}
}
