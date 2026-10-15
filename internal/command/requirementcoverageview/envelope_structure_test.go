package requirementcoverageview

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestCoverageEnvelopeStructureConservesWholeProducerOutputs(t *testing.T) {
	views := coverageStructureCases(t)
	many := cloneCoverageJSONValue(views["structured/missing-inventory"]).(map[string]any)
	failures := make([]any, 30)
	for index := range failures {
		failures[index] = fmt.Sprintf("Missing caller-owned proof route %d.", index)
	}
	many["failures"] = failures
	views["blocker-limit"] = many
	for _, profile := range []string{cliexec.ProfilePath, cliexec.ProfileNPMOffline, cliexec.ProfilePythonModule} {
		python := ""
		if profile == cliexec.ProfilePythonModule {
			python = "/usr/bin/python3"
		}
		renderer, err := cliexec.AdmitLauncherProfile(profile, python)
		if err != nil {
			t.Fatal(err)
		}
		for name, view := range views {
			t.Run(profile+"/"+name, func(t *testing.T) {
				output := agentEnvelope(view, renderer)
				before, err := json.Marshal(output)
				if err != nil {
					t.Fatal(err)
				}
				if err := EnvelopeShape().CheckGenerated(output, "envelope"); err != nil {
					t.Fatal(err)
				}
				if err := schemacheck.Validate(EnvelopeStructure(), output); err != nil {
					t.Fatal(err)
				}
				wire, err := schemacheck.Normalize(output)
				if err != nil {
					t.Fatal(err)
				}
				admitted, err := EnvelopeShape().Admit(wire, "envelope")
				if err != nil || !reflect.DeepEqual(admitted, wire) {
					t.Fatalf("wire shape changed: %v", err)
				}
				after, err := json.Marshal(output)
				if err != nil || string(before) != string(after) {
					t.Fatal("structural description mutated the producer output")
				}
				if output["costContract"].(map[string]any)["maxTokenBudget"] != 2400 {
					t.Fatal("native coverage token budget changed")
				}
			})
		}
	}
}

func TestCoverageEnvelopeStructureRejectsIndependentNestedCorruption(t *testing.T) {
	view := coverageStructureCases(t)["structured/missing-inventory"]
	base := agentEnvelope(view, cliexec.PathRenderer())
	mutations := map[string]func(map[string]any){
		"action-element":   func(r map[string]any) { r["actionPlan"] = []any{0} },
		"action-field":     func(r map[string]any) { delete(r["actionPlan"].([]any)[0].(map[string]any), "instruction") },
		"action-reference": func(r map[string]any) { r["actionPlan"].([]any)[0].(map[string]any)["evidenceRefs"] = []any{0} },
		"empty-bounds":     func(r map[string]any) { r["bounds"] = map[string]any{} },
		"bounds-field":     func(r map[string]any) { delete(r["bounds"].(map[string]any), "maxActionItems") },
		"negative-bound":   func(r map[string]any) { r["bounds"].(map[string]any)["maxActionItems"] = -1 },
		"zero-budget":      func(r map[string]any) { r["bounds"].(map[string]any)["maxTokenBudget"] = 0 },
		"negative-budget":  func(r map[string]any) { r["bounds"].(map[string]any)["maxTokenBudget"] = -1 },
		"large-budget":     func(r map[string]any) { r["bounds"].(map[string]any)["maxTokenBudget"] = 1 << 20 },
		"primitive-source": func(r map[string]any) { r["sourceReport"] = 0 },
		"source-field":     func(r map[string]any) { delete(r["sourceReport"].(map[string]any), "state") },
		"primitive-cost":   func(r map[string]any) { r["costContract"] = 0 },
		"cost-field":       func(r map[string]any) { delete(r["costContract"].(map[string]any), "graphQueryCount") },
		"cost-budget":      func(r map[string]any) { r["costContract"].(map[string]any)["maxTokenBudget"] = nil },
		"context-field":    func(r map[string]any) { delete(r["contextRefs"].([]any)[0].(map[string]any), "refId") },
		"command-element":  func(r map[string]any) { r["commands"] = []any{0} },
		"command-field":    func(r map[string]any) { delete(r["commands"].([]any)[0].(map[string]any), "reason") },
		"question-field":   func(r map[string]any) { delete(r["routeQuestions"].([]any)[0].(map[string]any), "question") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wire, err := schemacheck.Normalize(base)
			if err != nil {
				t.Fatal(err)
			}
			record := wire.(map[string]any)
			mutate(record)
			if err := EnvelopeShape().CheckGenerated(record, "envelope"); err == nil {
				t.Fatal("native structural declaration accepted corruption")
			}
			if err := schemacheck.Validate(EnvelopeStructure(), record); err == nil {
				t.Fatal("published structural schema accepted corruption")
			}
		})
	}
}
