package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestBindingPathIdentityAgreesWithPublicOwner(t *testing.T) {
	const primary = "internal/tools/workflowsmoke/workflow_smoke_test.go"
	const scenario = "proofkit.spec-proof-core.source-conversion-installed-carrier"
	const supplement = "proofkit.test.canonical-supplement"
	root := filepath.Join("..", "..", "..")
	for _, tc := range []struct{ name, path, refusal, canonical string }{
		{"distinct", "AGENTS.md", "", "AGENTS.md"},
		{"exact", primary, "binding is duplicated", primary},
		{"trailing", primary + " ", "binding witness path must use canonical witness framing", primary},
		{"leading", " " + primary, "binding witness path must use canonical witness framing", primary},
		{"unicode-framing", primary + "\u2003", "binding witness path must use canonical witness framing", primary},
		{"dot", "./" + primary, "binding witness path ", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := readAnyJSON(filepath.Join(root, "proofkit", "requirement-bindings.json"))
			if err != nil {
				t.Fatal(err)
			}
			doc := raw.(map[string]any)
			rows := doc["bindings"].([]any)
			var extra map[string]any
			for _, row := range rows {
				binding := row.(map[string]any)
				if binding["scenarioId"] == scenario && binding["witnessPath"] == primary {
					extra = maps.Clone(binding)
					break
				}
			}
			if extra == nil {
				t.Fatal("the oracle did not identify its independently named primary")
			}
			extra["witnessId"], extra["witnessPath"] = supplement, tc.path
			delete(extra, "witnessSelectors")
			doc["bindings"] = append(rows, extra)
			wire, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			metricInput, err := admission.DecodeTypedJSON[bindingFile](bytes.NewReader(wire), int64(len(wire)))
			if err != nil {
				t.Fatal(err)
			}
			metricErr := validateBindingWitnessSelectorsAtRoot(root, metricInput)
			if tc.refusal == "" && metricErr != nil || tc.refusal != "" && (metricErr == nil || !strings.Contains(metricErr.Error(), tc.refusal)) {
				t.Fatalf("metric path identity: %v, expected %q", metricErr, tc.refusal)
			}
			publicInput, err := admission.DecodeJSON(bytes.NewReader(wire), int64(len(wire)))
			if err != nil {
				t.Fatal(err)
			}
			result, err := requirementbinding.Build(publicInput)
			if tc.canonical == "" {
				if err == nil {
					t.Fatal("public owner admitted a noncanonical dot path")
				}
				return
			}
			if err != nil || result.Record.State != "passed" {
				t.Fatalf("public owner control failed: %v", err)
			}
			matches := 0
			for _, binding := range result.Input.Bindings {
				if binding.WitnessID == supplement {
					matches++
					if binding.WitnessPath != tc.canonical {
						t.Fatal("public canonical path differs from the independent expected identity")
					}
				}
			}
			if matches != 1 {
				t.Fatal("canonical public supplement was absent or duplicated")
			}
		})
	}
}

func TestRequiredBindingAnchorWithSupplement(t *testing.T) {
	const requirement = "REQ-PROOFKIT-SPEC-044"
	const scenario = "proofkit.spec-proof-core.source-conversion-installed-carrier"
	const primaryPath = "internal/tools/workflowsmoke/workflow_smoke_test.go"
	root := filepath.Join("..", "..", "..")
	bindings, err := readJSON[bindingFile](filepath.Join(root, "proofkit", "requirement-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Put a real, separately selectable witness before the required carrier.
	extra := bindingSelectorFixture(scenario, "internal/app/requirement_source_conversion_command_test.go", "TestRequirementSourceConversionCLI")
	extra.RequirementID, extra.WitnessID = requirement, "proofkit.test.cli-supplement"
	extra.CommandIDs, extra.EnvironmentClasses = []string{"proofkit.go-test"}, []string{"local-go"}
	bindings.Bindings = append([]bindingScenario{extra}, bindings.Bindings...)
	primary := slices.IndexFunc(bindings.Bindings, func(b bindingScenario) bool {
		return b.RequirementID == requirement && b.ScenarioID == scenario && b.WitnessPath == primaryPath
	})
	if primary < 0 {
		t.Fatal("missing installed-carrier test seed")
	}
	if err := validateBindingWitnessSelectorsAtRoot(root, bindings); err != nil {
		t.Fatalf("supplement before required carrier: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*bindingFile)
		want   string
	}{
		{"lexical-primary-alias", func(b *bindingFile) {
			alias := b.Bindings[primary]
			alias.WitnessID = "proofkit.test.lexical-copy"
			alias.WitnessPath = "./" + alias.WitnessPath
			b.Bindings = append(b.Bindings, alias)
		}, "binding witness path "},
		{"remove-primary", func(b *bindingFile) {
			b.Bindings = slices.Delete(b.Bindings, primary, primary+1)
		}, "required independent-falsifier binding is missing: " + requirement + "/" + scenario + " (want exact witness path \"" + primaryPath + "\")"},
		{"duplicate-primary-path", func(b *bindingFile) {
			duplicate := b.Bindings[primary]
			duplicate.WitnessID = "proofkit.test.another-carrier"
			b.Bindings = append(b.Bindings, duplicate)
		}, "required independent-falsifier binding is duplicated: " + requirement + "/" + scenario},
		{"primary-selector", func(b *bindingFile) {
			b.Bindings[primary].WitnessSelectors = b.Bindings[primary].WitnessSelectors[:1]
		}, "binding " + scenario + " witness selectors="},
		{"primary-command-ids", func(b *bindingFile) {
			b.Bindings[primary].CommandIDs = extra.CommandIDs
		}, "binding " + scenario + " commandIds="},
		{"primary-environment", func(b *bindingFile) {
			b.Bindings[primary].EnvironmentClasses = extra.EnvironmentClasses
		}, "binding " + scenario + " environmentClasses="},
		{"supplement-wrong-command", func(b *bindingFile) {
			b.Bindings[0].WitnessSelectors[0].Command = b.Bindings[primary].WitnessSelectors[0].Command
		}, "binding " + scenario + " selector command="},
		{"supplement-wrong-selector", func(b *bindingFile) {
			b.Bindings[0].WitnessSelectors = bindingSelectorFixture(scenario, extra.WitnessPath, "TestMissingSupplement").WitnessSelectors
		}, "binding " + scenario + " selector TestMissingSupplement is missing from " + extra.WitnessPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneBindingFile(bindings)
			tc.mutate(&candidate)
			if err := validateBindingWitnessSelectorsAtRoot(root, candidate); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
