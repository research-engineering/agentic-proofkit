package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

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
