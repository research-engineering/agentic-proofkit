package main

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestCompactIndependentSchemaWitnessIsRequired(t *testing.T) {
	bindings, err := readJSON[bindingFile](filepath.Join("..", "..", "..", "proofkit", "requirement-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(bindings.Bindings, func(row bindingScenario) bool {
		return row.ScenarioID == "proofkit.supply-chain-quality.compact-schema-independent-runtime"
	})
	if index < 0 {
		t.Fatal("independent schema witness missing")
	}
	if err := validateRequiredBindingWitnessSelectors(bindings); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"missing", "path", "command", "environment", "owner", "selector"} {
		t.Run(mutation, func(t *testing.T) {
			candidate := cloneBindingFile(bindings)
			row := &candidate.Bindings[index]
			switch mutation {
			case "missing":
				candidate.Bindings = append(candidate.Bindings[:index], candidate.Bindings[index+1:]...)
			case "path":
				row.WitnessPath = "scripts/stable-json.test.mjs"
			case "command":
				row.CommandIDs = []string{"proofkit.go-test"}
			case "environment":
				row.EnvironmentClasses = []string{"local-go"}
			case "owner":
				row.RequirementID = "REQ-PROOFKIT-QUALITY-009"
			case "selector":
				row.WitnessSelectors = []witnessSelector{{Selector: "invented"}}
			}
			if validateRequiredBindingWitnessSelectors(candidate) == nil {
				t.Fatal("independent witness drift admitted")
			}
		})
	}
}
