package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestRootDistinctOutputWitnessBindingsAreExact(t *testing.T) {
	contract := readCLIContract(t)
	bindings := readRootDistinctOutputBindings(t)
	if err := validateRootDistinctOutputWitnessBindings(contract, bindings); err != nil {
		t.Fatalf("current root-distinct output witness inventory is invalid: %v", err)
	}

	mutants := []struct {
		name   string
		mutate func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile)
	}{
		{
			name: "empty",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				for index := range bindings.Bindings {
					selectors := make([]rootDistinctOutputWitnessSelector, 0, len(bindings.Bindings[index].WitnessSelectors))
					for _, selector := range bindings.Bindings[index].WitnessSelectors {
						if !isRootDistinctOutputSelector(selector.Selector) {
							selectors = append(selectors, selector)
						}
					}
					bindings.Bindings[index].WitnessSelectors = selectors
				}
			},
		},
		{
			name: "missing",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				binding := rootDistinctBindingForMutation(t, bindings, "proofkit.package-boundary.cli-output-root-witnesses")
				binding.WitnessSelectors = binding.WitnessSelectors[:len(binding.WitnessSelectors)-1]
			},
		},
		{
			name: "surplus",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				binding := rootDistinctBindingForMutation(t, bindings, "proofkit.package-boundary.cli-output-root-witnesses")
				binding.WitnessSelectors = append(binding.WitnessSelectors, binding.WitnessSelectors[0])
			},
		},
		{
			name: "selector-substitution",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				output := rootDistinctOutputContractForMutation(t, contract, "adoption-contract-envelope")
				output["nativeOutputWitnessSelector"].(map[string]any)["test"] = "TestSelfCheckOutputUsesExactRootShape"
			},
		},
		{
			name: "source-missing",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				output := rootDistinctOutputContractForMutation(t, contract, "pilot-admission")
				sources := output["nativeSources"].([]any)
				output["nativeSources"] = sources[1:]
			},
		},
		{
			name: "source-surplus",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				output := rootDistinctOutputContractForMutation(t, contract, "pilot-admission")
				output["nativeSources"] = append(output["nativeSources"].([]any), map[string]any{
					"path":            "internal/command/stackpreset",
					"canonicalDigest": "sha256:" + strings.Repeat("a", 64),
					"evidenceClass":   "source_checkout",
				})
			},
		},
		{
			name: "source-substitution",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				output := rootDistinctOutputContractForMutation(t, contract, "pilot-admission")
				output["nativeSources"].([]any)[0].(map[string]any)["path"] = "internal/kernel/admission"
			},
		},
		{
			name: "native-source-form-downgrade",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				output := rootDistinctOutputContractForMutation(t, contract, "pilot-admission")
				sources := output["nativeSources"].([]any)
				output["nativeSource"] = sources[len(sources)-1]
				delete(output, "nativeSources")
			},
		},
		{
			name: "path-relocation",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				output := rootDistinctOutputContractForMutation(t, contract, "self-check")
				output["nativeOutputWitnessSelector"].(map[string]any)["path"] = "internal/app/app_test.go"
			},
		},
		{
			name: "direction-transfer",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				command := rootDistinctCommandForMutation(t, contract, "self-check")
				input := cloneRootDistinctJSONFixture(t, command.OutputContract).(map[string]any)
				input["nativeAdmissionWitnessSelector"] = input["nativeOutputWitnessSelector"]
				delete(input, "nativeOutputWitnessSelector")
				command.InputContract = input
				command.OutputContract = nil
			},
		},
		{
			name: "scenario-transfer",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				binding := rootDistinctBindingForMutation(t, bindings, "proofkit.supply-chain-quality.cli-abi-golden")
				binding.ScenarioID = "proofkit.supply-chain-quality.cli-abi-mutant"
			},
		},
		{
			name: "contract-command-drift",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				output := rootDistinctOutputContractForMutation(t, contract, "self-check")
				output["nativeOutputWitnessSelector"].(map[string]any)["command"] = "go test ./internal/app -run '^TestCLIABIGoldenCorpus$'"
			},
		},
		{
			name: "binding-command-drift",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				binding := rootDistinctBindingForMutation(t, bindings, "proofkit.package-boundary.cli-output-root-witnesses")
				binding.WitnessSelectors[0].Command = "go test ./internal/app -run '^TestCLIABIGoldenCorpus$'"
			},
		},
		{
			name: "owner-transfer",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				binding := rootDistinctBindingForMutation(t, bindings, "proofkit.package-boundary.cli-output-root-witnesses")
				binding.RequirementID = "REQ-PROOFKIT-QUALITY-009"
			},
		},
		{
			name: "binding-path-relocation",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				binding := rootDistinctBindingForMutation(t, bindings, "proofkit.spec-proof-core.adoption-contract-envelope-cli-abi")
				binding.WitnessPath = "internal/command/adoptioncontract/adoptioncontract_test.go"
			},
		},
		{
			name: "command-transfer",
			mutate: func(t *testing.T, contract *cliContract, bindings *rootDistinctOutputBindingFile) {
				rootDistinctCommandForMutation(t, contract, "pilot-admission").Command = "pilot-admission-mutant"
			},
		},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			mutantContract := cloneRootDistinctJSONFixture(t, contract)
			mutantBindings := cloneRootDistinctJSONFixture(t, bindings)
			mutant.mutate(t, &mutantContract, &mutantBindings)
			if err := validateRootDistinctOutputWitnessBindings(mutantContract, mutantBindings); err == nil {
				t.Fatal("mutant preserved the exact root-distinct output witness inventory")
			}
		})
	}
}

type rootDistinctOutputBindingFile struct {
	Bindings []rootDistinctOutputBinding `json:"bindings"`
}

type rootDistinctOutputBinding struct {
	RequirementID    string                              `json:"requirementId"`
	ScenarioID       string                              `json:"scenarioId"`
	WitnessPath      string                              `json:"witnessPath"`
	WitnessSelectors []rootDistinctOutputWitnessSelector `json:"witnessSelectors"`
}

type rootDistinctOutputWitnessSelector struct {
	Command  string `json:"command"`
	Selector string `json:"selector"`
}

type rootDistinctOutputContractExpectation struct {
	Command           string
	NativeSourceForm  string
	NativeSourcePaths []string
	SelectorPath      string
	SelectorTest      string
	ExecutableCommand string
}

type rootDistinctOutputBindingMapping struct {
	RequirementID string
	ScenarioID    string
	SelectorTest  string
}

type rootDistinctOutputContractBoundary struct {
	Command                   string
	Direction                 string
	NativeSourceForm          string
	NativeSourcePaths         []string
	ContractSelectorPath      string
	ContractSelectorTest      string
	ContractExecutableCommand string
}

type rootDistinctOutputWitnessTuple struct {
	Command                   string   `json:"command"`
	Direction                 string   `json:"direction"`
	NativeSourceForm          string   `json:"nativeSourceForm"`
	NativeSourcePaths         []string `json:"nativeSourcePaths"`
	ContractSelectorPath      string   `json:"contractSelectorPath"`
	ContractSelectorTest      string   `json:"contractSelectorTest"`
	ContractExecutableCommand string   `json:"contractExecutableCommand"`
	BindingWitnessPath        string   `json:"bindingWitnessPath"`
	BindingExecutableCommand  string   `json:"bindingExecutableCommand"`
	RequirementID             string   `json:"requirementId"`
	ScenarioID                string   `json:"scenarioId"`
}

func validateRootDistinctOutputWitnessBindings(contract cliContract, bindings rootDistinctOutputBindingFile) error {
	got := rootDistinctOutputWitnessTuples(contract, bindings)
	want := expectedRootDistinctOutputWitnessTuples()
	gotKeys := rootDistinctOutputWitnessTupleKeys(got)
	wantKeys := rootDistinctOutputWitnessTupleKeys(want)
	if !slices.Equal(gotKeys, wantKeys) {
		return fmt.Errorf("root-distinct output witness tuples=%v, want exact %v", gotKeys, wantKeys)
	}
	return nil
}

func rootDistinctOutputWitnessTuples(contract cliContract, bindings rootDistinctOutputBindingFile) []rootDistinctOutputWitnessTuple {
	contractBoundaries := rootDistinctOutputContractBoundaries(contract)
	tuples := []rootDistinctOutputWitnessTuple{}
	for _, binding := range bindings.Bindings {
		for _, selector := range binding.WitnessSelectors {
			if !isRootDistinctOutputSelector(selector.Selector) {
				continue
			}
			for _, boundary := range contractBoundaries {
				if boundary.ContractSelectorTest != selector.Selector {
					continue
				}
				tuples = append(tuples, rootDistinctOutputWitnessTuple{
					Command:                   boundary.Command,
					Direction:                 boundary.Direction,
					NativeSourceForm:          boundary.NativeSourceForm,
					NativeSourcePaths:         cloneStrings(boundary.NativeSourcePaths),
					ContractSelectorPath:      boundary.ContractSelectorPath,
					ContractSelectorTest:      boundary.ContractSelectorTest,
					ContractExecutableCommand: boundary.ContractExecutableCommand,
					BindingWitnessPath:        binding.WitnessPath,
					BindingExecutableCommand:  selector.Command,
					RequirementID:             binding.RequirementID,
					ScenarioID:                binding.ScenarioID,
				})
			}
		}
	}
	return tuples
}

func rootDistinctOutputContractBoundaries(contract cliContract) []rootDistinctOutputContractBoundary {
	expectedByCommand := map[string]rootDistinctOutputContractExpectation{}
	for _, expected := range rootDistinctOutputContractExpectations() {
		expectedByCommand[expected.Command] = expected
	}
	boundaries := []rootDistinctOutputContractBoundary{}
	for _, command := range contract.Commands {
		for _, direction := range []struct {
			name        string
			raw         any
			selectorKey string
		}{
			{name: "input", raw: command.InputContract, selectorKey: "nativeAdmissionWitnessSelector"},
			{name: "output", raw: command.OutputContract, selectorKey: "nativeOutputWitnessSelector"},
		} {
			value, ok := direction.raw.(map[string]any)
			if !ok {
				continue
			}
			selector, _ := value[direction.selectorKey].(map[string]any)
			selectorTest, _ := selector["test"].(string)
			_, targetCommand := expectedByCommand[command.Command]
			if !isRootDistinctOutputSelector(selectorTest) && !(targetCommand && direction.name == "output") {
				continue
			}
			sourceForm, sourcePaths := rootDistinctNativeSourcePaths(value)
			selectorPath, _ := selector["path"].(string)
			executableCommand, _ := selector["command"].(string)
			boundaries = append(boundaries, rootDistinctOutputContractBoundary{
				Command:                   command.Command,
				Direction:                 direction.name,
				NativeSourceForm:          sourceForm,
				NativeSourcePaths:         sourcePaths,
				ContractSelectorPath:      selectorPath,
				ContractSelectorTest:      selectorTest,
				ContractExecutableCommand: executableCommand,
			})
		}
	}
	return boundaries
}

func rootDistinctNativeSourcePaths(contract map[string]any) (string, []string) {
	rawSource, hasSource := contract["nativeSource"]
	rawSources, hasSources := contract["nativeSources"]
	paths := []string{}
	if source, ok := rawSource.(map[string]any); ok {
		if path, ok := source["path"].(string); ok {
			paths = append(paths, path)
		}
	}
	if sources, ok := rawSources.([]any); ok {
		for _, raw := range sources {
			source, _ := raw.(map[string]any)
			if path, ok := source["path"].(string); ok {
				paths = append(paths, path)
			}
		}
	}
	sort.Strings(paths)
	switch {
	case hasSource && !hasSources:
		return "nativeSource", paths
	case !hasSource && hasSources:
		return "nativeSources", paths
	case hasSource && hasSources:
		return "nativeSource+nativeSources", paths
	default:
		return "missing", paths
	}
}

func expectedRootDistinctOutputWitnessTuples() []rootDistinctOutputWitnessTuple {
	expectedBySelector := map[string]rootDistinctOutputContractExpectation{}
	for _, expected := range rootDistinctOutputContractExpectations() {
		expectedBySelector[expected.SelectorTest] = expected
	}
	tuples := make([]rootDistinctOutputWitnessTuple, 0, len(rootDistinctOutputBindingMappings()))
	for _, mapping := range rootDistinctOutputBindingMappings() {
		expected := expectedBySelector[mapping.SelectorTest]
		tuples = append(tuples, rootDistinctOutputWitnessTuple{
			Command:                   expected.Command,
			Direction:                 "output",
			NativeSourceForm:          expected.NativeSourceForm,
			NativeSourcePaths:         cloneStrings(expected.NativeSourcePaths),
			ContractSelectorPath:      expected.SelectorPath,
			ContractSelectorTest:      expected.SelectorTest,
			ContractExecutableCommand: expected.ExecutableCommand,
			BindingWitnessPath:        expected.SelectorPath,
			BindingExecutableCommand:  expected.ExecutableCommand,
			RequirementID:             mapping.RequirementID,
			ScenarioID:                mapping.ScenarioID,
		})
	}
	return tuples
}

func rootDistinctOutputContractExpectations() []rootDistinctOutputContractExpectation {
	return []rootDistinctOutputContractExpectation{
		{
			Command:           "adoption-contract-envelope",
			NativeSourceForm:  "nativeSource",
			NativeSourcePaths: []string{"internal/command/adoptioncontract"},
			SelectorPath:      "internal/app/cli_abi_test.go",
			SelectorTest:      "TestAdoptionContractEnvelopeCLIABI",
			ExecutableCommand: "go test ./internal/app -run '^TestAdoptionContractEnvelopeCLIABI$'",
		},
		{
			Command:           "pilot-admission",
			NativeSourceForm:  "nativeSources",
			NativeSourcePaths: []string{"internal/app", "internal/command/pilotadmission"},
			SelectorPath:      "internal/app/cli_abi_test.go",
			SelectorTest:      "TestStandaloneMultiVariantCommandsUseExactRootShapes",
			ExecutableCommand: "go test ./internal/app -run '^TestStandaloneMultiVariantCommandsUseExactRootShapes$'",
		},
		{
			Command:           "requirement-authoring-plan",
			NativeSourceForm:  "nativeSource",
			NativeSourcePaths: []string{"internal/command/requirementauthoringplan"},
			SelectorPath:      "internal/app/cli_abi_test.go",
			SelectorTest:      "TestRequirementAuthoringPlanOutputUsesVersionedRootShape",
			ExecutableCommand: "go test ./internal/app -run '^TestRequirementAuthoringPlanOutputUsesVersionedRootShape$'",
		},
		{
			Command:           "self-check",
			NativeSourceForm:  "nativeSource",
			NativeSourcePaths: []string{"internal/app"},
			SelectorPath:      "internal/app/cli_abi_test.go",
			SelectorTest:      "TestSelfCheckOutputUsesExactRootShape",
			ExecutableCommand: "go test ./internal/app -run '^TestSelfCheckOutputUsesExactRootShape$'",
		},
	}
}

func rootDistinctOutputBindingMappings() []rootDistinctOutputBindingMapping {
	return []rootDistinctOutputBindingMapping{
		{
			RequirementID: "REQ-PROOFKIT-PACKAGE-002",
			ScenarioID:    "proofkit.package-boundary.cli-output-root-witnesses",
			SelectorTest:  "TestAdoptionContractEnvelopeCLIABI",
		},
		{
			RequirementID: "REQ-PROOFKIT-PACKAGE-002",
			ScenarioID:    "proofkit.package-boundary.cli-output-root-witnesses",
			SelectorTest:  "TestRequirementAuthoringPlanOutputUsesVersionedRootShape",
		},
		{
			RequirementID: "REQ-PROOFKIT-PACKAGE-002",
			ScenarioID:    "proofkit.package-boundary.cli-output-root-witnesses",
			SelectorTest:  "TestSelfCheckOutputUsesExactRootShape",
		},
		{
			RequirementID: "REQ-PROOFKIT-PACKAGE-002",
			ScenarioID:    "proofkit.package-boundary.cli-output-root-witnesses",
			SelectorTest:  "TestStandaloneMultiVariantCommandsUseExactRootShapes",
		},
		{
			RequirementID: "REQ-PROOFKIT-QUALITY-004",
			ScenarioID:    "proofkit.supply-chain-quality.cli-abi-golden",
			SelectorTest:  "TestAdoptionContractEnvelopeCLIABI",
		},
		{
			RequirementID: "REQ-PROOFKIT-QUALITY-004",
			ScenarioID:    "proofkit.supply-chain-quality.cli-abi-golden",
			SelectorTest:  "TestRequirementAuthoringPlanOutputUsesVersionedRootShape",
		},
		{
			RequirementID: "REQ-PROOFKIT-QUALITY-004",
			ScenarioID:    "proofkit.supply-chain-quality.cli-abi-golden",
			SelectorTest:  "TestSelfCheckOutputUsesExactRootShape",
		},
		{
			RequirementID: "REQ-PROOFKIT-QUALITY-004",
			ScenarioID:    "proofkit.supply-chain-quality.cli-abi-golden",
			SelectorTest:  "TestStandaloneMultiVariantCommandsUseExactRootShapes",
		},
		{
			RequirementID: "REQ-PROOFKIT-SPEC-011",
			ScenarioID:    "proofkit.spec-proof-core.adoption-contract-envelope-cli-abi",
			SelectorTest:  "TestAdoptionContractEnvelopeCLIABI",
		},
	}
}

func isRootDistinctOutputSelector(selector string) bool {
	for _, expected := range rootDistinctOutputContractExpectations() {
		if expected.SelectorTest == selector {
			return true
		}
	}
	return false
}

func rootDistinctOutputWitnessTupleKeys(tuples []rootDistinctOutputWitnessTuple) []string {
	keys := make([]string, 0, len(tuples))
	for _, tuple := range tuples {
		encoded, err := json.Marshal(tuple)
		if err != nil {
			panic(err)
		}
		keys = append(keys, string(encoded))
	}
	sort.Strings(keys)
	return keys
}

func readRootDistinctOutputBindings(t *testing.T) rootDistinctOutputBindingFile {
	t.Helper()
	file, err := os.Open(filepath.Join(repoRoot(t), "proofkit", "requirement-bindings.json"))
	if err != nil {
		t.Fatalf("open requirement bindings: %v", err)
	}
	defer file.Close()
	bindings, err := admission.DecodeTypedJSON[rootDistinctOutputBindingFile](file, 16<<20)
	if err != nil {
		t.Fatalf("decode requirement bindings: %v", err)
	}
	return bindings
}

func rootDistinctCommandForMutation(t *testing.T, contract *cliContract, command string) *cliContractCommand {
	t.Helper()
	for index := range contract.Commands {
		if contract.Commands[index].Command == command {
			return &contract.Commands[index]
		}
	}
	t.Fatalf("root-distinct command %s is missing", command)
	return nil
}

func rootDistinctOutputContractForMutation(t *testing.T, contract *cliContract, command string) map[string]any {
	t.Helper()
	output, ok := rootDistinctCommandForMutation(t, contract, command).OutputContract.(map[string]any)
	if !ok {
		t.Fatalf("%s output contract is missing", command)
	}
	return output
}

func rootDistinctBindingForMutation(t *testing.T, bindings *rootDistinctOutputBindingFile, scenarioID string) *rootDistinctOutputBinding {
	t.Helper()
	for index := range bindings.Bindings {
		if bindings.Bindings[index].ScenarioID == scenarioID {
			return &bindings.Bindings[index]
		}
	}
	t.Fatalf("root-distinct binding %s is missing", scenarioID)
	return nil
}

func cloneRootDistinctJSONFixture[T any](t *testing.T, input T) T {
	t.Helper()
	content, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal JSON fixture: %v", err)
	}
	var clone T
	if err := json.Unmarshal(content, &clone); err != nil {
		t.Fatalf("unmarshal JSON fixture: %v", err)
	}
	return clone
}
