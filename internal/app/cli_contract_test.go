package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptioncontract"
	"github.com/research-engineering/agentic-proofkit/internal/command/agentroute"
	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

const (
	cliContractPublicABISHA256               = "f267002d9ef3b46a724e71a65cc46ce0a66975bb647656d05ba6c00cf6c285a2"
	maxAggregateFileReadBytesForContractTest = 64 << 20
	maxPackageManifestBytesForContractTest   = 256 << 10
	maxSourceFileBytesForContractTest        = 8 << 20
)

func TestCLIContractMatchesDispatcherAndHelp(t *testing.T) {
	contract := readCLIContract(t)
	assertCLIContractSchema(t)
	if problems := commandDescriptorContractParityProblems(commandDescriptors, contract.Commands); len(problems) != 0 {
		t.Fatalf("command descriptor/contract parity problems: %v", problems)
	}
	if problems := commandDescriptorTopologyProblems(commandDescriptors); len(problems) != 0 {
		t.Fatalf("command descriptor topology problems: %v", problems)
	}
	contractCommands := map[string]struct{}{}
	commandNames := make([]string, 0, len(contract.Commands))
	for _, command := range contract.Commands {
		if _, ok := contractCommands[command.Command]; ok {
			t.Fatalf("duplicate CLI contract command: %s", command.Command)
		}
		descriptor, ok := commandDescriptorFor(command.Command)
		if !ok {
			t.Fatalf("CLI contract command %s missing private descriptor", command.Command)
		}
		contractCommands[command.Command] = struct{}{}
		commandNames = append(commandNames, command.Command)
		assertSortedUnique(t, command.AllowedFlags, command.Command+" flags")
		assertSortedUnique(t, command.OutputModes, command.Command+" output modes")
		if string(descriptor.input) != command.Input {
			t.Fatalf("%s descriptor input=%s contract input=%s", command.Command, descriptor.input, command.Input)
		}
		if string(descriptor.scopeClass) != command.ScopeClass {
			t.Fatalf("%s descriptor scopeClass=%s contract=%s", command.Command, descriptor.scopeClass, command.ScopeClass)
		}
		if !slices.Equal(descriptor.routeTokens, effectiveContractRoute(command)) {
			t.Fatalf("%s descriptor route=%v contract route=%v", command.Command, descriptor.routeTokens, effectiveContractRoute(command))
		}
		assertStringSet(t, descriptor.allowedFlags, command.AllowedFlags, command.Command+" descriptor flags")
		assertStringSet(t, descriptor.outputModes, command.OutputModes, command.Command+" descriptor output modes")
		if descriptor.agentEnvelope != (command.AgentEnvelope != nil && *command.AgentEnvelope) {
			t.Fatalf("%s descriptor agentEnvelope=%v contract=%v", command.Command, descriptor.agentEnvelope, command.AgentEnvelope)
		}
		if descriptor.contractEnvelope != (command.ContractEnvelope != nil && *command.ContractEnvelope) {
			t.Fatalf("%s descriptor contractEnvelope=%v contract=%v", command.Command, descriptor.contractEnvelope, command.ContractEnvelope)
		}
		if command.Input == "required" {
			if !command.Stdin || !contains(command.AllowedFlags, "--input") {
				t.Fatalf("%s required input must support stdin through --input", command.Command)
			}
			if command.InputPointer != contains(command.AllowedFlags, "--input-pointer") {
				t.Fatalf("%s inputPointer must match --input-pointer admission", command.Command)
			}
		} else if command.Stdin || command.InputPointer || contains(command.AllowedFlags, "--input") || contains(command.AllowedFlags, "--input-pointer") {
			t.Fatalf("%s no-input command must not advertise stdin or input-pointer", command.Command)
		}
		if command.AgentEnvelope != nil && *command.AgentEnvelope && !contains(command.AllowedFlags, "--agent-envelope") {
			t.Fatalf("%s agent envelope flag missing", command.Command)
		}
		if command.ContractEnvelope != nil && *command.ContractEnvelope && !contains(command.AllowedFlags, "--contract-envelope") {
			t.Fatalf("%s contract envelope flag missing", command.Command)
		}
	}
	assertSortedUnique(t, commandNames, "CLI contract commands")
	for command := range supportedCommands {
		if _, ok := contractCommands[command]; !ok {
			t.Fatalf("supported command %s missing from CLI contract", command)
		}
	}
	for command := range contractCommands {
		if _, ok := supportedCommands[command]; !ok {
			t.Fatalf("CLI contract command %s missing from dispatcher", command)
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"help"}, strings.NewReader(""), &stdout, &stderr)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("help failed status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	help := stdout.String()
	for _, command := range contract.Commands {
		if command.Command == "help" {
			continue
		}
		route := commandRouteText(effectiveContractRoute(command))
		line := helpLineForCommand(help, route)
		if line == "" {
			t.Fatalf("help output does not route command %s", command.Command)
		}
		for _, flag := range command.AllowedFlags {
			if flag == "--help" || flag == "-h" {
				continue
			}
			if !strings.Contains(line, flag) {
				t.Fatalf("help line for %s missing advertised flag %s: %s", command.Command, flag, line)
			}
		}
		helpFlags := helpLineFlags(line)
		if !equalStringSets(helpFlags, command.AllowedFlags) {
			t.Fatalf("help line for %s flags=%v want %v: %s", command.Command, helpFlags, command.AllowedFlags, line)
		}
	}
	for command := range contractCommands {
		contractCommand := commandByContractID(contract.Commands, command)
		route := commandRouteText(effectiveContractRoute(contractCommand))
		if !strings.Contains(help, "agentic-proofkit "+route) && command != "help" {
			t.Fatalf("help output does not route command %s through %s", command, route)
		}
	}
}

func TestCLIContractsAreCompleteGeneratedAndWitnessBound(t *testing.T) {
	contract := readCLIContract(t)
	if len(contract.ContractDefinitions) == 0 {
		t.Fatal("CLI contract must expose reusable closed definitions")
	}
	definitions := cliContractDefinitionMap(t, contract.ContractDefinitions)
	for _, command := range contract.Commands {
		metadata, ok := generatedCommandContractMetadataByName[command.Command]
		if !ok {
			t.Fatalf("%s missing generated command-contract metadata", command.Command)
		}
		if command.Input == "required" {
			assertBoundCommandContract(t, command.Command, "input", command.InputContract, definitions, metadata.InputContractSHA256, "nativeAdmissionWitnessSelector")
			if len(metadata.InputSchemaSummary) == 0 {
				t.Fatalf("%s input help summary is empty", command.Command)
			}
		}
		if slices.Contains(command.OutputModes, "json") {
			assertBoundCommandContract(t, command.Command, "output", command.OutputContract, definitions, metadata.OutputContractSHA256, "nativeOutputWitnessSelector")
		}
	}
	presetChoices := generatedCommandContractMetadataByName["stack-preset"].FlagChoices["--preset"]
	if !slices.Equal(presetChoices, stackpreset.IDs()) {
		t.Fatalf("generated app preset choices=%v package projection=%v", presetChoices, stackpreset.IDs())
	}
}

func TestCLIContractInputRootShapesMatchNativeOwnerVariants(t *testing.T) {
	contract := readCLIContract(t)
	definitions := cliContractDefinitionMap(t, contract.ContractDefinitions)
	tests := []struct {
		definitionID string
		allowed      []string
		required     []string
	}{
		{
			definitionID: "proofkit.external-consumer.input.v1.root-shape",
			allowed:      []string{"evidence", "input", "schemaVersion"},
			required:     []string{"evidence", "input", "schemaVersion"},
		},
		{
			definitionID: "proofkit.registry-consumer.input.v1.root-shape",
			allowed:      []string{"input", "proof", "schemaVersion"},
			required:     []string{"input", "schemaVersion"},
		},
		{
			definitionID: "proofkit.requirement-proof-source-set.input.v2.root-shape",
			allowed:      []string{"canonicalEnvelope", "projection", "schemaVersion", "sourceSet", "sources"},
			required:     []string{"canonicalEnvelope", "schemaVersion", "sourceSet", "sources"},
		},
		{
			definitionID: "proofkit.secret-scan.input.v1.root-shape",
			allowed:      []string{"files", "nonClaims", "reportId", "schemaVersion", "suppressions"},
			required:     []string{"files", "nonClaims", "reportId", "schemaVersion"},
		},
		{
			definitionID: "proofkit.selective-gate-obligation-decision-input.input.v1.root-shape",
			allowed:      []string{"commandRoutes", "decisionId", "evidence", "nonClaims", "receiptCurrentnessScopeAdmission", "receiptTrustClassAdmission", "schemaVersion"},
			required:     []string{"commandRoutes", "decisionId", "evidence", "nonClaims", "schemaVersion"},
		},
	}
	for _, test := range tests {
		t.Run(test.definitionID, func(t *testing.T) {
			definition := definitions[test.definitionID]
			if definition == nil {
				t.Fatalf("missing definition %s", test.definitionID)
			}
			variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
			if len(variants) != 1 {
				t.Fatalf("variants=%d want 1", len(variants))
			}
			variant := variants[0].(map[string]any)
			if actual := stringsFromAny(variant["allowedFields"].([]any)); !slices.Equal(actual, test.allowed) {
				t.Fatalf("allowedFields=%v want %v", actual, test.allowed)
			}
			if actual := stringsFromAny(variant["requiredFields"].([]any)); !slices.Equal(actual, test.required) {
				t.Fatalf("requiredFields=%v want %v", actual, test.required)
			}
		})
	}
}

func TestCLIContractRootShapeVariantInventoryIsClosedAndModeComplete(t *testing.T) {
	contract := readCLIContract(t)
	definitions := cliContractDefinitionMap(t, contract.ContractDefinitions)
	usedDefinitions := map[string]string{}
	for _, command := range contract.Commands {
		for _, direction := range []struct {
			name string
			raw  any
		}{
			{name: "input", raw: command.InputContract},
			{name: "output", raw: command.OutputContract},
		} {
			if direction.raw == nil {
				continue
			}
			binding := canonicalJSONValue(t, direction.raw).(map[string]any)
			definitionID := binding["rootDefinitionRef"].(string)
			if prior, exists := usedDefinitions[definitionID]; exists {
				t.Fatalf("root-shape definition %s is shared by %s and %s %s", definitionID, prior, command.Command, direction.name)
			}
			usedDefinitions[definitionID] = command.Command + " " + direction.name
			definition := definitions[definitionID]
			if definition == nil {
				t.Fatalf("%s %s root-shape definition %s is missing", command.Command, direction.name, definitionID)
			}
			assertRootShapeDefinition(t, definitionID, definition)
		}
	}
	if len(usedDefinitions) != len(definitions) {
		t.Fatalf("used root-shape definitions=%d want all %d definitions", len(usedDefinitions), len(definitions))
	}

	expectedConditions := map[string][]string{
		"adoption-contract-envelope output":   {"--agent-envelope=absent", "--agent-envelope=present", "--materialization-manifest=absent", "--materialization-manifest=present", "--mode=adoption", "--mode=bootstrap", "--mode=guidance", "--mode=pilot", "--mode=workflow", "--pilot=absent"},
		"conformance-profile output":          {"--list", "--profile", "--verify", "without --format"},
		"pilot-admission output":              {"--pilot all", "--pilot first", "--pilot stack-diverse", "without --pilot"},
		"requirement-browser-server input":    {"--view coverage", "--view proof", "--view source", "--view spec-tree", "--view workspace"},
		"requirement-browser-server output":   {"--serve", "--session-mode one-shot-question", "state=cancelled|expired", "state=submitted", "without --serve"},
		"requirement-proof-source-set output": {"canonical_contract", "resolver_input"},
		"requirement-proof-view input":        {"compact", "structured"},
		"requirement-proof-view output":       {"compact", "structured"},
		"test-evidence-inventory input":       {"direct inventory", "discovery-draft", "proof-binding-derived", "source-set", "wrapped inventory"},
		"test-evidence-inventory output":      {"normalized-inventory", "proof-binding-derived", "failure report", "without --normalized-inventory"},
		"witness-plan input":                  {"without projection", "projection=requirement-bindings"},
	}
	exactHighRiskConditions := map[string][]string{
		"adoption-contract-envelope output": {
			"--agent-envelope=absent --materialization-manifest=absent --mode=adoption --pilot=absent",
			"--agent-envelope=absent --materialization-manifest=absent --mode=bootstrap --pilot=absent",
			"--agent-envelope=present --materialization-manifest=absent --mode=bootstrap --pilot=absent",
			"--agent-envelope=absent --materialization-manifest=present --mode=bootstrap --pilot=absent",
			"--agent-envelope=present --materialization-manifest=absent --mode=guidance --pilot=absent",
			"--agent-envelope=absent --materialization-manifest=absent --mode=guidance --pilot=absent",
			"--agent-envelope=absent --materialization-manifest=absent --mode=pilot --pilot=all",
			"--agent-envelope=absent --materialization-manifest=absent --mode=pilot --pilot=absent",
			"--agent-envelope=absent --materialization-manifest=absent --mode=pilot --pilot=first",
			"--agent-envelope=absent --materialization-manifest=absent --mode=pilot --pilot=stack-diverse",
			"--agent-envelope=present --materialization-manifest=absent --mode=workflow --pilot=absent",
			"--agent-envelope=absent --materialization-manifest=absent --mode=workflow --pilot=absent",
		},
		"conformance-profile output": {
			"--list",
			"--profile <id> --format json",
			"--profile <id> without --format (defaults json)",
			"--verify",
		},
		"pilot-admission input": {
			"--contract-envelope --pilot all",
			"--contract-envelope --pilot first",
			"--contract-envelope without --pilot (defaults first)",
			"--contract-envelope --pilot stack-diverse",
			"--contract-envelope --stack-diverse",
			"without --contract-envelope; --pilot first",
			"without --contract-envelope; without --pilot (defaults first)",
			"without --contract-envelope; --pilot stack-diverse",
			"without --contract-envelope; --stack-diverse",
		},
		"pilot-admission output": {
			"--contract-envelope --pilot all",
			"--contract-envelope --pilot first",
			"--contract-envelope --pilot stack-diverse",
			"--contract-envelope --stack-diverse",
			"--contract-envelope without --pilot (defaults first)",
			"direct input",
		},
		"requirement-browser-server output": {
			"without --serve; --view coverage",
			"without --serve; --view proof",
			"without --serve; --view source",
			"without --serve; --view spec-tree",
			"without --serve; --view workspace",
			"--open; --serve; --session-mode one-shot-question; --view workspace; state=cancelled|expired",
			"--open; --serve; --session-mode one-shot-question; --view workspace; state=submitted",
		},
		"requirement-proof-source-set output": {
			"projection.kind=canonical_contract",
			"projection.kind=resolver_input",
		},
		"requirement-proof-view input": {
			"compact proof contract root",
			"structured requirement proof binding root",
		},
		"requirement-proof-view output": {
			"compact proof contract root",
			"structured requirement proof binding root",
		},
		"witness-plan input": {
			"without projection",
			"projection=requirement-bindings",
		},
	}
	for _, command := range contract.Commands {
		for _, direction := range []struct {
			name string
			raw  any
		}{
			{name: "input", raw: command.InputContract},
			{name: "output", raw: command.OutputContract},
		} {
			if direction.raw == nil {
				continue
			}
			binding := canonicalJSONValue(t, direction.raw).(map[string]any)
			definition := definitions[binding["rootDefinitionRef"].(string)]
			conditionText := rootShapeConditionText(t, definition)
			key := command.Command + " " + direction.name
			if expected, ok := exactHighRiskConditions[key]; ok {
				actual := rootShapeConditions(t, definition)
				if !slices.Equal(actual, expected) {
					t.Fatalf("%s exact root-shape conditions=%v want %v", key, actual, expected)
				}
			}
			for _, expected := range expectedConditions[key] {
				if !strings.Contains(conditionText, expected) {
					t.Fatalf("%s root-shape variants omit condition %q: %s", key, expected, conditionText)
				}
			}
			if direction.name == "input" && command.ContractEnvelope != nil && *command.ContractEnvelope {
				for _, expected := range []string{"--contract-envelope", "without --contract-envelope"} {
					if !strings.Contains(conditionText, expected) {
						t.Fatalf("%s input root-shape variants omit %q: %s", command.Command, expected, conditionText)
					}
				}
			}
			if direction.name == "output" && command.AgentEnvelope != nil && *command.AgentEnvelope {
				if !strings.Contains(conditionText, "--agent-envelope") {
					t.Fatalf("%s output root-shape variants omit --agent-envelope: %s", command.Command, conditionText)
				}
				if len(definition["fieldTree"].(map[string]any)["variants"].([]any)) < 2 {
					t.Fatalf("%s output must distinguish agent and non-agent root shapes", command.Command)
				}
			}
		}
	}
}

func TestCLIConditionModelClosesAdoptionOutputRoutes(t *testing.T) {
	contract := readCLIContract(t)
	definitions := cliContractDefinitionMap(t, contract.ContractDefinitions)
	definition := definitions["proofkit.adoption-contract-envelope.output.v1.root-shape"]
	if definition == nil {
		t.Fatal("adoption output root-shape definition is missing")
	}
	fieldTree := definition["fieldTree"].(map[string]any)
	if fieldTree["conditionModel"] != "cli_flag_conjunction_v1" {
		t.Fatalf("conditionModel=%v want cli_flag_conjunction_v1", fieldTree["conditionModel"])
	}
	conditionOwners := map[string]string{}
	for _, raw := range fieldTree["variants"].([]any) {
		variant := raw.(map[string]any)
		for _, condition := range stringsFromAny(variant["when"].([]any)) {
			if previous, duplicate := conditionOwners[condition]; duplicate {
				t.Fatalf("condition %q is owned by %s and %v", condition, previous, variant["variantId"])
			}
			conditionOwners[condition] = variant["variantId"].(string)
		}
	}
	if len(conditionOwners) != 12 {
		t.Fatalf("adoption output condition cases=%d want 12", len(conditionOwners))
	}

	validConditionOwners := map[string]string{}
	validOptionCount := 0
	modeDomain := adoptioncontract.SupportedModes()
	pilotDomain := append([]string{""}, adoptioncontract.SupportedPilotVariants()...)
	mutatedModes := adoptioncontract.SupportedModes()
	if len(mutatedModes) == 0 {
		t.Fatal("native mode domain is empty")
	}
	mutatedModes[0] = "caller-mutant"
	if slices.Contains(adoptioncontract.SupportedModes(), "caller-mutant") {
		t.Fatal("native mode domain aliases caller-owned memory")
	}
	mutatedPilots := adoptioncontract.SupportedPilotVariants()
	if len(mutatedPilots) == 0 {
		t.Fatal("native pilot domain is empty")
	}
	mutatedPilots[0] = "caller-mutant"
	if slices.Contains(adoptioncontract.SupportedPilotVariants(), "caller-mutant") {
		t.Fatal("native pilot domain aliases caller-owned memory")
	}
	for _, mode := range modeDomain {
		for _, agentEnvelope := range []bool{false, true} {
			for _, materializationManifest := range []bool{false, true} {
				for _, pilot := range pilotDomain {
					options := adoptioncontract.Options{
						AgentEnvelope:           agentEnvelope,
						MaterializationManifest: materializationManifest,
						Mode:                    mode,
						Pilot:                   pilot,
					}
					condition := adoptionOutputCondition(options)
					_, matched := conditionOwners[condition]
					err := adoptioncontract.ValidateOptions(options)
					if err == nil && !matched {
						t.Fatalf("valid options %#v have no condition %q", options, condition)
					}
					if err != nil && matched {
						t.Fatalf("invalid options %#v match condition %q owned by %s: %v", options, condition, conditionOwners[condition], err)
					}
					if err == nil {
						validOptionCount++
						validConditionOwners[condition] = conditionOwners[condition]
					}
				}
			}
		}
	}
	if total := len(modeDomain) * 2 * 2 * len(pilotDomain); total != 80 {
		t.Fatalf("native normalized adoption option domain=%d want 80", total)
	}
	if validOptionCount != 12 {
		t.Fatalf("valid normalized adoption output options=%d want 12", validOptionCount)
	}
	if !maps.Equal(validConditionOwners, conditionOwners) {
		t.Fatalf("reachable condition owners=%v want exact declared set %v", validConditionOwners, conditionOwners)
	}
}

func adoptionOutputCondition(options adoptioncontract.Options) string {
	flagState := func(present bool) string {
		if present {
			return "present"
		}
		return "absent"
	}
	pilot := options.Pilot
	if pilot == "" {
		pilot = "absent"
	}
	return fmt.Sprintf(
		"--agent-envelope=%s --materialization-manifest=%s --mode=%s --pilot=%s",
		flagState(options.AgentEnvelope),
		flagState(options.MaterializationManifest),
		options.Mode,
		pilot,
	)
}

func adoptionOutputConditionFromParsed(options adoptionContractArgs) string {
	return adoptionOutputCondition(adoptioncontract.Options{
		AgentEnvelope:           options.agentEnvelope,
		MaterializationManifest: options.materializationManifest,
		Mode:                    options.mode,
		Pilot:                   options.explicitPilot(),
	})
}

func assertRootShapeDefinition(t *testing.T, id string, definition map[string]any) {
	t.Helper()
	if definition["closed"] != true {
		t.Fatalf("%s root-shape definition is not closed", id)
	}
	if refs := definition["definitionRefs"].([]any); len(refs) != 0 {
		t.Fatalf("%s root-shape definition has nested refs: %v", id, refs)
	}
	fieldTree := definition["fieldTree"].(map[string]any)
	expectedFieldTreeKeys := []string{"kind", "nonClaims", "variants"}
	if _, present := fieldTree["conditionModel"]; present {
		expectedFieldTreeKeys = []string{"conditionModel", "kind", "nonClaims", "variants"}
	}
	assertStringSet(t, sortedMapKeys(fieldTree), expectedFieldTreeKeys, id+" fieldTree keys")
	if fieldTree["kind"] != "root_shape_only" {
		t.Fatalf("%s fieldTree kind=%v want root_shape_only", id, fieldTree["kind"])
	}
	assertStringSet(t, stringsFromAny(fieldTree["nonClaims"].([]any)), []string{
		"Root-shape definitions do not claim nested field shapes, leaf types, cardinalities, or semantic validity.",
		"Root-shape definitions do not replace direct public-CLI runtime witnesses for variant selection.",
	}, id+" non-claims")
	variants := fieldTree["variants"].([]any)
	if len(variants) == 0 {
		t.Fatalf("%s has no root-shape variants", id)
	}
	rootKinds := map[string]struct{}{}
	for _, raw := range variants {
		variant := raw.(map[string]any)
		assertStringSet(t, sortedMapKeys(variant), []string{"allowedFields", "requiredFields", "rootKind", "variantId", "when"}, id+" variant keys")
		allowed := stringsFromAny(variant["allowedFields"].([]any))
		required := stringsFromAny(variant["requiredFields"].([]any))
		assertSortedUnique(t, allowed, id+" allowed root fields")
		assertSortedUnique(t, required, id+" required root fields")
		for _, field := range required {
			if !slices.Contains(allowed, field) {
				t.Fatalf("%s variant %v requires root field %s outside allowed fields", id, variant["variantId"], field)
			}
		}
		rootKind := variant["rootKind"].(string)
		rootKinds[rootKind] = struct{}{}
		if rootKind != "object" && (len(allowed) != 0 || len(required) != 0) {
			t.Fatalf("%s variant %v non-object root declares fields", id, variant["variantId"])
		}
		if when := stringsFromAny(variant["when"].([]any)); len(when) == 0 {
			t.Fatalf("%s variant %v has no CLI condition", id, variant["variantId"])
		}
	}
	switch definition["rootType"] {
	case "object":
		if len(rootKinds) != 1 {
			t.Fatalf("%s object root has kinds %v", id, rootKinds)
		}
		if _, ok := rootKinds["object"]; !ok {
			t.Fatalf("%s object root omits object variant", id)
		}
	case "union":
		if len(rootKinds) < 2 {
			t.Fatalf("%s union does not enumerate distinct root kinds: %v", id, rootKinds)
		}
		if _, unbounded := rootKinds["json_value"]; unbounded {
			t.Fatalf("%s union includes unbounded json_value", id)
		}
	case "json_value":
		if len(variants) != 1 {
			t.Fatalf("%s json_value root has %d variants, want one", id, len(variants))
		}
		if _, ok := rootKinds["json_value"]; !ok {
			t.Fatalf("%s json_value root is not explicitly unconstrained", id)
		}
	default:
		t.Fatalf("%s has unsupported rootType %v", id, definition["rootType"])
	}
}

func rootShapeConditionText(t *testing.T, definition map[string]any) string {
	t.Helper()
	return strings.Join(rootShapeConditions(t, definition), "\n")
}

func rootShapeConditions(t *testing.T, definition map[string]any) []string {
	t.Helper()
	fieldTree := definition["fieldTree"].(map[string]any)
	conditions := []string{}
	for _, raw := range fieldTree["variants"].([]any) {
		variant := raw.(map[string]any)
		conditions = append(conditions, stringsFromAny(variant["when"].([]any))...)
	}
	return conditions
}

func assertPublicCLIRootVariant(t *testing.T, commandName string, direction string, variantID string, value any) {
	t.Helper()
	contract := readCLIContract(t)
	definitions := cliContractDefinitionMap(t, contract.ContractDefinitions)
	var command *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == commandName {
			command = &contract.Commands[index]
			break
		}
	}
	if command == nil {
		t.Fatalf("root oracle command %s is missing", commandName)
	}
	rawContract := command.OutputContract
	if direction == "input" {
		rawContract = command.InputContract
	}
	binding := canonicalJSONValue(t, rawContract).(map[string]any)
	definition := definitions[binding["rootDefinitionRef"].(string)]
	fieldTree := definition["fieldTree"].(map[string]any)
	var selected map[string]any
	for _, raw := range fieldTree["variants"].([]any) {
		variant := raw.(map[string]any)
		if variant["variantId"] == variantID {
			selected = variant
			break
		}
	}
	if selected == nil {
		t.Fatalf("%s %s root variant %s is missing", commandName, direction, variantID)
	}
	switch selected["rootKind"] {
	case "array":
		if _, ok := value.([]any); !ok {
			t.Fatalf("%s %s variant %s requires array root, got %T", commandName, direction, variantID, value)
		}
	case "json_value":
		return
	case "object":
		record, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("%s %s variant %s requires object root, got %T", commandName, direction, variantID, value)
		}
		allowed := stringsFromAny(selected["allowedFields"].([]any))
		for key := range record {
			if !slices.Contains(allowed, key) {
				t.Fatalf("%s %s variant %s emitted uncontracted root field %s; allowed=%v", commandName, direction, variantID, key, allowed)
			}
		}
		for _, field := range stringsFromAny(selected["requiredFields"].([]any)) {
			if _, exists := record[field]; !exists {
				t.Fatalf("%s %s variant %s omitted required root field %s; value=%v", commandName, direction, variantID, field, record)
			}
		}
	default:
		t.Fatalf("%s %s variant %s has unsupported root kind %v", commandName, direction, variantID, selected["rootKind"])
	}
}

func assertPublicCLIRootVariantCondition(t *testing.T, commandName string, direction string, variantID string, condition string) {
	t.Helper()
	contract := readCLIContract(t)
	definitions := cliContractDefinitionMap(t, contract.ContractDefinitions)
	var command *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == commandName {
			command = &contract.Commands[index]
			break
		}
	}
	if command == nil {
		t.Fatalf("condition oracle command %s is missing", commandName)
	}
	rawContract := command.OutputContract
	if direction == "input" {
		rawContract = command.InputContract
	}
	binding := canonicalJSONValue(t, rawContract).(map[string]any)
	definition := definitions[binding["rootDefinitionRef"].(string)]
	for _, raw := range definition["fieldTree"].(map[string]any)["variants"].([]any) {
		variant := raw.(map[string]any)
		if variant["variantId"] != variantID {
			continue
		}
		if !slices.Contains(stringsFromAny(variant["when"].([]any)), condition) {
			t.Fatalf("%s %s variant %s omits exact condition %q", commandName, direction, variantID, condition)
		}
		return
	}
	t.Fatalf("%s %s root variant %s is missing", commandName, direction, variantID)
}

func TestContractMapDecisionTreeHasThreeCells(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "proofkit-contract-map.md"))
	if err != nil {
		t.Fatal(err)
	}
	inDecisionTree := false
	rowCount := 0
	for _, line := range strings.Split(string(content), "\n") {
		if line == "Decision tree:" {
			inDecisionTree = true
			continue
		}
		if !inDecisionTree {
			continue
		}
		if line == "## Routing Rules" {
			break
		}
		if !strings.HasPrefix(line, "|") {
			continue
		}
		rowCount++
		if separators := strings.Count(line, "|"); separators != 4 {
			t.Fatalf("decision-tree row has %d separators, want 4 for three cells: %s", separators, line)
		}
	}
	if rowCount < 3 {
		t.Fatalf("decision-tree row count=%d, want a non-empty three-column table", rowCount)
	}
}

func assertBoundCommandContract(t *testing.T, command string, direction string, raw any, definitions map[string]map[string]any, wantDigest string, selectorKey string) {
	t.Helper()
	if raw == nil {
		t.Fatalf("%s missing %s contract", command, direction)
	}
	value := canonicalJSONValue(t, raw).(map[string]any)
	for _, field := range []string{"contractId", "schemaVersion", "rootType", "closed", "rootDefinitionRef", "rootDefinitionDigest", "ownerRequirementRefs", selectorKey, "compatibilitySummary"} {
		if _, ok := value[field]; !ok {
			t.Fatalf("%s %s contract missing %s", command, direction, field)
		}
	}
	if (value["rootType"] != "object" && value["rootType"] != "json_value" && value["rootType"] != "union") || value["closed"] != true {
		t.Fatalf("%s %s contract root is not closed: %#v", command, direction, value)
	}
	source, hasSource := value["nativeSource"].(map[string]any)
	rawSources, hasSources := value["nativeSources"].([]any)
	if hasSource == hasSources {
		t.Fatalf("%s %s contract must declare exactly one native source form", command, direction)
	}
	if hasSource && source["evidenceClass"] != "source_checkout" {
		t.Fatalf("%s %s native source is not source-checkout evidence", command, direction)
	}
	for index, rawSource := range rawSources {
		source, ok := rawSource.(map[string]any)
		if !ok || source["evidenceClass"] != "source_checkout" {
			t.Fatalf("%s %s nativeSources[%d] is not source-checkout evidence", command, direction, index)
		}
	}
	selector := value[selectorKey].(map[string]any)
	if selector["evidenceClass"] != "source_checkout" {
		t.Fatalf("%s %s selector is not source-checkout evidence", command, direction)
	}
	resolved := resolvedCommandContract(t, value, definitions)
	intermediate, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	canonicalValue, err := admission.DecodeJSON(bytes.NewReader(intermediate), int64(len(intermediate)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := stablejson.MarshalLayout(canonicalValue, stablejson.LayoutCompact)
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.TrimSuffix(encoded, []byte{'\n'})
	sum := sha256.Sum256(encoded)
	gotDigest := "sha256:" + fmt.Sprintf("%x", sum[:])
	if gotDigest != wantDigest {
		t.Fatalf("%s %s generated digest=%s want %s", command, direction, wantDigest, gotDigest)
	}
}

func TestRequirementBrowserHelpMatchesWorkspaceInputContract(t *testing.T) {
	contract := readCLIContract(t)
	var browser cliContractCommand
	for _, command := range contract.Commands {
		if command.Command == "requirement-browser-server" {
			browser = command
			break
		}
	}
	if browser.Command == "" {
		t.Fatal("requirement-browser-server contract missing")
	}
	inputContract := canonicalJSONValue(t, browser.InputContract).(map[string]any)
	optionalFields := inputContract["workspaceOptionalFields"].([]any)
	descriptor, ok := commandDescriptorFor("requirement-browser-server")
	if !ok {
		t.Fatal("requirement-browser-server descriptor missing")
	}
	summary := strings.Join(descriptor.inputSchemaSummary, "\n")
	for _, rawField := range optionalFields {
		field := rawField.(string)
		if !strings.Contains(summary, "workspace mode: "+field+"=") {
			t.Fatalf("requirement-browser-server help omits workspace optional field %q", field)
		}
	}
}

func TestProofkitContractMapRoutesRequiredInputCommands(t *testing.T) {
	contract := readCLIContract(t)
	documentBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "proofkit-contract-map.md"))
	if err != nil {
		t.Fatalf("read proofkit contract map: %v", err)
	}
	document := string(documentBytes)
	for _, command := range contract.Commands {
		if command.Input != "required" {
			continue
		}
		route := strings.Join(effectiveContractRoute(command), " ")
		if !strings.Contains(document, "`"+route+"`") {
			t.Fatalf("docs/proofkit-contract-map.md does not route required-input command %s through %s", command.Command, route)
		}
	}
}

func TestCLIContractPublicABIGoldenStable(t *testing.T) {
	got := currentCLIContractPublicABISHA256(t)
	if got != cliContractPublicABISHA256 {
		t.Fatalf("public CLI ABI hash drifted: got %s want %s", got, cliContractPublicABISHA256)
	}
}

func currentCLIContractPublicABISHA256(t *testing.T) string {
	t.Helper()
	contract := readCLIContract(t)
	definitions := cliContractDefinitionMap(t, contract.ContractDefinitions)
	commands := []any{}
	for _, command := range contract.Commands {
		record := map[string]any{
			"atMostOneOfFlagGroups":    stringMatrixAsAny(command.AtMostOneOfFlagGroups),
			"allowedFlags":             stringsAsAny(command.AllowedFlags),
			"command":                  command.Command,
			"exactlyOneOfFlagGroups":   stringMatrixAsAny(command.ExactlyOneOfFlagGroups),
			"flagChoices":              command.FlagChoices,
			"flagPresenceRequirements": command.FlagPresenceRequirements,
			"flagValueRequirements":    command.FlagValueRequirements,
			"input":                    command.Input,
			"inputPointer":             command.InputPointer,
			"outputModes":              stringsAsAny(command.OutputModes),
			"route":                    stringsAsAny(effectiveContractRoute(command)),
			"requiredFlags":            stringsAsAny(command.RequiredFlags),
			"scopeClass":               command.ScopeClass,
			"singleOccurrenceFlags":    stringsAsAny(command.SingleOccurrenceFlags),
			"stdin":                    command.Stdin,
		}
		if command.AgentEnvelope != nil {
			record["agentEnvelope"] = *command.AgentEnvelope
		}
		if command.ContractEnvelope != nil {
			record["contractEnvelope"] = *command.ContractEnvelope
		}
		metadata := generatedCommandContractMetadataByName[command.Command]
		if command.InputContract != nil {
			record["inputContract"] = resolvedCommandContract(t, canonicalJSONValue(t, command.InputContract).(map[string]any), definitions)
			record["inputContractSHA256"] = metadata.InputContractSHA256
		}
		if command.OutputContract != nil {
			record["outputContract"] = resolvedCommandContract(t, canonicalJSONValue(t, command.OutputContract).(map[string]any), definitions)
			record["outputContractSHA256"] = metadata.OutputContractSHA256
		}
		commands = append(commands, record)
	}
	abi := map[string]any{
		"commands":            commands,
		"contractDefinitions": contract.ContractDefinitions,
		"contractId":          contract.ContractID,
		"packageName":         contract.PackageName,
		"processContract":     contract.ProcessContract,
		"schemaVersion":       contract.SchemaVersion,
	}
	encoded, err := json.Marshal(abi)
	if err != nil {
		t.Fatalf("marshal CLI ABI projection: %v", err)
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum[:])
}

func cliContractDefinitionMap(t *testing.T, raw []any) map[string]map[string]any {
	t.Helper()
	definitions := make(map[string]map[string]any, len(raw))
	for _, value := range raw {
		record := canonicalJSONValue(t, value).(map[string]any)
		id, _ := record["definitionId"].(string)
		if id == "" {
			t.Fatal("CLI contract definition has no definitionId")
		}
		definitions[id] = record
	}
	return definitions
}

func resolvedCommandContract(t *testing.T, contract map[string]any, definitions map[string]map[string]any) map[string]any {
	t.Helper()
	rootID, _ := contract["rootDefinitionRef"].(string)
	return map[string]any{
		"contract":               contract,
		"resolvedRootDefinition": resolveCLIContractDefinition(t, rootID, definitions, map[string]bool{}),
	}
}

func resolveCLIContractDefinition(t *testing.T, id string, definitions map[string]map[string]any, visiting map[string]bool) map[string]any {
	t.Helper()
	if visiting[id] {
		t.Fatalf("CLI contract definition cycle includes %s", id)
	}
	definition, ok := definitions[id]
	if !ok {
		t.Fatalf("CLI contract references missing definition %s", id)
	}
	visiting[id] = true
	resolved := maps.Clone(definition)
	references := stringsFromAny(resolved["definitionRefs"].([]any))
	children := make([]any, 0, len(references))
	for _, reference := range references {
		children = append(children, resolveCLIContractDefinition(t, reference, definitions, visiting))
	}
	delete(visiting, id)
	resolved["resolvedDefinitionRefs"] = children
	return resolved
}

func TestCommandDescriptorContractParityRejectsMutations(t *testing.T) {
	t.Run("missing generated metadata", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered == nil || !strings.Contains(fmt.Sprint(recovered), "missing generated contract metadata") {
				t.Fatalf("descriptor panic = %v, want generated metadata failure", recovered)
			}
		}()
		_ = command("missing-generated-command", commandInputNone, nil, modes("text"), nil)
	})

	contract := readCLIContract(t)
	cases := []struct {
		name        string
		descriptors []commandDescriptor
		commands    []cliContractCommand
	}{
		{
			name: "descriptor only command",
			descriptors: append(cloneCommandDescriptors(commandDescriptors), commandDescriptor{
				name:              "descriptor-only",
				routeTokens:       []string{"descriptor-only"},
				input:             commandInputNone,
				runner:            commandRunnerHelp,
				scopeClass:        commandScopeBuiltInPackageCatalog,
				allowedFlags:      flags("--help"),
				outputModes:       modes("text"),
				semanticOwnerDirs: ownerDirs("descriptoronly"),
			}),
			commands: contract.Commands,
		},
		{
			name:        "contract only command",
			descriptors: cloneCommandDescriptors(commandDescriptors),
			commands: append(cloneCLIContractCommands(contract.Commands), cliContractCommand{
				AllowedFlags: []string{"--help"},
				Command:      "contract-only",
				Input:        "none",
				OutputModes:  []string{"text"},
			}),
		},
		{
			name: "input drift",
			descriptors: mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
				descriptor.input = commandInputNone
			}),
			commands: contract.Commands,
		},
		{
			name: "flag drift",
			descriptors: mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
				descriptor.allowedFlags = []string{"--extra", "--input", "--input-pointer"}
			}),
			commands: contract.Commands,
		},
		{
			name: "output drift",
			descriptors: mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
				descriptor.outputModes = []string{"json", "markdown"}
			}),
			commands: contract.Commands,
		},
		{
			name: "exactly-one constraint drift",
			descriptors: mutateDescriptor("conformance-profile", func(descriptor *commandDescriptor) {
				descriptor.exactlyOneOfFlagGroups = nil
			}),
			commands: contract.Commands,
		},
		{
			name: "flag value requirement drift",
			descriptors: mutateDescriptor("conformance-profile", func(descriptor *commandDescriptor) {
				descriptor.flagValueRequirements = nil
			}),
			commands: contract.Commands,
		},
		{
			name: "flag presence requirement drift",
			descriptors: mutateDescriptor("requirement-browser-server", func(descriptor *commandDescriptor) {
				descriptor.flagPresenceRequirements = nil
			}),
			commands: contract.Commands,
		},
		{
			name: "at-most-one constraint drift",
			descriptors: mutateDescriptor("requirement-browser-server", func(descriptor *commandDescriptor) {
				descriptor.atMostOneOfFlagGroups = nil
			}),
			commands: contract.Commands,
		},
		{
			name: "single-occurrence constraint drift",
			descriptors: mutateDescriptor("requirement-source-view", func(descriptor *commandDescriptor) {
				descriptor.singleOccurrenceFlags = nil
			}),
			commands: contract.Commands,
		},
		{
			name: "flag choice drift",
			descriptors: mutateDescriptor("requirement-browser-server", func(descriptor *commandDescriptor) {
				descriptor.flagValueChoices["--scope"] = []string{"graph"}
			}),
			commands: contract.Commands,
		},
		{
			name: "scope class drift",
			descriptors: mutateDescriptor("typescript-public-api-surfaces", func(descriptor *commandDescriptor) {
				descriptor.scopeClass = commandScopeExplicitCallerInput
			}),
			commands: contract.Commands,
		},
		{
			name: "envelope drift",
			descriptors: mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
				descriptor.agentEnvelope = true
			}),
			commands: contract.Commands,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if problems := commandDescriptorContractParityProblems(tc.descriptors, tc.commands); len(problems) == 0 {
				t.Fatal("mutated command descriptor/contract parity was admitted")
			}
		})
	}
}

func TestCommandDescriptorTopologyRejectsInvalidRunner(t *testing.T) {
	descriptors := mutateDescriptor("adoption-checklist", func(descriptor *commandDescriptor) {
		descriptor.runner = commandRunner("unknown_runner")
	})
	if problems := commandDescriptorTopologyProblems(descriptors); len(problems) == 0 {
		t.Fatal("descriptor with unknown runner was admitted")
	}
}

func TestCommandDescriptorTopologyRejectsInvalidScopeClass(t *testing.T) {
	descriptors := mutateDescriptor("typescript-public-api-surfaces", func(descriptor *commandDescriptor) {
		descriptor.scopeClass = commandScopeClass("unknown_scope")
	})
	if problems := commandDescriptorTopologyProblems(descriptors); len(problems) == 0 {
		t.Fatal("descriptor with unknown scope class was admitted")
	}
}

func TestCommandDescriptorTopologyRejectsImplicitPlanningRoute(t *testing.T) {
	descriptors := append(cloneCommandDescriptors(commandDescriptors), commandDescriptor{
		name:              "new-planning-command",
		routeTokens:       []string{"new-planning-command"},
		input:             commandInputRequired,
		runner:            commandRunnerPlanning,
		scopeClass:        commandScopeExplicitCallerInput,
		allowedFlags:      flags("--input"),
		outputModes:       modes("json"),
		semanticOwnerDirs: ownerDirs("newplanning"),
	})
	if problems := commandDescriptorTopologyProblems(descriptors); len(problems) == 0 {
		t.Fatal("planning runner descriptor without explicit route was admitted")
	}
}

func TestCLIContractModeSpecificPromises(t *testing.T) {
	contract := readCLIContract(t)
	commands := map[string]cliContractCommand{}
	for _, command := range contract.Commands {
		commands[command.Command] = command
	}
	assertCommand(t, commands["help"], "none", []string{"--help", "-h"}, []string{"text"})
	assertCommand(t, commands["stack-preset"], "none", []string{"--preset"}, []string{"json"})
	assertCommand(t, commands["json-report-cli-adapter-source"], "none", []string{"--format", "--language"}, []string{"json"})
	assertScopeClass(t, commands["help"], commandScopeBuiltInPackageCatalog)
	assertScopeClass(t, commands["stack-preset"], commandScopeBuiltInPackageCatalog)
	assertScopeClass(t, commands["json-report-cli-adapter-source"], commandScopeBuiltInPackageCatalog)
	assertScopeClass(t, commands["typescript-public-api-surfaces"], commandScopeExplicitFileSystemScan)
	assertCommand(t, commands["adoption-contract-envelope"], "required", []string{"--agent-envelope", "--checked-scope", "--guidance-mode", "--input", "--materialization-manifest", "--mode", "--pilot", "--touched-rule-id"}, []string{"json"})
	assertCommand(t, commands["agent-route"], "required", []string{"--agent-envelope", "--agent-envelope-mode", "--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["capability-map-admission"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["conformance-profile"], "required", []string{"--format", "--input", "--input-pointer", "--list", "--profile", "--verify"}, []string{"json", "markdown"})
	assertCommand(t, commands["requirement-coverage-input-compose"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["requirement-coverage-view"], "required", []string{"--agent-envelope", "--format", "--input", "--input-pointer"}, []string{"html", "json", "markdown"})
	assertCommand(t, commands["requirement-proof-view"], "required", []string{"--empty-local-environment-policy", "--format", "--input", "--input-pointer", "--local-environment-class", "--scope"}, []string{"html", "json", "markdown"})
	assertCommand(t, commands["requirement-source-view"], "required", []string{"--format", "--input", "--input-pointer"}, []string{"html", "json", "markdown"})
	assertCommand(t, commands["requirement-spec-tree"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["requirement-spec-tree-view"], "required", []string{"--format", "--input", "--input-pointer", "--output"}, []string{"html", "json", "markdown"})
	assertCommand(t, commands["requirement-browser-server"], "required", []string{"--empty-local-environment-policy", "--host", "--input", "--input-pointer", "--local-environment-class", "--open", "--port", "--scope", "--serve", "--session-mode", "--session-timeout-seconds", "--view"}, []string{"json", "server"})
	assertCommand(t, commands["test-evidence-inventory"], "required", []string{"--input", "--input-pointer", "--normalized-inventory", "--projection"}, []string{"json", "normalized-inventory"})
	assertCommand(t, commands["workspace-manifest-facts"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["requirement-impact-input-compose"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["registry-consumer-proof-input-compose"], "required", []string{"--input", "--input-pointer"}, []string{"json"})
	assertCommand(t, commands["requirement-authoring-plan"], "required", []string{"--input", "--input-pointer"}, []string{"json"})

	expectedAgentEnvelopeCommands := commandsWithBool(commands, func(command cliContractCommand) bool {
		return command.AgentEnvelope != nil && *command.AgentEnvelope
	})
	assertStringSet(t, agentEnvelopeCommands, expectedAgentEnvelopeCommands, "agent envelope command helper list")
	for _, command := range expectedAgentEnvelopeCommands {
		if commands[command].AgentEnvelope == nil || !*commands[command].AgentEnvelope {
			t.Fatalf("%s must advertise agent envelope support", command)
		}
	}
	expectedContractEnvelopeCommands := commandsWithBool(commands, func(command cliContractCommand) bool {
		return command.ContractEnvelope != nil && *command.ContractEnvelope
	})
	assertStringSet(t, contractEnvelopeCommands, expectedContractEnvelopeCommands, "contract envelope command helper list")
	for _, command := range expectedContractEnvelopeCommands {
		if commands[command].ContractEnvelope == nil || !*commands[command].ContractEnvelope {
			t.Fatalf("%s must advertise contract envelope support", command)
		}
	}
}

func assertStringSet(t *testing.T, actual []string, expected []string, label string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("%s length=%d want %d; actual=%v expected=%v", label, len(actual), len(expected), actual, expected)
	}
	for index, value := range expected {
		if actual[index] != value {
			t.Fatalf("%s[%d]=%q want %q; actual=%v expected=%v", label, index, actual[index], value, actual, expected)
		}
	}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func commandsWithBool(commands map[string]cliContractCommand, predicate func(cliContractCommand) bool) []string {
	values := []string{}
	for name, command := range commands {
		if predicate(command) {
			values = append(values, name)
		}
	}
	sort.Strings(values)
	return values
}

func commandDescriptorContractParityProblems(descriptors []commandDescriptor, commands []cliContractCommand) []string {
	problems := []string{}
	descriptorByName := map[string]commandDescriptor{}
	for _, descriptor := range descriptors {
		if _, exists := descriptorByName[descriptor.name]; exists {
			problems = append(problems, "duplicate descriptor "+descriptor.name)
			continue
		}
		descriptorByName[descriptor.name] = descriptor
	}
	commandByName := map[string]cliContractCommand{}
	for _, command := range commands {
		if _, exists := commandByName[command.Command]; exists {
			problems = append(problems, "duplicate contract command "+command.Command)
			continue
		}
		commandByName[command.Command] = command
	}
	for name, descriptor := range descriptorByName {
		command, ok := commandByName[name]
		if !ok {
			problems = append(problems, "descriptor command missing contract "+name)
			continue
		}
		if string(descriptor.input) != command.Input {
			problems = append(problems, "input drift "+name)
		}
		if !slices.Equal(descriptor.routeTokens, effectiveContractRoute(command)) {
			problems = append(problems, "route drift "+name)
		}
		if !equalStringSets(descriptor.allowedFlags, command.AllowedFlags) {
			problems = append(problems, "flag drift "+name)
		}
		if !equalStringSets(descriptor.requiredFlags, command.RequiredFlags) {
			problems = append(problems, "required flag drift "+name)
		}
		if !reflect.DeepEqual(descriptor.exactlyOneOfFlagGroups, command.ExactlyOneOfFlagGroups) {
			problems = append(problems, "exactly-one flag group drift "+name)
		}
		if !reflect.DeepEqual(descriptor.atMostOneOfFlagGroups, command.AtMostOneOfFlagGroups) {
			problems = append(problems, "at-most-one flag group drift "+name)
		}
		if !reflect.DeepEqual(descriptor.flagPresenceRequirements, command.FlagPresenceRequirements) {
			problems = append(problems, "flag presence requirement drift "+name)
		}
		if !reflect.DeepEqual(descriptor.flagValueRequirements, command.FlagValueRequirements) {
			problems = append(problems, "flag value requirement drift "+name)
		}
		if !equalFlagChoiceMaps(descriptor.flagValueChoices, command.FlagChoices) {
			problems = append(problems, "flag choice drift "+name)
		}
		if !equalStringSets(descriptor.singleOccurrenceFlags, command.SingleOccurrenceFlags) {
			problems = append(problems, "single-occurrence flag drift "+name)
		}
		if !equalStringSets(descriptor.outputModes, command.OutputModes) {
			problems = append(problems, "output mode drift "+name)
		}
		if string(descriptor.scopeClass) != command.ScopeClass {
			problems = append(problems, "scope class drift "+name)
		}
		if descriptor.agentEnvelope != (command.AgentEnvelope != nil && *command.AgentEnvelope) {
			problems = append(problems, "agent envelope drift "+name)
		}
		if descriptor.contractEnvelope != (command.ContractEnvelope != nil && *command.ContractEnvelope) {
			problems = append(problems, "contract envelope drift "+name)
		}
	}
	for name := range commandByName {
		if _, ok := descriptorByName[name]; !ok {
			problems = append(problems, "contract command missing descriptor "+name)
		}
	}
	sort.Strings(problems)
	return problems
}

func commandDescriptorTopologyProblems(descriptors []commandDescriptor) []string {
	problems := []string{}
	for _, descriptor := range descriptors {
		if !isKnownCommandRunner(descriptor.runner) {
			problems = append(problems, "unknown runner "+descriptor.name)
		}
		if !isKnownCommandScopeClass(descriptor.scopeClass) {
			problems = append(problems, "unknown scope class "+descriptor.name)
		}
		if descriptor.runner == commandRunnerPlanning && !isExplicitPlanningCommand(descriptor.name) {
			problems = append(problems, "planning command lacks explicit route "+descriptor.name)
		}
		if len(descriptor.semanticOwnerDirs) == 0 {
			problems = append(problems, "missing semantic owner dirs "+descriptor.name)
		}
		if !isSortedUnique(descriptor.allowedFlags) || !isSortedUnique(descriptor.requiredFlags) || !isSortedUnique(descriptor.singleOccurrenceFlags) || !isSortedUnique(descriptor.outputModes) || !isSortedUnique(descriptor.semanticOwnerDirs) || !isSortedUnique(descriptor.semanticAppTests) || !isSortedUniqueFlagPresenceRequirements(descriptor.flagPresenceRequirements) || !isSortedUniqueFlagValueRequirements(descriptor.flagValueRequirements) {
			problems = append(problems, "unsorted descriptor list "+descriptor.name)
		}
		for _, requiredFlag := range descriptor.requiredFlags {
			if !slices.Contains(descriptor.allowedFlags, requiredFlag) {
				problems = append(problems, "required flag is not allowed "+descriptor.name+" "+requiredFlag)
			}
		}
		for _, group := range descriptor.exactlyOneOfFlagGroups {
			if len(group) < 2 || !isSortedUnique(group) {
				problems = append(problems, "invalid exactly-one flag group "+descriptor.name)
			}
			for _, flag := range group {
				if !slices.Contains(descriptor.allowedFlags, flag) {
					problems = append(problems, "exactly-one flag is not allowed "+descriptor.name+" "+flag)
				}
			}
		}
		for _, group := range descriptor.atMostOneOfFlagGroups {
			if len(group) < 2 || !isSortedUnique(group) {
				problems = append(problems, "invalid at-most-one flag group "+descriptor.name)
			}
			for _, flag := range group {
				if !slices.Contains(descriptor.allowedFlags, flag) {
					problems = append(problems, "at-most-one flag is not allowed "+descriptor.name+" "+flag)
				}
			}
		}
		for _, requirement := range descriptor.flagPresenceRequirements {
			if requirement.Flag == "" || !slices.Contains(descriptor.allowedFlags, requirement.Flag) || !isSortedUnique(requirement.RequiredFlags) || !isSortedUniqueRequiredFlagValues(requirement.RequiredFlagValues) {
				problems = append(problems, "invalid flag presence requirement "+descriptor.name)
			}
			for _, flag := range requirement.RequiredFlags {
				if !slices.Contains(descriptor.allowedFlags, flag) {
					problems = append(problems, "presence-required flag is not allowed "+descriptor.name+" "+flag)
				}
			}
			for _, required := range requirement.RequiredFlagValues {
				if !slices.Contains(descriptor.allowedFlags, required.Flag) {
					problems = append(problems, "presence-required flag is not allowed "+descriptor.name+" "+required.Flag)
				}
			}
		}
		for _, requirement := range descriptor.flagValueRequirements {
			if requirement.Flag == "" || requirement.Value == "" || !slices.Contains(descriptor.allowedFlags, requirement.Flag) || !isSortedUnique(requirement.RequiredFlags) || !isSortedUniqueRequiredFlagValues(requirement.RequiredFlagValues) {
				problems = append(problems, "invalid flag value requirement "+descriptor.name)
			}
			for _, flag := range requirement.RequiredFlags {
				if !slices.Contains(descriptor.allowedFlags, flag) {
					problems = append(problems, "value-required flag is not allowed "+descriptor.name+" "+flag)
				}
			}
			for _, required := range requirement.RequiredFlagValues {
				if !slices.Contains(descriptor.allowedFlags, required.Flag) {
					problems = append(problems, "value-required flag is not allowed "+descriptor.name+" "+required.Flag)
				}
			}
		}
		for _, flag := range descriptor.singleOccurrenceFlags {
			if !slices.Contains(descriptor.allowedFlags, flag) {
				problems = append(problems, "single-occurrence flag is not allowed "+descriptor.name+" "+flag)
			}
		}
		if descriptor.input == commandInputNone && descriptor.runner == commandRunnerGenericInput {
			problems = append(problems, "no-input command uses generic input runner "+descriptor.name)
		}
	}
	sort.Strings(problems)
	return problems
}

func cloneCommandDescriptors(descriptors []commandDescriptor) []commandDescriptor {
	clone := make([]commandDescriptor, 0, len(descriptors))
	for _, descriptor := range descriptors {
		clone = append(clone, descriptor.clone())
	}
	return clone
}

func cloneCLIContractCommands(commands []cliContractCommand) []cliContractCommand {
	clone := make([]cliContractCommand, 0, len(commands))
	for _, command := range commands {
		copied := command
		copied.AllowedFlags = cloneStrings(command.AllowedFlags)
		copied.RequiredFlags = cloneStrings(command.RequiredFlags)
		copied.ExactlyOneOfFlagGroups = cloneStringMatrix(command.ExactlyOneOfFlagGroups)
		copied.AtMostOneOfFlagGroups = cloneStringMatrix(command.AtMostOneOfFlagGroups)
		copied.FlagPresenceRequirements = cloneFlagPresenceRequirements(command.FlagPresenceRequirements)
		copied.FlagValueRequirements = cloneFlagValueRequirements(command.FlagValueRequirements)
		copied.FlagChoices = cloneStringMap(command.FlagChoices)
		copied.SingleOccurrenceFlags = cloneStrings(command.SingleOccurrenceFlags)
		copied.OutputModes = cloneStrings(command.OutputModes)
		clone = append(clone, copied)
	}
	return clone
}

func mutateDescriptor(name string, mutate func(*commandDescriptor)) []commandDescriptor {
	descriptors := cloneCommandDescriptors(commandDescriptors)
	for index := range descriptors {
		if descriptors[index].name == name {
			mutate(&descriptors[index])
			return descriptors
		}
	}
	panic("unknown command descriptor in test: " + name)
}

func helpLineForCommand(help string, command string) string {
	prefix := "  agentic-proofkit " + command
	for _, line := range strings.Split(help, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func helpLineFlags(line string) []string {
	flags := []string{}
	seen := map[string]struct{}{}
	for _, field := range strings.Fields(line) {
		for _, part := range strings.Split(field, "|") {
			token := strings.Trim(part, "[](),")
			if strings.HasPrefix(token, "<") || token == "-" || token == "->" {
				continue
			}
			if strings.HasPrefix(token, "--") || (len(token) == 2 && strings.HasPrefix(token, "-")) {
				if _, exists := seen[token]; exists {
					continue
				}
				seen[token] = struct{}{}
				flags = append(flags, token)
			}
		}
	}
	sort.Strings(flags)
	return flags
}

func stringsAsAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func TestHelpCommandContractForms(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.021600527281664046126364606050061357909698227432892268285315907924565443932022")
	for _, args := range [][]string{{"help"}, {"help", "--help"}, {"help", "-h"}, {"--help"}, {"-h"}, {"help", "repo-profile-admission"}, {"repo-profile-admission", "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), args, strings.NewReader(`{"bad":`), &stdout, &stderr)
			if status != 0 || stderr.Len() != 0 {
				t.Fatalf("help failed status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "agentic-proofkit help") && !strings.Contains(stdout.String(), "agentic-proofkit repo-profile-admission") {
				t.Fatalf("help output missing help route: %s", stdout.String())
			}
			if strings.Contains(stdout.String(), "bad") {
				t.Fatalf("help output read stdin: %s", stdout.String())
			}
		})
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"help", "--input", "-"}, strings.NewReader(""), &stdout, &stderr)
	if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "help supports only") {
		t.Fatalf("unexpected invalid help result status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	status = Run(t.Context(), []string{"help", "unknown-command"}, strings.NewReader(""), &stdout, &stderr)
	if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "unsupported help target: unknown-command") {
		t.Fatalf("unexpected unknown help result status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}

	for _, item := range []struct {
		command string
		needles []string
	}{
		{command: "migration-parity-admission", needles: []string{"Input schema summary:", "parityRecords[]", "targetProofkitRefs[]"}},
		{command: "migration-plan", needles: []string{"Input schema summary:", "retirementCandidates[]", "followUpCommands[]"}},
		{command: "package-runtime-dependency-admission", needles: []string{"Input schema summary:", "expectedLockfileIntegrity", "packageResolution{}"}},
	} {
		t.Run("schema summary "+item.command, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			status = Run(t.Context(), []string{"help", item.command}, strings.NewReader(""), &stdout, &stderr)
			if status != 0 || stderr.Len() != 0 {
				t.Fatalf("help %s failed status=%d stdout=%s stderr=%s", item.command, status, stdout.String(), stderr.String())
			}
			for _, needle := range item.needles {
				if !strings.Contains(stdout.String(), needle) {
					t.Fatalf("help %s missing %q: %s", item.command, needle, stdout.String())
				}
			}
		})
	}
}

func TestConformanceProfileContractRejectsHTMLMode(t *testing.T) {
	contract := readCLIContract(t)
	var profile *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "conformance-profile" {
			profile = &contract.Commands[index]
			break
		}
	}
	if profile == nil {
		t.Fatal("conformance-profile missing from CLI contract")
	}
	if contains(profile.OutputModes, "html") {
		t.Fatal("conformance-profile contract must not advertise html output")
	}
}

func TestDescriptorFlagConstraintsMatchCommandParsers(t *testing.T) {
	tests := []struct {
		name       string
		descriptor string
		valid      func() error
		invalid    func() error
	}{
		{
			name: "adoption mode required", descriptor: "adoption-contract-envelope",
			valid: func() error {
				_, err := parseAdoptionContractArgs([]string{"--input", "-", "--mode", "adoption"})
				return err
			},
			invalid: func() error { _, err := parseAdoptionContractArgs([]string{"--input", "-"}); return err },
		},
		{
			name: "conformance exactly one mode", descriptor: "conformance-profile",
			valid: func() error {
				_, err := parseConformanceProfileArgs([]string{"--input", "-", "--profile", "core"})
				return err
			},
			invalid: func() error {
				_, err := parseConformanceProfileArgs([]string{"--input", "-", "--list", "--verify"})
				return err
			},
		},
		{
			name: "resolver exactly one environment policy", descriptor: "requirement-proof-resolver",
			valid: func() error {
				_, err := parseRequirementProofResolverArgs([]string{"--input", "-", "--empty-local-environment-policy"})
				return err
			},
			invalid: func() error {
				_, err := parseRequirementProofResolverArgs([]string{"--input", "-", "--empty-local-environment-policy", "--local-environment-class", "local-go"})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, ok := commandDescriptorFor(test.descriptor)
			if !ok || (len(descriptor.requiredFlags) == 0 && len(descriptor.exactlyOneOfFlagGroups) == 0) {
				t.Fatalf("%s lacks a machine-readable flag constraint", test.descriptor)
			}
			if err := test.valid(); err != nil {
				t.Fatalf("valid constrained argv rejected: %v", err)
			}
			if err := test.invalid(); err == nil {
				t.Fatal("invalid constrained argv was accepted")
			}
		})
	}
	if _, err := parseConformanceProfileArgs([]string{"--input", "-", "--list", "--format", "markdown"}); err == nil {
		t.Fatal("conformance markdown without --profile was accepted")
	}
}

func TestDescriptorFlagConstraintsAreRenderedTruthfully(t *testing.T) {
	expectedConstrainedUsage := map[string]string{
		"adopt-materialize-apply":        "agentic-proofkit adopt materialize apply --input <path|-> [--color <auto|never>] --expect-desired-state <sha256-ref> --expect-transaction <sha256-ref> [--format <json|text>] [--input-pointer <pointer>] --repo-root <path>",
		"adopt-materialize-plan":         "agentic-proofkit adopt materialize plan --input <path|-> [--color <auto|never>] [--format <json|text>] [--input-pointer <pointer>] --repo-root <path>",
		"adopt-materialize-recover":      "agentic-proofkit adopt materialize recover --action <resume|rollback> [--color <auto|never>] [--format <json|text>] --repo-root <path> --transaction <sha256-ref>",
		"adopt-plan":                     "agentic-proofkit adopt plan [--color <auto|never>] [--format <json|text>] --mode <audit-from-code|code-baseline|fresh> --repo-root <path> [--stack <agentic_runtime_repo|generated_docs_contract_repo|python_service|python_typescript_service|typescript_monorepo|typescript_workspace>]",
		"adoption-contract-envelope":     "agentic-proofkit adoption-contract-envelope --input <path|-> [--agent-envelope] [--checked-scope <scope>] [--guidance-mode <mode>] [--materialization-manifest] --mode <mode> [--pilot <value>] [--touched-rule-id <id>]",
		"conformance-profile":            "agentic-proofkit conformance-profile --input <path|-> [--format <mode>] [--input-pointer <pointer>] (--list | --profile <value> | --verify)",
		"integration-check":              "agentic-proofkit integration check [--format <json|text>] --repo-root <path> --tool <claude|codex>",
		"integration-apply":              "agentic-proofkit integration apply [--color <auto|never>] --expect-desired-state <sha256-ref> --expect-transaction <sha256-ref> [--format <json|text>] --operation <install|remove|update> --repo-root <path> --tool <claude|codex>",
		"integration-plan":               "agentic-proofkit integration plan [--color <auto|never>] [--format <json|text>] --operation <install|remove|update> --repo-root <path> --tool <claude|codex>",
		"integration-recover":            "agentic-proofkit integration recover --action <resume|rollback> [--color <auto|never>] [--format <json|text>] --repo-root <path> --transaction <sha256-ref>",
		"integration-source":             "agentic-proofkit integration source [--format <json|text>] --tool <claude|codex>",
		"json-report-cli-adapter-source": "agentic-proofkit json-report-cli-adapter-source [--format <mode>] --language <value>",
		"next":                           "agentic-proofkit next [--color <auto|never>] [--format <json|text>] --repo-root <path>",
		"requirement-browser-server":     "agentic-proofkit requirement-browser-server --input <path|-> [--empty-local-environment-policy] [--host <127.0.0.1|::1>] [--input-pointer <pointer>] [--local-environment-class <id>] [--open] [--port <port>] [--scope <graph|slice>] [--serve] [--session-mode <browse|one-shot-question>] [--session-timeout-seconds <1..7200>] --view <coverage|proof|source|spec-tree|workspace>",
		"requirement-context-compose":    "agentic-proofkit requirement-context-compose --input <path|-> [--input-pointer <pointer>] --repo-root <path>",
		"requirement-proof-resolver":     "agentic-proofkit requirement-proof-resolver --input <path|-> [--input-pointer <pointer>] (--empty-local-environment-policy | --local-environment-class <id>)",
		"repository-inventory":           "agentic-proofkit repository-inventory --repo-root <path>",
		"stack-preset":                   "agentic-proofkit stack-preset --preset <agentic_runtime_repo|generated_docs_contract_repo|python_service|python_typescript_service|typescript_monorepo|typescript_workspace>",
		"status":                         "agentic-proofkit status [--color <auto|never>] [--format <json|text>] --repo-root <path>",
		"typescript-public-api-surfaces": "agentic-proofkit typescript-public-api-surfaces --input <path|-> [--input-pointer <pointer>] --repo-root <path>",
	}
	constrainedCount := 0
	for _, descriptor := range commandDescriptors {
		usageLine := commandUsageLine(descriptor)
		for _, flag := range descriptor.requiredFlags {
			if !strings.Contains(usageLine, " "+flag) || strings.Contains(usageLine, "["+flag) {
				t.Fatalf("%s required flag %s is not rendered as required: %s", descriptor.name, flag, usageLine)
			}
		}
		if len(descriptor.requiredFlags) > 0 || len(descriptor.exactlyOneOfFlagGroups) > 0 {
			constrainedCount++
			expected, admitted := expectedConstrainedUsage[descriptor.name]
			if !admitted {
				t.Fatalf("%s has constraints but no independent help oracle", descriptor.name)
			}
			if usageLine != expected {
				t.Fatalf("%s constrained usage = %q, want %q", descriptor.name, usageLine, expected)
			}
		}
		commandHelp := commandUsage(descriptor)
		for _, group := range descriptor.atMostOneOfFlagGroups {
			expected := "  At most one of: " + strings.Join(group, ", ")
			if !strings.Contains(commandHelp, expected) {
				t.Fatalf("%s at-most-one constraint %q is missing from command help", descriptor.name, expected)
			}
		}
		for _, requirement := range descriptor.flagPresenceRequirements {
			required := cloneStrings(requirement.RequiredFlags)
			for _, value := range requirement.RequiredFlagValues {
				required = append(required, value.Flag+" "+value.Value)
			}
			expected := fmt.Sprintf("  %s requires: %s", requirement.Flag, strings.Join(required, ", "))
			if !strings.Contains(commandHelp, expected) {
				t.Fatalf("%s presence constraint %q is missing from command help", descriptor.name, expected)
			}
		}
		for _, requirement := range descriptor.flagValueRequirements {
			required := cloneStrings(requirement.RequiredFlags)
			for _, value := range requirement.RequiredFlagValues {
				required = append(required, value.Flag+" "+value.Value)
			}
			expected := fmt.Sprintf("  %s %s requires: %s", requirement.Flag, requirement.Value, strings.Join(required, ", "))
			if !strings.Contains(commandHelp, expected) {
				t.Fatalf("%s value constraint %q is missing from command help", descriptor.name, expected)
			}
		}
		for _, flag := range descriptor.singleOccurrenceFlags {
			expected := "  May be specified once: " + flag
			if !strings.Contains(commandHelp, expected) {
				t.Fatalf("%s occurrence constraint %q is missing from command help", descriptor.name, expected)
			}
		}
	}
	if constrainedCount != len(expectedConstrainedUsage) {
		t.Fatalf("constrained descriptor count = %d, independent help oracle count = %d", constrainedCount, len(expectedConstrainedUsage))
	}
}

func TestDescriptorFlagConstraintsExecuteBeforeCommandDispatch(t *testing.T) {
	cases := []struct {
		command string
		args    []string
	}{
		{command: "adoption-contract-envelope", args: []string{"--input", "-"}},
		{command: "conformance-profile", args: []string{"--input", "-", "--list", "--verify"}},
		{command: "pilot-admission", args: []string{"--input", "-", "--pilot", "all"}},
		{command: "requirement-browser-server", args: []string{"--input", "-", "--open", "--view", "source"}},
		{command: "requirement-browser-server", args: []string{"--input", "-", "--scope", "graph", "--view", "source"}},
		{command: "requirement-browser-server", args: []string{"--empty-local-environment-policy", "--input", "-", "--local-environment-class", "local-go", "--view", "proof"}},
		{command: "requirement-browser-server", args: []string{"--input", "-", "--open", "--serve", "--session-mode", "one-shot-question", "--view", "spec-tree"}},
		{command: "requirement-browser-server", args: []string{"--input", "-", "--serve", "--session-timeout-seconds", "30", "--view", "workspace"}},
		{command: "requirement-browser-server", args: []string{"--input", "-", "--scope", "unknown", "--view", "proof"}},
		{command: "requirement-browser-server", args: []string{"--input", "-", "--serve", "--session-mode", "browse", "--session-mode", "browse", "--view", "workspace"}},
		{command: "requirement-proof-resolver", args: []string{"--input", "-"}},
		{command: "stack-preset", args: nil},
	}
	for _, item := range cases {
		descriptor := commandDescriptorByName[item.command]
		if err := validateFlagConstraints(descriptor, classifyDescriptorArguments(descriptor, item.args)); err == nil {
			t.Fatalf("%s invalid argv was admitted by descriptor owner", item.command)
		}
	}
}

func TestRequirementBrowserDescriptorMatchesRuntimeConditionalFlags(t *testing.T) {
	descriptor := commandDescriptorByName["requirement-browser-server"]
	wantChoices := map[string][]string{
		"--host":         {"127.0.0.1", "::1"},
		"--scope":        {"graph", "slice"},
		"--session-mode": {"browse", "one-shot-question"},
		"--view":         {"coverage", "proof", "source", "spec-tree", "workspace"},
	}
	if !reflect.DeepEqual(descriptor.flagValueChoices, wantChoices) {
		t.Fatalf("browser flag choices=%v, want %v", descriptor.flagValueChoices, wantChoices)
	}
	if !slices.Equal(descriptor.singleOccurrenceFlags, requirementBrowserSingleOccurrenceFlags) {
		t.Fatalf("browser singleton flags=%v, want %v", descriptor.singleOccurrenceFlags, requirementBrowserSingleOccurrenceFlags)
	}
	help := commandUsage(descriptor)
	for _, fragment := range []string{"--host <127.0.0.1|::1>", "--scope <graph|slice>", "--session-mode <browse|one-shot-question>", "--view <coverage|proof|source|spec-tree|workspace>"} {
		if !strings.Contains(help, fragment) {
			t.Fatalf("browser help missing descriptor choice projection %q:\n%s", fragment, help)
		}
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "source view", args: []string{"--input", "-", "--view", "source"}},
		{name: "browse session", args: []string{"--input", "-", "--serve", "--session-mode", "browse", "--view", "workspace"}},
		{name: "one shot session", args: []string{"--input", "-", "--open", "--serve", "--session-mode", "one-shot-question", "--session-timeout-seconds", "30", "--view", "workspace"}},
		{name: "proof scope", args: []string{"--input", "-", "--local-environment-class", "local-go", "--scope", "graph", "--view", "proof"}},
		{name: "open without serve", args: []string{"--input", "-", "--open", "--view", "source"}},
		{name: "browse wrong view", args: []string{"--input", "-", "--serve", "--session-mode", "browse", "--view", "source"}},
		{name: "timeout without one shot", args: []string{"--input", "-", "--serve", "--session-timeout-seconds", "30", "--view", "workspace"}},
		{name: "scope outside proof", args: []string{"--input", "-", "--scope", "graph", "--view", "source"}},
		{name: "conflicting environment policy", args: []string{"--empty-local-environment-policy", "--input", "-", "--local-environment-class", "local-go", "--view", "proof"}},
		{name: "invalid scope", args: []string{"--input", "-", "--scope", "unknown", "--view", "proof"}},
		{name: "repeated session mode", args: []string{"--input", "-", "--serve", "--session-mode", "browse", "--session-mode", "browse", "--view", "workspace"}},
		{name: "repeated session timeout", args: []string{"--input", "-", "--open", "--serve", "--session-mode", "one-shot-question", "--session-timeout-seconds", "30", "--session-timeout-seconds", "30", "--view", "workspace"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptorErr := validateFlagConstraints(descriptor, classifyDescriptorArguments(descriptor, test.args))
			_, runtimeErr := parseRequirementBrowserArgs(test.args)
			if (descriptorErr == nil) != (runtimeErr == nil) {
				t.Fatalf("descriptor error=%v runtime error=%v for argv %v", descriptorErr, runtimeErr, test.args)
			}
		})
	}
}

type cliContract struct {
	Commands            []cliContractCommand `json:"commands"`
	ContractDefinitions []any                `json:"contractDefinitions"`
	ContractID          string               `json:"contractId"`
	PackageName         string               `json:"packageName"`
	ProcessContract     any                  `json:"processContract"`
	SchemaVersion       int                  `json:"schemaVersion"`
}

type cliContractCommand struct {
	AgentEnvelope            *bool                     `json:"agentEnvelope,omitempty"`
	AllowedFlags             []string                  `json:"allowedFlags"`
	AtMostOneOfFlagGroups    [][]string                `json:"atMostOneOfFlagGroups,omitempty"`
	Command                  string                    `json:"command"`
	ContractEnvelope         *bool                     `json:"contractEnvelope,omitempty"`
	ExactlyOneOfFlagGroups   [][]string                `json:"exactlyOneOfFlagGroups,omitempty"`
	FlagChoices              map[string][]string       `json:"flagChoices,omitempty"`
	FlagPresenceRequirements []flagPresenceRequirement `json:"flagPresenceRequirements,omitempty"`
	FlagValueRequirements    []flagValueRequirement    `json:"flagValueRequirements,omitempty"`
	Input                    string                    `json:"input"`
	InputContract            any                       `json:"inputContract,omitempty"`
	InputPointer             bool                      `json:"inputPointer"`
	OutputContract           any                       `json:"outputContract,omitempty"`
	OutputModes              []string                  `json:"outputModes"`
	RequiredFlags            []string                  `json:"requiredFlags,omitempty"`
	Route                    []string                  `json:"route,omitempty"`
	ScopeClass               string                    `json:"scopeClass"`
	SingleOccurrenceFlags    []string                  `json:"singleOccurrenceFlags,omitempty"`
	Stdin                    bool                      `json:"stdin"`
}

func readCLIContract(t *testing.T) cliContract {
	t.Helper()
	file, err := os.Open(filepath.Join(repoRoot(t), "proofkit", "cli-contract.v2.json"))
	if err != nil {
		t.Fatalf("open CLI contract: %v", err)
	}
	defer file.Close()
	contract, err := admission.DecodeTypedJSON[cliContract](file, 16<<20)
	if err != nil {
		t.Fatalf("decode CLI contract: %v", err)
	}
	return contract
}

func assertCLIContractSchema(t *testing.T) {
	t.Helper()
	file, err := os.Open(filepath.Join(repoRoot(t), "proofkit", "cli-contract.v2.json"))
	if err != nil {
		t.Fatalf("open CLI contract: %v", err)
	}
	defer file.Close()
	record, err := admission.DecodeTypedJSON[map[string]json.RawMessage](file, 16<<20)
	if err != nil {
		t.Fatalf("decode raw CLI contract: %v", err)
	}
	assertKeys(t, "CLI contract", keys(record), []string{"commands", "contractDefinitions", "contractId", "packageName", "processContract", "schemaVersion"})
	var processContract map[string]json.RawMessage
	if err := json.Unmarshal(record["processContract"], &processContract); err != nil {
		t.Fatalf("decode process contract: %v", err)
	}
	assertKeys(t, "CLI process contract", keys(processContract), []string{"commandRouteGrammar", "failureExitCode", "globalOptions", "helpGrammar", "stderr", "stdout", "successExitCode"})
	var routeGrammar map[string]any
	if err := json.Unmarshal(processContract["commandRouteGrammar"], &routeGrammar); err != nil {
		t.Fatalf("decode command route grammar: %v", err)
	}
	assertKeys(t, "CLI command route grammar", keysAny(routeGrammar), []string{"ambiguityPolicy", "maximumTokens", "minimumTokens", "omittedRoutePolicy", "separator", "tokenPattern"})
	if routeGrammar["minimumTokens"] != float64(commandroute.MinimumTokens) ||
		routeGrammar["maximumTokens"] != float64(commandroute.MaximumTokens) ||
		routeGrammar["separator"] != commandroute.Separator ||
		routeGrammar["tokenPattern"] != commandroute.TokenPattern ||
		routeGrammar["ambiguityPolicy"] != commandroute.AmbiguityPolicy ||
		routeGrammar["omittedRoutePolicy"] != commandroute.OmittedRoutePolicy {
		t.Fatalf("CLI command route grammar does not match runtime owner: %#v", routeGrammar)
	}
	var globalOptions map[string]any
	if err := json.Unmarshal(processContract["globalOptions"], &globalOptions); err != nil {
		t.Fatalf("decode global options: %v", err)
	}
	assertKeys(t, "CLI global options", keysAny(globalOptions), []string{"jsonLayout"})
	jsonLayout, ok := globalOptions["jsonLayout"].(map[string]any)
	if !ok {
		t.Fatalf("CLI jsonLayout option must be an object: %#v", globalOptions["jsonLayout"])
	}
	assertKeys(t, "CLI jsonLayout option", keysAny(jsonLayout), []string{"default", "flag", "position", "scope", "values"})
	assertStringSet(t, stringsFromAny(jsonLayout["values"].([]any)), []string{"compact", "pretty"}, "JSON layout values")
	if jsonLayout["flag"] != "--json-layout" || jsonLayout["position"] != "before_command" || jsonLayout["default"] != "pretty" || jsonLayout["scope"] != "json_output_only" {
		t.Fatalf("CLI jsonLayout option does not describe runtime admission: %#v", jsonLayout)
	}
	var helpGrammar map[string]any
	if err := json.Unmarshal(processContract["helpGrammar"], &helpGrammar); err != nil {
		t.Fatalf("decode help grammar: %v", err)
	}
	assertKeys(t, "CLI help grammar", keysAny(helpGrammar), []string{"commandHelpExclusive", "commandHelpFlags", "helpCatalogFormsSource", "helpCommandPositionalTarget", "helpReadsCommandInput", "rootHelpFlags"})
	assertStringSet(t, stringsFromAny(helpGrammar["rootHelpFlags"].([]any)), []string{"--help", "-h"}, "root help flags")
	assertStringSet(t, stringsFromAny(helpGrammar["commandHelpFlags"].([]any)), []string{"--help", "-h"}, "command help flags")
	if helpGrammar["commandHelpExclusive"] != true ||
		helpGrammar["helpCommandPositionalTarget"] != "optional_supported_command_route" ||
		helpGrammar["helpCatalogFormsSource"] != "proofkit/command-families.v1.json" ||
		helpGrammar["helpReadsCommandInput"] != false {
		t.Fatalf("CLI help grammar does not describe runtime help routing: %#v", helpGrammar)
	}
	var successExitCode int
	if err := json.Unmarshal(processContract["successExitCode"], &successExitCode); err != nil || successExitCode != 0 {
		t.Fatalf("successExitCode=%d err=%v, want 0", successExitCode, err)
	}
	var failureExitCode int
	if err := json.Unmarshal(processContract["failureExitCode"], &failureExitCode); err != nil || failureExitCode != 1 {
		t.Fatalf("failureExitCode=%d err=%v, want 1", failureExitCode, err)
	}
	var commands []map[string]json.RawMessage
	if err := json.Unmarshal(record["commands"], &commands); err != nil {
		t.Fatalf("decode raw CLI commands: %v", err)
	}
	allowedCommandKeys := map[string]struct{}{
		"agentEnvelope":            {},
		"allowedFlags":             {},
		"atMostOneOfFlagGroups":    {},
		"command":                  {},
		"contractEnvelope":         {},
		"exactlyOneOfFlagGroups":   {},
		"flagChoices":              {},
		"flagPresenceRequirements": {},
		"flagValueRequirements":    {},
		"input":                    {},
		"inputContract":            {},
		"inputPointer":             {},
		"outputContract":           {},
		"outputModes":              {},
		"requiredFlags":            {},
		"route":                    {},
		"scopeClass":               {},
		"singleOccurrenceFlags":    {},
		"stdin":                    {},
	}
	for index, command := range commands {
		for key := range command {
			if _, ok := allowedCommandKeys[key]; !ok {
				t.Fatalf("CLI command %d has unsupported key %s", index, key)
			}
		}
		for _, required := range []string{"allowedFlags", "command", "input", "inputPointer", "outputModes", "scopeClass", "stdin"} {
			if _, ok := command[required]; !ok {
				t.Fatalf("CLI command %d missing required key %s", index, required)
			}
		}
		var flagChoices map[string][]string
		if raw, ok := command["flagChoices"]; ok {
			if err := json.Unmarshal(raw, &flagChoices); err != nil {
				t.Fatalf("decode CLI command %d flag choices: %v", index, err)
			}
			var allowedFlags []string
			if err := json.Unmarshal(command["allowedFlags"], &allowedFlags); err != nil {
				t.Fatalf("decode CLI command %d allowed flags: %v", index, err)
			}
			for flag, choices := range flagChoices {
				if !slices.Contains(allowedFlags, flag) || !isSortedUnique(choices) {
					t.Fatalf("CLI command %d has invalid choices for %s: %v", index, flag, choices)
				}
			}
		}
		var presenceRequirements []map[string]json.RawMessage
		if raw, ok := command["flagPresenceRequirements"]; ok {
			if err := json.Unmarshal(raw, &presenceRequirements); err != nil {
				t.Fatalf("decode CLI command %d flag presence requirements: %v", index, err)
			}
		}
		for requirementIndex, requirement := range presenceRequirements {
			allowedRequirementKeys := map[string]struct{}{
				"flag":               {},
				"requiredFlagValues": {},
				"requiredFlags":      {},
			}
			for key := range requirement {
				if _, ok := allowedRequirementKeys[key]; !ok {
					t.Fatalf("CLI command %d flag presence requirement %d has unsupported key %s", index, requirementIndex, key)
				}
			}
			for _, required := range []string{"flag", "requiredFlags"} {
				if _, ok := requirement[required]; !ok {
					t.Fatalf("CLI command %d flag presence requirement %d missing required key %s", index, requirementIndex, required)
				}
			}
			var requiredValues []map[string]json.RawMessage
			if raw, ok := requirement["requiredFlagValues"]; ok {
				if err := json.Unmarshal(raw, &requiredValues); err != nil {
					t.Fatalf("decode CLI command %d flag presence requirement %d required values: %v", index, requirementIndex, err)
				}
			}
			for valueIndex, requiredValue := range requiredValues {
				assertKeys(t, fmt.Sprintf("CLI command %d flag presence requirement %d required value %d", index, requirementIndex, valueIndex), keys(requiredValue), []string{"flag", "value"})
			}
		}
		var requirements []map[string]json.RawMessage
		if raw, ok := command["flagValueRequirements"]; ok {
			if err := json.Unmarshal(raw, &requirements); err != nil {
				t.Fatalf("decode CLI command %d flag value requirements: %v", index, err)
			}
		}
		for requirementIndex, requirement := range requirements {
			allowedRequirementKeys := map[string]struct{}{
				"flag":               {},
				"requiredFlagValues": {},
				"requiredFlags":      {},
				"value":              {},
			}
			for key := range requirement {
				if _, ok := allowedRequirementKeys[key]; !ok {
					t.Fatalf("CLI command %d flag value requirement %d has unsupported key %s", index, requirementIndex, key)
				}
			}
			for _, required := range []string{"flag", "requiredFlags", "value"} {
				if _, ok := requirement[required]; !ok {
					t.Fatalf("CLI command %d flag value requirement %d missing required key %s", index, requirementIndex, required)
				}
			}
			var requiredValues []map[string]json.RawMessage
			if raw, ok := requirement["requiredFlagValues"]; ok {
				if err := json.Unmarshal(raw, &requiredValues); err != nil {
					t.Fatalf("decode CLI command %d flag value requirement %d required values: %v", index, requirementIndex, err)
				}
			}
			for valueIndex, requiredValue := range requiredValues {
				assertKeys(t, fmt.Sprintf("CLI command %d flag value requirement %d required value %d", index, requirementIndex, valueIndex), keys(requiredValue), []string{"flag", "value"})
				for _, required := range []string{"flag", "value"} {
					if _, ok := requiredValue[required]; !ok {
						t.Fatalf("CLI command %d flag value requirement %d required value %d missing required key %s", index, requirementIndex, valueIndex, required)
					}
				}
			}
		}
	}
}

func effectiveContractRoute(command cliContractCommand) []string {
	route, ok := commandroute.Resolve(command.Command, command.Route)
	if !ok {
		return nil
	}
	return route
}

func commandByContractID(commands []cliContractCommand, commandID string) cliContractCommand {
	for _, command := range commands {
		if command.Command == commandID {
			return command
		}
	}
	panic("unknown CLI contract command: " + commandID)
}

func stringMatrixAsAny(values [][]string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, stringsAsAny(value))
	}
	return out
}

func TestRequirementProofSourceSetContractDescribesProjection(t *testing.T) {
	contract := readCLIContract(t)
	var sourceSet *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "requirement-proof-source-set" {
			sourceSet = &contract.Commands[index]
			break
		}
	}
	if sourceSet == nil {
		t.Fatal("requirement-proof-source-set missing from CLI contract")
	}
	if sourceSet.InputContract == nil {
		t.Fatal("requirement-proof-source-set must expose inputContract")
	}
	if sourceSet.OutputContract == nil {
		t.Fatal("requirement-proof-source-set must expose outputContract")
	}
	inputContract := canonicalJSONValue(t, sourceSet.InputContract).(map[string]any)
	optionalFields := inputContract["optionalFields"].(map[string]any)
	projection := optionalFields["projection"].(map[string]any)
	fields := projection["fields"].(map[string]any)
	kind := fields["kind"].(map[string]any)
	if !reflect.DeepEqual(kind["enum"], []any{"canonical_contract", "resolver_input"}) {
		t.Fatalf("projection.kind enum=%v, want canonical_contract/resolver_input", kind["enum"])
	}
	if _, ok := fields["selectedSourceIds"]; !ok {
		t.Fatal("projection.selectedSourceIds missing from source-set input contract")
	}
	outputContract := canonicalJSONValue(t, sourceSet.OutputContract).(map[string]any)
	variants := outputContract["variants"].([]any)
	if len(variants) != 2 {
		t.Fatalf("source-set output variants=%v, want 2", variants)
	}
	wantVariants := map[string]string{
		"proofkit.requirement-proof-source-set.canonical_contract": "contract",
		"proofkit.requirement-proof-source-set.resolver_input":     "resolverInput",
	}
	for _, raw := range variants {
		variant := raw.(map[string]any)
		kind, _ := variant["projectionKind"].(string)
		field, _ := variant["payloadField"].(string)
		if wantVariants[kind] != field {
			t.Fatalf("unexpected source-set output variant kind=%q field=%q", kind, field)
		}
		delete(wantVariants, kind)
	}
	if len(wantVariants) != 0 {
		t.Fatalf("source-set output variants missing: %v", wantVariants)
	}
}

func TestTypeScriptPublicAPIContractOwnsExplicitScanTopology(t *testing.T) {
	contract := readCLIContract(t)
	var publicAPI *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "typescript-public-api-surfaces" {
			publicAPI = &contract.Commands[index]
			break
		}
	}
	if publicAPI == nil || publicAPI.InputContract == nil {
		t.Fatal("typescript-public-api-surfaces must expose its input topology contract")
	}
	inputContract := canonicalJSONValue(t, publicAPI.InputContract).(map[string]any)
	fields := inputContract["fields"].(map[string]any)
	entries := fields["entries"].(map[string]any)
	item := entries["item"].(map[string]any)
	required := stringsFromAny(item["requiredFields"].([]any))
	assertStringSet(t, required, []string{
		"exportConditions",
		"exportKey",
		"packageManifestPath",
		"packageName",
		"runtimeExports",
		"typeExports",
	}, "TypeScript public API required fields")
	pathAuthority := item["pathAuthority"].(string)
	if !strings.Contains(pathAuthority, "packageManifestPath") || !strings.Contains(pathAuthority, "sourcePath") || !strings.Contains(pathAuthority, "canonical resolved source target") {
		t.Fatalf("TypeScript public API path authority is incomplete: %q", pathAuthority)
	}
	if rule := item["exportConditionsRule"]; rule != "non-empty and sorted unique by condition" {
		t.Fatalf("TypeScript public API export condition rule=%v", rule)
	}
	budgets := inputContract["resourceBudgets"].(map[string]any)
	if budgets["maxSourceFileBytes"] != float64(maxSourceFileBytesForContractTest) ||
		budgets["maxPackageManifestBytes"] != float64(maxPackageManifestBytesForContractTest) ||
		budgets["maxAggregateFileReadBytes"] != float64(maxAggregateFileReadBytesForContractTest) {
		t.Fatalf("TypeScript public API resource budgets drifted: %#v", budgets)
	}
	grammar := inputContract["sourceGrammar"].(map[string]any)
	if grammar["grammarId"] != "proofkit.typescript-public-api.export-subset.v1" || grammar["mode"] != "fail_closed" {
		t.Fatalf("TypeScript public API source grammar is not fail-closed: %#v", grammar)
	}
	rejected := strings.Join(stringsFromAny(grammar["rejectedLexicalForms"].([]any)), " ")
	for _, required := range []string{"slash tokens outside comments", "template interpolation", "non-ASCII code identifiers", "unbalanced delimiters", "angle-bracket syntax"} {
		if !strings.Contains(rejected, required) {
			t.Fatalf("TypeScript public API source grammar omits %q: %s", required, rejected)
		}
	}
	nonClaims := stringsFromAny(inputContract["nonClaims"].([]any))
	joinedNonClaims := strings.Join(nonClaims, " ")
	if !strings.Contains(joinedNonClaims, "compiler output provenance") || !strings.Contains(joinedNonClaims, "does not parse JSX") || !strings.Contains(joinedNonClaims, "does not parse unrestricted TypeScript") {
		t.Fatalf("TypeScript public API input contract omits scanner non-claims: %v", nonClaims)
	}
}

func TestGenericCommandBuilderRegistryExactlyMatchesGenericDescriptors(t *testing.T) {
	want := commandNamesMatching(func(descriptor commandDescriptor) bool {
		return descriptor.runner == commandRunnerGenericInput
	})
	got := make([]string, 0, len(genericCommandBuilders))
	for command := range genericCommandBuilders {
		got = append(got, command)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("generic command builder registry=%v, want descriptor-owned commands=%v", got, want)
	}
}

func TestRequirementCoverageViewContractDescribesMachineClassifications(t *testing.T) {
	contract := readCLIContract(t)
	var coverage *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "requirement-coverage-view" {
			coverage = &contract.Commands[index]
			break
		}
	}
	if coverage == nil {
		t.Fatal("requirement-coverage-view missing from CLI contract")
	}
	if coverage.OutputContract == nil {
		t.Fatal("requirement-coverage-view must expose outputContract")
	}
	outputContract := canonicalJSONValue(t, coverage.OutputContract).(map[string]any)
	classificationRecords := outputContract["classificationRecords"].(map[string]any)
	failure := classificationRecords["failureClassifications"].(map[string]any)
	warning := classificationRecords["warningClassifications"].(map[string]any)
	if failure["sourceField"] != "failures" || failure["severity"] != "failure" {
		t.Fatalf("failure classification contract drift: %#v", failure)
	}
	if warning["sourceField"] != "warnings" || warning["severity"] != "warning" {
		t.Fatalf("warning classification contract drift: %#v", warning)
	}
	ids := stringsFromAny(outputContract["classificationIds"].([]any))
	assertStringSet(t, ids, []string{
		"declared_dead_zone",
		"failed_test_inventory",
		"missing_requirement_binding",
		"missing_declared_test_route",
		"nonsemantic_command_evidence",
		"nonsemantic_governance_evidence",
		"not_applicable_with_reason",
		"owner_scope_violation",
		"proof_route_candidate_only",
		"routing_smoke_only",
		"unclassified_gap",
		"unknown_reference",
	}, "requirement coverage classification ids")
}

func TestRequirementCoverageViewBreakingRootUsesVersionedOutputContract(t *testing.T) {
	contract := readCLIContract(t)
	definitions := cliContractDefinitionMap(t, contract.ContractDefinitions)
	for _, command := range contract.Commands {
		if command.Command != "requirement-coverage-view" {
			continue
		}
		output := canonicalJSONValue(t, command.OutputContract).(map[string]any)
		if output["contractId"] != "proofkit.requirement-coverage-view.output.v3" || output["schemaVersion"] != float64(3) {
			t.Fatalf("requirement coverage output identity=%#v, want versioned v3 contract", output)
		}
		definitionID := output["rootDefinitionRef"].(string)
		definition := definitions[definitionID]
		if definitionID != "proofkit.requirement-coverage-view.output.v3.root-shape" || definition["schemaVersion"] != float64(3) {
			t.Fatalf("requirement coverage root definition=%#v, want versioned v3 root", definition)
		}
		for _, rawVariant := range definition["fieldTree"].(map[string]any)["variants"].([]any) {
			variant := rawVariant.(map[string]any)
			required := stringsFromAny(variant["requiredFields"].([]any))
			if variant["variantId"] == "02-report" &&
				slices.Contains(required, "coverageBasis") &&
				slices.Contains(required, "unmappedTests") {
				return
			}
		}
		t.Fatal("requirement coverage v3 report root must require coverageBasis and unmappedTests")
	}
	t.Fatal("requirement-coverage-view missing from CLI contract")
}

func TestTestEvidenceInventoryContractDescribesMachineClassifications(t *testing.T) {
	contract := readCLIContract(t)
	var inventory *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "test-evidence-inventory" {
			inventory = &contract.Commands[index]
			break
		}
	}
	if inventory == nil {
		t.Fatal("test-evidence-inventory missing from CLI contract")
	}
	if inventory.OutputContract == nil {
		t.Fatal("test-evidence-inventory must expose outputContract")
	}
	outputContract := canonicalJSONValue(t, inventory.OutputContract).(map[string]any)
	classificationRecords := outputContract["classificationRecords"].(map[string]any)
	failure := classificationRecords["failureClassifications"].(map[string]any)
	warning := classificationRecords["warningClassifications"].(map[string]any)
	if failure["sourceDiagnosticKey"] != "failures" || failure["severity"] != "failure" {
		t.Fatalf("inventory failure classification contract drift: %#v", failure)
	}
	if warning["sourceDiagnosticKey"] != "warnings" || warning["severity"] != "warning" {
		t.Fatalf("inventory warning classification contract drift: %#v", warning)
	}
	qualityFindingFields := outputContract["qualityFindingFields"].(map[string]any)
	assertStringSet(t, sortedMapKeys(qualityFindingFields), []string{
		"class",
		"evidenceRefs",
		"findingId",
		"nonClaims",
		"ownerReviewState",
		"severity",
	}, "test evidence inventory quality finding fields")
	ids := stringsFromAny(outputContract["classificationIds"].([]any))
	assertStringSet(t, ids, []string{
		"candidate_only",
		"declared_duplicate_falsifier",
		"duplicate_falsifier_candidate",
		"empty_oracle",
		"fixture_leak_risk",
		"flaky_time",
		"implementation_mirror",
		"import_cost_leak",
		"invalid_falsifier_supersession",
		"missing_edge",
		"missing_executable_command_ref",
		"missing_declared_route_anchor",
		"mock_tests_mock",
		"over_broad_integration",
		"proof_route_candidate",
		"routing_smoke_only",
		"selector_fragility",
		"snapshot_without_oracle",
		"tautology",
		"unasserted_diagnostic",
		"incomplete_declared_oracle_metadata",
		"wrong_boundary",
		"wrong_evidence_boundary",
	}, "test evidence inventory classification ids")
}

func TestRequirementCoverageInputComposeContractDescribesDirectViewInput(t *testing.T) {
	contract := readCLIContract(t)
	var compose *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "requirement-coverage-input-compose" {
			compose = &contract.Commands[index]
			break
		}
	}
	if compose == nil {
		t.Fatal("requirement-coverage-input-compose missing from CLI contract")
	}
	if compose.OutputContract == nil {
		t.Fatal("requirement-coverage-input-compose must expose outputContract")
	}
	if compose.InputContract == nil {
		t.Fatal("requirement-coverage-input-compose must expose inputContract")
	}
	inputContract := canonicalJSONValue(t, compose.InputContract).(map[string]any)
	modes := inputContract["modes"].(map[string]any)
	normalized := modes["normalized"].(map[string]any)
	assertStringSet(t, stringsFromAny(normalized["requires"].([]any)), []string{
		"compactProofContract",
		"normalizedTestEvidenceInventory",
	}, "requirement coverage input compose normalized required fields")
	assertStringSet(t, stringsFromAny(normalized["forbids"].([]any)), []string{
		"requirementProofBinding",
		"testEvidenceInventory",
	}, "requirement coverage input compose normalized forbidden fields")
	direct := modes["direct"].(map[string]any)
	assertStringSet(t, stringsFromAny(direct["requires"].([]any)), []string{
		"requirementProofBinding",
		"testEvidenceInventory",
	}, "requirement coverage input compose direct required fields")
	assertStringSet(t, stringsFromAny(direct["forbids"].([]any)), []string{
		"compactProofContract",
		"normalizedTestEvidenceInventory",
	}, "requirement coverage input compose direct forbidden fields")
	if direct["admittedInventoryAuthority"] != "caller_owned_inventory" {
		t.Fatalf("direct admittedInventoryAuthority=%#v want caller_owned_inventory", direct["admittedInventoryAuthority"])
	}
	assertStringSet(t, stringsFromAny(direct["rejects"].([]any)), []string{
		"caller_owned_inventory_source_set",
		"caller_owned_test_discovery_candidate_inventory",
	}, "requirement coverage input compose direct rejected authorities")
	outputContract := canonicalJSONValue(t, compose.OutputContract).(map[string]any)
	fields := stringsFromAny(outputContract["requiredFields"].([]any))
	assertStringSet(t, fields, []string{
		"compactProofContract",
		"coverageUniverse",
		"localEnvironmentPolicy",
		"options",
		"ownerInvariantRegistry",
		"requirementProofBinding",
		"requirementSource",
		"schemaVersion",
		"testEvidenceInventory",
		"viewInputId",
	}, "requirement coverage input compose required fields")
	optionalFields := stringsFromAny(outputContract["optionalFields"].([]any))
	assertStringSet(t, optionalFields, []string{
		"normalizedTestEvidenceInventory",
	}, "requirement coverage input compose optional fields")
	if outputContract["provenanceRule"] == "" {
		t.Fatalf("requirement coverage input compose output contract must describe normalized provenance")
	}
}

func TestWitnessPlanContractDescribesBindingProjectionInput(t *testing.T) {
	contract := readCLIContract(t)
	var witnessPlan *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "witness-plan" {
			witnessPlan = &contract.Commands[index]
			break
		}
	}
	if witnessPlan == nil {
		t.Fatal("witness-plan missing from CLI contract")
	}
	if witnessPlan.InputContract == nil {
		t.Fatal("witness-plan must expose inputContract")
	}
	inputContract := canonicalJSONValue(t, witnessPlan.InputContract).(map[string]any)
	variants := inputContract["variants"].(map[string]any)
	bindingProjection := variants["requirement-bindings"].(map[string]any)
	assertStringSet(t, stringsFromAny(bindingProjection["requires"].([]any)), []string{
		"projection",
		"requirementProofBinding",
		"schemaVersion",
		"vocabulary",
	}, "witness-plan requirement-bindings required fields")
	assertStringSet(t, stringsFromAny(bindingProjection["admissionRules"].([]any)), []string{
		"requirementProofBinding must pass requirement-bindings admission",
		"vocabulary must pass witness command vocabulary admission",
		"binding-derived projection requires exactly one admitted parallelGroup; multi-group vocabularies require an explicit witness command catalog",
		"display command text must be display-only command text without shell control tokens, quoting, escaping, or secret-like tokens",
		"each referenced environment class must admit networkPolicy none, credentialClass none, and cachePolicy disabled",
	}, "witness-plan requirement-bindings admission rules")
}

func TestRequirementImpactInputComposeContractDescribesDirectImpactInput(t *testing.T) {
	contract := readCLIContract(t)
	var compose *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "requirement-impact-input-compose" {
			compose = &contract.Commands[index]
			break
		}
	}
	if compose == nil {
		t.Fatal("requirement-impact-input-compose missing from CLI contract")
	}
	if compose.OutputContract == nil {
		t.Fatal("requirement-impact-input-compose must expose outputContract")
	}
	outputContract := canonicalJSONValue(t, compose.OutputContract).(map[string]any)
	fields := stringsFromAny(outputContract["requiredFields"].([]any))
	assertStringSet(t, fields, []string{
		"baseCommit",
		"baseRef",
		"changedBindingRecordIds",
		"changedPaths",
		"changedRequirementIds",
		"changedWitnessPathCoverage",
		"generatedArtifactRules",
		"headCommit",
		"headRef",
		"ignoredProofLikePaths",
		"nonClaims",
		"obligationCatalog",
		"preexistingFailures",
		"proofLikePaths",
		"schemaVersion",
	}, "requirement impact input compose required fields")
}

func TestWorkspaceManifestFactsContractDescribesFactProjection(t *testing.T) {
	contract := readCLIContract(t)
	var workspace *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "workspace-manifest-facts" {
			workspace = &contract.Commands[index]
			break
		}
	}
	if workspace == nil {
		t.Fatal("workspace-manifest-facts missing from CLI contract")
	}
	if workspace.OutputContract == nil {
		t.Fatal("workspace-manifest-facts must expose outputContract")
	}
	outputContract := canonicalJSONValue(t, workspace.OutputContract).(map[string]any)
	fields := stringsFromAny(outputContract["requiredFields"].([]any))
	assertStringSet(t, fields, []string{
		"changedPackagePlanPackages",
		"diagnostics",
		"knownPackageNames",
		"manifestSources",
		"nonClaims",
		"packageUniverse",
		"packages",
		"projectionId",
		"reportId",
		"reportKind",
		"root",
		"schemaVersion",
		"shardPartitionPackages",
		"state",
		"summary",
	}, "workspace manifest facts required fields")
	records := outputContract["records"].(map[string]any)
	assertOutputRecordFields(t, records, "root", []string{"dependencyRefs", "name", "scripts"})
	assertOutputRecordFields(t, records, "package", []string{"dependencyRefs", "dirName", "name", "scripts"})
	assertOutputRecordFields(t, records, "script", []string{"command", "name"})
	assertOutputRecordFields(t, records, "dependencyRef", []string{"field", "name", "version"})
	assertOutputRecordFields(t, records, "rootManifestSource", []string{"manifestPath", "name", "packageDir"})
	assertOutputRecordFields(t, records, "packageManifestSource", []string{"dirName", "manifestPath", "name", "packageDir"})
	assertOutputRecordFields(t, records, "workspaceDependencyEdge", []string{"field", "fromKind", "fromName", "toName", "version"})
	assertOutputRecordFields(t, records, "changedPackagePlanPackage", []string{"dirName", "name", "workspaceDependencies"})
	assertOutputRecordFields(t, records, "shardPartitionPackage", []string{"name", "workspaceDependencies"})
}

func assertOutputRecordFields(t *testing.T, records map[string]any, recordName string, expected []string) {
	t.Helper()
	record, ok := records[recordName].(map[string]any)
	if !ok {
		t.Fatalf("output record %s missing", recordName)
	}
	fields := stringsFromAny(record["requiredFields"].([]any))
	assertStringSet(t, fields, expected, recordName+" required fields")
}

func TestAgentRouteInputContractMatchesAdmission(t *testing.T) {
	contract := readCLIContract(t)
	var route *cliContractCommand
	for index := range contract.Commands {
		if contract.Commands[index].Command == "agent-route" {
			route = &contract.Commands[index]
			break
		}
	}
	if route == nil {
		t.Fatal("agent-route missing from CLI contract")
	}
	if route.InputContract == nil {
		t.Fatal("agent-route must expose inputContract")
	}
	if route.OutputContract == nil {
		t.Fatal("agent-route must expose its versioned output contract")
	}
	got := commandOwnedContractProjection(t, route.InputContract)
	want := canonicalJSONValue(t, agentroute.InputContract())
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("agent-route input contract drift\ngot:  %#v\nwant: %#v", got, want)
	}
	gotOutput := commandOwnedContractProjection(t, route.OutputContract)
	wantOutput := canonicalJSONValue(t, agentroute.OutputContract())
	if !reflect.DeepEqual(gotOutput, wantOutput) {
		t.Fatalf("agent-route output contract drift\ngot:  %#v\nwant: %#v", gotOutput, wantOutput)
	}
}

func TestAgentRouteOutputContractPreservesReportSemantics(t *testing.T) {
	contract := readCLIContract(t)
	var output map[string]any
	for _, command := range contract.Commands {
		if command.Command == "agent-route" {
			output = canonicalJSONValue(t, command.OutputContract).(map[string]any)
			break
		}
	}
	if output == nil {
		t.Fatal("agent-route output contract is missing")
	}
	report, ok := output["reportContract"].(map[string]any)
	if !ok || report["contractId"] != "proofkit.agent-route.report.v3" || report["schemaVersion"] != float64(3) {
		t.Fatalf("agent-route report contract identity is invalid: %#v", report)
	}
	assertStringSet(t, stringsFromAny(report["requiredFields"].([]any)), []string{
		"guidanceSlice", "reportId", "reportKind", "schemaVersion", "selectedRouteFamily", "state", "summary",
	}, "agent-route report contract required fields")
	fields := report["fields"].(map[string]any)
	if fields["schemaVersion"].(map[string]any)["value"] != float64(3) {
		t.Fatalf("agent-route report schema value drifted: %#v", fields["schemaVersion"])
	}
	family := fields["selectedRouteFamily"].(map[string]any)
	assertStringSet(t, stringsFromAny(family["enum"].([]any)), []string{
		"adoption", "migration", "release_and_deployment", "rendered_views", "repository_structure", "requirement_proof_binding", "requirement_source", "selective_evidence", "selective_planning", "test_inventory_and_coverage", "unknown",
	}, "agent-route report route families")
	guidance := fields["guidanceSlice"].(map[string]any)
	if guidance["routeFamilyRule"] != "must equal selectedRouteFamily" {
		t.Fatalf("agent-route guidance relation drifted: %#v", guidance)
	}
	summary := fields["summary"].(map[string]any)
	if summary["availableCommandCount"] != "exact count before blocked-state command suppression" || summary["launcherProfile"] != "exact admitted command-renderer profile that affects route argv and report identity" {
		t.Fatalf("agent-route report summary contract drifted: %#v", summary)
	}
}

func commandOwnedContractProjection(t *testing.T, value any) any {
	t.Helper()
	record := canonicalJSONValue(t, value).(map[string]any)
	for _, key := range []string{
		"closed",
		"compatibilitySummary",
		"nativeAdmissionWitnessSelector",
		"nativeOutputWitnessSelector",
		"nativeSource",
		"nativeSources",
		"ownerRequirementRefs",
		"rootDefinitionDigest",
		"rootDefinitionRef",
		"rootType",
	} {
		delete(record, key)
	}
	return record
}

func canonicalJSONValue(t *testing.T, value any) any {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("unmarshal value: %v", err)
	}
	return decoded
}

func stringsFromAny(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, _ := value.(string)
		result = append(result, text)
	}
	return result
}

func assertCommand(t *testing.T, command cliContractCommand, input string, flags []string, modes []string) {
	t.Helper()
	if command.Command == "" {
		t.Fatal("command missing from contract")
	}
	if command.Input != input {
		t.Fatalf("%s input=%s want %s", command.Command, command.Input, input)
	}
	if !equalStrings(command.AllowedFlags, flags) {
		t.Fatalf("%s flags=%v want %v", command.Command, command.AllowedFlags, flags)
	}
	if !equalStrings(command.OutputModes, modes) {
		t.Fatalf("%s modes=%v want %v", command.Command, command.OutputModes, modes)
	}
}

func assertScopeClass(t *testing.T, command cliContractCommand, scopeClass commandScopeClass) {
	t.Helper()
	if command.ScopeClass != string(scopeClass) {
		t.Fatalf("%s scopeClass=%s want %s", command.Command, command.ScopeClass, scopeClass)
	}
}

func assertSortedUnique(t *testing.T, values []string, context string) {
	t.Helper()
	for index := range values {
		if values[index] == "" {
			t.Fatalf("%s contains empty item", context)
		}
		if index > 0 && values[index-1] >= values[index] {
			t.Fatalf("%s must be sorted and unique: %v", context, values)
		}
	}
}

func assertKeys(t *testing.T, context string, got []string, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if !equalStrings(got, want) {
		t.Fatalf("%s keys=%v want %v", context, got, want)
	}
}

func keys(record map[string]json.RawMessage) []string {
	result := make([]string, 0, len(record))
	for key := range record {
		result = append(result, key)
	}
	return result
}

func keysAny(record map[string]any) []string {
	result := make([]string, 0, len(record))
	for key := range record {
		result = append(result, key)
	}
	return result
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalStringSets(left []string, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	return equalStrings(left, right)
}

func equalFlagChoiceMaps(left map[string][]string, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for flag, choices := range left {
		if !slices.Equal(choices, right[flag]) {
			return false
		}
	}
	return true
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
