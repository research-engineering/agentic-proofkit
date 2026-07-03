package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

const outputPath = "artifacts/proofkit/coverage-metrics.json"

var commandCoverageInventoryInput = app.CommandCoverageInventory

type requirementSource struct {
	Requirements []requirementRecord `json:"requirements"`
	SourceID     string              `json:"sourceId"`
}

type requirementRecord struct {
	ClaimLevel    string    `json:"claimLevel"`
	Lifecycle     lifecycle `json:"lifecycle"`
	RequirementID string    `json:"requirementId"`
}

type lifecycle struct {
	State string `json:"state"`
}

type bindingFile struct {
	Requirements []bindingRequirement `json:"requirements"`
	Bindings     []bindingScenario    `json:"bindings"`
}

type bindingRequirement struct {
	ClaimLevel    string `json:"claimLevel"`
	ProofState    string `json:"proofState"`
	RequirementID string `json:"requirementId"`
	SpecPath      string `json:"specPath"`
}

type bindingScenario struct {
	CommandIDs    []string `json:"commandIds"`
	RequirementID string   `json:"requirementId"`
	ScenarioID    string   `json:"scenarioId"`
	WitnessID     string   `json:"witnessId"`
}

type witnessPlan struct {
	Commands []struct {
		ID string `json:"id"`
	} `json:"commands"`
}

type cliContract struct {
	Commands []struct {
		Command string `json:"command"`
	} `json:"commands"`
}

type metrics struct {
	ArtifactKind  string              `json:"artifactKind"`
	SchemaVersion int                 `json:"schemaVersion"`
	Requirements  requirementMetrics  `json:"requirements"`
	ProofBindings proofBindingMetrics `json:"proofBindings"`
	WitnessPlan   witnessPlanMetrics  `json:"witnessPlan"`
	CLIContract   cliContractMetrics  `json:"cliContract"`
	CommandRoutes commandRouteMetrics `json:"commandRoutes"`
	DeadZones     deadZoneMetrics     `json:"deadZones"`
	NonClaims     []string            `json:"nonClaims"`
}

type requirementMetrics struct {
	Active       int `json:"active"`
	Blocking     int `json:"blocking"`
	SourceFiles  int `json:"sourceFiles"`
	TotalRecords int `json:"totalRecords"`
}

type proofBindingMetrics struct {
	BoundRequirementCount         int `json:"boundRequirementCount"`
	ScenarioCount                 int `json:"scenarioCount"`
	WitnessBackedRequirementCount int `json:"witnessBackedRequirementCount"`
}

type witnessPlanMetrics struct {
	CommandCount int `json:"commandCount"`
}

type cliContractMetrics struct {
	CommandCount int `json:"commandCount"`
}

type commandRouteMetrics struct {
	AdmittedInventoryEntryCount               int      `json:"admittedInventoryEntryCount"`
	CommandCount                              int      `json:"commandCount"`
	ContractOnlyCommandCount                  int      `json:"contractOnlyCommandCount"`
	ContractOnlyCommands                      []string `json:"contractOnlyCommands"`
	CommandWithoutSemanticFalsifierRouteCount int      `json:"commandWithoutSemanticFalsifierRouteCount"`
	CommandsWithoutSemanticFalsifierRoute     []string `json:"commandsWithoutSemanticFalsifierRoute"`
	RouteCount                                int      `json:"routeCount"`
	RouteOnlyCommandCount                     int      `json:"routeOnlyCommandCount"`
	RouteOnlyCommands                         []string `json:"routeOnlyCommands"`
	RouteSmokeCount                           int      `json:"routeSmokeCount"`
	SemanticInventoryEntryCount               int      `json:"semanticInventoryEntryCount"`
	SemanticRouteCount                        int      `json:"semanticRouteCount"`
	UnknownSemanticCommandRefs                []string `json:"unknownSemanticCommandRefs"`
	UnknownSemanticCommandRefCount            int      `json:"unknownSemanticCommandRefCount"`
}

type deadZoneMetrics struct {
	BindingWithoutRequirementIDs  []string `json:"bindingWithoutRequirementIds"`
	RequirementWithoutBindingIDs  []string `json:"requirementWithoutBindingIds"`
	ScenarioWithoutCommandIDs     []string `json:"scenarioWithoutCommandIds"`
	ScenarioWithoutRequirementIDs []string `json:"scenarioWithoutRequirementIds"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	requirements, err := readRequirements()
	if err != nil {
		return err
	}
	bindings, err := readJSON[bindingFile]("proofkit/requirement-bindings.json")
	if err != nil {
		return err
	}
	witnesses, err := readJSON[witnessPlan]("proofkit/witness-plan.json")
	if err != nil {
		return err
	}
	contract, err := readJSON[cliContract]("proofkit/cli-contract.v1.json")
	if err != nil {
		return err
	}
	commandInventory, err := readCommandCoverageInventory()
	if err != nil {
		out := buildMetrics(requirements, bindings, witnesses, contract, testevidenceinventory.Inventory{})
		return writeMetrics(out, err)
	}
	out := buildMetrics(requirements, bindings, witnesses, contract, commandInventory)
	closeoutErr := errors.Join(
		requireCommandSemanticFalsifierRoutes(out.CommandRoutes),
		requireNoLinkageDeadZones(out.DeadZones),
	)
	return writeMetrics(out, closeoutErr)
}

func writeMetrics(out metrics, routeErr error) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	content, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, append(content, '\n'), 0o644); err != nil {
		return err
	}
	if routeErr != nil {
		return routeErr
	}
	fmt.Printf("coverage metrics: requirements=%d bound=%d scenarios=%d commands=%d\n",
		out.Requirements.TotalRecords,
		out.ProofBindings.BoundRequirementCount,
		out.ProofBindings.ScenarioCount,
		out.CLIContract.CommandCount,
	)
	return nil
}

func readRequirements() ([]requirementRecord, error) {
	paths, err := filepath.Glob("docs/specs/*/requirements.v1.json")
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no requirement source files found")
	}
	sort.Strings(paths)
	out := []requirementRecord{}
	for _, path := range paths {
		raw, err := readAnyJSON(path)
		if err != nil {
			return nil, err
		}
		result, err := requirementsourceadmission.Evaluate(raw)
		if err != nil {
			return nil, fmt.Errorf("%s requirement source admission failed: %w", path, err)
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("%s requirement source admission failed: %v", path, result.Failures)
		}
		if filepath.ToSlash(path) != result.Source.RequirementsPath {
			return nil, fmt.Errorf("%s requirement source requirementsPath must match the source file path", path)
		}
		for _, requirement := range result.Source.Requirements {
			out = append(out, requirementRecord{
				ClaimLevel:    requirement.ClaimLevel,
				Lifecycle:     lifecycle{State: requirement.Lifecycle.State},
				RequirementID: requirement.RequirementID,
			})
		}
	}
	return out, nil
}

func readAnyJSON(path string) (any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	out, err := admission.DecodeJSON(file, 16<<20)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return out, nil
}

func readJSON[T any](path string) (T, error) {
	var out T
	file, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer file.Close()
	out, err = admission.DecodeTypedJSON[T](file, 16<<20)
	if err != nil {
		return out, fmt.Errorf("decode %s: %w", path, err)
	}
	return out, nil
}

func buildMetrics(requirements []requirementRecord, bindings bindingFile, witnesses witnessPlan, contract cliContract, commandInventory testevidenceinventory.Inventory) metrics {
	requirementIDs := map[string]struct{}{}
	active := 0
	blocking := 0
	for _, requirement := range requirements {
		requirementIDs[requirement.RequirementID] = struct{}{}
		if requirement.Lifecycle.State == "active" {
			active++
		}
		if requirement.ClaimLevel == "blocking" {
			blocking++
		}
	}
	boundIDs := map[string]struct{}{}
	witnessBacked := map[string]struct{}{}
	bindingWithoutRequirement := []string{}
	for _, binding := range bindings.Requirements {
		boundIDs[binding.RequirementID] = struct{}{}
		if _, ok := requirementIDs[binding.RequirementID]; !ok {
			bindingWithoutRequirement = append(bindingWithoutRequirement, binding.RequirementID)
		}
		if binding.ProofState == "witness_backed" {
			witnessBacked[binding.RequirementID] = struct{}{}
		}
	}
	requirementWithoutBinding := []string{}
	for id := range requirementIDs {
		if _, ok := boundIDs[id]; !ok {
			requirementWithoutBinding = append(requirementWithoutBinding, id)
		}
	}
	commandIDs := map[string]struct{}{}
	for _, command := range witnesses.Commands {
		commandIDs[command.ID] = struct{}{}
	}
	scenarioWithoutCommand := []string{}
	scenarioWithoutRequirement := []string{}
	for _, scenario := range bindings.Bindings {
		if _, ok := requirementIDs[scenario.RequirementID]; !ok {
			scenarioWithoutRequirement = append(scenarioWithoutRequirement, scenario.ScenarioID)
		}
		for _, commandID := range scenario.CommandIDs {
			if _, ok := commandIDs[commandID]; !ok {
				scenarioWithoutCommand = append(scenarioWithoutCommand, scenario.ScenarioID)
				break
			}
		}
	}
	sort.Strings(bindingWithoutRequirement)
	sort.Strings(requirementWithoutBinding)
	sort.Strings(scenarioWithoutCommand)
	sort.Strings(scenarioWithoutRequirement)
	commandRoutes := buildCommandRouteMetrics(contract, app.CommandCoverageSummaries(), commandInventory)
	return metrics{
		ArtifactKind:  "proofkit.coverage-metrics.v1",
		SchemaVersion: 1,
		Requirements: requirementMetrics{
			Active:       active,
			Blocking:     blocking,
			SourceFiles:  requirementSourceCount(),
			TotalRecords: len(requirements),
		},
		ProofBindings: proofBindingMetrics{
			BoundRequirementCount:         len(boundIDs),
			ScenarioCount:                 len(bindings.Bindings),
			WitnessBackedRequirementCount: len(witnessBacked),
		},
		WitnessPlan:   witnessPlanMetrics{CommandCount: len(commandIDs)},
		CLIContract:   cliContractMetrics{CommandCount: len(contract.Commands)},
		CommandRoutes: commandRoutes,
		DeadZones: deadZoneMetrics{
			BindingWithoutRequirementIDs:  bindingWithoutRequirement,
			RequirementWithoutBindingIDs:  requirementWithoutBinding,
			ScenarioWithoutCommandIDs:     scenarioWithoutCommand,
			ScenarioWithoutRequirementIDs: scenarioWithoutRequirement,
		},
		NonClaims: []string{
			"Coverage metrics report explicit requirement, binding, witness, and CLI inventory linkage only.",
			"Coverage metrics report command semantic-route inventory but do not execute those tests or claim exhaustive test semantic completeness.",
			"Coverage metrics do not claim line coverage, semantic correctness, command execution, receipt freshness, or merge satisfaction.",
		},
	}
}

func readCommandCoverageInventory() (testevidenceinventory.Inventory, error) {
	raw, err := commandCoverageInventoryInput()
	if err != nil {
		return testevidenceinventory.Inventory{}, fmt.Errorf("command coverage route inventory failed: %w", err)
	}
	return readCommandCoverageInventoryFrom(raw)
}

func readCommandCoverageInventoryFrom(raw any) (testevidenceinventory.Inventory, error) {
	result, err := testevidenceinventory.Evaluate(raw)
	if err != nil {
		return testevidenceinventory.Inventory{}, fmt.Errorf("command coverage inventory admission failed: %w", err)
	}
	if result.ExitCode != 0 {
		return testevidenceinventory.Inventory{}, fmt.Errorf("command coverage inventory admission failed: %v", result.Failures)
	}
	return result.Inventory, nil
}

func buildCommandRouteMetrics(contract cliContract, summaries []app.CommandCoverageSummary, inventory testevidenceinventory.Inventory) commandRouteMetrics {
	missing := []string{}
	contractRefs := map[string]string{}
	knownRefs := map[string]struct{}{}
	semanticRefs := map[string]struct{}{}
	routeOnlyCount := 0
	semanticEntryCount := 0
	for _, command := range contract.Commands {
		contractRefs[app.CommandCoverageCommandRef(command.Command)] = command.Command
	}
	for _, summary := range summaries {
		knownRefs[summary.CommandRef] = struct{}{}
	}
	for _, entry := range inventory.Entries {
		switch entry.EvidenceClass {
		case "semantic_falsifier":
			semanticEntryCount++
			for _, commandRef := range entry.CommandRefs {
				semanticRefs[commandRef] = struct{}{}
			}
		case "routing_smoke_nonclaim":
			routeOnlyCount++
		}
	}
	unknownRefs := []string{}
	for ref := range semanticRefs {
		if _, ok := knownRefs[ref]; !ok {
			unknownRefs = append(unknownRefs, ref)
		}
	}
	contractOnly := []string{}
	for ref, command := range contractRefs {
		if _, ok := knownRefs[ref]; !ok {
			contractOnly = append(contractOnly, command)
		}
	}
	routeOnly := []string{}
	for _, summary := range summaries {
		if _, ok := contractRefs[summary.CommandRef]; !ok {
			routeOnly = append(routeOnly, summary.Command)
		}
	}
	sort.Strings(contractOnly)
	sort.Strings(routeOnly)
	sort.Strings(unknownRefs)
	out := commandRouteMetrics{
		AdmittedInventoryEntryCount:    len(inventory.Entries),
		CommandCount:                   len(summaries),
		ContractOnlyCommands:           contractOnly,
		ContractOnlyCommandCount:       len(contractOnly),
		RouteOnlyCommands:              routeOnly,
		RouteOnlyCommandCount:          len(routeOnly),
		RouteSmokeCount:                routeOnlyCount,
		SemanticInventoryEntryCount:    semanticEntryCount,
		UnknownSemanticCommandRefs:     unknownRefs,
		UnknownSemanticCommandRefCount: len(unknownRefs),
	}
	for _, summary := range summaries {
		out.RouteCount += summary.RouteCount
		out.SemanticRouteCount += summary.SemanticRouteCount
		if _, ok := semanticRefs[summary.CommandRef]; !ok {
			missing = append(missing, summary.Command)
		}
	}
	sort.Strings(missing)
	out.CommandsWithoutSemanticFalsifierRoute = missing
	out.CommandWithoutSemanticFalsifierRouteCount = len(missing)
	return out
}

func requireCommandSemanticFalsifierRoutes(metrics commandRouteMetrics) error {
	if len(metrics.CommandsWithoutSemanticFalsifierRoute) == 0 &&
		len(metrics.UnknownSemanticCommandRefs) == 0 &&
		len(metrics.ContractOnlyCommands) == 0 &&
		len(metrics.RouteOnlyCommands) == 0 {
		return nil
	}
	return fmt.Errorf("command semantic falsifier route defects: missing=%v unknownRefs=%v contractOnly=%v routeOnly=%v",
		metrics.CommandsWithoutSemanticFalsifierRoute,
		metrics.UnknownSemanticCommandRefs,
		metrics.ContractOnlyCommands,
		metrics.RouteOnlyCommands,
	)
}

func requireNoLinkageDeadZones(metrics deadZoneMetrics) error {
	if len(metrics.BindingWithoutRequirementIDs) == 0 &&
		len(metrics.RequirementWithoutBindingIDs) == 0 &&
		len(metrics.ScenarioWithoutCommandIDs) == 0 &&
		len(metrics.ScenarioWithoutRequirementIDs) == 0 {
		return nil
	}
	return fmt.Errorf("coverage metrics contain requirement/proof linkage dead zones: bindingWithoutRequirement=%v requirementWithoutBinding=%v scenarioWithoutCommand=%v scenarioWithoutRequirement=%v",
		metrics.BindingWithoutRequirementIDs,
		metrics.RequirementWithoutBindingIDs,
		metrics.ScenarioWithoutCommandIDs,
		metrics.ScenarioWithoutRequirementIDs,
	)
}

func requirementSourceCount() int {
	paths, err := filepath.Glob("docs/specs/*/requirements.v1.json")
	if err != nil {
		return 0
	}
	return len(paths)
}
