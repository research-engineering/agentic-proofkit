package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/gotestsource"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/commandoracle"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
)

const outputPath = "artifacts/proofkit/coverage-metrics.json"

var commandCoverageInventoryInput = app.CommandCoverageInventory
var commandOracleExecute = commandoracle.Execute
var commandOracleInvalidateDiagnostic = commandoracle.InvalidateDiagnostic
var commandOracleValidateCurrent = commandoracle.ValidateCurrent
var commandOracleWriteDiagnostic = commandoracle.WriteDiagnostic

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
	CommandIDs         []string          `json:"commandIds"`
	EnvironmentClasses []string          `json:"environmentClasses"`
	RequirementID      string            `json:"requirementId"`
	ScenarioID         string            `json:"scenarioId"`
	WitnessID          string            `json:"witnessId"`
	WitnessPath        string            `json:"witnessPath"`
	WitnessSelectors   []witnessSelector `json:"witnessSelectors"`
}

type witnessSelector struct {
	Command  string `json:"command"`
	Selector string `json:"selector"`
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
	Provenance    coverageProvenance  `json:"provenance"`
}

type coverageProvenance struct {
	GeneratedAt          string `json:"generatedAt"`
	ProducerCommandID    string `json:"producerCommandId"`
	SourceRevision       string `json:"sourceRevision"`
	SourceSnapshotDigest string `json:"sourceSnapshotDigest"`
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
	CommandCount int      `json:"commandCount"`
	Commands     []string `json:"commands"`
}

type commandRouteMetrics struct {
	AdmittedInventoryEntryCount                        int      `json:"admittedInventoryEntryCount"`
	CommandCount                                       int      `json:"commandCount"`
	Commands                                           []string `json:"commands"`
	CommandWithoutProofRouteCandidateCount             int      `json:"commandWithoutProofRouteCandidateCount"`
	CommandsWithoutProofRouteCandidate                 []string `json:"commandsWithoutProofRouteCandidate"`
	ContractOnlyCommandCount                           int      `json:"contractOnlyCommandCount"`
	ContractOnlyCommands                               []string `json:"contractOnlyCommands"`
	CommandWithoutDeclaredSemanticFalsifierRouteCount  int      `json:"commandWithoutDeclaredSemanticFalsifierRouteCount"`
	CommandsWithoutDeclaredSemanticFalsifierRoute      []string `json:"commandsWithoutDeclaredSemanticFalsifierRoute"`
	RouteCount                                         int      `json:"routeCount"`
	RouteOnlyCommandCount                              int      `json:"routeOnlyCommandCount"`
	RouteOnlyCommands                                  []string `json:"routeOnlyCommands"`
	RouteSmokeCount                                    int      `json:"routeSmokeCount"`
	ProofRouteCandidateInventoryEntryCount             int      `json:"proofRouteCandidateInventoryEntryCount"`
	ProofRouteCandidateRouteCount                      int      `json:"proofRouteCandidateRouteCount"`
	DeclaredSemanticFalsifierRouteEntryCount           int      `json:"declaredSemanticFalsifierRouteEntryCount"`
	UnknownProofRouteCandidateRefs                     []string `json:"unknownProofRouteCandidateRefs"`
	UnknownProofRouteCandidateRefCount                 int      `json:"unknownProofRouteCandidateRefCount"`
	UnknownDeclaredSemanticRouteCommandRefs            []string `json:"unknownDeclaredSemanticRouteCommandRefs"`
	UnknownDeclaredSemanticRouteCommandRefCount        int      `json:"unknownDeclaredSemanticRouteCommandRefCount"`
	CommandOracleCandidateSetDigest                    string   `json:"commandOracleCandidateSetDigest"`
	CommandOracleCounterfeitCorpusDigest               string   `json:"commandOracleCounterfeitCorpusDigest"`
	CommandOracleRecordDigest                          string   `json:"commandOracleRecordDigest"`
	CommandOracleSourceSnapshotDigest                  string   `json:"commandOracleSourceSnapshotDigest"`
	CommandWithoutExecutionBackedSemanticRouteCount    int      `json:"commandWithoutExecutionBackedSemanticRouteCount"`
	CommandsWithoutExecutionBackedSemanticRoute        []string `json:"commandsWithoutExecutionBackedSemanticRoute"`
	ExecutionBackedSemanticRouteEntryCount             int      `json:"executionBackedSemanticRouteEntryCount"`
	UnknownExecutionBackedSemanticRouteCommandRefCount int      `json:"unknownExecutionBackedSemanticRouteCommandRefCount"`
	UnknownExecutionBackedSemanticRouteCommandRefs     []string `json:"unknownExecutionBackedSemanticRouteCommandRefs"`
}

type commandExecutionSummary struct {
	CandidateCount          int
	CandidateSetDigest      string
	CommandRefs             []string
	CounterfeitCorpusDigest string
	RecordDigest            string
	SourceSnapshotDigest    string
}

type deadZoneMetrics struct {
	BindingWithoutRequirementIDs  []string `json:"bindingWithoutRequirementIds"`
	RequirementWithoutBindingIDs  []string `json:"requirementWithoutBindingIds"`
	ScenarioWithoutCommandIDs     []string `json:"scenarioWithoutCommandIds"`
	ScenarioWithoutRequirementIDs []string `json:"scenarioWithoutRequirementIds"`
}

func main() {
	if err := run(); err != nil {
		diagnostic.WriteError(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if err := invalidateExecutionMetrics(); err != nil {
		return err
	}
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
	contract, err := readJSON[cliContract]("proofkit/cli-contract.v2.json")
	if err != nil {
		return err
	}
	commandInventory, err := readCommandCoverageInventory()
	if err != nil {
		out := buildMetrics(requirements, bindings, witnesses, contract, testevidenceinventory.Inventory{})
		return writeMetrics(out, err)
	}
	executionEvidence, err := commandOracleExecute(context.Background(), ".")
	if err != nil {
		out := buildMetrics(requirements, bindings, witnesses, contract, commandInventory)
		if provenanceErr := bindCurrentSourceProvenance(&out); provenanceErr != nil {
			err = errors.Join(err, provenanceErr)
		}
		return writeMetrics(out, err)
	}
	out := buildMetricsWithExecution(requirements, bindings, witnesses, contract, commandInventory, commandExecutionSummaryFromEvidence(executionEvidence))
	bindCommandOracleProvenance(&out, executionEvidence)
	closeoutErr := errors.Join(
		requireCommandRouteInventoryClosure(out.CommandRoutes),
		requireNoLinkageDeadZones(out.DeadZones),
		validateBindingWitnessSelectorsAtRoot(".", bindings),
	)
	if closeoutErr != nil {
		return writeMetrics(out, closeoutErr)
	}
	return writeCurrentExecutionMetrics(context.Background(), out, executionEvidence)
}

func commandExecutionSummaryFromEvidence(evidence commandoracle.Evidence) commandExecutionSummary {
	return commandExecutionSummary{
		CandidateCount:          len(evidence.Candidates),
		CandidateSetDigest:      evidence.Record.CandidateSetDigest,
		CommandRefs:             commandoracle.ExecutionCommandRefs(evidence),
		CounterfeitCorpusDigest: evidence.Record.CounterfeitCorpusDigest,
		RecordDigest:            evidence.RecordDigest,
		SourceSnapshotDigest:    evidence.Record.SourceSnapshotDigest,
	}
}

func validateBindingWitnessSelectorsAtRoot(root string, bindings bindingFile) error {
	if err := validateRequiredBindingWitnessSelectors(bindings); err != nil {
		return err
	}
	return validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings)
}

func validateRequiredBindingWitnessSelectors(bindings bindingFile) error {
	required := requiredBindingWitnessInventory()
	seenRequired := map[inventoryKey]struct{}{}
	for _, binding := range bindings.Bindings {
		key := inventoryKey{requirementID: binding.RequirementID, scenarioID: binding.ScenarioID}
		want, isRequired := required[key]
		if strings.HasPrefix(binding.RequirementID, "REQ-PROOFKIT-WORKFLOW-") && !isRequired {
			return fmt.Errorf("workflow binding is absent from the exact independent-falsifier inventory: %s/%s", binding.RequirementID, binding.ScenarioID)
		}
		if !isRequired {
			continue
		}
		if _, duplicate := seenRequired[key]; duplicate {
			return fmt.Errorf("required independent-falsifier binding is duplicated: %s/%s", binding.RequirementID, binding.ScenarioID)
		}
		if binding.WitnessPath != want.witnessPath {
			return fmt.Errorf("binding %s witness path=%q, want exact %q", binding.ScenarioID, binding.WitnessPath, want.witnessPath)
		}
		if want.commandIDs != nil && !equalStrings(binding.CommandIDs, want.commandIDs) {
			return fmt.Errorf("binding %s commandIds=%v, want exact %v", binding.ScenarioID, binding.CommandIDs, want.commandIDs)
		}
		if want.environmentClasses != nil && !equalStrings(binding.EnvironmentClasses, want.environmentClasses) {
			return fmt.Errorf("binding %s environmentClasses=%v, want exact %v", binding.ScenarioID, binding.EnvironmentClasses, want.environmentClasses)
		}
		seenRequired[key] = struct{}{}
		got := make([]string, 0, len(binding.WitnessSelectors))
		for _, selector := range binding.WitnessSelectors {
			got = append(got, selector.Selector)
		}
		sort.Strings(got)
		if !equalStrings(got, want.selectors) {
			return fmt.Errorf("binding %s witness selectors=%v, want %v", binding.ScenarioID, got, want.selectors)
		}
	}
	for key := range required {
		if _, ok := seenRequired[key]; !ok {
			return fmt.Errorf("required independent-falsifier binding is missing: %s/%s", key.requirementID, key.scenarioID)
		}
	}
	return nil
}

func validateBindingWitnessSelectorExecutabilityAtRoot(root string, bindings bindingFile) error {
	activeWitnessPackages := map[string]map[string]struct{}{}
	packageFunctionScopes := map[string]map[string]*ast.FuncDecl{}
	for _, binding := range bindings.Bindings {
		if len(binding.WitnessSelectors) == 0 {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(binding.WitnessPath))
		source, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse binding witness %s: %w", binding.WitnessPath, err)
		}
		witnessFunctions := map[string]*ast.FuncDecl{}
		for _, declaration := range source.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil {
				witnessFunctions[function.Name.Name] = function
			}
		}
		testingAliases, dotImportedTesting := importedTestingNames(source)
		packagePath := "./" + filepath.ToSlash(filepath.Dir(binding.WitnessPath))
		for _, selector := range binding.WitnessSelectors {
			function, ok := witnessFunctions[selector.Selector]
			if !ok {
				return fmt.Errorf("binding %s selector %s is missing from %s", binding.ScenarioID, selector.Selector, binding.WitnessPath)
			}
			if !validGoTestFunction(function, testingAliases, dotImportedTesting) {
				return fmt.Errorf("binding %s selector %s is not a valid Go test function", binding.ScenarioID, selector.Selector)
			}
			expectedCommand := fmt.Sprintf("go test %s -run '^%s$'", packagePath, selector.Selector)
			if selector.Command != expectedCommand {
				return fmt.Errorf("binding %s selector command=%q, want %q", binding.ScenarioID, selector.Command, expectedCommand)
			}
		}
		if !strings.HasSuffix(binding.WitnessPath, "_test.go") {
			return fmt.Errorf("binding %s witness %s must be an active _test.go file", binding.ScenarioID, binding.WitnessPath)
		}
		activeFiles, checked := activeWitnessPackages[packagePath]
		if !checked {
			activeFiles, err = activeGoTestFiles(root, packagePath)
			if err != nil {
				return fmt.Errorf("discover binding witness %s: %w", binding.WitnessPath, err)
			}
			activeWitnessPackages[packagePath] = activeFiles
		}
		witnessAbsolute, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(binding.WitnessPath)))
		if err != nil {
			return err
		}
		if _, active := activeFiles[filepath.Clean(witnessAbsolute)]; !active {
			return fmt.Errorf("binding %s witness %s is not active for the current Go build", binding.ScenarioID, binding.WitnessPath)
		}
		scopeKey := packagePath + ":" + source.Name.Name
		functionScope, scoped := packageFunctionScopes[scopeKey]
		if !scoped {
			functionScope, err = activePackageFunctions(activeFiles, source.Name.Name)
			if err != nil {
				return fmt.Errorf("parse active package functions for %s: %w", binding.WitnessPath, err)
			}
			packageFunctionScopes[scopeKey] = functionScope
		}
		for _, selector := range binding.WitnessSelectors {
			function := witnessFunctions[selector.Selector]
			if gotestsource.HasSkip(function) {
				return fmt.Errorf("binding %s selector %s contains t.Skip and cannot serve as an always-executable witness", binding.ScenarioID, selector.Selector)
			}
			if !gotestsource.HasFailureCapableAssertionCandidate(function, functionScope) {
				return fmt.Errorf("binding %s selector %s has no failure-capable assertion candidate", binding.ScenarioID, selector.Selector)
			}
		}
	}
	return nil
}

func activePackageFunctions(activeFiles map[string]struct{}, packageName string) (map[string]*ast.FuncDecl, error) {
	paths := make([]string, 0, len(activeFiles))
	for path := range activeFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	functions := map[string]*ast.FuncDecl{}
	for _, path := range paths {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return nil, err
		}
		if file.Name.Name != packageName {
			continue
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil {
				functions[function.Name.Name] = function
			}
		}
	}
	return functions, nil
}

func activeGoTestFiles(root, packagePath string) (map[string]struct{}, error) {
	command := exec.Command("go", "list", "-json", packagePath)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list %s: %w", packagePath, err)
	}
	var listed struct {
		Dir          string
		TestGoFiles  []string
		XTestGoFiles []string
	}
	if err := json.Unmarshal(output, &listed); err != nil {
		return nil, fmt.Errorf("decode go list %s: %w", packagePath, err)
	}
	activeFiles := map[string]struct{}{}
	for _, file := range append(listed.TestGoFiles, listed.XTestGoFiles...) {
		activeAbsolute, err := filepath.Abs(filepath.Join(listed.Dir, file))
		if err != nil {
			return nil, err
		}
		activeFiles[filepath.Clean(activeAbsolute)] = struct{}{}
	}
	return activeFiles, nil
}

func importedTestingNames(source *ast.File) (map[string]struct{}, bool) {
	aliases := map[string]struct{}{}
	dotImported := false
	for _, specification := range source.Imports {
		path, err := strconv.Unquote(specification.Path.Value)
		if err != nil || path != "testing" {
			continue
		}
		switch {
		case specification.Name == nil:
			aliases["testing"] = struct{}{}
		case specification.Name.Name == ".":
			dotImported = true
		case specification.Name.Name != "_":
			aliases[specification.Name.Name] = struct{}{}
		}
	}
	return aliases, dotImported
}

func validGoTestFunction(function *ast.FuncDecl, testingAliases map[string]struct{}, dotImportedTesting bool) bool {
	if !validGoTestName(function.Name.Name) ||
		function.Type.TypeParams != nil ||
		function.Type.Results != nil && len(function.Type.Results.List) != 0 ||
		function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return false
	}
	parameter := function.Type.Params.List[0]
	if len(parameter.Names) > 1 {
		return false
	}
	pointer, ok := parameter.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if identifier, ok := pointer.X.(*ast.Ident); ok {
		return dotImportedTesting && identifier.Name == "T"
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "T" {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	_, ok = testingAliases[identifier.Name]
	return ok
}

func validGoTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") {
		return false
	}
	suffix := strings.TrimPrefix(name, "Test")
	if suffix == "" {
		return true
	}
	first, _ := utf8.DecodeRuneInString(suffix)
	return !unicode.IsLower(first)
}

func equalStrings(left, right []string) bool {
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func bindCurrentSourceProvenance(out *metrics) error {
	revision, sourceDigest, err := packageartifactrecord.SourceSnapshot(".")
	if err != nil {
		return fmt.Errorf("bind coverage metrics source snapshot: %w", err)
	}
	out.Provenance = coverageProvenance{
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		ProducerCommandID:    "proofkit.coverage-metrics",
		SourceRevision:       revision,
		SourceSnapshotDigest: sourceDigest,
	}
	return nil
}

func bindCommandOracleProvenance(out *metrics, evidence commandoracle.Evidence) {
	out.Provenance = coverageProvenance{
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		ProducerCommandID:    "proofkit.coverage-metrics",
		SourceRevision:       evidence.Record.SourceRevision,
		SourceSnapshotDigest: evidence.Record.SourceSnapshotDigest,
	}
}

func writeMetrics(out metrics, routeErr error) error {
	if err := writeMetricsFile(out); err != nil {
		return err
	}
	if routeErr != nil {
		return routeErr
	}
	printMetricsSummary(out)
	return nil
}

func writeCurrentExecutionMetrics(ctx context.Context, out metrics, evidence commandoracle.Evidence) error {
	if err := commandOracleValidateCurrent(ctx, ".", evidence); err != nil {
		return errors.Join(err, invalidateExecutionMetrics())
	}
	if err := commandOracleWriteDiagnostic(".", evidence); err != nil {
		return errors.Join(err, invalidateExecutionMetrics())
	}
	if err := writeMetricsFile(out); err != nil {
		return errors.Join(err, invalidateExecutionMetrics())
	}
	if err := commandOracleValidateCurrent(ctx, ".", evidence); err != nil {
		return errors.Join(err, invalidateExecutionMetrics())
	}
	printMetricsSummary(out)
	return nil
}

func invalidateExecutionMetrics() error {
	err := commandOracleInvalidateDiagnostic(".")
	if removeErr := invalidateMetricsFile(); removeErr != nil {
		err = errors.Join(err, removeErr)
	}
	return err
}

func invalidateMetricsFile() error {
	return artifactfile.Remove(".", outputPath)
}

func writeMetricsFile(out metrics) error {
	content, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return artifactfile.WriteAtomic(".", outputPath, append(content, '\n'), 0o644)
}

func printMetricsSummary(out metrics) {
	fmt.Printf("coverage metrics: requirements=%d bound=%d scenarios=%d commands=%d\n",
		out.Requirements.TotalRecords,
		out.ProofBindings.BoundRequirementCount,
		out.ProofBindings.ScenarioCount,
		out.CLIContract.CommandCount,
	)
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
	return buildMetricsWithExecution(requirements, bindings, witnesses, contract, commandInventory, commandExecutionSummary{})
}

func buildMetricsWithExecution(requirements []requirementRecord, bindings bindingFile, witnesses witnessPlan, contract cliContract, commandInventory testevidenceinventory.Inventory, execution commandExecutionSummary) metrics {
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
	contractCommands := cliContractCommandNames(contract)
	commandRoutes := buildCommandRouteMetricsWithExecution(contract, app.CommandCoverageSummaries(), commandInventory, execution)
	return metrics{
		ArtifactKind:  "proofkit.coverage-metrics.v2",
		SchemaVersion: 2,
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
		CLIContract:   cliContractMetrics{CommandCount: len(contractCommands), Commands: contractCommands},
		CommandRoutes: commandRoutes,
		DeadZones: deadZoneMetrics{
			BindingWithoutRequirementIDs:  bindingWithoutRequirement,
			RequirementWithoutBindingIDs:  requirementWithoutBinding,
			ScenarioWithoutCommandIDs:     scenarioWithoutCommand,
			ScenarioWithoutRequirementIDs: scenarioWithoutRequirement,
		},
		NonClaims: []string{
			"Coverage metrics report explicit requirement, binding, witness, and CLI inventory linkage only.",
			"Static command route metadata remains proof_route_candidate; route prose, source markers, test existence, and failure-capable AST nodes do not become execution-backed semantic evidence.",
			"Execution-backed command route counts require a current materialized source snapshot, exact selected Go test lifecycle events, and owner-reserved cooperative attributes.",
			"Successful selected tests do not prove assertion-branch execution, mutation adequacy, exhaustive semantic correctness, producer authentication, receipt freshness, merge satisfaction, or production readiness.",
		},
	}
}

func cliContractCommandNames(contract cliContract) []string {
	commands := make([]string, 0, len(contract.Commands))
	for _, command := range contract.Commands {
		commands = append(commands, command.Command)
	}
	sort.Strings(commands)
	return commands
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
