package gradualadoption

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/contractenv"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

var standardQuestions = []string{"what changed", "what proves it", "who owns it"}

var gradualAdoptionNonClaims = []string{
	"Gradual adoption reports do not approve rollout, merge, release, deployment, or production readiness.",
	"Gradual adoption reports do not execute native witnesses or prove proof freshness.",
	"Gradual adoption reports admit caller-owned profile facts only.",
}

type adoptionInput struct {
	AdoptionID        string
	AdoptionMode      string
	AgentReport       map[string]any
	Budget            map[string]any
	Module            map[string]any
	NativeWitnesses   map[string]any
	NonClaims         []string
	PackageVersionRef string
	ProofBinding      map[string]any
	Repository        map[string]any
	Rollback          map[string]any
	RolloutClaim      bool
}

type adoptionReportResult struct {
	Record      report.Record
	WitnessPlan map[string]any
}

func Build(raw any) (map[string]any, int, error) {
	result, err := BuildReport(raw)
	if err != nil {
		return nil, 1, err
	}
	return result.Record.JSONValue(), exitCode(result.Record), nil
}

func BuildFromContractEnvelope(raw any) (map[string]any, int, error) {
	input, err := InputFromContractEnvelope(raw)
	if err != nil {
		return nil, 1, err
	}
	return Build(input)
}

func BuildReport(raw any) (adoptionReportResult, error) {
	input, err := admitAdoptionInput(raw)
	if err != nil {
		return adoptionReportResult{}, err
	}
	failures := []string{}
	repository := admitRepository(input.Repository, &failures)
	module := admitModule(input.Module, &failures, "gradual adoption")
	proofBinding := admitProofBinding(input.ProofBinding, &failures)
	witnessCommands, witnessPlan, err := admitWitnessCommands(input.NativeWitnesses, &failures)
	if err != nil {
		return adoptionReportResult{}, err
	}
	agentReport := admitAgentReport(input.AgentReport, &failures)
	budget := admitBudget(input.Budget, &failures)
	rollback := admitRollback(input.Rollback, &failures)

	if input.AdoptionMode != "non_blocking" {
		failures = append(failures, "adoptionMode must be non_blocking")
	}
	if input.RolloutClaim {
		failures = append(failures, "rolloutClaim must be false for gradual adoption")
	}
	if input.PackageVersionRef == "" {
		failures = append(failures, "packageVersionRef must be non-empty")
	}
	if !sameStringSet(stringArrayFromMap(module, "requirementIds"), stringArrayFromMap(proofBinding, "requirementIds")) {
		failures = append(failures, "module requirementIds must match proofBinding requirementIds")
	}
	if !sameStringSet(stringArrayFromMap(proofBinding, "witnessCommandIds"), witnessIDs(witnessCommands)) {
		failures = append(failures, "proofBinding witnessCommandIds must match native witness command ids")
	}

	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.gradual-adoption",
		ReportID:      input.AdoptionID,
		State:         state,
		Summary: map[string]any{
			"addedSecondsBudget":      intFromMap(budget, "maxAddedSeconds"),
			"copiedVerifierFileCount": intFromMap(budget, "copiedVerifierFileCount"),
			"customRuleCount":         intFromMap(budget, "customRuleCount"),
			"moduleId":                stringFromMap(module, "moduleId"),
			"outputMode":              stringFromMap(agentReport, "outputMode"),
			"profileLineCount":        intFromMap(budget, "profileLines"),
			"repositoryClass":         stringFromMap(repository, "repositoryClass"),
			"requirementCount":        len(stringArrayFromMap(module, "requirementIds")),
			"rolloutClaim":            input.RolloutClaim,
			"setupMinutesBudget":      intFromMap(budget, "maxSetupMinutes"),
			"witnessCommandCount":     len(witnessCommands),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "agentReport", Value: map[string]any{
				"artifactPath":   stringFromMap(agentReport, "artifactPath"),
				"routeQuestions": anyStringArrayFromMap(agentReport, "routeQuestions"),
				"schemaId":       stringFromMap(agentReport, "schemaId"),
			}},
			{Key: "module", Value: map[string]any{
				"moduleId":       stringFromMap(module, "moduleId"),
				"requirementIds": anyStringArrayFromMap(module, "requirementIds"),
				"specPath":       stringFromMap(module, "specPath"),
			}},
			{Key: "packageVersionRef", Value: input.PackageVersionRef},
			{Key: "proofBinding", Value: map[string]any{
				"bindingPath":       stringFromMap(proofBinding, "bindingPath"),
				"witnessCommandIds": anyStringArrayFromMap(proofBinding, "witnessCommandIds"),
			}},
			{Key: "rollback", Value: map[string]any{
				"disableCommand": stringFromMap(rollback, "disableCommand"),
				"owner":          stringFromMap(rollback, "owner"),
				"versionPin":     stringFromMap(rollback, "versionPin"),
			}},
			{Key: "witnessPlan", Value: map[string]any{
				"commandIds":     commandIDsFromPlan(witnessPlan),
				"parallelGroups": parallelGroupsFromPlan(witnessPlan),
			}},
		},
		RuleResults: adoptionRuleResults(failures),
		NonClaims:   admit.StringSliceToAny(input.NonClaims),
	}
	return adoptionReportResult{Record: record, WitnessPlan: witnessPlan}, nil
}

func InputFromContractEnvelope(raw any) (map[string]any, error) {
	envelope, err := contractenv.Object(raw, "proofkit.gradual-adoption-profile.v1", "gradual adoption", "input")
	if err != nil {
		return nil, err
	}
	return contractenv.ObjectField(envelope, "input", "gradual adoption contract envelope")
}

func admitAdoptionInput(raw any) (adoptionInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return adoptionInput{}, fmt.Errorf("proofkit gradual adoption input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"adoptionId", "adoptionMode", "agentReport", "budget", "module", "nativeWitnesses", "nonClaims", "packageVersionRef", "proofBinding", "repository", "rollback", "rolloutClaim", "schemaVersion"}, "proofkit gradual adoption input"); err != nil {
		return adoptionInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return adoptionInput{}, fmt.Errorf("proofkit gradual adoption schemaVersion must be 1")
	}
	adoptionID, err := admit.RuleID(record["adoptionId"], "proofkit gradual adoption adoptionId")
	if err != nil {
		return adoptionInput{}, err
	}
	mode, err := text(record["adoptionMode"], "adoptionMode")
	if err != nil {
		return adoptionInput{}, err
	}
	rolloutClaim, ok := record["rolloutClaim"].(bool)
	if !ok {
		return adoptionInput{}, fmt.Errorf("rolloutClaim must be boolean")
	}
	versionRef, err := text(record["packageVersionRef"], "packageVersionRef")
	if err != nil {
		return adoptionInput{}, err
	}
	nonClaims, err := admit.SortedTextArray(record["nonClaims"], "gradual adoption nonClaims", false)
	if err != nil {
		return adoptionInput{}, err
	}
	nonClaims, err = admit.MergeNonClaims(gradualAdoptionNonClaims, nonClaims, "gradual adoption")
	if err != nil {
		return adoptionInput{}, err
	}
	agentReport, err := objectField(record, "agentReport", "proofkit gradual adoption agentReport")
	if err != nil {
		return adoptionInput{}, err
	}
	budget, err := objectField(record, "budget", "proofkit gradual adoption budget")
	if err != nil {
		return adoptionInput{}, err
	}
	module, err := objectField(record, "module", "proofkit gradual adoption module")
	if err != nil {
		return adoptionInput{}, err
	}
	nativeWitnesses, err := objectField(record, "nativeWitnesses", "proofkit gradual adoption nativeWitnesses")
	if err != nil {
		return adoptionInput{}, err
	}
	proofBinding, err := objectField(record, "proofBinding", "proofkit gradual adoption proofBinding")
	if err != nil {
		return adoptionInput{}, err
	}
	repository, err := objectField(record, "repository", "proofkit gradual adoption repository")
	if err != nil {
		return adoptionInput{}, err
	}
	rollback, err := objectField(record, "rollback", "proofkit gradual adoption rollback")
	if err != nil {
		return adoptionInput{}, err
	}
	return adoptionInput{
		AdoptionID:        adoptionID,
		AdoptionMode:      mode,
		AgentReport:       agentReport,
		Budget:            budget,
		Module:            module,
		NativeWitnesses:   nativeWitnesses,
		NonClaims:         nonClaims,
		PackageVersionRef: versionRef,
		ProofBinding:      proofBinding,
		Repository:        repository,
		Rollback:          rollback,
		RolloutClaim:      rolloutClaim,
	}, nil
}

func admitRepository(raw map[string]any, failures *[]string) map[string]any {
	addErr(failures, admit.KnownKeys(raw, []string{"customRuleBoundary", "primaryLanguages", "profilePath", "repositoryClass", "repositoryId", "verifierCodeCopied"}, "gradual adoption repository"))
	repositoryID, err := admit.RuleID(raw["repositoryId"], "gradual adoption repositoryId")
	addErr(failures, err)
	repositoryClass, err := text(raw["repositoryClass"], "repositoryClass")
	addErr(failures, err)
	profilePath, err := safePath(raw["profilePath"], "repository profilePath")
	addErr(failures, err)
	languages, err := admit.SortedTextArray(raw["primaryLanguages"], "repository primaryLanguages", false)
	addErr(failures, err)
	if raw["verifierCodeCopied"] != false {
		*failures = append(*failures, "gradual adoption must not copy verifier source code")
	}
	if raw["customRuleBoundary"] != "profile_only" {
		*failures = append(*failures, "custom rule boundary must be profile_only")
	}
	return map[string]any{
		"customRuleBoundary": "profile_only",
		"primaryLanguages":   admit.StringSliceToAny(languages),
		"profilePath":        profilePath,
		"repositoryClass":    repositoryClass,
		"repositoryId":       repositoryID,
		"verifierCodeCopied": false,
	}
}

func admitModule(raw map[string]any, failures *[]string, context string) map[string]any {
	addErr(failures, admit.KnownKeys(raw, []string{"moduleId", "requirementIds", "specPath"}, context+" module"))
	requirementIDs, err := sortedRuleIDArray(raw["requirementIds"], context+" module requirementIds")
	addErr(failures, err)
	if len(requirementIDs) == 0 {
		*failures = append(*failures, "module must declare at least one requirement")
	}
	if len(requirementIDs) > 15 {
		*failures = append(*failures, "gradual adoption module must stay bounded to at most 15 requirements")
	}
	moduleID, err := admit.RuleID(raw["moduleId"], context+" moduleId")
	addErr(failures, err)
	specPath, err := safePath(raw["specPath"], "module specPath")
	addErr(failures, err)
	return map[string]any{
		"moduleId":       moduleID,
		"requirementIds": admit.StringSliceToAny(requirementIDs),
		"specPath":       specPath,
	}
}

func admitProofBinding(raw map[string]any, failures *[]string) map[string]any {
	addErr(failures, admit.KnownKeys(raw, []string{"bindingFormat", "bindingPath", "requirementIds", "witnessCommandIds"}, "gradual adoption proofBinding"))
	if raw["bindingFormat"] != "requirement_to_witness" {
		*failures = append(*failures, "proofBinding bindingFormat must be requirement_to_witness")
	}
	requirementIDs, err := sortedRuleIDArray(raw["requirementIds"], "proofBinding requirementIds")
	addErr(failures, err)
	witnessCommandIDs, err := sortedRuleIDArray(raw["witnessCommandIds"], "proofBinding witnessCommandIds")
	addErr(failures, err)
	if len(witnessCommandIDs) == 0 {
		*failures = append(*failures, "proofBinding must declare at least one witness command")
	}
	bindingPath, err := safePath(raw["bindingPath"], "proofBinding bindingPath")
	addErr(failures, err)
	return map[string]any{
		"bindingFormat":     "requirement_to_witness",
		"bindingPath":       bindingPath,
		"requirementIds":    admit.StringSliceToAny(requirementIDs),
		"witnessCommandIds": admit.StringSliceToAny(witnessCommandIDs),
	}
}

func admitWitnessCommands(raw map[string]any, failures *[]string) ([]witnesscommand.Command, map[string]any, error) {
	addErr(failures, admit.KnownKeys(raw, []string{"commands", "vocabulary"}, "gradual adoption nativeWitnesses"))
	vocabulary, err := witnesscommand.AdmitVocabulary(raw["vocabulary"])
	if err != nil {
		return nil, nil, err
	}
	rawCommands, ok := raw["commands"].([]any)
	if !ok {
		return nil, nil, fmt.Errorf("gradual adoption nativeWitnesses.commands must be an array")
	}
	commands := make([]witnesscommand.Command, 0, len(rawCommands))
	for _, rawCommand := range rawCommands {
		command, err := witnesscommand.AdmitWithVocabulary(rawCommand, vocabulary)
		if err != nil {
			return nil, nil, err
		}
		commands = append(commands, command)
	}
	if len(commands) == 0 {
		*failures = append(*failures, "gradual adoption must declare at least one native witness command")
	}
	plan, err := witnesscommand.PlanCommands(commands)
	if err != nil {
		return nil, nil, err
	}
	return commands, plan.JSONValue(), nil
}

func admitAgentReport(raw map[string]any, failures *[]string) map[string]any {
	addErr(failures, admit.KnownKeys(raw, []string{"artifactPath", "outputMode", "reportKind", "routeQuestions", "schemaId"}, "gradual adoption agentReport"))
	if raw["reportKind"] != "proofkit.gradual-adoption" {
		*failures = append(*failures, "agentReport reportKind must be proofkit.gradual-adoption")
	}
	if raw["outputMode"] != "non_blocking" {
		*failures = append(*failures, "agentReport outputMode must be non_blocking")
	}
	questions, err := admit.SortedTextArray(raw["routeQuestions"], "agentReport routeQuestions", false)
	addErr(failures, err)
	for _, question := range standardQuestions {
		if !contains(questions, question) {
			*failures = append(*failures, fmt.Sprintf("agentReport routeQuestions must include %s", question))
		}
	}
	artifactPath, err := safePath(raw["artifactPath"], "agentReport artifactPath")
	addErr(failures, err)
	schemaID, err := admit.RuleID(raw["schemaId"], "agentReport schemaId")
	addErr(failures, err)
	return map[string]any{
		"artifactPath":   artifactPath,
		"outputMode":     "non_blocking",
		"reportKind":     "proofkit.gradual-adoption",
		"routeQuestions": admit.StringSliceToAny(questions),
		"schemaId":       schemaID,
	}
}

func admitBudget(raw map[string]any, failures *[]string) map[string]any {
	addErr(failures, admit.KnownKeys(raw, []string{"copiedVerifierFileCount", "customRuleCount", "maxAddedSeconds", "maxCustomRuleCount", "maxProfileLines", "maxSetupMinutes", "profileLines"}, "gradual adoption budget"))
	profileLines := nonNegativeInt(raw["profileLines"], "profileLines", failures, 1)
	maxProfileLines := nonNegativeInt(raw["maxProfileLines"], "maxProfileLines", failures, 1)
	customRuleCount := nonNegativeInt(raw["customRuleCount"], "customRuleCount", failures, 0)
	maxCustomRuleCount := nonNegativeInt(raw["maxCustomRuleCount"], "maxCustomRuleCount", failures, 0)
	copiedVerifierFileCount := nonNegativeInt(raw["copiedVerifierFileCount"], "copiedVerifierFileCount", failures, 0)
	if copiedVerifierFileCount != 0 {
		*failures = append(*failures, "copiedVerifierFileCount must be 0")
	}
	if profileLines > maxProfileLines {
		*failures = append(*failures, "profileLines must not exceed maxProfileLines")
	}
	if customRuleCount > maxCustomRuleCount {
		*failures = append(*failures, "customRuleCount must not exceed maxCustomRuleCount")
	}
	return map[string]any{
		"copiedVerifierFileCount": 0,
		"customRuleCount":         customRuleCount,
		"maxAddedSeconds":         nonNegativeInt(raw["maxAddedSeconds"], "maxAddedSeconds", failures, 0),
		"maxCustomRuleCount":      maxCustomRuleCount,
		"maxProfileLines":         maxProfileLines,
		"maxSetupMinutes":         nonNegativeInt(raw["maxSetupMinutes"], "maxSetupMinutes", failures, 1),
		"profileLines":            profileLines,
	}
}

func admitRollback(raw map[string]any, failures *[]string) map[string]any {
	addErr(failures, admit.KnownKeys(raw, []string{"disableCommand", "owner", "versionPin"}, "gradual adoption rollback"))
	disableCommand := ""
	if command, err := admit.DisplayOnlyCommandText(raw["disableCommand"], "gradual adoption rollback disableCommand"); err != nil {
		*failures = append(*failures, err.Error())
	} else {
		disableCommand = command
	}
	return map[string]any{
		"disableCommand": disableCommand,
		"owner":          stringOrEmpty(raw["owner"]),
		"versionPin":     stringOrEmpty(raw["versionPin"]),
	}
}

func adoptionRuleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{{
			RuleID:      "proofkit.gradual-adoption.accepted",
			Status:      "passed",
			Message:     "gradual adoption profile is bounded and non-blocking",
			Diagnostics: []report.Diagnostic{},
		}}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.gradual-adoption.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}

func objectField(record map[string]any, key string, context string) (map[string]any, error) {
	value, ok := record[key].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	return value, nil
}

func object(raw any) map[string]any {
	record, _ := raw.(map[string]any)
	return record
}

func safePath(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a repository-relative POSIX path", context)
	}
	return admit.SafeRepoRelativePath(value, context)
}

func text(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func sortedRuleIDArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		id, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return admit.SortedText(result, context, true)
}

func nonNegativeInt(raw any, context string, failures *[]string, min int) int {
	value, err := intFromRaw(raw)
	if err != nil {
		*failures = append(*failures, fmt.Sprintf("%s %s", context, err.Error()))
		return 0
	}
	if value < min {
		*failures = append(*failures, fmt.Sprintf("%s must be an integer >= %d", context, min))
		return 0
	}
	return value
}

func intFromRaw(raw any) (int, error) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("must be a JSON integer")
	}
	value, err := number.Int64()
	if err != nil || int64(int(value)) != value {
		return 0, fmt.Errorf("must be a JSON integer")
	}
	return int(value), nil
}

func addErr(failures *[]string, err error) {
	if err != nil {
		*failures = append(*failures, err.Error())
	}
}

func stringArrayFromMap(record map[string]any, key string) []string {
	return admit.AnySliceToString(record[key].([]any))
}

func anyStringArrayFromMap(record map[string]any, key string) []any {
	return record[key].([]any)
}

func anyArrayFromMap(record map[string]any, key string) []any {
	value, _ := record[key].([]any)
	return value
}

func stringFromMap(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}

func intFromMap(record map[string]any, key string) int {
	value, _ := record[key].(int)
	return value
}

func stringOrEmpty(raw any) string {
	value, _ := raw.(string)
	return value
}

func sameStringSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string{}, left...)
	rightCopy := append([]string{}, right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func witnessIDs(commands []witnesscommand.Command) []string {
	ids := make([]string, 0, len(commands))
	for _, command := range commands {
		ids = append(ids, command.ID)
	}
	sort.Strings(ids)
	return ids
}

func commandIDsFromPlan(plan map[string]any) []any {
	rawCommands, _ := plan["commands"].([]any)
	ids := make([]string, 0, len(rawCommands))
	for _, raw := range rawCommands {
		command := raw.(map[string]any)
		ids = append(ids, command["id"].(string))
	}
	sort.Strings(ids)
	return admit.StringSliceToAny(ids)
}

func parallelGroupsFromPlan(plan map[string]any) []any {
	rawGroups, _ := plan["parallelGroups"].([]any)
	return rawGroups
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func exitCode(record report.Record) int {
	if record.State == "passed" {
		return 0
	}
	return 1
}
