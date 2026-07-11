package pilotadmission

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/contractenv"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.pilot-admission"

var stackDiversityDimensions = []string{
	"docs_spec_layout",
	"generated_artifact_policy",
	"language_runtime_test_shape",
	"proof_environment_classes",
	"repository_topology",
}

var cacheInvalidationClasses = []string{"package_version", "profile", "schema", "source"}

type Options struct {
	RequireStackDiverseReleaseCandidate bool
}

type admittedBlockingRequirement struct {
	Evidence      string
	Owner         string
	RequirementID string
	Status        string
}

type admittedBlockingDisposition struct {
	ExplicitlyDeferredRequirements int
	Requirements                   []admittedBlockingRequirement
	TotalBlockingRequirements      int
	WitnessBackedRequirements      int
}

type admittedAgentReportRoute struct {
	ArtifactPath       string
	Command            string
	ExpectedUpdatePath string
	ReportKind         string
	SchemaID           string
	TaskType           string
}

type admittedCacheScheduler struct {
	CacheKeyInputs                []string
	DestructiveConcurrencyAllowed bool
	InvalidationInputs            []string
	MaxParallelGroups             int
	ParallelGroups                []string
	SchedulerPolicy               string
}

type admittedTimingBudget struct {
	MaxAddedSeconds          any
	MeasuredSeparately       bool
	ReportArtifactPath       string
	TrackedFixtureAsBaseline bool
}

type admittedCustomRule struct {
	DowngradeGenericFailures bool
	Owner                    string
	Purpose                  string
	RuleID                   string
}

type admittedInfrastructureBudget struct {
	CopiedVerifierFileCount    int
	CustomRuleCount            int
	CustomRules                []admittedCustomRule
	ManualTruthSurfaceCount    int
	ManualUpdateStepCount      int
	MaxCustomRuleCount         int
	MaxManualTruthSurfaceCount int
	MaxManualUpdateStepCount   int
	MaxProfileLines            int
	ProfileLines               int
}

type admittedFalsePositiveBudget struct {
	DispositionOwner             string
	EnforcementMode              string
	MaxAllowedFalsePositiveCount int
	SampleWindowRuns             int
}

type admittedRollback struct {
	Owner           string
	RollbackCommand string
	VersionPin      string
}

type admittedImpactDemo struct {
	DemoID                   string
	GeneratedMirrorPathCount int
	Report                   map[string]any
	SourceOwnedPathCount     int
}

type admittedStackDiversityDimension struct {
	Baseline  string
	Candidate string
	Dimension string
	Evidence  string
}

type admittedStackDiversity struct {
	BaselinePilotID string
	Dimensions      []admittedStackDiversityDimension
}

type admittedCacheNegativeCheck struct {
	CheckID                     string
	Evidence                    string
	ExpectedOutcome             string
	InvalidatedInputClass       string
	LiveOrCredentialedCacheable bool
}

func Build(raw any, options Options) (report.Record, int, error) {
	input, ok := raw.(map[string]any)
	if !ok {
		return report.Record{}, 1, fmt.Errorf("proofkit pilot admission input must be an object")
	}
	if err := admit.KnownKeys(input, []string{"agentReportRoutes", "blockingRequirements", "cacheNegativeChecks", "cacheScheduler", "falsePositiveBudget", "impactDemo", "impactDemos", "infrastructureBudget", "metrics", "nonClaims", "packageVersionRef", "pilotId", "pilotMode", "profile", "rollback", "rolloutClaim", "schemaVersion", "stackDiversity", "timingBudget"}, "proofkit pilot admission input"); err != nil {
		return report.Record{}, 1, err
	}
	if !admit.JSONNumberEquals(input["schemaVersion"], 1) {
		return report.Record{}, 1, fmt.Errorf("proofkit pilot admission schemaVersion must be 1")
	}
	failures := []string{}
	pilotID, err := admit.RuleID(input["pilotId"], "proofkit pilot pilotId")
	if err != nil {
		return report.Record{}, 1, err
	}
	profile, err := object(input["profile"], "proofkit pilot profile")
	if err != nil {
		return report.Record{}, 1, err
	}
	if err := admit.KnownKeys(profile, []string{"commandMatcherBridge", "customRuleBoundary", "primaryLanguages", "repositoryClass", "repositoryId", "structuredWitnessCommands", "verifierCodeCopied"}, "proofkit pilot profile"); err != nil {
		return report.Record{}, 1, err
	}
	repositoryID, err := admit.RuleID(profile["repositoryId"], "proofkit pilot repositoryId")
	if err != nil {
		return report.Record{}, 1, err
	}
	_ = repositoryID
	repositoryClass, err := nonEmptyText(profile["repositoryClass"], "proofkit pilot repositoryClass")
	if err != nil {
		return report.Record{}, 1, err
	}
	primaryLanguages, err := admit.SortedTextArray(profile["primaryLanguages"], "proofkit pilot primaryLanguages", false)
	if err != nil {
		return report.Record{}, 1, err
	}
	if profile["structuredWitnessCommands"] != true {
		failures = append(failures, "profile must require structuredWitnessCommands")
	}
	if profile["customRuleBoundary"] != "profile_only" {
		failures = append(failures, "profile customRuleBoundary must be profile_only")
	}
	if profile["verifierCodeCopied"] != false {
		failures = append(failures, "profile must not copy repository-specific verifier code")
	}
	if profile["commandMatcherBridge"] != "compatibility_adapter_only" && profile["commandMatcherBridge"] != "none" {
		failures = append(failures, "profile commandMatcherBridge must be compatibility_adapter_only or none")
	}
	_ = primaryLanguages

	blockingRaw, err := object(input["blockingRequirements"], "proofkit pilot blockingRequirements")
	if err != nil {
		return report.Record{}, 1, err
	}
	blocking := admitBlockingDisposition(blockingRaw, &failures)
	agentReportRoutes, err := admitAgentReportRoutes(input["agentReportRoutes"], &failures)
	if err != nil {
		return report.Record{}, 1, err
	}
	cacheScheduler, err := admitCacheScheduler(input["cacheScheduler"], &failures)
	if err != nil {
		return report.Record{}, 1, err
	}
	_ = cacheScheduler
	timingBudget, err := admitTimingBudget(input["timingBudget"], &failures)
	if err != nil {
		return report.Record{}, 1, err
	}
	infrastructureBudget, err := admitInfrastructureBudget(input["infrastructureBudget"], &failures)
	if err != nil {
		return report.Record{}, 1, err
	}
	falsePositiveBudget, err := admitFalsePositiveBudget(input["falsePositiveBudget"], &failures)
	if err != nil {
		return report.Record{}, 1, err
	}
	rollback, err := admitRollback(input["rollback"])
	if err != nil {
		return report.Record{}, 1, err
	}
	impactDemos, err := admitImpactDemos(input, &failures)
	if err != nil {
		return report.Record{}, 1, err
	}
	impactReports := make([]map[string]any, 0, len(impactDemos))
	for _, demo := range impactDemos {
		impactReports = append(impactReports, demo.Report)
	}
	stackDiversity, err := admitStackDiversity(input["stackDiversity"], &failures, options)
	if err != nil {
		return report.Record{}, 1, err
	}
	cacheNegativeChecks, err := admitCacheNegativeChecks(input["cacheNegativeChecks"], &failures, options)
	if err != nil {
		return report.Record{}, 1, err
	}
	nonClaims, err := admit.SortedTextArray(input["nonClaims"], "proofkit pilot nonClaims", false)
	if err != nil {
		return report.Record{}, 1, err
	}
	if input["pilotMode"] != "non_blocking" {
		failures = append(failures, "pilotMode must be non_blocking")
	}
	if input["rolloutClaim"] != false {
		failures = append(failures, "rolloutClaim must be false for pilot admission")
	}
	packageVersionRef, err := nonEmptyText(input["packageVersionRef"], "packageVersionRef")
	if err != nil {
		failures = append(failures, "packageVersionRef must be non-empty")
		packageVersionRef = ""
	}
	if options.RequireStackDiverseReleaseCandidate {
		assertStackDiverseImpactCoverage(impactReports, &failures)
	}

	changedRequirementIDs := map[string]struct{}{}
	impactObligationCount := 0
	for _, impactReport := range impactReports {
		for _, obligation := range arrayValue(impactReport["obligations"]) {
			record, ok := obligation.(map[string]any)
			if !ok {
				continue
			}
			if recordID, ok := record["recordId"].(string); ok {
				changedRequirementIDs[recordID] = struct{}{}
			}
			impactObligationCount++
		}
	}
	generatedMirrorImpactPathCount := 0
	sourceOwnedImpactPathCount := 0
	for _, demo := range impactDemos {
		generatedMirrorImpactPathCount += demo.GeneratedMirrorPathCount
		sourceOwnedImpactPathCount += demo.SourceOwnedPathCount
	}

	state := "passed"
	exitCode := 0
	if len(failures) > 0 {
		state = "failed"
		exitCode = 1
	}
	var stackDiversityDimensionCount int
	if stackDiversity != nil {
		stackDiversityDimensionCount = len(stackDiversity.Dimensions)
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      pilotID,
		State:         state,
		Summary: map[string]any{
			"agentReportRouteCount":              len(agentReportRoutes),
			"cacheNegativeCheckCount":            len(cacheNegativeChecks),
			"changedRequirementCount":            len(changedRequirementIDs),
			"copiedVerifierFileCount":            infrastructureBudget.CopiedVerifierFileCount,
			"customRuleCount":                    infrastructureBudget.CustomRuleCount,
			"explicitlyDeferredRequirementCount": blocking.ExplicitlyDeferredRequirements,
			"falsePositiveSampleWindowRuns":      falsePositiveBudget.SampleWindowRuns,
			"generatedMirrorImpactPathCount":     generatedMirrorImpactPathCount,
			"impactDemoCount":                    len(impactDemos),
			"impactObligationCount":              impactObligationCount,
			"maxAddedSeconds":                    timingBudget.MaxAddedSeconds,
			"pilotMode":                          input["pilotMode"],
			"profileLineCount":                   infrastructureBudget.ProfileLines,
			"repositoryClass":                    repositoryClass,
			"sourceOwnedImpactPathCount":         sourceOwnedImpactPathCount,
			"stackDiversityDimensionCount":       stackDiversityDimensionCount,
			"totalBlockingRequirementCount":      blocking.TotalBlockingRequirements,
			"witnessBackedRequirementCount":      blocking.WitnessBackedRequirements,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "blockingRequirements", Value: blockingRequirementDiagnostics(blocking.Requirements)},
			{Key: "cacheNegativeChecks", Value: cacheNegativeCheckDiagnostics(cacheNegativeChecks)},
			{Key: "customRules", Value: customRuleDiagnostics(infrastructureBudget.CustomRules)},
			{Key: "impactDemos", Value: impactDemoDiagnostics(impactDemos)},
			{Key: "packageVersionRef", Value: packageVersionRef},
			{Key: "rollbackVersionPin", Value: rollback.VersionPin},
			{Key: "stackDiversity", Value: stackDiversityDiagnostics(stackDiversity)},
			{Key: "timingReportArtifactPath", Value: timingBudget.ReportArtifactPath},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	return record, exitCode, nil
}

func BuildFromContractEnvelope(raw any, field string, options Options) (report.Record, int, error) {
	envelope, err := contractenv.Object(raw, "proofkit.pilot-admission.v1", "pilot admission", field)
	if err != nil {
		return report.Record{}, 1, err
	}
	input, err := contractenv.ObjectField(envelope, field, "pilot admission contract envelope")
	if err != nil {
		return report.Record{}, 1, err
	}
	return Build(input, options)
}

func admitBlockingDisposition(record map[string]any, failures *[]string) admittedBlockingDisposition {
	addErr(failures, admit.KnownKeys(record, []string{"dispositionPolicy", "explicitlyDeferredRequirements", "requirements", "totalBlockingRequirements", "unmappedRequirements", "witnessBackedRequirements"}, "blocking disposition"))
	if record["dispositionPolicy"] != "all_blocking_requirements_must_be_witnessed_or_explicitly_deferred" {
		*failures = append(*failures, "blocking disposition policy must require witnessed or explicitly deferred blocking requirements")
	}
	total := nonNegativeInteger(record["totalBlockingRequirements"], "totalBlockingRequirements", failures, 0)
	witnessed := nonNegativeInteger(record["witnessBackedRequirements"], "witnessBackedRequirements", failures, 0)
	deferred := nonNegativeInteger(record["explicitlyDeferredRequirements"], "explicitlyDeferredRequirements", failures, 0)
	unmapped := nonNegativeInteger(record["unmappedRequirements"], "unmappedRequirements", failures, 0)
	rawRequirements, ok := record["requirements"].([]any)
	if !ok {
		*failures = append(*failures, "blocking disposition must declare requirements array")
		rawRequirements = []any{}
	}
	requirements := make([]admittedBlockingRequirement, 0, len(rawRequirements))
	for _, raw := range rawRequirements {
		requirements = append(requirements, admitBlockingRequirement(raw, failures))
	}
	sort.Slice(requirements, func(left int, right int) bool {
		return requirements[left].RequirementID < requirements[right].RequirementID
	})
	assertSortedUniqueOrFail(requirementIDs(requirements), "blocking requirement requirementId", failures)
	derivedWitnessed := 0
	derivedDeferred := 0
	for _, requirement := range requirements {
		if requirement.Status == "witness_backed" {
			derivedWitnessed++
		}
		if requirement.Status == "explicitly_deferred" {
			derivedDeferred++
		}
	}
	if total == 0 {
		*failures = append(*failures, "blocking disposition must cover at least one blocking requirement")
	}
	if len(requirements) == 0 {
		*failures = append(*failures, "blocking disposition must list exact blocking requirement records")
	}
	if unmapped != 0 {
		*failures = append(*failures, "blocking disposition must not leave unmapped requirements")
	}
	if total != len(requirements) {
		*failures = append(*failures, "totalBlockingRequirements must match exact blocking requirement records")
	}
	if witnessed != derivedWitnessed {
		*failures = append(*failures, "witnessBackedRequirements must match exact witness_backed requirement records")
	}
	if deferred != derivedDeferred {
		*failures = append(*failures, "explicitlyDeferredRequirements must match exact explicitly_deferred requirement records")
	}
	if witnessed+deferred != total {
		*failures = append(*failures, "blocking disposition counts must exactly cover totalBlockingRequirements")
	}
	return admittedBlockingDisposition{
		ExplicitlyDeferredRequirements: deferred,
		Requirements:                   requirements,
		TotalBlockingRequirements:      total,
		WitnessBackedRequirements:      witnessed,
	}
}

func admitBlockingRequirement(raw any, failures *[]string) admittedBlockingRequirement {
	record, ok := raw.(map[string]any)
	if !ok {
		*failures = append(*failures, "blocking requirement must be an object")
		return admittedBlockingRequirement{}
	}
	addErr(failures, admit.KnownKeys(record, []string{"evidence", "owner", "requirementId", "status"}, "blocking requirement"))
	requirementID, err := nonEmptyText(record["requirementId"], "blocking requirement requirementId")
	if err != nil {
		*failures = append(*failures, err.Error())
	}
	if _, err := admit.RuleID(requirementID, "blocking requirement requirementId"); err != nil {
		*failures = append(*failures, err.Error())
	}
	status, _ := record["status"].(string)
	if status != "witness_backed" && status != "explicitly_deferred" {
		*failures = append(*failures, "blocking requirement status must be witness_backed or explicitly_deferred")
	}
	owner, err := nonEmptyText(record["owner"], "blocking requirement owner")
	if err != nil {
		*failures = append(*failures, err.Error())
	}
	evidence, err := nonEmptyText(record["evidence"], "blocking requirement evidence")
	if err != nil {
		*failures = append(*failures, err.Error())
	}
	return admittedBlockingRequirement{Evidence: evidence, Owner: owner, RequirementID: requirementID, Status: status}
}

func admitAgentReportRoutes(raw any, failures *[]string) ([]admittedAgentReportRoute, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("proofkit pilot agentReportRoutes must be an array")
	}
	if len(values) == 0 {
		*failures = append(*failures, "pilot must define at least one agent report route")
	}
	routes := make([]admittedAgentReportRoute, 0, len(values))
	for _, value := range values {
		record, err := object(value, "proofkit pilot agent report route")
		if err != nil {
			return nil, err
		}
		addErr(failures, admit.KnownKeys(record, []string{"artifactPath", "command", "expectedUpdatePath", "reportKind", "schemaId", "taskType"}, "proofkit pilot agent report route"))
		taskType, err := admit.RuleID(record["taskType"], "proofkit pilot taskType")
		if err != nil {
			return nil, err
		}
		artifactPath, err := safePath(record["artifactPath"], "proofkit pilot artifactPath")
		if err != nil {
			return nil, err
		}
		schemaID, err := admit.RuleID(record["schemaId"], "proofkit pilot schemaId")
		if err != nil {
			return nil, err
		}
		command, err := admit.DisplayOnlyCommandText(record["command"], "proofkit pilot command")
		if err != nil {
			return nil, err
		}
		routeReportKind, err := admit.RuleID(record["reportKind"], "proofkit pilot reportKind")
		if err != nil {
			return nil, err
		}
		expectedUpdatePath, err := safePath(record["expectedUpdatePath"], "proofkit pilot expectedUpdatePath")
		if err != nil {
			return nil, err
		}
		routes = append(routes, admittedAgentReportRoute{
			ArtifactPath: artifactPath, Command: command, ExpectedUpdatePath: expectedUpdatePath,
			ReportKind: routeReportKind, SchemaID: schemaID, TaskType: taskType,
		})
	}
	sort.Slice(routes, func(left int, right int) bool {
		return routes[left].TaskType < routes[right].TaskType
	})
	assertSortedUniqueOrFail(routeTaskTypes(routes), "pilot agent report route taskType", failures)
	return routes, nil
}

func admitCacheScheduler(raw any, failures *[]string) (admittedCacheScheduler, error) {
	record, err := object(raw, "proofkit pilot cacheScheduler")
	if err != nil {
		return admittedCacheScheduler{}, err
	}
	addErr(failures, admit.KnownKeys(record, []string{"cacheKeyInputs", "destructiveConcurrencyAllowed", "invalidationInputs", "maxParallelGroups", "parallelGroups", "schedulerPolicy"}, "proofkit pilot cacheScheduler"))
	if record["schedulerPolicy"] != "bounded_parallel_groups" {
		*failures = append(*failures, "cache scheduler policy must be bounded_parallel_groups")
	}
	if record["destructiveConcurrencyAllowed"] != false {
		*failures = append(*failures, "cache scheduler must not allow destructive concurrency")
	}
	cacheKeyInputs := safePathArray(record["cacheKeyInputs"], "cacheKeyInputs", failures)
	invalidationInputs := safePathArray(record["invalidationInputs"], "invalidationInputs", failures)
	parallelGroups, err := admit.SortedTextArray(record["parallelGroups"], "parallelGroups", false)
	if err != nil {
		return admittedCacheScheduler{}, err
	}
	maxParallelGroups := nonNegativeInteger(record["maxParallelGroups"], "maxParallelGroups", failures, 1)
	return admittedCacheScheduler{
		CacheKeyInputs: cacheKeyInputs, DestructiveConcurrencyAllowed: false,
		InvalidationInputs: invalidationInputs, MaxParallelGroups: maxParallelGroups,
		ParallelGroups: parallelGroups, SchedulerPolicy: stringValue(record["schedulerPolicy"]),
	}, nil
}

func admitTimingBudget(raw any, failures *[]string) (admittedTimingBudget, error) {
	record, err := object(raw, "proofkit pilot timingBudget")
	if err != nil {
		return admittedTimingBudget{}, err
	}
	addErr(failures, admit.KnownKeys(record, []string{"maxAddedSeconds", "measuredSeparately", "reportArtifactPath", "trackedFixtureAsBaseline"}, "proofkit pilot timingBudget"))
	if record["measuredSeparately"] != true {
		*failures = append(*failures, "timing budget must be measured separately")
	}
	if record["trackedFixtureAsBaseline"] != false {
		*failures = append(*failures, "tracked fixtures must not be timing baselines")
	}
	maxAddedSeconds := nonNegativeNumber(record["maxAddedSeconds"], "maxAddedSeconds", failures)
	reportArtifactPath, err := safePath(record["reportArtifactPath"], "timing reportArtifactPath")
	if err != nil {
		return admittedTimingBudget{}, err
	}
	return admittedTimingBudget{
		MaxAddedSeconds: maxAddedSeconds, MeasuredSeparately: record["measuredSeparately"] == true,
		ReportArtifactPath: reportArtifactPath, TrackedFixtureAsBaseline: record["trackedFixtureAsBaseline"] == true,
	}, nil
}

func admitInfrastructureBudget(raw any, failures *[]string) (admittedInfrastructureBudget, error) {
	record, err := object(raw, "proofkit pilot infrastructureBudget")
	if err != nil {
		return admittedInfrastructureBudget{}, err
	}
	addErr(failures, admit.KnownKeys(record, []string{"copiedVerifierFileCount", "customRuleCount", "customRules", "manualTruthSurfaceCount", "manualUpdateStepCount", "maxCustomRuleCount", "maxManualTruthSurfaceCount", "maxManualUpdateStepCount", "maxProfileLines", "profileLines"}, "proofkit pilot infrastructureBudget"))
	rawRules, ok := record["customRules"].([]any)
	if !ok {
		*failures = append(*failures, "infrastructure budget must declare customRules array")
		rawRules = []any{}
	}
	customRules := make([]admittedCustomRule, 0, len(rawRules))
	for _, rawRule := range rawRules {
		rule, err := admitCustomRule(rawRule, failures)
		if err != nil {
			return admittedInfrastructureBudget{}, err
		}
		customRules = append(customRules, rule)
	}
	assertSortedUniqueOrFail(customRuleIDs(customRules), "custom rule ruleId", failures)
	budget := admittedInfrastructureBudget{
		CopiedVerifierFileCount:    nonNegativeInteger(record["copiedVerifierFileCount"], "copiedVerifierFileCount", failures, 0),
		CustomRuleCount:            nonNegativeInteger(record["customRuleCount"], "customRuleCount", failures, 0),
		CustomRules:                customRules,
		ManualTruthSurfaceCount:    nonNegativeInteger(record["manualTruthSurfaceCount"], "manualTruthSurfaceCount", failures, 0),
		ManualUpdateStepCount:      nonNegativeInteger(record["manualUpdateStepCount"], "manualUpdateStepCount", failures, 0),
		MaxCustomRuleCount:         nonNegativeInteger(record["maxCustomRuleCount"], "maxCustomRuleCount", failures, 0),
		MaxManualTruthSurfaceCount: nonNegativeInteger(record["maxManualTruthSurfaceCount"], "maxManualTruthSurfaceCount", failures, 0),
		MaxManualUpdateStepCount:   nonNegativeInteger(record["maxManualUpdateStepCount"], "maxManualUpdateStepCount", failures, 0),
		MaxProfileLines:            nonNegativeInteger(record["maxProfileLines"], "maxProfileLines", failures, 0),
		ProfileLines:               nonNegativeInteger(record["profileLines"], "profileLines", failures, 0),
	}
	if budget.ProfileLines > budget.MaxProfileLines {
		*failures = append(*failures, "profileLines must not exceed maxProfileLines")
	}
	if budget.CustomRuleCount > budget.MaxCustomRuleCount {
		*failures = append(*failures, "customRuleCount must not exceed maxCustomRuleCount")
	}
	if budget.CustomRuleCount != len(customRules) {
		*failures = append(*failures, "customRuleCount must match exact customRules records")
	}
	if budget.ManualTruthSurfaceCount > budget.MaxManualTruthSurfaceCount {
		*failures = append(*failures, "manualTruthSurfaceCount must not exceed maxManualTruthSurfaceCount")
	}
	if budget.ManualUpdateStepCount > budget.MaxManualUpdateStepCount {
		*failures = append(*failures, "manualUpdateStepCount must not exceed maxManualUpdateStepCount")
	}
	if budget.CopiedVerifierFileCount != 0 {
		*failures = append(*failures, "copiedVerifierFileCount must be zero")
	}
	return budget, nil
}

func admitCustomRule(raw any, failures *[]string) (admittedCustomRule, error) {
	record, err := object(raw, "proofkit pilot custom rule")
	if err != nil {
		return admittedCustomRule{}, err
	}
	addErr(failures, admit.KnownKeys(record, []string{"downgradeGenericFailures", "owner", "purpose", "ruleId"}, "proofkit pilot custom rule"))
	if record["downgradeGenericFailures"] != false {
		*failures = append(*failures, "custom rules must not downgrade generic proofkit failures")
	}
	ruleID, err := admit.RuleID(record["ruleId"], "custom rule ruleId")
	if err != nil {
		return admittedCustomRule{}, err
	}
	owner, err := nonEmptyText(record["owner"], "custom rule owner")
	if err != nil {
		return admittedCustomRule{}, err
	}
	purpose, err := nonEmptyText(record["purpose"], "custom rule purpose")
	if err != nil {
		return admittedCustomRule{}, err
	}
	return admittedCustomRule{DowngradeGenericFailures: false, Owner: owner, Purpose: purpose, RuleID: ruleID}, nil
}

func admitFalsePositiveBudget(raw any, failures *[]string) (admittedFalsePositiveBudget, error) {
	record, err := object(raw, "proofkit pilot falsePositiveBudget")
	if err != nil {
		return admittedFalsePositiveBudget{}, err
	}
	addErr(failures, admit.KnownKeys(record, []string{"dispositionOwner", "enforcementMode", "maxAllowedFalsePositiveCount", "sampleWindowRuns"}, "proofkit pilot falsePositiveBudget"))
	if record["enforcementMode"] != "non_blocking" {
		*failures = append(*failures, "false-positive budget enforcement must stay non_blocking")
	}
	sampleWindowRuns := nonNegativeInteger(record["sampleWindowRuns"], "sampleWindowRuns", failures, 1)
	maxAllowedFalsePositiveCount := nonNegativeInteger(record["maxAllowedFalsePositiveCount"], "maxAllowedFalsePositiveCount", failures, 0)
	dispositionOwner, err := nonEmptyText(record["dispositionOwner"], "false-positive dispositionOwner")
	if err != nil {
		return admittedFalsePositiveBudget{}, err
	}
	return admittedFalsePositiveBudget{
		DispositionOwner: dispositionOwner, EnforcementMode: stringValue(record["enforcementMode"]),
		MaxAllowedFalsePositiveCount: maxAllowedFalsePositiveCount, SampleWindowRuns: sampleWindowRuns,
	}, nil
}

func admitRollback(raw any) (admittedRollback, error) {
	record, err := object(raw, "proofkit pilot rollback")
	if err != nil {
		return admittedRollback{}, err
	}
	if err := admit.KnownKeys(record, []string{"owner", "rollbackCommand", "versionPin"}, "proofkit pilot rollback"); err != nil {
		return admittedRollback{}, err
	}
	versionPin, err := nonEmptyText(record["versionPin"], "rollback versionPin")
	if err != nil {
		return admittedRollback{}, err
	}
	rollbackCommand, err := admit.DisplayOnlyCommandText(record["rollbackCommand"], "rollback command")
	if err != nil {
		return admittedRollback{}, err
	}
	owner, err := nonEmptyText(record["owner"], "rollback owner")
	if err != nil {
		return admittedRollback{}, err
	}
	return admittedRollback{Owner: owner, RollbackCommand: rollbackCommand, VersionPin: versionPin}, nil
}

func admitImpactDemos(input map[string]any, failures *[]string) ([]admittedImpactDemo, error) {
	rawDemos := []any{}
	if values, ok := input["impactDemos"].([]any); ok {
		rawDemos = values
	} else if demo, ok := input["impactDemo"]; ok {
		rawDemos = []any{demo}
	}
	if len(rawDemos) == 0 {
		*failures = append(*failures, "pilot admission must declare at least one impact demo")
	}
	demos := make([]admittedImpactDemo, 0, len(rawDemos))
	for index, rawDemo := range rawDemos {
		demo, err := admitImpactDemo(rawDemo, failures, fmt.Sprintf("impact-demo-%03d", index+1))
		if err != nil {
			return nil, err
		}
		demos = append(demos, demo)
	}
	sort.Slice(demos, func(left int, right int) bool {
		return demos[left].DemoID < demos[right].DemoID
	})
	assertSortedUniqueOrFail(impactDemoIDs(demos), "impact demo demoId", failures)
	return demos, nil
}

func admitImpactDemo(raw any, failures *[]string, fallbackDemoID string) (admittedImpactDemo, error) {
	record, err := object(raw, "proofkit pilot impact demo")
	if err != nil {
		return admittedImpactDemo{}, err
	}
	addErr(failures, admit.KnownKeys(record, []string{"demoId", "generatedMirrorPaths", "impactInput", "sourceOwnedChangedPaths"}, "proofkit pilot impact demo"))
	demoIDRaw := record["demoId"]
	if demoIDRaw == nil {
		demoIDRaw = fallbackDemoID
	}
	demoID, err := admit.RuleID(demoIDRaw, "impact demo demoId")
	if err != nil {
		return admittedImpactDemo{}, err
	}
	sourceOwnedChangedPaths := safePathArray(record["sourceOwnedChangedPaths"], "sourceOwnedChangedPaths", failures)
	generatedMirrorPaths := safePathArray(record["generatedMirrorPaths"], "generatedMirrorPaths", failures)
	generatedMirrorSet := stringSet(generatedMirrorPaths)
	impactInput, err := object(record["impactInput"], "proofkit pilot impactInput")
	if err != nil {
		return admittedImpactDemo{}, err
	}
	impactReport, _, err := impact.Build(impactInput)
	if err != nil {
		return admittedImpactDemo{}, err
	}
	changed := stringSet(stringsFromAnyArray(arrayValue(impactReport["changedPaths"])))
	if impactReport["impactState"] != "ok" {
		for _, failure := range stringsFromAnyArray(arrayValue(impactReport["failures"])) {
			*failures = append(*failures, "impact demo failed: "+failure)
		}
	}
	obligations := arrayValue(impactReport["obligations"])
	if len(obligations) == 0 {
		*failures = append(*failures, "impact demo must route at least one changed proof input to an obligation")
	}
	if len(sourceOwnedChangedPaths) == 0 {
		*failures = append(*failures, "impact demo must declare source-owned changed paths")
	}
	for _, path := range sourceOwnedChangedPaths {
		if _, ok := changed[path]; !ok {
			*failures = append(*failures, "impact demo source-owned path is absent from changedPaths: "+path)
		}
		if _, ok := generatedMirrorSet[path]; ok {
			*failures = append(*failures, "impact demo source-owned path must not be a generated mirror: "+path)
		}
	}
	return admittedImpactDemo{
		DemoID: demoID, GeneratedMirrorPathCount: len(generatedMirrorSet),
		Report: impactReport, SourceOwnedPathCount: len(sourceOwnedChangedPaths),
	}, nil
}

func admitStackDiversity(raw any, failures *[]string, options Options) (*admittedStackDiversity, error) {
	if raw == nil {
		if options.RequireStackDiverseReleaseCandidate {
			*failures = append(*failures, "stack-diverse pilot must declare stackDiversity")
		}
		return nil, nil
	}
	record, err := object(raw, "proofkit pilot stackDiversity")
	if err != nil {
		return nil, err
	}
	addErr(failures, admit.KnownKeys(record, []string{"baselinePilotId", "dimensions"}, "proofkit pilot stackDiversity"))
	baselinePilotID, err := admit.RuleID(record["baselinePilotId"], "stack diversity baselinePilotId")
	if err != nil {
		return nil, err
	}
	rawDimensions, ok := record["dimensions"].([]any)
	if !ok {
		return nil, fmt.Errorf("stack diversity dimensions must be an array")
	}
	dimensions := make([]admittedStackDiversityDimension, 0, len(rawDimensions))
	for _, rawDimension := range rawDimensions {
		dimensionRecord, err := object(rawDimension, "stack diversity dimension")
		if err != nil {
			return nil, err
		}
		addErr(failures, admit.KnownKeys(dimensionRecord, []string{"baseline", "candidate", "dimension", "evidence"}, "stack diversity dimension"))
		dimension := stringValue(dimensionRecord["dimension"])
		baseline, err := nonEmptyText(dimensionRecord["baseline"], "stack diversity baseline")
		if err != nil {
			return nil, err
		}
		candidate, err := nonEmptyText(dimensionRecord["candidate"], "stack diversity candidate")
		if err != nil {
			return nil, err
		}
		evidence, err := nonEmptyText(dimensionRecord["evidence"], "stack diversity evidence")
		if err != nil {
			return nil, err
		}
		dimensions = append(dimensions, admittedStackDiversityDimension{
			Baseline: baseline, Candidate: candidate, Dimension: dimension, Evidence: evidence,
		})
	}
	sort.Slice(dimensions, func(left int, right int) bool {
		return dimensions[left].Dimension < dimensions[right].Dimension
	})
	assertSortedUniqueOrFail(stackDimensionIDs(dimensions), "stack diversity dimension", failures)
	required := stringSet(stackDiversityDimensions)
	for _, dimension := range dimensions {
		if _, ok := required[dimension.Dimension]; !ok {
			*failures = append(*failures, "unsupported stack diversity dimension: "+dimension.Dimension)
		}
		if dimension.Baseline == dimension.Candidate {
			*failures = append(*failures, "stack diversity dimension must differ from baseline: "+dimension.Dimension)
		}
	}
	if options.RequireStackDiverseReleaseCandidate {
		for _, dimension := range stackDiversityDimensions {
			if !hasStackDimension(dimensions, dimension) {
				*failures = append(*failures, "stack-diverse pilot missing required dimension: "+dimension)
			}
		}
	}
	return &admittedStackDiversity{BaselinePilotID: baselinePilotID, Dimensions: dimensions}, nil
}

func admitCacheNegativeChecks(raw any, failures *[]string, options Options) ([]admittedCacheNegativeCheck, error) {
	if raw == nil {
		raw = []any{}
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("cache negative checks must be an array")
	}
	checks := make([]admittedCacheNegativeCheck, 0, len(values))
	for _, value := range values {
		record, err := object(value, "cache negative check")
		if err != nil {
			return nil, err
		}
		addErr(failures, admit.KnownKeys(record, []string{"checkId", "evidence", "expectedOutcome", "invalidatedInputClass", "liveOrCredentialedCacheable"}, "cache negative check"))
		if record["expectedOutcome"] != "invalidate_output" {
			*failures = append(*failures, "cache negative check expectedOutcome must be invalidate_output")
		}
		if record["liveOrCredentialedCacheable"] != false {
			*failures = append(*failures, "cache negative checks must keep live or credentialed proof non-cacheable")
		}
		checkID, err := admit.RuleID(record["checkId"], "cache negative checkId")
		if err != nil {
			return nil, err
		}
		evidence, err := nonEmptyText(record["evidence"], "cache negative evidence")
		if err != nil {
			return nil, err
		}
		checks = append(checks, admittedCacheNegativeCheck{
			CheckID: checkID, Evidence: evidence, ExpectedOutcome: stringValue(record["expectedOutcome"]),
			InvalidatedInputClass: stringValue(record["invalidatedInputClass"]), LiveOrCredentialedCacheable: false,
		})
	}
	sort.Slice(checks, func(left int, right int) bool {
		return checks[left].CheckID < checks[right].CheckID
	})
	assertSortedUniqueOrFail(cacheCheckIDs(checks), "cache negative checkId", failures)
	required := stringSet(cacheInvalidationClasses)
	if options.RequireStackDiverseReleaseCandidate {
		for _, inputClass := range cacheInvalidationClasses {
			if !hasCacheInputClass(checks, inputClass) {
				*failures = append(*failures, "stack-diverse pilot missing cache invalidation check for "+inputClass)
			}
		}
	}
	for _, check := range checks {
		if _, ok := required[check.InvalidatedInputClass]; !ok {
			*failures = append(*failures, "unsupported cache invalidation input class: "+check.InvalidatedInputClass)
		}
	}
	return checks, nil
}

func assertStackDiverseImpactCoverage(impactReports []map[string]any, failures *[]string) {
	covered := map[string]struct{}{}
	for _, impactReport := range impactReports {
		for _, obligation := range arrayValue(impactReport["obligations"]) {
			record, ok := obligation.(map[string]any)
			if !ok {
				continue
			}
			for _, reason := range stringsFromAnyArray(arrayValue(record["changeReasons"])) {
				covered[reason] = struct{}{}
			}
		}
	}
	for _, reason := range []string{"proof_binding_changed", "proof_witness_changed", "record_changed"} {
		if _, ok := covered[reason]; !ok {
			*failures = append(*failures, "stack-diverse pilot missing impact demo for "+reason)
		}
	}
}

func ruleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{{
			RuleID:      "proofkit.pilot-admission.accepted",
			Status:      "passed",
			Message:     "pilot admission contract is complete and non-blocking",
			Diagnostics: []report.Diagnostic{},
		}}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.pilot-admission.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}

func blockingRequirementDiagnostics(requirements []admittedBlockingRequirement) []any {
	values := make([]any, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, map[string]any{
			"evidence":      requirement.Evidence,
			"owner":         requirement.Owner,
			"requirementId": requirement.RequirementID,
			"status":        requirement.Status,
		})
	}
	return values
}

func cacheNegativeCheckDiagnostics(checks []admittedCacheNegativeCheck) []any {
	values := make([]any, 0, len(checks))
	for _, check := range checks {
		values = append(values, map[string]any{
			"checkId":                     check.CheckID,
			"evidence":                    check.Evidence,
			"expectedOutcome":             check.ExpectedOutcome,
			"invalidatedInputClass":       check.InvalidatedInputClass,
			"liveOrCredentialedCacheable": check.LiveOrCredentialedCacheable,
		})
	}
	return values
}

func customRuleDiagnostics(rules []admittedCustomRule) []any {
	values := make([]any, 0, len(rules))
	for _, rule := range rules {
		values = append(values, map[string]any{
			"downgradeGenericFailures": rule.DowngradeGenericFailures,
			"owner":                    rule.Owner,
			"purpose":                  rule.Purpose,
			"ruleId":                   rule.RuleID,
		})
	}
	return values
}

func impactDemoDiagnostics(demos []admittedImpactDemo) []any {
	values := make([]any, 0, len(demos))
	for _, demo := range demos {
		values = append(values, map[string]any{
			"demoId":          demo.DemoID,
			"obligationCount": len(arrayValue(demo.Report["obligations"])),
			"state":           demo.Report["impactState"],
		})
	}
	return values
}

func stackDiversityDiagnostics(diversity *admittedStackDiversity) []any {
	if diversity == nil {
		return []any{}
	}
	values := make([]any, 0, len(diversity.Dimensions))
	for _, dimension := range diversity.Dimensions {
		values = append(values, map[string]any{
			"baseline":  dimension.Baseline,
			"candidate": dimension.Candidate,
			"dimension": dimension.Dimension,
			"evidence":  dimension.Evidence,
		})
	}
	return values
}

func object(raw any, context string) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	return record, nil
}

func addErr(failures *[]string, err error) {
	if err != nil {
		*failures = append(*failures, err.Error())
	}
}

func arrayValue(raw any) []any {
	values, ok := raw.([]any)
	if !ok {
		return []any{}
	}
	return values
}

func stringValue(raw any) string {
	value, _ := raw.(string)
	return value
}

func nonEmptyText(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func safePath(raw any, context string) (string, error) {
	value, err := nonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func safePathArray(raw any, context string, failures *[]string) []string {
	values, ok := raw.([]any)
	if !ok {
		*failures = append(*failures, context+" must be an array")
		return []string{}
	}
	paths := make([]string, 0, len(values))
	for _, value := range values {
		path, err := safePath(value, context)
		if err != nil {
			*failures = append(*failures, err.Error())
			return []string{}
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		*failures = append(*failures, context+" must be non-empty")
	}
	assertSortedUniqueOrFail(paths, context, failures)
	return paths
}

func nonNegativeInteger(raw any, context string, failures *[]string, min int) int {
	number, ok := raw.(json.Number)
	if !ok {
		*failures = append(*failures, fmt.Sprintf("%s must be an integer >= %d", context, min))
		return 0
	}
	value, err := number.Int64()
	if err != nil || value < int64(min) || int64(int(value)) != value {
		*failures = append(*failures, fmt.Sprintf("%s must be an integer >= %d", context, min))
		return 0
	}
	return int(value)
}

func nonNegativeNumber(raw any, context string, failures *[]string) any {
	number, ok := raw.(json.Number)
	if !ok {
		*failures = append(*failures, context+" must be a finite number >= 0")
		return 0
	}
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || value < 0 {
		*failures = append(*failures, context+" must be a finite number >= 0")
		return 0
	}
	return number
}

func assertSortedUniqueOrFail(values []string, context string, failures *[]string) {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			*failures = append(*failures, context+" must be sorted and unique")
			return
		}
	}
}

func stringSet(values []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func stringsFromAnyArray(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func requirementIDs(requirements []admittedBlockingRequirement) []string {
	values := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		values = append(values, requirement.RequirementID)
	}
	return values
}

func routeTaskTypes(routes []admittedAgentReportRoute) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, route.TaskType)
	}
	return values
}

func customRuleIDs(rules []admittedCustomRule) []string {
	values := make([]string, 0, len(rules))
	for _, rule := range rules {
		values = append(values, rule.RuleID)
	}
	return values
}

func impactDemoIDs(demos []admittedImpactDemo) []string {
	values := make([]string, 0, len(demos))
	for _, demo := range demos {
		values = append(values, demo.DemoID)
	}
	return values
}

func stackDimensionIDs(dimensions []admittedStackDiversityDimension) []string {
	values := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		values = append(values, dimension.Dimension)
	}
	return values
}

func cacheCheckIDs(checks []admittedCacheNegativeCheck) []string {
	values := make([]string, 0, len(checks))
	for _, check := range checks {
		values = append(values, check.CheckID)
	}
	return values
}

func hasStackDimension(dimensions []admittedStackDiversityDimension, id string) bool {
	for _, dimension := range dimensions {
		if dimension.Dimension == id {
			return true
		}
	}
	return false
}

func hasCacheInputClass(checks []admittedCacheNegativeCheck, id string) bool {
	for _, check := range checks {
		if check.InvalidatedInputClass == id {
			return true
		}
	}
	return false
}
