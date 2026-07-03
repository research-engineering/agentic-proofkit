package projectstructure

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var scaffoldNonClaims = []string{
	"Project-structure scaffold reports do not execute native witnesses.",
	"Project-structure scaffold reports do not own final module specifications or final repository profile policy.",
	"Project-structure scaffold reports do not prove proof freshness, merge readiness, release readiness, rollout readiness, or product readiness.",
	"Project-structure scaffold reports do not read repository state.",
	"Project-structure scaffold reports do not write files.",
}

type Result struct {
	AdoptionWorkflowInput map[string]any
	AdoptionWorkflowPlan  map[string]any
	Bootstrap             gradualadoption.BootstrapResult
	ExitCode              int
	Manifest              map[string]any
	Record                report.Record
	RepoProfile           scaffoldprofileplan.Result
}

func Build(raw any) (map[string]any, int, error) {
	result, err := BuildResult(raw)
	if err != nil {
		return nil, 1, err
	}
	return result.JSONValue(), result.ExitCode, nil
}

func BuildEnvelope(raw any) (map[string]any, int, error) {
	result, err := BuildResult(raw)
	if err != nil {
		return nil, 1, err
	}
	return BuildEnvelopeFromResult(result)
}

func BuildResult(raw any) (Result, error) {
	input, ok := raw.(map[string]any)
	if !ok {
		return Result{}, fmt.Errorf("project structure scaffold input must be an object")
	}
	if err := admit.KnownKeys(input, []string{"bootstrap", "nonClaims", "paths", "repoProfileScaffold", "scaffoldId", "schemaVersion", "workflow"}, "project structure scaffold input"); err != nil {
		return Result{}, err
	}
	if !admit.JSONNumberEquals(input["schemaVersion"], 1) {
		return Result{}, fmt.Errorf("project structure scaffold schemaVersion must be 1")
	}
	scaffoldID, err := admit.RuleID(input["scaffoldId"], "project structure scaffoldId")
	if err != nil {
		return Result{}, err
	}
	paths, err := projectPaths(input["paths"])
	if err != nil {
		return Result{}, err
	}
	workflow, err := object(input["workflow"], "project structure scaffold workflow")
	if err != nil {
		return Result{}, err
	}
	if workflow["scenario"] != "new_repository" {
		return Result{}, fmt.Errorf("project structure scaffold workflow.scenario must be new_repository")
	}
	repoProfileInput, err := object(input["repoProfileScaffold"], "project structure scaffold repoProfileScaffold")
	if err != nil {
		return Result{}, err
	}
	bootstrapInput, err := object(input["bootstrap"], "project structure scaffold bootstrap")
	if err != nil {
		return Result{}, err
	}
	repoProfile, err := scaffoldprofileplan.BuildResult(repoProfileInput)
	if err != nil {
		return Result{}, err
	}
	bootstrap, err := gradualadoption.BuildBootstrapResult(bootstrapInput)
	if err != nil {
		return Result{}, err
	}
	bootstrapManifest, err := gradualadoption.BootstrapMaterializationManifest(bootstrap)
	if err != nil {
		return Result{}, err
	}
	workflowInput, err := adoptionWorkflowInput(bootstrapInput, repoProfile.Plan, paths, workflow)
	if err != nil {
		return Result{}, err
	}
	adoptionWorkflow, err := adoptionworkflow.BuildResult(workflowInput)
	if err != nil {
		return Result{}, err
	}
	failures := pathConsistencyFailures(bootstrapInput, repoProfile.Plan)
	if bootstrap.Record.State != "passed" {
		failures = append(failures, "project structure scaffold requires a passed bootstrap report")
	}
	if adoptionWorkflow.Plan["planState"] != "ready_for_caller_review" {
		failures = append(failures, "project structure scaffold requires a ready adoption workflow plan")
	}
	nonClaims, err := mergedNonClaims(input["nonClaims"])
	if err != nil {
		return Result{}, err
	}
	manifest, err := buildMaterializationManifest(materializationInput{
		adoptionWorkflowInput: workflowInput,
		bootstrapInput:        bootstrapInput,
		bootstrapManifest:     bootstrapManifest,
		paths:                 paths,
		repoProfileInput:      repoProfileInput,
		repoProfilePlan:       repoProfile.Plan,
		scaffoldID:            scaffoldID,
		sourceReports: []report.Record{
			repoProfile.Record,
			bootstrap.Record,
			adoptionWorkflow.Record,
		},
	})
	if err != nil {
		return Result{}, err
	}
	state := "passed"
	exitCode := 0
	if len(failures) > 0 {
		state = "failed"
		exitCode = 1
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.project-structure-scaffold",
		ReportID:      scaffoldID,
		State:         state,
		Summary: map[string]any{
			"callerContentRequiredCount": manifest["callerContentRequiredCount"],
			"fileCount":                  manifest["fileCount"],
			"payloadFileCount":           manifest["payloadFileCount"],
			"sourceReportCount":          len(anyArray(manifest["sourceReports"])),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "materializationManifestSummary", Value: materializationManifestSummary(manifest)},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	return Result{
		AdoptionWorkflowInput: workflowInput,
		AdoptionWorkflowPlan:  adoptionWorkflow.Plan,
		Bootstrap:             bootstrap,
		ExitCode:              exitCode,
		Manifest:              manifest,
		Record:                record,
		RepoProfile:           repoProfile,
	}, nil
}

func (result Result) JSONValue() map[string]any {
	return map[string]any{
		"adoptionWorkflowInput":   result.AdoptionWorkflowInput,
		"adoptionWorkflowPlan":    result.AdoptionWorkflowPlan,
		"bootstrapReport":         result.Bootstrap.JSONValue(),
		"exitCode":                result.ExitCode,
		"materializationManifest": result.Manifest,
		"repoProfileScaffoldPlan": result.RepoProfile.Plan,
		"report":                  result.Record.JSONValue(),
	}
}

func adoptionWorkflowInput(bootstrapInput map[string]any, repoProfilePlan map[string]any, paths projectPathSet, workflow map[string]any) (map[string]any, error) {
	workflowID, err := admit.RuleID(workflow["workflowId"], "project structure scaffold workflowId")
	if err != nil {
		return nil, err
	}
	bootstrapPaths, err := object(bootstrapInput["paths"], "project structure scaffold bootstrap paths")
	if err != nil {
		return nil, err
	}
	proofBindingPath, err := safePath(bootstrapInput["proofBindingPath"], "project structure scaffold proofBindingPath")
	if err != nil {
		return nil, err
	}
	witnessPlanInputPath, err := safePath(bootstrapPaths["witnessPlanInputPath"], "project structure scaffold witnessPlanInputPath")
	if err != nil {
		return nil, err
	}
	adoptionGuidancePath, err := safePath(bootstrapPaths["adoptionGuidancePath"], "project structure scaffold adoptionGuidancePath")
	if err != nil {
		return nil, err
	}
	workflowNonClaims, err := sortedUniqueText(rawStringArray(workflow["nonClaims"]), "project structure scaffold workflow nonClaims", false)
	if err != nil {
		return nil, err
	}
	nonClaims, err := sortedUniqueText(append([]string{
		"Adoption workflow input does not prove file materialization or native witness execution.",
		"Adoption workflow input is starter routing only.",
	}, workflowNonClaims...), "project structure scaffold workflow nonClaims", false)
	if err != nil {
		return nil, err
	}
	input := map[string]any{
		"inputRefs": []any{
			map[string]any{"inputKind": "gradual_adoption_bootstrap", "path": paths.bootstrapInputPath, "refId": "gradual_adoption_bootstrap"},
			map[string]any{"inputKind": "gradual_adoption_guidance", "path": adoptionGuidancePath, "refId": "gradual_adoption_guidance"},
			map[string]any{"inputKind": "repo_profile_scaffold", "path": paths.repoProfileScaffoldInputPath, "refId": "repo_profile_scaffold"},
			map[string]any{"inputKind": "requirement_bindings", "path": proofBindingPath, "refId": "requirement_bindings"},
			map[string]any{"inputKind": "witness_plan", "path": witnessPlanInputPath, "refId": "witness_plan"},
		},
		"nonClaims":     admit.StringSliceToAny(nonClaims),
		"scenario":      "new_repository",
		"schemaVersion": json.Number("1"),
		"workflowId":    workflowID,
	}
	if presetID, ok := repoProfilePlan["presetId"].(string); ok && presetID != "" {
		input["presetId"] = presetID
	}
	return input, nil
}

func pathConsistencyFailures(bootstrapInput map[string]any, repoProfilePlan map[string]any) []string {
	failures := []string{}
	repository := mapValue(bootstrapInput["repository"])
	ownerRoute := mapValue(bootstrapInput["ownerRoute"])
	module := mapValue(bootstrapInput["module"])
	repoProfileDraft := mapValue(repoProfilePlan["repoProfileDraft"])
	proofs := mapValue(repoProfileDraft["proofs"])
	if stringValue(repoProfilePlan["profilePath"]) != stringValue(repository["profilePath"]) {
		failures = append(failures, "repo profile scaffold profilePath must match bootstrap repository.profilePath")
	}
	if stringValue(proofs["bindingPath"]) != stringValue(bootstrapInput["proofBindingPath"]) {
		failures = append(failures, "repo profile scaffold bindingPath must match bootstrap proofBindingPath")
	}
	if !containsString(anyArray(ownerRoute["proofBindingPaths"]), stringValue(bootstrapInput["proofBindingPath"])) {
		failures = append(failures, "bootstrap ownerRoute proofBindingPaths must include bootstrap proofBindingPath")
	}
	if !containsString(anyArray(ownerRoute["specPaths"]), stringValue(module["specPath"])) {
		failures = append(failures, "bootstrap ownerRoute specPaths must include bootstrap module specPath")
	}
	return failures
}

func mergedNonClaims(raw any) ([]string, error) {
	caller, err := sortedUniqueText(rawStringArray(raw), "project structure scaffold nonClaims", false)
	if err != nil {
		return nil, err
	}
	return sortedUniqueText(append(append([]string{}, scaffoldNonClaims...), caller...), "project structure scaffold nonClaims", false)
}

func ruleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{{
			RuleID:      "proofkit.project-structure-scaffold.accepted",
			Status:      "passed",
			Message:     "project structure scaffold is deterministic and non-authoritative",
			Diagnostics: []report.Diagnostic{},
		}}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.project-structure-scaffold.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}

func sortedUniqueText(values []string, context string, allowEmpty bool) ([]string, error) {
	for index, value := range values {
		if value == "" {
			return nil, fmt.Errorf("%s must be a string array", context)
		}
		values[index] = stringTrim(value)
	}
	sort.Strings(values)
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}

func rawStringArray(raw any) []string {
	values := anyArray(raw)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
