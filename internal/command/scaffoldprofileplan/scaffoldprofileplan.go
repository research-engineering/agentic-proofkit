package scaffoldprofileplan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var scaffoldNonClaims = []string{
	"Repo-profile scaffold plans do not read repository state.",
	"Repo-profile scaffold plans do not write files.",
	"Repo-profile scaffold plans do not execute native witnesses.",
	"Repo-profile scaffold plans do not prove profile correctness, proof freshness, merge readiness, or rollout readiness.",
}

var supportedMatcherKinds = map[string]struct{}{
	"bun_repo_script":              {},
	"bun_workspace_package_script": {},
	"exact_argv":                   {},
	"python_pytest_contract":       {},
}

var supportedNetworkPolicies = map[string]struct{}{
	"external": {},
	"loopback": {},
	"none":     {},
}

var supportedCredentialClasses = map[string]struct{}{
	"live-cloud":   {},
	"live-github":  {},
	"local-secret": {},
	"none":         {},
}

type input struct {
	SchemaVersion       int
	PlanID              string
	PresetID            *string
	Repository          repositoryInput
	Paths               pathsInput
	Requirements        requirementsInput
	EnvironmentClasses  []string
	CommandMatcherHints []commandMatcher
	NonClaims           []string
}

type repositoryInput struct {
	Name             string
	RootPackageName  string
	PrimaryLanguages []string
	ProfilePath      string
}

type pathsInput struct {
	PolicyPath               string
	RouterPath               string
	BindingPath              string
	GeneratedArtifacts       []generatedArtifact
	ProofLikePaths           []string
	ProofLikePathsFromPreset bool
	RetiredProofLikePaths    []string
	SpecGlobs                []string
	SpecGlobsFromPreset      bool
}

type requirementsInput struct {
	IDPattern string
}

type generatedArtifact struct {
	Path          string
	Generator     string
	SourceOfTruth []string
}

type commandMatcher struct {
	ID                   string
	Kind                 string
	AllowedArgv          []string
	AllowedScripts       []string
	AllowedTestPathGlobs []string
	NetworkPolicy        string
	CredentialClass      string
	ParallelGroup        string
	HasAllowedArgv       bool
	HasAllowedScripts    bool
	HasAllowedTestGlobs  bool
}

type Result struct {
	ExitCode int
	Plan     map[string]any
	Record   report.Record
}

func Build(raw any) (any, error) {
	result, err := BuildResult(raw)
	if err != nil {
		return nil, err
	}
	return result.Plan, nil
}

func BuildResult(raw any) (Result, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Result{}, err
	}
	plan, err := buildPlan(input)
	if err != nil {
		return Result{}, err
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.repo-profile-scaffold-plan",
		ReportID:      input.PlanID,
		State:         "passed",
		Summary: map[string]any{
			"callerRequiredGapCount": len(anyArray(plan["callerRequiredGaps"])),
			"commandMatcherCount":    len(input.CommandMatcherHints),
			"environmentClassCount":  len(input.EnvironmentClasses),
			"generatedArtifactCount": len(input.Paths.GeneratedArtifacts),
			"presetId":               nullableString(input.PresetID),
			"proofLikePathCount":     len(input.Paths.ProofLikePaths),
			"specGlobCount":          len(input.Paths.SpecGlobs),
		},
		Diagnostics: []report.Diagnostic{{Key: "plan", Value: plan}},
		RuleResults: []report.RuleResult{{
			RuleID:      "proofkit.repo-profile-scaffold-plan.accepted",
			Status:      "passed",
			Message:     "repo-profile scaffold plan is deterministic and non-authoritative",
			Diagnostics: []report.Diagnostic{},
		}},
		NonClaims: plan["nonClaims"].([]any),
	}
	return Result{ExitCode: 0, Plan: plan, Record: record}, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("repo-profile scaffold input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commandMatcherHints", "environmentClasses", "nonClaims", "paths", "planId", "presetId", "repository", "requirements", "schemaVersion"}, "repo-profile scaffold input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("repo-profile scaffold plan schemaVersion must be 1")
	}
	planID, err := admit.RuleID(record["planId"], "repo-profile scaffold planId")
	if err != nil {
		return input{}, err
	}
	presetID, preset, err := admitPreset(record["presetId"])
	if err != nil {
		return input{}, err
	}
	repository, err := admitRepository(record["repository"])
	if err != nil {
		return input{}, err
	}
	paths, err := admitPaths(record["paths"], presetID, preset)
	if err != nil {
		return input{}, err
	}
	requirements, err := admitRequirements(record["requirements"])
	if err != nil {
		return input{}, err
	}
	environmentClasses, err := admitEnvironmentClasses(record["environmentClasses"], presetID, preset)
	if err != nil {
		return input{}, err
	}
	commandMatchers, err := admitCommandMatchers(record["commandMatcherHints"])
	if err != nil {
		return input{}, err
	}
	nonClaims, err := sortedUniqueTextRaw(record["nonClaims"], "repo-profile scaffold nonClaims", false)
	if err != nil {
		return input{}, err
	}
	return input{
		SchemaVersion:       1,
		PlanID:              planID,
		PresetID:            presetID,
		Repository:          repository,
		Paths:               paths,
		Requirements:        requirements,
		EnvironmentClasses:  environmentClasses,
		CommandMatcherHints: commandMatchers,
		NonClaims:           nonClaims,
	}, nil
}

func admitPreset(raw any) (*string, *stackpreset.Profile, error) {
	if raw == nil {
		return nil, nil, nil
	}
	presetID, ok := raw.(string)
	if !ok || !stackpreset.IsPresetID(presetID) {
		return nil, nil, fmt.Errorf("repo-profile scaffold presetId must be a known stack preset id")
	}
	preset, _ := stackpreset.ProfileFor(presetID)
	return &presetID, &preset, nil
}

func admitRepository(raw any) (repositoryInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return repositoryInput{}, fmt.Errorf("repo-profile scaffold repository must be an object")
	}
	if err := admit.KnownKeys(record, []string{"name", "primaryLanguages", "profilePath", "rootPackageName"}, "repo-profile scaffold repository"); err != nil {
		return repositoryInput{}, err
	}
	name, err := nonEmptyText(record["name"], "repo-profile scaffold repository.name")
	if err != nil {
		return repositoryInput{}, err
	}
	rootPackageName, err := nonEmptyText(record["rootPackageName"], "repo-profile scaffold repository.rootPackageName")
	if err != nil {
		return repositoryInput{}, err
	}
	primaryLanguages, err := sortedUniqueTextRaw(record["primaryLanguages"], "repo-profile scaffold repository.primaryLanguages", false)
	if err != nil {
		return repositoryInput{}, err
	}
	profilePath, err := safePath(record["profilePath"], "repo-profile scaffold profilePath")
	if err != nil {
		return repositoryInput{}, err
	}
	return repositoryInput{
		Name:             name,
		RootPackageName:  rootPackageName,
		PrimaryLanguages: primaryLanguages,
		ProfilePath:      profilePath,
	}, nil
}

func admitPaths(raw any, presetID *string, preset *stackpreset.Profile) (pathsInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return pathsInput{}, fmt.Errorf("repo-profile scaffold paths must be an object")
	}
	if err := admit.KnownKeys(record, []string{"bindingPath", "generatedArtifacts", "policyPath", "proofLikePaths", "retiredProofLikePaths", "routerPath", "specGlobs"}, "repo-profile scaffold paths"); err != nil {
		return pathsInput{}, err
	}
	policyPath, err := safePath(record["policyPath"], "repo-profile scaffold paths.policyPath")
	if err != nil {
		return pathsInput{}, err
	}
	routerPath, err := safePath(record["routerPath"], "repo-profile scaffold paths.routerPath")
	if err != nil {
		return pathsInput{}, err
	}
	bindingPath, err := safePath(record["bindingPath"], "repo-profile scaffold paths.bindingPath")
	if err != nil {
		return pathsInput{}, err
	}
	generatedArtifacts, err := admitGeneratedArtifacts(record["generatedArtifacts"])
	if err != nil {
		return pathsInput{}, err
	}
	specGlobsRaw, specGlobsFromPreset := record["specGlobs"], false
	if specGlobsRaw == nil {
		if preset != nil && presetID != nil {
			values := []any{}
			for _, pathValue := range preset.StarterProofLikePaths {
				if strings.HasPrefix(pathValue, "docs/specs/") {
					values = append(values, pathValue)
				}
			}
			specGlobsRaw = values
			specGlobsFromPreset = true
		} else {
			specGlobsRaw = []any{"docs/specs/**/*.md"}
		}
	}
	specGlobs, err := sortedUniquePathsRaw(specGlobsRaw, "repo-profile scaffold paths.specGlobs", false)
	if err != nil {
		return pathsInput{}, err
	}
	proofLikePathsRaw, proofLikePathsFromPreset := record["proofLikePaths"], false
	if proofLikePathsRaw == nil {
		if preset != nil && presetID != nil {
			values := make([]any, 0, len(preset.StarterProofLikePaths))
			for _, pathValue := range preset.StarterProofLikePaths {
				values = append(values, pathValue)
			}
			proofLikePathsRaw = values
			proofLikePathsFromPreset = true
		} else {
			proofLikePathsRaw = []any{}
		}
	}
	proofLikePaths, err := sortedUniquePathsRaw(proofLikePathsRaw, "repo-profile scaffold paths.proofLikePaths", true)
	if err != nil {
		return pathsInput{}, err
	}
	retiredRaw := record["retiredProofLikePaths"]
	if retiredRaw == nil {
		retiredRaw = []any{}
	}
	retiredProofLikePaths, err := sortedUniquePathsRaw(retiredRaw, "repo-profile scaffold paths.retiredProofLikePaths", true)
	if err != nil {
		return pathsInput{}, err
	}
	return pathsInput{
		PolicyPath:               policyPath,
		RouterPath:               routerPath,
		BindingPath:              bindingPath,
		GeneratedArtifacts:       generatedArtifacts,
		ProofLikePaths:           proofLikePaths,
		ProofLikePathsFromPreset: proofLikePathsFromPreset,
		RetiredProofLikePaths:    retiredProofLikePaths,
		SpecGlobs:                specGlobs,
		SpecGlobsFromPreset:      specGlobsFromPreset,
	}, nil
}

func admitRequirements(raw any) (requirementsInput, error) {
	if raw == nil {
		return requirementsInput{}, fmt.Errorf("repo-profile scaffold requirements.idPattern must be caller-provided")
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return requirementsInput{}, fmt.Errorf("repo-profile scaffold requirements must be an object")
	}
	if err := admit.KnownKeys(record, []string{"idPattern"}, "repo-profile scaffold requirements"); err != nil {
		return requirementsInput{}, err
	}
	idPattern, err := nonEmptyText(record["idPattern"], "repo-profile scaffold requirements.idPattern")
	if err != nil {
		return requirementsInput{}, err
	}
	return requirementsInput{IDPattern: idPattern}, nil
}

func admitEnvironmentClasses(raw any, presetID *string, preset *stackpreset.Profile) ([]string, error) {
	if raw == nil {
		if preset != nil && presetID != nil {
			values := make([]any, 0, len(preset.StarterEnvironmentClasses))
			for _, value := range preset.StarterEnvironmentClasses {
				values = append(values, value)
			}
			raw = values
		} else {
			raw = []any{}
		}
	}
	return sortedUniqueTextRaw(raw, "repo-profile scaffold environmentClasses", true)
}

func admitGeneratedArtifacts(raw any) ([]generatedArtifact, error) {
	if raw == nil {
		return []generatedArtifact{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("repo-profile scaffold paths.generatedArtifacts must be a string array")
	}
	artifacts := make([]generatedArtifact, 0, len(values))
	for index, item := range values {
		record, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("generated artifact #%d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"generator", "path", "sourceOfTruth"}, fmt.Sprintf("generated artifact #%d", index+1)); err != nil {
			return nil, err
		}
		pathValue, err := safePath(record["path"], fmt.Sprintf("repo-profile scaffold paths.generatedArtifacts[%d].path", index))
		if err != nil {
			return nil, err
		}
		generator, err := safePath(record["generator"], fmt.Sprintf("repo-profile scaffold paths.generatedArtifacts[%d].generator", index))
		if err != nil {
			return nil, err
		}
		sourceOfTruth, err := sortedUniquePathsRaw(record["sourceOfTruth"], fmt.Sprintf("repo-profile scaffold paths.generatedArtifacts[%d].sourceOfTruth", index), true)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, generatedArtifact{
			Path:          pathValue,
			Generator:     generator,
			SourceOfTruth: sourceOfTruth,
		})
	}
	sort.Slice(artifacts, func(left, right int) bool {
		return artifacts[left].Path < artifacts[right].Path
	})
	paths := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		paths = append(paths, artifact.Path)
	}
	if err := assertSortedUnique(paths, "repo-profile scaffold paths.generatedArtifacts"); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func admitCommandMatchers(raw any) ([]commandMatcher, error) {
	if raw == nil {
		return []commandMatcher{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("repo-profile scaffold commandMatcherHints must be a string array")
	}
	matchers := make([]commandMatcher, 0, len(values))
	for _, item := range values {
		matcher, err := admitCommandMatcher(item)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
	}
	sort.Slice(matchers, func(left, right int) bool {
		return matchers[left].ID < matchers[right].ID
	})
	ids := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		ids = append(ids, matcher.ID)
	}
	if err := assertSortedUnique(ids, "repo-profile scaffold commandMatcher ids"); err != nil {
		return nil, err
	}
	for _, matcher := range matchers {
		if matcher.Kind == "exact_argv" && !matcher.HasAllowedArgv {
			return nil, fmt.Errorf("repo-profile scaffold commandMatcher %s must declare allowedArgv", matcher.ID)
		}
		if matcher.Kind == "exact_argv" && (matcher.HasAllowedScripts || matcher.HasAllowedTestGlobs) {
			return nil, fmt.Errorf("repo-profile scaffold commandMatcher %s must not declare script or test path matchers", matcher.ID)
		}
		if matcher.Kind != "exact_argv" && matcher.HasAllowedArgv {
			return nil, fmt.Errorf("repo-profile scaffold commandMatcher %s must not declare allowedArgv", matcher.ID)
		}
		if matcher.Kind == "python_pytest_contract" && !matcher.HasAllowedTestGlobs {
			return nil, fmt.Errorf("repo-profile scaffold commandMatcher %s must declare allowedTestPathGlobs", matcher.ID)
		}
		if matcher.Kind == "python_pytest_contract" && matcher.HasAllowedScripts {
			return nil, fmt.Errorf("repo-profile scaffold commandMatcher %s must not declare allowedScripts", matcher.ID)
		}
		if matcher.Kind != "python_pytest_contract" && matcher.Kind != "exact_argv" && !matcher.HasAllowedScripts {
			return nil, fmt.Errorf("repo-profile scaffold commandMatcher %s must declare allowedScripts", matcher.ID)
		}
		if matcher.Kind != "python_pytest_contract" && matcher.Kind != "exact_argv" && matcher.HasAllowedTestGlobs {
			return nil, fmt.Errorf("repo-profile scaffold commandMatcher %s must not declare allowedTestPathGlobs", matcher.ID)
		}
	}
	return matchers, nil
}

func admitCommandMatcher(raw any) (commandMatcher, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return commandMatcher{}, fmt.Errorf("repo-profile scaffold commandMatcher must be an object")
	}
	if err := admit.KnownKeys(record, []string{"allowedArgv", "allowedScripts", "allowedTestPathGlobs", "credentialClass", "id", "kind", "networkPolicy", "parallelGroup"}, "repo-profile scaffold commandMatcher"); err != nil {
		return commandMatcher{}, err
	}
	id, err := nonEmptyText(record["id"], "repo-profile scaffold commandMatcher id")
	if err != nil {
		return commandMatcher{}, err
	}
	kind, err := enum(record["kind"], supportedMatcherKinds, "repo-profile scaffold commandMatcher kind")
	if err != nil {
		return commandMatcher{}, err
	}
	networkPolicy, err := enum(record["networkPolicy"], supportedNetworkPolicies, "repo-profile scaffold commandMatcher networkPolicy")
	if err != nil {
		return commandMatcher{}, err
	}
	credentialClass, err := enum(record["credentialClass"], supportedCredentialClasses, "repo-profile scaffold commandMatcher credentialClass")
	if err != nil {
		return commandMatcher{}, err
	}
	parallelGroup, err := nonEmptyText(record["parallelGroup"], "repo-profile scaffold commandMatcher parallelGroup")
	if err != nil {
		return commandMatcher{}, err
	}
	matcher := commandMatcher{
		ID:              id,
		Kind:            kind,
		NetworkPolicy:   networkPolicy,
		CredentialClass: credentialClass,
		ParallelGroup:   parallelGroup,
	}
	if value, ok := record["allowedScripts"]; ok {
		scripts, err := sortedUniqueTextRaw(value, "repo-profile scaffold commandMatcher allowedScripts", false)
		if err != nil {
			return commandMatcher{}, err
		}
		matcher.AllowedScripts = scripts
		matcher.HasAllowedScripts = true
	}
	if value, ok := record["allowedArgv"]; ok {
		argv, err := admit.TextArray(value, "repo-profile scaffold commandMatcher allowedArgv", false)
		if err != nil {
			return commandMatcher{}, err
		}
		matcher.AllowedArgv = argv
		matcher.HasAllowedArgv = true
	}
	if value, ok := record["allowedTestPathGlobs"]; ok {
		globs, err := sortedUniquePathsRaw(value, "repo-profile scaffold commandMatcher allowedTestPathGlobs", false)
		if err != nil {
			return commandMatcher{}, err
		}
		matcher.AllowedTestPathGlobs = globs
		matcher.HasAllowedTestGlobs = true
	}
	return matcher, nil
}

func buildPlan(input input) (map[string]any, error) {
	draft, err := repoProfileDraft(input)
	if err != nil {
		return nil, err
	}
	gaps := scaffoldGaps(input)
	provenance := scaffoldProvenance(input)
	nonClaims, err := sortedUniqueText(anyStrings(append(append([]string{}, scaffoldNonClaims...), input.NonClaims...)), "repo-profile scaffold nonClaims", false)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"callerRequiredGaps": gaps,
		"nextCommands": []any{
			fmt.Sprintf("Review and write %s from the scaffold plan.", input.Repository.ProfilePath),
			"Run the consumer-owned repo-profile structural admission check with caller-provided facts.",
			"Run the consumer-owned native witnesses before enabling enforcement.",
		},
		"nonClaims":        admit.StringSliceToAny(nonClaims),
		"planId":           input.PlanID,
		"planKind":         "proofkit.repo-profile-scaffold-plan",
		"presetId":         nullableString(input.PresetID),
		"profilePath":      input.Repository.ProfilePath,
		"provenance":       provenance,
		"repoProfileDraft": draft,
		"schemaVersion":    1,
	}, nil
}

func repoProfileDraft(input input) (map[string]any, error) {
	if len(input.Paths.ProofLikePaths) == 0 {
		return nil, fmt.Errorf("repo profile proofs.proofLikePaths must be a non-empty string array")
	}
	if len(input.Paths.SpecGlobs) == 0 {
		return nil, fmt.Errorf("repo profile requirements.specGlobs must be a non-empty string array")
	}
	if len(input.EnvironmentClasses) == 0 {
		return nil, fmt.Errorf("repo profile proofs.environmentClasses must be a non-empty string array")
	}
	for index, artifact := range input.Paths.GeneratedArtifacts {
		if len(artifact.SourceOfTruth) == 0 {
			return nil, fmt.Errorf("generated artifact #%d sourceOfTruth must be a non-empty string array", index+1)
		}
	}
	return map[string]any{
		"commandMatchers": commandMatchersJSON(input.CommandMatcherHints),
		"documents": map[string]any{
			"generatedArtifacts": generatedArtifactsJSON(input.Paths.GeneratedArtifacts),
			"policyPath":         input.Paths.PolicyPath,
			"routerPath":         input.Paths.RouterPath,
		},
		"nonClaims": []any{
			"This repository profile draft does not prove repository facts or command pass evidence.",
			"This repository profile draft is caller-reviewed starter content.",
		},
		"proofs": map[string]any{
			"bindingPath":           input.Paths.BindingPath,
			"environmentClasses":    admit.StringSliceToAny(input.EnvironmentClasses),
			"proofLikePaths":        admit.StringSliceToAny(input.Paths.ProofLikePaths),
			"retiredProofLikePaths": admit.StringSliceToAny(input.Paths.RetiredProofLikePaths),
		},
		"repository": map[string]any{
			"name":             input.Repository.Name,
			"primaryLanguages": admit.StringSliceToAny(input.Repository.PrimaryLanguages),
			"rootPackageName":  input.Repository.RootPackageName,
		},
		"requirements": map[string]any{
			"idPattern": input.Requirements.IDPattern,
			"specGlobs": admit.StringSliceToAny(input.Paths.SpecGlobs),
		},
		"schema": "proofkit.repo-profile.v1",
	}, nil
}

func scaffoldGaps(input input) []any {
	gaps := []map[string]any{}
	if len(input.CommandMatcherHints) == 0 {
		gaps = append(gaps, gap(
			"command-matchers",
			"commandMatchers",
			"Command admission cannot be inferred safely from preset names or shell text.",
			"Declare caller-reviewed command matchers for the repository witness commands.",
		))
	}
	if len(input.Paths.GeneratedArtifacts) == 0 {
		gaps = append(gaps, gap(
			"generated-artifacts",
			"documents.generatedArtifacts",
			"Generated artifact ownership is repository-specific.",
			"Declare generated artifacts only when the repository has generated lookup surfaces.",
		))
	}
	gaps = append(gaps, gap(
		"tracked-facts",
		"facts",
		"Profile admission needs caller-provided tracked files, package scripts, root scripts, docs policy generated artifacts, and command/environment pairs.",
		"Collect repository facts outside Proofkit and pass them to repo-profile structural admission.",
	))
	sort.Slice(gaps, func(left, right int) bool {
		return gaps[left]["gapId"].(string) < gaps[right]["gapId"].(string)
	})
	result := make([]any, 0, len(gaps))
	for _, item := range gaps {
		result = append(result, item)
	}
	return result
}

func gap(suffix string, fieldPath string, reason string, suggestedAction string) map[string]any {
	return map[string]any{
		"fieldPath":       fieldPath,
		"gapId":           "proofkit.repo-profile-scaffold.gap." + suffix,
		"nonClaim":        "Caller-required gaps are routing prompts, not Proofkit decisions or proof failures.",
		"owner":           "consumer_repository",
		"reason":          reason,
		"suggestedAction": suggestedAction,
	}
}

func scaffoldProvenance(input input) []any {
	rows := []map[string]any{
		provenanceRow("repository.name", "caller_input", "repository.name"),
		provenanceRow("repository.primaryLanguages", "caller_input", "repository.primaryLanguages"),
		provenanceRow("repository.rootPackageName", "caller_input", "repository.rootPackageName"),
		provenanceRow("documents.policyPath", "caller_input", "paths.policyPath"),
		provenanceRow("documents.routerPath", "caller_input", "paths.routerPath"),
		provenanceRow("proofs.bindingPath", "caller_input", "paths.bindingPath"),
		provenanceRow("requirements.idPattern", "caller_input", "requirements.idPattern"),
	}
	if input.Paths.SpecGlobsFromPreset && input.PresetID != nil {
		rows = append(rows, provenanceRow("requirements.specGlobs", "stack_preset", "stack-preset:"+*input.PresetID+".starterProofLikePaths"))
	} else {
		rows = append(rows, provenanceRow("requirements.specGlobs", "caller_input", "paths.specGlobs"))
	}
	if input.Paths.ProofLikePathsFromPreset && input.PresetID != nil {
		rows = append(rows, provenanceRow("proofs.proofLikePaths", "stack_preset", "stack-preset:"+*input.PresetID+".starterProofLikePaths"))
	} else {
		rows = append(rows, provenanceRow("proofs.proofLikePaths", "caller_input", "paths.proofLikePaths"))
	}
	if input.PresetID != nil && len(input.EnvironmentClasses) > 0 {
		rows = append(rows, provenanceRow("proofs.environmentClasses", "stack_preset", "stack-preset:"+*input.PresetID+".starterEnvironmentClasses"))
	} else {
		rows = append(rows, provenanceRow("proofs.environmentClasses", "caller_input", "environmentClasses"))
	}
	if len(input.Paths.GeneratedArtifacts) > 0 {
		rows = append(rows, provenanceRow("documents.generatedArtifacts", "caller_input", "paths.generatedArtifacts"))
	}
	if len(input.CommandMatcherHints) > 0 {
		rows = append(rows, provenanceRow("commandMatchers", "caller_input", "commandMatcherHints"))
	}
	sort.Slice(rows, func(left, right int) bool {
		return rows[left]["fieldPath"].(string) < rows[right]["fieldPath"].(string)
	})
	result := make([]any, 0, len(rows))
	for _, row := range rows {
		result = append(result, row)
	}
	return result
}

func provenanceRow(fieldPath string, source string, evidenceRef string) map[string]any {
	return map[string]any{
		"evidenceRef": evidenceRef,
		"fieldPath":   fieldPath,
		"nonClaim":    "Provenance identifies scaffold input origin only and does not prove repository truth.",
		"source":      source,
	}
}

func generatedArtifactsJSON(artifacts []generatedArtifact) []any {
	result := make([]any, 0, len(artifacts))
	for _, artifact := range artifacts {
		result = append(result, map[string]any{
			"generator":     artifact.Generator,
			"path":          artifact.Path,
			"sourceOfTruth": admit.StringSliceToAny(artifact.SourceOfTruth),
		})
	}
	return result
}

func commandMatchersJSON(matchers []commandMatcher) []any {
	result := make([]any, 0, len(matchers))
	for _, matcher := range matchers {
		item := map[string]any{
			"credentialClass": matcher.CredentialClass,
			"id":              matcher.ID,
			"kind":            matcher.Kind,
			"networkPolicy":   matcher.NetworkPolicy,
			"parallelGroup":   matcher.ParallelGroup,
		}
		if matcher.HasAllowedScripts {
			item["allowedScripts"] = admit.StringSliceToAny(matcher.AllowedScripts)
		}
		if matcher.HasAllowedArgv {
			item["allowedArgv"] = admit.StringSliceToAny(matcher.AllowedArgv)
		}
		if matcher.HasAllowedTestGlobs {
			item["allowedTestPathGlobs"] = admit.StringSliceToAny(matcher.AllowedTestPathGlobs)
		}
		result = append(result, item)
	}
	return result
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func rawArray(raw any, context string) ([]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	return values, nil
}

func sortedUniqueTextRaw(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := rawArray(raw, context)
	if err != nil {
		return nil, err
	}
	return sortedUniqueText(values, context, allowEmpty)
}

func sortedUniquePathsRaw(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := rawArray(raw, context)
	if err != nil {
		return nil, err
	}
	return sortedUniquePaths(values, context, allowEmpty)
}

func sortedUniqueText(raw []any, context string, allowEmpty bool) ([]string, error) {
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		value, err := nonEmptyText(item, context)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	sort.Strings(values)
	if err := assertSortedUnique(values, context); err != nil {
		return nil, err
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	return values, nil
}

func sortedUniquePaths(raw []any, context string, allowEmpty bool) ([]string, error) {
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		value, err := safePath(item, context)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	sort.Strings(values)
	if err := assertSortedUnique(values, context); err != nil {
		return nil, err
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	return values, nil
}

func anyStrings(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func anyArray(value any) []any {
	if values, ok := value.([]any); ok {
		return values
	}
	return []any{}
}

func nonEmptyText(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s must be non-empty text", context)
	}
	return strings.TrimSpace(value), nil
}

func safePath(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a repository-relative POSIX path", context)
	}
	return admit.SafeRepoRelativePath(value, context)
}

func enum(raw any, values map[string]struct{}, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a supported value", context)
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be a supported value", context)
	}
	return value, nil
}

func assertSortedUnique(values []string, context string) error {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}
