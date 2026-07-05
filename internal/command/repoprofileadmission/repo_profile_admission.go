package repoprofileadmission

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathpattern"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var boundaryNonClaims = []any{
	"Repo-profile structural admission does not read repository state.",
	"Repo-profile structural admission does not execute native witnesses.",
	"Repo-profile structural admission does not prove command pass evidence.",
}

var shellControlTokens = map[string]struct{}{
	"&&": {},
	"&":  {},
	"(":  {},
	")":  {},
	";":  {},
	"<":  {},
	">":  {},
	">>": {},
	"|":  {},
	"||": {},
}

var (
	workspaceScriptPattern = regexp.MustCompile(`^bun run --filter (\S+) ([a-z0-9:-]+)$`)
	rootScriptPattern      = regexp.MustCompile(`^bun run ([a-z0-9:-]+)$`)
	selftestScriptPattern  = regexp.MustCompile(`^bun (scripts(?:/[a-z0-9-]+)*/[a-z0-9-]+\.selftest\.ts)$`)
	pytestPattern          = regexp.MustCompile(`^python3 -m pytest (.+) -q$`)
	argvUnsafePattern      = regexp.MustCompile(`[\s\x00]`)
	argvQuotePattern       = regexp.MustCompile("[\"'\\x60\\\\]")
	commandWhitespace      = regexp.MustCompile(`[\t\r\n]`)
)

type generatedArtifact struct {
	Path          string
	Generator     string
	SourceOfTruth []string
}

type repository struct {
	Name             string
	PrimaryLanguages []string
	RootPackageName  string
}

type documents struct {
	PolicyPath         string
	RouterPath         string
	GeneratedArtifacts []generatedArtifact
}

type requirements struct {
	IDPattern string
	SpecGlobs []string
}

type proofs struct {
	BindingPath           string
	ProofLikePaths        []string
	RetiredProofLikePaths []string
	EnvironmentClasses    []string
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

type profile struct {
	Repository      repository
	Documents       documents
	Requirements    requirements
	Proofs          proofs
	CommandMatchers []commandMatcher
	NonClaims       []string
}

type commandEnvironmentPair struct {
	Command            string
	EnvironmentClasses []string
}

type packageScripts struct {
	PackageName string
	Scripts     []string
}

type facts struct {
	CommandEnvironmentPairs []commandEnvironmentPair
	DocsPolicyGenerated     []generatedArtifact
	PackageScripts          []packageScripts
	RootPackageName         string
	RootScripts             []string
	TrackedFiles            []string
}

type environmentPolicy struct {
	LiveGithubRequiredClasses  []string
	LocalSecretRequiredClasses []string
}

type policy struct {
	EnvironmentPolicy  environmentPolicy
	PackageNamePattern *string
}

type input struct {
	Profile profile
	Facts   facts
	Policy  policy
}

type admissionResult struct {
	CommandMatcherCount         int
	DistinctWitnessCommandCount int
	EnvironmentClassCount       int
	GeneratedArtifactCount      int
	Failures                    []string
}

func Build(raw any) (report.Record, int, error) {
	result, err := verify(raw)
	if err != nil {
		result = admissionResult{
			CommandMatcherCount:         0,
			DistinctWitnessCommandCount: 0,
			EnvironmentClassCount:       0,
			GeneratedArtifactCount:      0,
			Failures:                    []string{err.Error()},
		}
	}
	record := buildReport(result)
	if record.State == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func verify(raw any) (admissionResult, error) {
	input, err := admitInput(raw)
	if err != nil {
		return admissionResult{}, err
	}
	failures := []string{}
	trackedFiles := toSet(input.Facts.TrackedFiles)

	if input.Facts.RootPackageName != input.Profile.Repository.RootPackageName {
		failures = append(failures, "repo profile rootPackageName must match package.json name")
	}

	for _, item := range profilePaths(input.Profile) {
		safePath, ok := safePathOrFailure(item, "repo profile path", &failures)
		if ok {
			if _, exists := trackedFiles[safePath]; !exists {
				failures = append(failures, "repo profile path entry must exist in tracked files")
			}
		}
	}

	if _, err := admit.PreserveSortedText(input.Profile.Proofs.RetiredProofLikePaths, "repo profile proofs.retiredProofLikePaths", true); err != nil {
		failures = append(failures, err.Error())
	}
	for _, item := range input.Profile.Proofs.RetiredProofLikePaths {
		safePath, ok := safePathOrFailure(item, "repo profile retired proof-like path", &failures)
		if ok {
			if _, exists := trackedFiles[safePath]; exists {
				failures = append(failures, "repo profile retired proof-like path must not exist in tracked files")
			}
		}
	}

	if _, err := regexp.Compile(input.Profile.Requirements.IDPattern); err != nil {
		failures = append(failures, fmt.Sprintf("repo profile requirements.idPattern is not a valid regex: %s", err.Error()))
	}

	for _, entry := range globEntries(input.Profile) {
		for _, glob := range entry.Globs {
			if err := pathpattern.Validate(glob, entry.Label+" glob"); err != nil {
				failures = append(failures, err.Error())
				continue
			}
			matched := false
			for _, tracked := range input.Facts.TrackedFiles {
				if pathpattern.Match(glob, tracked) {
					matched = true
					break
				}
			}
			if !matched {
				failures = append(failures, entry.Label+" matches no tracked files")
			}
		}
	}

	docsPolicyArtifacts := map[string]generatedArtifact{}
	for _, artifact := range input.Facts.DocsPolicyGenerated {
		docsPolicyArtifacts[artifact.Path] = artifact
	}
	for _, artifact := range input.Profile.Documents.GeneratedArtifacts {
		policyArtifact, ok := docsPolicyArtifacts[artifact.Path]
		if !ok {
			failures = append(failures, "generated artifact entry must be mirrored in docs policy")
			continue
		}
		if policyArtifact.Generator != artifact.Generator {
			failures = append(failures, "generated artifact entry generator must match docs policy")
		}
		if !sameStringSet(policyArtifact.SourceOfTruth, artifact.SourceOfTruth) {
			failures = append(failures, "generated artifact entry sourceOfTruth must match docs policy")
		}
	}

	commandFailures, err := verifyCommandAdmission(input)
	if err != nil {
		return admissionResult{}, err
	}
	failures = append(failures, commandFailures...)

	return admissionResult{
		CommandMatcherCount:         len(input.Profile.CommandMatchers),
		DistinctWitnessCommandCount: len(toCommandSet(input.Facts.CommandEnvironmentPairs)),
		EnvironmentClassCount:       len(input.Profile.Proofs.EnvironmentClasses),
		GeneratedArtifactCount:      len(input.Profile.Documents.GeneratedArtifacts),
		Failures:                    sortedUniqueFailures(failures),
	}, nil
}

func buildReport(result admissionResult) report.Record {
	state := "passed"
	if len(result.Failures) > 0 {
		state = "failed"
	}
	rules := []report.RuleResult{}
	if state == "passed" {
		rules = append(rules, report.RuleResult{
			RuleID:      "proofkit.repo-profile-structural.accepted",
			Status:      "passed",
			Message:     "repo profile structural admission passed",
			Diagnostics: []report.Diagnostic{},
		})
	} else {
		for index, failure := range result.Failures {
			rules = append(rules, report.RuleResult{
				RuleID:      fmt.Sprintf("proofkit.repo-profile-structural.failure.%03d", index+1),
				Status:      "failed",
				Message:     failure,
				Diagnostics: []report.Diagnostic{},
			})
		}
	}
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.repo-profile-structural",
		ReportID:      "proofkit.repo-profile-structural",
		State:         state,
		Summary: map[string]any{
			"commandMatcherCount":         result.CommandMatcherCount,
			"distinctWitnessCommandCount": result.DistinctWitnessCommandCount,
			"environmentClassCount":       result.EnvironmentClassCount,
			"generatedArtifactCount":      result.GeneratedArtifactCount,
		},
		Diagnostics: []report.Diagnostic{},
		RuleResults: rules,
		NonClaims:   boundaryNonClaims,
	}
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("repo profile must be an object")
	}
	if err := admit.KnownKeys(record, []string{"facts", "policy", "profile"}, "repo profile input"); err != nil {
		return input{}, err
	}
	profileValue, err := admitProfile(record["profile"])
	if err != nil {
		return input{}, err
	}
	factsValue, err := admitFacts(record["facts"])
	if err != nil {
		return input{}, err
	}
	policyValue, err := admitPolicy(record["policy"])
	if err != nil {
		return input{}, err
	}
	return input{Profile: profileValue, Facts: factsValue, Policy: policyValue}, nil
}

func admitProfile(raw any) (profile, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return profile{}, fmt.Errorf("repo profile must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commandMatchers", "documents", "nonClaims", "proofs", "repository", "requirements", "schema"}, "repo profile"); err != nil {
		return profile{}, err
	}
	if record["schema"] != "proofkit.repo-profile.v1" {
		return profile{}, fmt.Errorf("repo profile schema must be proofkit.repo-profile.v1")
	}
	repositoryValue, err := admitRepository(record["repository"])
	if err != nil {
		return profile{}, err
	}
	documentsValue, err := admitDocuments(record["documents"])
	if err != nil {
		return profile{}, err
	}
	requirementsValue, err := admitRequirements(record["requirements"])
	if err != nil {
		return profile{}, err
	}
	proofsValue, err := admitProofs(record["proofs"])
	if err != nil {
		return profile{}, err
	}
	commandMatchers, err := admitCommandMatchers(record["commandMatchers"])
	if err != nil {
		return profile{}, err
	}
	nonClaims, err := stringArray(record["nonClaims"], "repo profile nonClaims", false, true)
	if err != nil {
		return profile{}, err
	}
	return profile{
		Repository:      repositoryValue,
		Documents:       documentsValue,
		Requirements:    requirementsValue,
		Proofs:          proofsValue,
		CommandMatchers: commandMatchers,
		NonClaims:       nonClaims,
	}, nil
}

func admitRepository(raw any) (repository, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return repository{}, fmt.Errorf("repo profile repository must be an object")
	}
	if err := admit.KnownKeys(record, []string{"name", "primaryLanguages", "rootPackageName"}, "repo profile repository"); err != nil {
		return repository{}, err
	}
	primaryLanguages, err := stringArray(record["primaryLanguages"], "repo profile repository.primaryLanguages", false, true)
	if err != nil {
		return repository{}, err
	}
	name, err := stringField(record, "name", "repo profile repository")
	if err != nil {
		return repository{}, err
	}
	rootPackageName, err := stringField(record, "rootPackageName", "repo profile repository")
	if err != nil {
		return repository{}, err
	}
	return repository{
		Name:             name,
		PrimaryLanguages: primaryLanguages,
		RootPackageName:  rootPackageName,
	}, nil
}

func admitDocuments(raw any) (documents, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return documents{}, fmt.Errorf("repo profile documents must be an object")
	}
	if err := admit.KnownKeys(record, []string{"generatedArtifacts", "policyPath", "routerPath"}, "repo profile documents"); err != nil {
		return documents{}, err
	}
	artifactsRaw, ok := record["generatedArtifacts"].([]any)
	if !ok {
		return documents{}, fmt.Errorf("repo profile documents.generatedArtifacts must be an array")
	}
	artifacts := make([]generatedArtifact, 0, len(artifactsRaw))
	for index, rawArtifact := range artifactsRaw {
		artifact, err := parseGeneratedArtifact(rawArtifact, fmt.Sprintf("generated artifact #%d", index+1))
		if err != nil {
			return documents{}, err
		}
		artifacts = append(artifacts, artifact)
	}
	policyPath, err := stringField(record, "policyPath", "repo profile documents")
	if err != nil {
		return documents{}, err
	}
	routerPath, err := stringField(record, "routerPath", "repo profile documents")
	if err != nil {
		return documents{}, err
	}
	return documents{
		PolicyPath:         policyPath,
		RouterPath:         routerPath,
		GeneratedArtifacts: artifacts,
	}, nil
}

func admitRequirements(raw any) (requirements, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return requirements{}, fmt.Errorf("repo profile requirements must be an object")
	}
	if err := admit.KnownKeys(record, []string{"idPattern", "specGlobs"}, "repo profile requirements"); err != nil {
		return requirements{}, err
	}
	specGlobs, err := stringArray(record["specGlobs"], "repo profile requirements.specGlobs", false, true)
	if err != nil {
		return requirements{}, err
	}
	idPattern, err := stringField(record, "idPattern", "repo profile requirements")
	if err != nil {
		return requirements{}, err
	}
	return requirements{
		IDPattern: idPattern,
		SpecGlobs: specGlobs,
	}, nil
}

func admitProofs(raw any) (proofs, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return proofs{}, fmt.Errorf("repo profile proofs must be an object")
	}
	if err := admit.KnownKeys(record, []string{"bindingPath", "environmentClasses", "proofLikePaths", "retiredProofLikePaths"}, "repo profile proofs"); err != nil {
		return proofs{}, err
	}
	proofLikePaths, err := stringArray(record["proofLikePaths"], "repo profile proofs.proofLikePaths", false, true)
	if err != nil {
		return proofs{}, err
	}
	retiredProofLikePaths, err := stringArray(record["retiredProofLikePaths"], "repo profile proofs.retiredProofLikePaths", true, true)
	if err != nil {
		return proofs{}, err
	}
	environmentClasses, err := stringArray(record["environmentClasses"], "repo profile proofs.environmentClasses", false, true)
	if err != nil {
		return proofs{}, err
	}
	bindingPath, err := stringField(record, "bindingPath", "repo profile proofs")
	if err != nil {
		return proofs{}, err
	}
	return proofs{
		BindingPath:           bindingPath,
		ProofLikePaths:        proofLikePaths,
		RetiredProofLikePaths: retiredProofLikePaths,
		EnvironmentClasses:    environmentClasses,
	}, nil
}

func admitCommandMatchers(raw any) ([]commandMatcher, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("repo profile commandMatchers must be an array")
	}
	matchers := make([]commandMatcher, 0, len(values))
	for index, value := range values {
		matcher, err := parseCommandMatcher(value, index)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
	}
	ids := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		ids = append(ids, matcher.ID)
	}
	if err := preserveSortedUnique(ids, "repo profile commandMatchers.id", true); err != nil {
		return nil, err
	}
	return matchers, nil
}

func parseCommandMatcher(raw any, index int) (commandMatcher, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return commandMatcher{}, fmt.Errorf("command matcher #%d must be an object", index)
	}
	if err := admit.KnownKeys(record, []string{"allowedArgv", "allowedScripts", "allowedTestPathGlobs", "credentialClass", "id", "kind", "networkPolicy", "parallelGroup"}, fmt.Sprintf("command matcher #%d", index)); err != nil {
		return commandMatcher{}, err
	}
	kind, err := stringField(record, "kind", fmt.Sprintf("command matcher #%d", index))
	if err != nil {
		return commandMatcher{}, err
	}
	if !contains([]string{"bun_workspace_package_script", "bun_repo_script", "exact_argv", "python_pytest_contract"}, kind) {
		return commandMatcher{}, fmt.Errorf("command matcher #%d has unsupported kind", index)
	}
	networkPolicy, err := stringField(record, "networkPolicy", fmt.Sprintf("command matcher #%d", index))
	if err != nil {
		return commandMatcher{}, err
	}
	if !contains([]string{"none", "loopback", "external"}, networkPolicy) {
		return commandMatcher{}, fmt.Errorf("command matcher #%d has unsupported networkPolicy", index)
	}
	credentialClass, err := stringField(record, "credentialClass", fmt.Sprintf("command matcher #%d", index))
	if err != nil {
		return commandMatcher{}, err
	}
	if !contains([]string{"none", "local-secret", "live-github", "live-cloud"}, credentialClass) {
		return commandMatcher{}, fmt.Errorf("command matcher #%d has unsupported credentialClass", index)
	}
	id, err := stringField(record, "id", fmt.Sprintf("command matcher #%d", index))
	if err != nil {
		return commandMatcher{}, err
	}
	parallelGroup, err := stringField(record, "parallelGroup", fmt.Sprintf("command matcher #%d", index))
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
		scripts, err := stringArray(value, fmt.Sprintf("command matcher #%d allowedScripts", index), false, true)
		if err != nil {
			return commandMatcher{}, err
		}
		matcher.AllowedScripts = scripts
		matcher.HasAllowedScripts = true
	}
	if value, ok := record["allowedArgv"]; ok {
		argv, err := parseOptionalArgv(value, fmt.Sprintf("command matcher #%d allowedArgv", index))
		if err != nil {
			return commandMatcher{}, err
		}
		matcher.AllowedArgv = argv
		matcher.HasAllowedArgv = true
	}
	if value, ok := record["allowedTestPathGlobs"]; ok {
		globs, err := stringArray(value, fmt.Sprintf("command matcher #%d allowedTestPathGlobs", index), false, true)
		if err != nil {
			return commandMatcher{}, err
		}
		matcher.AllowedTestPathGlobs = globs
		matcher.HasAllowedTestGlobs = true
	}
	return matcher, nil
}

func admitFacts(raw any) (facts, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return facts{}, fmt.Errorf("repo profile facts must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commandEnvironmentPairs", "docsPolicyGeneratedArtifacts", "packageScripts", "rootPackageName", "rootScripts", "trackedFiles"}, "repo profile facts"); err != nil {
		return facts{}, err
	}
	commandPairs, err := parseCommandEnvironmentPairs(record["commandEnvironmentPairs"])
	if err != nil {
		return facts{}, err
	}
	docsArtifactsRaw, ok := record["docsPolicyGeneratedArtifacts"].([]any)
	if !ok {
		return facts{}, fmt.Errorf("repo profile facts.docsPolicyGeneratedArtifacts must be an array")
	}
	docsArtifacts := make([]generatedArtifact, 0, len(docsArtifactsRaw))
	for index, rawArtifact := range docsArtifactsRaw {
		artifact, err := parseGeneratedArtifact(rawArtifact, fmt.Sprintf("docs policy generated artifact #%d", index+1))
		if err != nil {
			return facts{}, err
		}
		docsArtifacts = append(docsArtifacts, artifact)
	}
	packageScripts, err := parsePackageScripts(record["packageScripts"])
	if err != nil {
		return facts{}, err
	}
	rootScripts, err := sortUniqueStringArray(record["rootScripts"], "repo profile facts.rootScripts")
	if err != nil {
		return facts{}, err
	}
	trackedFiles, err := sortedUniquePaths(record["trackedFiles"], "repo profile facts.trackedFiles")
	if err != nil {
		return facts{}, err
	}
	rootPackageName, err := nonEmptyString(record["rootPackageName"], "repo profile facts.rootPackageName")
	if err != nil {
		return facts{}, err
	}
	return facts{
		CommandEnvironmentPairs: commandPairs,
		DocsPolicyGenerated:     docsArtifacts,
		PackageScripts:          packageScripts,
		RootPackageName:         rootPackageName,
		RootScripts:             rootScripts,
		TrackedFiles:            trackedFiles,
	}, nil
}

func admitPolicy(raw any) (policy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return policy{}, fmt.Errorf("repo profile policy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"environmentPolicy", "packageNamePattern"}, "repo profile policy"); err != nil {
		return policy{}, err
	}
	environment, ok := record["environmentPolicy"].(map[string]any)
	if !ok {
		return policy{}, fmt.Errorf("repo profile policy.environmentPolicy must be an object")
	}
	if err := admit.KnownKeys(environment, []string{"liveGithubRequiredClasses", "localSecretRequiredClasses"}, "repo profile policy.environmentPolicy"); err != nil {
		return policy{}, err
	}
	liveGithub, err := arrayOfNonEmptyStrings(environment["liveGithubRequiredClasses"], "repo profile environmentPolicy.liveGithubRequiredClasses", true)
	if err != nil {
		return policy{}, err
	}
	localSecret, err := arrayOfNonEmptyStrings(environment["localSecretRequiredClasses"], "repo profile environmentPolicy.localSecretRequiredClasses", true)
	if err != nil {
		return policy{}, err
	}
	var pattern *string
	if value, ok := record["packageNamePattern"]; ok && value != nil {
		text, err := nonEmptyString(value, "repo profile policy.packageNamePattern")
		if err != nil {
			return policy{}, err
		}
		pattern = &text
	}
	return policy{
		EnvironmentPolicy: environmentPolicy{
			LiveGithubRequiredClasses:  liveGithub,
			LocalSecretRequiredClasses: localSecret,
		},
		PackageNamePattern: pattern,
	}, nil
}

func parseGeneratedArtifact(raw any, context string) (generatedArtifact, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return generatedArtifact{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"generator", "path", "sourceOfTruth"}, context); err != nil {
		return generatedArtifact{}, err
	}
	sourceOfTruth, err := stringArray(record["sourceOfTruth"], context+" sourceOfTruth", false, true)
	if err != nil {
		return generatedArtifact{}, err
	}
	artifactPath, err := stringField(record, "path", context)
	if err != nil {
		return generatedArtifact{}, err
	}
	generator, err := stringField(record, "generator", context)
	if err != nil {
		return generatedArtifact{}, err
	}
	return generatedArtifact{
		Path:          artifactPath,
		Generator:     generator,
		SourceOfTruth: sourceOfTruth,
	}, nil
}

func parseCommandEnvironmentPairs(raw any) ([]commandEnvironmentPair, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("repo profile facts.commandEnvironmentPairs must be an array")
	}
	pairs := make([]commandEnvironmentPair, 0, len(values))
	for index, rawPair := range values {
		record, ok := rawPair.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("repo profile commandEnvironmentPairs #%d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"command", "environmentClasses"}, fmt.Sprintf("repo profile commandEnvironmentPairs #%d", index+1)); err != nil {
			return nil, err
		}
		command, err := admit.DisplayOnlyCommandText(record["command"], fmt.Sprintf("repo profile commandEnvironmentPairs #%d command", index+1))
		if err != nil {
			return nil, err
		}
		environmentClasses, err := arrayOfNonEmptyStrings(record["environmentClasses"], fmt.Sprintf("repo profile commandEnvironmentPairs #%d environmentClasses", index+1), true)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, commandEnvironmentPair{Command: command, EnvironmentClasses: environmentClasses})
	}
	return pairs, nil
}

func parsePackageScripts(raw any) ([]packageScripts, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("repo profile facts.packageScripts must be an array")
	}
	result := make([]packageScripts, 0, len(values))
	for index, rawItem := range values {
		record, ok := rawItem.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("repo profile packageScripts #%d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"packageName", "scripts"}, fmt.Sprintf("repo profile packageScripts #%d", index+1)); err != nil {
			return nil, err
		}
		packageName, err := nonEmptyString(record["packageName"], fmt.Sprintf("repo profile packageScripts #%d packageName", index+1))
		if err != nil {
			return nil, err
		}
		scripts, err := arrayOfNonEmptyStrings(record["scripts"], fmt.Sprintf("repo profile packageScripts #%d scripts", index+1), true)
		if err != nil {
			return nil, err
		}
		result = append(result, packageScripts{PackageName: packageName, Scripts: scripts})
	}
	return result, nil
}

func verifyCommandAdmission(input input) ([]string, error) {
	failures := []string{}
	packageScripts := map[string]map[string]struct{}{}
	for _, item := range input.Facts.PackageScripts {
		packageScripts[item.PackageName] = toSet(item.Scripts)
	}
	rootScripts := toSet(input.Facts.RootScripts)
	trackedFiles := toSet(input.Facts.TrackedFiles)
	var packageNamePattern *regexp.Regexp
	if input.Policy.PackageNamePattern != nil {
		compiled, err := regexp.Compile(*input.Policy.PackageNamePattern)
		if err != nil {
			return nil, err
		}
		packageNamePattern = compiled
	}
	validateMatchers(input.Profile.CommandMatchers, &failures)
	validateEnvironmentDeclarations(input, &failures)

	for _, pair := range input.Facts.CommandEnvironmentPairs {
		matched := false
		for _, matcher := range input.Profile.CommandMatchers {
			if matcherAcceptsCommand(commandMatchInput{
				Command:            pair.Command,
				EnvironmentClasses: pair.EnvironmentClasses,
				EnvironmentPolicy:  input.Policy.EnvironmentPolicy,
				Matcher:            matcher,
				PackageNamePattern: packageNamePattern,
				PackageScripts:     packageScripts,
				RootScripts:        rootScripts,
				TrackedFiles:       trackedFiles,
				TestPathGlobs:      matcher.AllowedTestPathGlobs,
			}) {
				matched = true
				break
			}
		}
		if !matched {
			failures = append(failures, fmt.Sprintf("repo profile command matchers admit no witness command/environment pair: %s [%s]", pair.Command, strings.Join(pair.EnvironmentClasses, ", ")))
		}
	}

	return sortedUniqueFailures(failures), nil
}

func validateMatchers(matchers []commandMatcher, failures *[]string) {
	ids := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		ids = append(ids, matcher.ID)
	}
	if !isPreserveSortedUnique(ids) {
		*failures = append(*failures, "repo profile commandMatchers.id must be sorted and unique")
	}
	for index, matcher := range matchers {
		if !contains([]string{"bun_workspace_package_script", "bun_repo_script", "exact_argv", "python_pytest_contract"}, matcher.Kind) {
			*failures = append(*failures, fmt.Sprintf("command matcher #%d has unsupported kind", index))
		}
		if !contains([]string{"none", "loopback", "external"}, matcher.NetworkPolicy) {
			*failures = append(*failures, fmt.Sprintf("command matcher #%d has unsupported networkPolicy", index))
		}
		if !contains([]string{"none", "local-secret", "live-github", "live-cloud"}, matcher.CredentialClass) {
			*failures = append(*failures, fmt.Sprintf("command matcher #%d has unsupported credentialClass", index))
		}
		if matcher.Kind == "python_pytest_contract" && !matcher.HasAllowedTestGlobs {
			*failures = append(*failures, fmt.Sprintf("command matcher %s must declare allowedTestPathGlobs", matcher.ID))
		}
		if matcher.HasAllowedTestGlobs {
			for _, glob := range matcher.AllowedTestPathGlobs {
				if err := pathpattern.Validate(glob, fmt.Sprintf("command matcher %s allowedTestPathGlobs entry", matcher.ID)); err != nil {
					*failures = append(*failures, err.Error())
				}
			}
		}
		if matcher.Kind == "python_pytest_contract" && matcher.HasAllowedScripts {
			*failures = append(*failures, fmt.Sprintf("command matcher %s must not declare allowedScripts", matcher.ID))
		}
		if matcher.Kind != "python_pytest_contract" && matcher.Kind != "exact_argv" && !matcher.HasAllowedScripts {
			*failures = append(*failures, fmt.Sprintf("command matcher %s must declare allowedScripts", matcher.ID))
		}
		if matcher.Kind != "python_pytest_contract" && matcher.Kind != "exact_argv" && matcher.HasAllowedTestGlobs {
			*failures = append(*failures, fmt.Sprintf("command matcher %s must not declare allowedTestPathGlobs", matcher.ID))
		}
		if matcher.Kind == "exact_argv" && !matcher.HasAllowedArgv {
			*failures = append(*failures, fmt.Sprintf("command matcher %s must declare allowedArgv", matcher.ID))
		}
		if matcher.Kind == "exact_argv" && matcher.HasAllowedScripts {
			*failures = append(*failures, fmt.Sprintf("command matcher %s must not declare allowedScripts", matcher.ID))
		}
		if matcher.Kind == "exact_argv" && matcher.HasAllowedTestGlobs {
			*failures = append(*failures, fmt.Sprintf("command matcher %s must not declare allowedTestPathGlobs", matcher.ID))
		}
		if matcher.Kind != "exact_argv" && matcher.HasAllowedArgv {
			*failures = append(*failures, fmt.Sprintf("command matcher %s must not declare allowedArgv", matcher.ID))
		}
		if matcher.HasAllowedArgv {
			validateAllowedArgv(matcher, failures)
		}
	}
}

func validateAllowedArgv(matcher commandMatcher, failures *[]string) {
	if len(matcher.AllowedArgv) == 0 {
		*failures = append(*failures, fmt.Sprintf("command matcher %s allowedArgv must be a non-empty argv array", matcher.ID))
		return
	}
	for _, token := range matcher.AllowedArgv {
		if token == "" || argvUnsafePattern.MatchString(token) || isShellControlToken(token) || argvQuotePattern.MatchString(token) {
			*failures = append(*failures, fmt.Sprintf("command matcher %s allowedArgv must contain literal argv tokens only", matcher.ID))
			return
		}
	}
}

func validateEnvironmentDeclarations(input input, failures *[]string) {
	declared := toSet(input.Profile.Proofs.EnvironmentClasses)
	used := map[string]struct{}{}
	for _, pair := range input.Facts.CommandEnvironmentPairs {
		for _, item := range pair.EnvironmentClasses {
			used[item] = struct{}{}
		}
	}
	usedNames := keys(used)
	sort.Strings(usedNames)
	for _, environmentClass := range usedNames {
		if _, ok := declared[environmentClass]; !ok {
			*failures = append(*failures, fmt.Sprintf("repo profile is missing proof environment class %s", environmentClass))
		}
	}
	for _, environmentClass := range input.Profile.Proofs.EnvironmentClasses {
		if _, ok := used[environmentClass]; !ok {
			*failures = append(*failures, fmt.Sprintf("repo profile declares unused proof environment class %s", environmentClass))
		}
	}
}

type commandMatchInput struct {
	Command            string
	EnvironmentClasses []string
	EnvironmentPolicy  environmentPolicy
	Matcher            commandMatcher
	PackageNamePattern *regexp.Regexp
	PackageScripts     map[string]map[string]struct{}
	RootScripts        map[string]struct{}
	TrackedFiles       map[string]struct{}
	TestPathGlobs      []string
}

func matcherAcceptsCommand(input commandMatchInput) bool {
	if !matcherPolicyMatchesEnvironment(input.Matcher, input.EnvironmentClasses, input.EnvironmentPolicy) {
		return false
	}
	switch input.Matcher.Kind {
	case "exact_argv":
		argv := strictCommandStringToArgv(input.Command)
		return argv != nil && sameOrderedStrings(argv, input.Matcher.AllowedArgv)
	case "bun_workspace_package_script":
		match := workspaceScriptPattern.FindStringSubmatch(input.Command)
		if match == nil {
			return false
		}
		packageName := match[1]
		scriptName := match[2]
		if input.PackageNamePattern != nil && !input.PackageNamePattern.MatchString(packageName) {
			return false
		}
		packageScriptSet, ok := input.PackageScripts[packageName]
		if !ok {
			return false
		}
		_, scriptExists := packageScriptSet[scriptName]
		return contains(input.Matcher.AllowedScripts, scriptName) && scriptExists
	case "bun_repo_script":
		if match := rootScriptPattern.FindStringSubmatch(input.Command); match != nil {
			scriptName := match[1]
			_, rootScriptExists := input.RootScripts[scriptName]
			return contains(input.Matcher.AllowedScripts, scriptName) && rootScriptExists
		}
		match := selftestScriptPattern.FindStringSubmatch(input.Command)
		if match == nil {
			return false
		}
		scriptPath := match[1]
		_, tracked := input.TrackedFiles[scriptPath]
		return contains(input.Matcher.AllowedScripts, scriptPath) && tracked
	default:
		match := pytestPattern.FindStringSubmatch(input.Command)
		if match == nil {
			return false
		}
		paths := strings.Fields(match[1])
		if len(paths) == 0 {
			return false
		}
		for _, item := range paths {
			safePath, err := safeRepoRelativePath(item, fmt.Sprintf("pytest witness path %s", item))
			if err != nil {
				return false
			}
			if _, tracked := input.TrackedFiles[safePath]; !tracked {
				return false
			}
			if !pathpattern.MatchAny(input.TestPathGlobs, safePath) {
				return false
			}
		}
		return true
	}
}

func matcherPolicyMatchesEnvironment(matcher commandMatcher, environmentClasses []string, policy environmentPolicy) bool {
	required := toSet(environmentClasses)
	requiresLiveGithub := intersects(required, policy.LiveGithubRequiredClasses)
	requiresLocalSecret := intersects(required, policy.LocalSecretRequiredClasses)
	if requiresLiveGithub && requiresLocalSecret {
		return false
	}
	if requiresLiveGithub {
		return matcher.NetworkPolicy == "external" && matcher.CredentialClass == "live-github"
	}
	if requiresLocalSecret {
		return matcher.NetworkPolicy == "loopback" && matcher.CredentialClass == "local-secret"
	}
	return matcher.NetworkPolicy == "none" && matcher.CredentialClass == "none"
}

func strictCommandStringToArgv(command string) []string {
	if command == "" || strings.TrimSpace(command) != command || commandWhitespace.MatchString(command) || argvQuotePattern.MatchString(command) {
		return nil
	}
	argv := strings.Split(command, " ")
	for _, token := range argv {
		if token == "" || isShellControlToken(token) {
			return nil
		}
	}
	return argv
}

func globEntries(profile profile) []struct {
	Label string
	Globs []string
} {
	entries := []struct {
		Label string
		Globs []string
	}{
		{Label: "requirement spec glob", Globs: profile.Requirements.SpecGlobs},
		{Label: "proof-like path glob", Globs: profile.Proofs.ProofLikePaths},
	}
	for _, matcher := range profile.CommandMatchers {
		if matcher.HasAllowedTestGlobs {
			entries = append(entries, struct {
				Label string
				Globs []string
			}{Label: fmt.Sprintf("command matcher %s test path glob", matcher.ID), Globs: matcher.AllowedTestPathGlobs})
		}
	}
	return entries
}

func profilePaths(profile profile) []string {
	paths := []string{
		profile.Documents.PolicyPath,
		profile.Documents.RouterPath,
		profile.Proofs.BindingPath,
	}
	for _, artifact := range profile.Documents.GeneratedArtifacts {
		paths = append(paths, artifact.Path, artifact.Generator)
		paths = append(paths, artifact.SourceOfTruth...)
	}
	return paths
}

func safePathOrFailure(value string, context string, failures *[]string) (string, bool) {
	pathValue, err := safeRepoRelativePath(value, context)
	if err != nil {
		*failures = append(*failures, err.Error())
		return "", false
	}
	return pathValue, true
}

func safeRepoRelativePath(value string, context string) (string, error) {
	return admit.SafeRepoRelativePath(value, context)
}

func stringField(record map[string]any, field string, context string) (string, error) {
	return admit.NonEmptyText(record[field], context+"."+field)
}

func nonEmptyString(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func arrayOfNonEmptyStrings(raw any, context string, allowEmpty bool) ([]string, error) {
	return admit.TextArray(raw, context, allowEmpty)
}

func stringArray(raw any, context string, allowEmpty bool, requireSorted bool) ([]string, error) {
	result, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	if requireSorted {
		if err := preserveSortedUnique(result, context, allowEmpty); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func sortUniqueStringArray(raw any, context string) ([]string, error) {
	values, err := arrayOfNonEmptyStrings(raw, context, true)
	if err != nil {
		return nil, err
	}
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	if len(sorted) != len(toSet(sorted)) {
		return nil, fmt.Errorf("%s must be unique", context)
	}
	return sorted, nil
}

func sortedUniquePaths(raw any, context string) ([]string, error) {
	values, err := arrayOfNonEmptyStrings(raw, context, true)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(values))
	for index, value := range values {
		pathValue, err := safeRepoRelativePath(value, fmt.Sprintf("%s entry #%d", context, index+1))
		if err != nil {
			return nil, err
		}
		paths = append(paths, pathValue)
	}
	sort.Strings(paths)
	if len(paths) != len(toSet(paths)) {
		return nil, fmt.Errorf("%s must be unique", context)
	}
	return paths, nil
}

func parseOptionalArgv(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty argv array", context)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%s must contain non-empty string tokens", context)
		}
		result = append(result, text)
	}
	return result, nil
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("%s must be non-empty", context)
	}
	if !isPreserveSortedUnique(values) {
		return fmt.Errorf("%s must be sorted and unique", context)
	}
	return nil
}

func isPreserveSortedUnique(values []string) bool {
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	if len(values) != len(toSet(values)) {
		return false
	}
	for index := range values {
		if values[index] != sorted[index] {
			return false
		}
	}
	return true
}

func sortedUniqueFailures(values []string) []string {
	set := toSet(values)
	result := keys(set)
	sort.Strings(result)
	return result
}

func sameStringSet(left []string, right []string) bool {
	leftSorted := append([]string{}, left...)
	rightSorted := append([]string{}, right...)
	sort.Strings(leftSorted)
	sort.Strings(rightSorted)
	return strings.Join(leftSorted, "\n") == strings.Join(rightSorted, "\n")
}

func sameOrderedStrings(left []string, right []string) bool {
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

func toSet(values []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func toCommandSet(values []commandEnvironmentPair) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value.Command] = struct{}{}
	}
	return set
}

func keys(set map[string]struct{}) []string {
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	return result
}

func intersects(set map[string]struct{}, values []string) bool {
	for _, value := range values {
		if _, ok := set[value]; ok {
			return true
		}
	}
	return false
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func isShellControlToken(value string) bool {
	_, ok := shellControlTokens[value]
	return ok
}
