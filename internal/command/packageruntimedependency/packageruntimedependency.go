package packageruntimedependency

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.package-runtime-dependency-admission"

var (
	packageNamePattern    = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	packageVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	secretLikeTextPattern = regexp.MustCompile(`(?i)(?:authorization\s*:|bearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:access_?token|api_?key|password|secret|token)\s*[=:]\s*\S+|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+|sk-(?:proj-)?[A-Za-z0-9_-]{10,}|xox[abprs]-[A-Za-z0-9-]+|glpat-[A-Za-z0-9_-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)`)
)

var standardNonClaims = []any{
	"Package runtime dependency admission does not resolve packages or read package manifests.",
	"Package runtime dependency admission does not read lockfiles or authenticate registry access.",
	"Package runtime dependency admission does not execute native witnesses or prove proof freshness.",
}

type resolutionInput struct {
	DependencySpec       *string
	LockfileEntryPresent bool
	PackageName          string
	PackageRoot          string
	PackageVersion       string
	RealPackageRoot      string
	ResolvedEntryPoint   string
}

type locationsInput struct {
	ExpectedPackageRoot *string
	LocalWorkspaceRoot  *string
	NodeModulesRoot     *string
}

type input struct {
	AdmissibleLocations    locationsInput
	ExpectedDependencySpec string
	ExpectedPackageName    string
	ExpectedPackageVersion string
	NonClaims              []string
	PackageResolution      resolutionInput
	ReportID               string
}

type locationFacts struct {
	ExpectedPackageRootInsideNodeModules        bool
	PackageRootInsideExpectedPackageRoot        bool
	PackageRootInsideLocalWorkspace             bool
	PackageRootInsideNodeModules                bool
	RealPackageRootInsideExpectedPackageRoot    bool
	RealPackageRootInsideLocalWorkspace         bool
	RealPackageRootInsideNodeModules            bool
	ResolvedEntryPointInsideExpectedPackageRoot bool
	ResolvedEntryPointInsideLocalWorkspace      bool
	ResolvedEntryPointInsideNodeModules         bool
}

func Build(raw any) (report.Record, int) {
	input, err := admitInput(raw)
	if err != nil {
		return invalidInputReport(sanitizedError(err)), 1
	}
	facts := makeLocationFacts(input)
	mode := classifyMode(facts)
	packageIdentityFailures := []string{}
	if input.PackageResolution.PackageName != input.ExpectedPackageName {
		packageIdentityFailures = append(packageIdentityFailures, "resolved package name does not match expected package name")
	}
	if input.PackageResolution.PackageVersion != input.ExpectedPackageVersion {
		packageIdentityFailures = append(packageIdentityFailures, "resolved package version does not match expected package version")
	}
	dependencyFailures := []string{}
	if input.PackageResolution.DependencySpec == nil || *input.PackageResolution.DependencySpec != input.ExpectedDependencySpec {
		dependencyFailures = append(dependencyFailures, "runtime dependency spec does not match expected dependency spec")
	}
	lockfileFailures := []string{}
	if !input.PackageResolution.LockfileEntryPresent {
		lockfileFailures = append(lockfileFailures, "lockfile entry for runtime dependency is missing")
	}
	locationFailures := []string{}
	if mode != "external_package" {
		locationFailures = append(locationFailures, fmt.Sprintf("runtime dependency resolved as %s", mode))
	}
	failures := append([]string{}, packageIdentityFailures...)
	failures = append(failures, dependencyFailures...)
	failures = append(failures, lockfileFailures...)
	failures = append(failures, locationFailures...)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(admit.AnySliceToString(standardNonClaims), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.ReportID,
		State:         state,
		Summary: map[string]any{
			"accepted":                len(failures) == 0,
			"dependencySpecMatched":   len(dependencyFailures) == 0,
			"expectedPackageName":     input.ExpectedPackageName,
			"expectedPackageVersion":  input.ExpectedPackageVersion,
			"failureCount":            len(failures),
			"lockfileEntryPresent":    input.PackageResolution.LockfileEntryPresent,
			"mode":                    mode,
			"packageIdentityMatched":  len(packageIdentityFailures) == 0,
			"runtimeLocationAdmitted": mode == "external_package",
		},
		Diagnostics: locationDiagnostics(mode, facts),
		RuleResults: []report.RuleResult{
			ruleResult("proofkit.package-runtime-dependency-admission.dependency-spec", dependencyFailures, "runtime dependency spec matches expected dependency spec", []report.Diagnostic{
				{Key: "dependencySpecMatched", Value: len(dependencyFailures) == 0},
			}),
			ruleResult("proofkit.package-runtime-dependency-admission.lockfile-entry", lockfileFailures, "runtime dependency lockfile entry is present", []report.Diagnostic{
				{Key: "lockfileEntryPresent", Value: input.PackageResolution.LockfileEntryPresent},
			}),
			ruleResult("proofkit.package-runtime-dependency-admission.package-identity", packageIdentityFailures, "resolved package identity matches expected package identity", []report.Diagnostic{
				{Key: "expectedPackageName", Value: input.ExpectedPackageName},
				{Key: "expectedPackageVersion", Value: input.ExpectedPackageVersion},
			}),
			ruleResult("proofkit.package-runtime-dependency-admission.runtime-location", locationFailures, "runtime dependency resolved through admitted external package location", []report.Diagnostic{
				{Key: "mode", Value: mode},
			}),
		},
		NonClaims: admit.StringSliceToAny(nonClaims),
	}
	if state == "passed" {
		return record, 0
	}
	return record, 1
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("package runtime dependency admission input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"admissibleLocations", "expectedDependencySpec", "expectedPackageName", "expectedPackageVersion", "nonClaims", "packageResolution", "reportId", "schemaVersion"}, "package runtime dependency admission input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("package runtime dependency admission input schemaVersion must be 1")
	}
	reportID, err := admit.RuleID(record["reportId"], "package runtime dependency admission reportId")
	if err != nil {
		return input{}, err
	}
	resolution, err := admitResolution(record["packageResolution"])
	if err != nil {
		return input{}, err
	}
	locations, err := admitLocations(record["admissibleLocations"])
	if err != nil {
		return input{}, err
	}
	nonClaims, err := stringArray(record["nonClaims"], "package runtime dependency admission nonClaims", true)
	if err != nil {
		return input{}, err
	}
	expectedDependencySpec, err := dependencySpec(record["expectedDependencySpec"], "expectedDependencySpec")
	if err != nil {
		return input{}, err
	}
	expectedPackageName, err := packageName(record["expectedPackageName"], "expectedPackageName")
	if err != nil {
		return input{}, err
	}
	expectedPackageVersion, err := packageVersion(record["expectedPackageVersion"], "expectedPackageVersion")
	if err != nil {
		return input{}, err
	}
	return input{
		AdmissibleLocations:    locations,
		ExpectedDependencySpec: expectedDependencySpec,
		ExpectedPackageName:    expectedPackageName,
		ExpectedPackageVersion: expectedPackageVersion,
		NonClaims:              nonClaims,
		PackageResolution:      resolution,
		ReportID:               reportID,
	}, nil
}

func admitResolution(raw any) (resolutionInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return resolutionInput{}, fmt.Errorf("package runtime dependency resolution must be an object")
	}
	if err := admit.KnownKeys(record, []string{"dependencySpec", "lockfileEntryPresent", "packageName", "packageRoot", "packageVersion", "realPackageRoot", "resolvedEntryPoint"}, "package runtime dependency resolution"); err != nil {
		return resolutionInput{}, err
	}
	lockfileEntryPresent, ok := record["lockfileEntryPresent"].(bool)
	if !ok {
		return resolutionInput{}, fmt.Errorf("package runtime dependency resolution lockfileEntryPresent must be boolean")
	}
	var admittedDependencySpec *string
	if record["dependencySpec"] != nil {
		value, err := dependencySpec(record["dependencySpec"], "packageResolution.dependencySpec")
		if err != nil {
			return resolutionInput{}, err
		}
		admittedDependencySpec = &value
	}
	packageName, err := packageName(record["packageName"], "packageResolution.packageName")
	if err != nil {
		return resolutionInput{}, err
	}
	packageVersion, err := packageVersion(record["packageVersion"], "packageResolution.packageVersion")
	if err != nil {
		return resolutionInput{}, err
	}
	packageRoot, err := runtimePath(record["packageRoot"], "packageResolution.packageRoot")
	if err != nil {
		return resolutionInput{}, err
	}
	realPackageRoot, err := runtimePath(record["realPackageRoot"], "packageResolution.realPackageRoot")
	if err != nil {
		return resolutionInput{}, err
	}
	resolvedEntryPoint, err := runtimePath(record["resolvedEntryPoint"], "packageResolution.resolvedEntryPoint")
	if err != nil {
		return resolutionInput{}, err
	}
	return resolutionInput{
		DependencySpec:       admittedDependencySpec,
		LockfileEntryPresent: lockfileEntryPresent,
		PackageName:          packageName,
		PackageRoot:          packageRoot,
		PackageVersion:       packageVersion,
		RealPackageRoot:      realPackageRoot,
		ResolvedEntryPoint:   resolvedEntryPoint,
	}, nil
}

func admitLocations(raw any) (locationsInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return locationsInput{}, fmt.Errorf("package runtime dependency admissibleLocations must be an object")
	}
	if err := admit.KnownKeys(record, []string{"expectedPackageRoot", "localWorkspaceRoot", "nodeModulesRoot"}, "package runtime dependency admissibleLocations"); err != nil {
		return locationsInput{}, err
	}
	expectedPackageRoot, err := nullableRuntimePath(record["expectedPackageRoot"], "admissibleLocations.expectedPackageRoot")
	if err != nil {
		return locationsInput{}, err
	}
	localWorkspaceRoot, err := nullableRuntimePath(record["localWorkspaceRoot"], "admissibleLocations.localWorkspaceRoot")
	if err != nil {
		return locationsInput{}, err
	}
	nodeModulesRoot, err := nullableRuntimePath(record["nodeModulesRoot"], "admissibleLocations.nodeModulesRoot")
	if err != nil {
		return locationsInput{}, err
	}
	return locationsInput{
		ExpectedPackageRoot: expectedPackageRoot,
		LocalWorkspaceRoot:  localWorkspaceRoot,
		NodeModulesRoot:     nodeModulesRoot,
	}, nil
}

func makeLocationFacts(input input) locationFacts {
	locations := input.AdmissibleLocations
	resolution := input.PackageResolution
	return locationFacts{
		ExpectedPackageRootInsideNodeModules:        isInsidePath(locations.ExpectedPackageRoot, locations.NodeModulesRoot),
		PackageRootInsideExpectedPackageRoot:        isInsidePath(&resolution.PackageRoot, locations.ExpectedPackageRoot),
		PackageRootInsideLocalWorkspace:             isInsidePath(&resolution.PackageRoot, locations.LocalWorkspaceRoot),
		PackageRootInsideNodeModules:                isInsidePath(&resolution.PackageRoot, locations.NodeModulesRoot),
		RealPackageRootInsideExpectedPackageRoot:    isInsidePath(&resolution.RealPackageRoot, locations.ExpectedPackageRoot),
		RealPackageRootInsideLocalWorkspace:         isInsidePath(&resolution.RealPackageRoot, locations.LocalWorkspaceRoot),
		RealPackageRootInsideNodeModules:            isInsidePath(&resolution.RealPackageRoot, locations.NodeModulesRoot),
		ResolvedEntryPointInsideExpectedPackageRoot: isInsidePath(&resolution.ResolvedEntryPoint, locations.ExpectedPackageRoot),
		ResolvedEntryPointInsideLocalWorkspace:      isInsidePath(&resolution.ResolvedEntryPoint, locations.LocalWorkspaceRoot),
		ResolvedEntryPointInsideNodeModules:         isInsidePath(&resolution.ResolvedEntryPoint, locations.NodeModulesRoot),
	}
}

func classifyMode(facts locationFacts) string {
	if facts.PackageRootInsideLocalWorkspace || facts.RealPackageRootInsideLocalWorkspace || facts.ResolvedEntryPointInsideLocalWorkspace {
		return "local_workspace"
	}
	if facts.ExpectedPackageRootInsideNodeModules &&
		facts.PackageRootInsideExpectedPackageRoot &&
		facts.RealPackageRootInsideExpectedPackageRoot &&
		facts.ResolvedEntryPointInsideExpectedPackageRoot &&
		facts.PackageRootInsideNodeModules &&
		facts.RealPackageRootInsideNodeModules &&
		facts.ResolvedEntryPointInsideNodeModules {
		return "external_package"
	}
	return "unadmitted_package"
}

func locationDiagnostics(mode string, facts locationFacts) []report.Diagnostic {
	return []report.Diagnostic{
		{Key: "expectedPackageRootInsideNodeModules", Value: facts.ExpectedPackageRootInsideNodeModules},
		{Key: "mode", Value: mode},
		{Key: "packageRootInsideExpectedPackageRoot", Value: facts.PackageRootInsideExpectedPackageRoot},
		{Key: "packageRootInsideLocalWorkspace", Value: facts.PackageRootInsideLocalWorkspace},
		{Key: "packageRootInsideNodeModules", Value: facts.PackageRootInsideNodeModules},
		{Key: "realPackageRootInsideExpectedPackageRoot", Value: facts.RealPackageRootInsideExpectedPackageRoot},
		{Key: "realPackageRootInsideLocalWorkspace", Value: facts.RealPackageRootInsideLocalWorkspace},
		{Key: "realPackageRootInsideNodeModules", Value: facts.RealPackageRootInsideNodeModules},
		{Key: "resolvedEntryPointInsideExpectedPackageRoot", Value: facts.ResolvedEntryPointInsideExpectedPackageRoot},
		{Key: "resolvedEntryPointInsideLocalWorkspace", Value: facts.ResolvedEntryPointInsideLocalWorkspace},
		{Key: "resolvedEntryPointInsideNodeModules", Value: facts.ResolvedEntryPointInsideNodeModules},
	}
}

func ruleResult(ruleID string, failures []string, passedMessage string, diagnostics []report.Diagnostic) report.RuleResult {
	message := passedMessage
	if len(failures) > 0 {
		message = strings.Join(failures, "; ")
	}
	sort.Slice(diagnostics, func(left int, right int) bool {
		return diagnostics[left].Key < diagnostics[right].Key
	})
	return report.RuleResult{
		Diagnostics: diagnostics,
		Message:     message,
		RuleID:      ruleID,
		Status:      status(len(failures) == 0),
	}
}

func status(passed bool) string {
	if passed {
		return "passed"
	}
	return "failed"
}

func invalidInputReport(message string) report.Record {
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      "invalid-input",
		State:         "failed",
		Summary: map[string]any{
			"accepted":     false,
			"failureCount": 1,
			"mode":         "unadmitted_package",
		},
		Diagnostics: []report.Diagnostic{
			{Key: "error", Value: message},
		},
		RuleResults: []report.RuleResult{
			{
				Diagnostics: []report.Diagnostic{
					{Key: "phase", Value: "input_admission"},
				},
				Message: message,
				RuleID:  "proofkit.package-runtime-dependency-admission.input",
				Status:  "failed",
			},
		},
		NonClaims: standardNonClaims,
	}
}

func packageName(raw any, context string) (string, error) {
	text, err := nonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !packageNamePattern.MatchString(text) {
		return "", fmt.Errorf("%s must be an npm package name", context)
	}
	return text, nil
}

func packageVersion(raw any, context string) (string, error) {
	text, err := nonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !packageVersionPattern.MatchString(text) {
		return "", fmt.Errorf("%s must be an exact semantic version", context)
	}
	return text, nil
}

func dependencySpec(raw any, context string) (string, error) {
	text, err := nonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(text, "\x00\r\n") {
		return "", fmt.Errorf("%s must be single-line text", context)
	}
	return text, nil
}

func nullableRuntimePath(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := runtimePath(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func runtimePath(raw any, context string) (string, error) {
	text, err := nonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(text, '\x00') {
		return "", fmt.Errorf("%s must not contain NUL bytes", context)
	}
	normalized := strings.ReplaceAll(text, "\\", "/")
	for strings.Contains(normalized, "//") {
		normalized = strings.ReplaceAll(normalized, "//", "/")
	}
	normalized = strings.TrimSuffix(normalized, "/")
	segments := strings.Split(normalized, "/")
	if normalized == "" {
		return "", fmt.Errorf("%s must be a normalized runtime path fact", context)
	}
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("%s must be a normalized runtime path fact", context)
		}
	}
	return normalized, nil
}

func isInsidePath(candidate *string, root *string) bool {
	if candidate == nil || root == nil {
		return false
	}
	return *candidate == *root || strings.HasPrefix(*candidate, *root+"/")
}

func stringArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for index, item := range values {
		text, err := nonEmptyText(item, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		if _, ok := seen[text]; ok {
			continue
		}
		seen[text] = struct{}{}
		result = append(result, text)
	}
	sort.Strings(result)
	return result, nil
}

func nonEmptyText(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	rawText := raw.(string)
	if rawText != strings.TrimSpace(rawText) {
		return "", fmt.Errorf("%s must not contain leading or trailing whitespace", context)
	}
	return value, nil
}

func sanitizedError(err error) string {
	message := err.Error()
	if secretLikeTextPattern.MatchString(message) {
		return "package runtime dependency admission input is invalid"
	}
	return message
}
