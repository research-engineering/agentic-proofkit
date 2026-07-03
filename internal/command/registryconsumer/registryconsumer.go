package registryconsumer

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.registry-consumer"

var boundaryNonClaims = []string{
	"Registry consumer does not fetch registry metadata, hold credentials, execute native consumer tests, approve rollback, approve rollout, or prove registry freshness.",
	"Registry consumer validates caller-owned registry install evidence only.",
}

var (
	packageVersionPattern     = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	packageNamePattern        = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	registryURLPattern        = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]*)?$`)
	tarballNamePattern        = regexp.MustCompile(`^[A-Za-z0-9._@-]+-\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\.tgz$`)
	hexSHA1Pattern            = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexSHA256Pattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	npmSHA512IntegrityPattern = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]+={0,2}$`)
)

type input struct {
	ConsumerID         string
	DependencyName     string
	DependencySpec     string
	NonClaims          []string
	PackageName        string
	PackageVersion     string
	RegistryURL        string
	ReleaseAuthority   releaseauthority.ConsumerProjectionAdmission
	RollbackVersionPin string
	TarballFileName    string
	TarballIntegrity   string
	TarballShasum      string
}

type proof struct {
	CLIWitnessPlanOutputSHA256   string
	DependencySpec               string
	FrozenLockContainsPackage    bool
	FrozenLockUsesWorkspace      bool
	InstallLockContainsPackage   bool
	InstallLockUsesWorkspace     bool
	RegistryPackIntegrityMatch   bool
	RegistryPackNameMatches      bool
	RegistryPackShasumMatches    bool
	RegistryPackVersionMatches   bool
	ReleaseAuthorityKind         string
	ReleaseAuthorityOutputSHA256 string
	ReleaseAuthorityState        string
	RollbackLockContainsPackage  bool
	BinarySmokeOutputSHA256      string
	TempConsumerLocation         string
}

type reportInput struct {
	Input input
	Proof *proof
}

func Build(raw any) (report.Record, int, error) {
	admitted, err := admitReportInput(raw)
	if err != nil {
		return failedAdmissionReport(err), 1, nil
	}
	failures := []string{}
	failures = append(failures, inputFailures(admitted.Input)...)
	failures = append(failures, releaseAuthorityFailures(admitted.Input)...)
	failures = append(failures, consumerProofFailures(admitted.Input, admitted.Proof)...)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      admitted.Input.ConsumerID,
		State:         state,
		Summary: map[string]any{
			"consumerId":     admitted.Input.ConsumerID,
			"dependencyName": admitted.Input.DependencyName,
			"dependencySpec": admitted.Input.DependencySpec,
			"packageName":    admitted.Input.PackageName,
			"packageVersion": admitted.Input.PackageVersion,
			"registryUrl":    admitted.Input.RegistryURL,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "consumerProof", Value: consumerProofDiagnostic(admitted.Proof)},
			{Key: "registryArtifact", Value: map[string]any{
				"tarballFileName":  admitted.Input.TarballFileName,
				"tarballIntegrity": admitted.Input.TarballIntegrity,
				"tarballShasum":    admitted.Input.TarballShasum,
			}},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(commandNonClaims(admitted.Input.NonClaims)),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitReportInput(raw any) (reportInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return reportInput{}, fmt.Errorf("proofkit registry-consumer report input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"input", "proof", "schemaVersion"}, "proofkit registry-consumer report input"); err != nil {
		return reportInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return reportInput{}, fmt.Errorf("proofkit registry-consumer report input schemaVersion must be 1")
	}
	inputValue, err := admitInput(record["input"])
	if err != nil {
		return reportInput{}, err
	}
	var proofValue *proof
	if record["proof"] != nil {
		value, err := admitProof(record["proof"])
		if err != nil {
			return reportInput{}, err
		}
		proofValue = &value
	}
	return reportInput{Input: inputValue, Proof: proofValue}, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("proofkit registry-consumer input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"consumerId", "dependencyName", "dependencySpec", "nonClaims", "packageName", "packageVersion", "registryUrl", "releaseAuthorityInput", "rollbackVersionPin", "schemaVersion", "tarballFileName", "tarballIntegrity", "tarballShasum"}, "proofkit registry-consumer input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("proofkit registry-consumer input schemaVersion must be 1")
	}
	packageNameValue, err := packageName(record["packageName"], "proofkit registry-consumer packageName")
	if err != nil {
		return input{}, err
	}
	packageVersionValue, err := packageVersion(record["packageVersion"], "proofkit registry-consumer packageVersion")
	if err != nil {
		return input{}, err
	}
	consumerID, err := text(record["consumerId"], "proofkit registry-consumer consumerId")
	if err != nil {
		return input{}, err
	}
	dependencyName, err := packageName(record["dependencyName"], "proofkit registry-consumer dependencyName")
	if err != nil {
		return input{}, err
	}
	dependencySpec, err := packageVersion(record["dependencySpec"], "proofkit registry-consumer dependencySpec")
	if err != nil {
		return input{}, err
	}
	registryURL, err := registryURL(record["registryUrl"], "proofkit registry-consumer registryUrl")
	if err != nil {
		return input{}, err
	}
	tarballFileName, err := tarballFileName(record["tarballFileName"], "proofkit registry-consumer tarballFileName")
	if err != nil {
		return input{}, err
	}
	tarballIntegrity, err := text(record["tarballIntegrity"], "proofkit registry-consumer tarballIntegrity")
	if err != nil {
		return input{}, err
	}
	tarballShasum, err := text(record["tarballShasum"], "proofkit registry-consumer tarballShasum")
	if err != nil {
		return input{}, err
	}
	releaseAuthorityValue := releaseauthority.AdmitConsumerProjection(record["releaseAuthorityInput"])
	rollbackVersionPin, err := registryVersionPin(record["rollbackVersionPin"], packageNameValue, "proofkit registry-consumer rollbackVersionPin")
	if err != nil {
		return input{}, err
	}
	nonClaims, err := sortedNonEmptyStrings(record["nonClaims"], "proofkit registry-consumer nonClaims")
	if err != nil {
		return input{}, err
	}
	return input{
		ConsumerID:         consumerID,
		DependencyName:     dependencyName,
		DependencySpec:     dependencySpec,
		NonClaims:          nonClaims,
		PackageName:        packageNameValue,
		PackageVersion:     packageVersionValue,
		RegistryURL:        registryURL,
		ReleaseAuthority:   releaseAuthorityValue,
		RollbackVersionPin: rollbackVersionPin,
		TarballFileName:    tarballFileName,
		TarballIntegrity:   tarballIntegrity,
		TarballShasum:      tarballShasum,
	}, nil
}

func admitProof(raw any) (proof, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return proof{}, fmt.Errorf("proofkit registry-consumer proof must be an object")
	}
	if err := admit.KnownKeys(record, []string{"binarySmokeOutputSha256", "cliWitnessPlanOutputSha256", "dependencySpec", "frozenLockContainsPackage", "frozenLockUsesWorkspace", "installLockContainsPackage", "installLockUsesWorkspace", "registryPackIntegrityMatches", "registryPackNameMatches", "registryPackShasumMatches", "registryPackVersionMatches", "releaseAuthorityOutputSha256", "releaseAuthorityReportKind", "releaseAuthorityState", "rollbackLockContainsPackage", "tempConsumerLocation"}, "proofkit registry-consumer proof"); err != nil {
		return proof{}, err
	}
	tempConsumerLocation, err := text(record["tempConsumerLocation"], "proofkit registry-consumer proof tempConsumerLocation")
	if err != nil {
		return proof{}, err
	}
	if tempConsumerLocation != "os-temp" {
		return proof{}, fmt.Errorf("proofkit registry-consumer proof tempConsumerLocation must be os-temp")
	}
	dependencySpec, err := text(record["dependencySpec"], "proofkit registry-consumer proof dependencySpec")
	if err != nil {
		return proof{}, err
	}
	registryPackIntegrityMatches, err := admit.Bool(record["registryPackIntegrityMatches"], "proofkit registry-consumer proof registryPackIntegrityMatches")
	if err != nil {
		return proof{}, err
	}
	registryPackNameMatches, err := admit.Bool(record["registryPackNameMatches"], "proofkit registry-consumer proof registryPackNameMatches")
	if err != nil {
		return proof{}, err
	}
	registryPackShasumMatches, err := admit.Bool(record["registryPackShasumMatches"], "proofkit registry-consumer proof registryPackShasumMatches")
	if err != nil {
		return proof{}, err
	}
	registryPackVersionMatches, err := admit.Bool(record["registryPackVersionMatches"], "proofkit registry-consumer proof registryPackVersionMatches")
	if err != nil {
		return proof{}, err
	}
	installLockContainsPackage, err := admit.Bool(record["installLockContainsPackage"], "proofkit registry-consumer proof installLockContainsPackage")
	if err != nil {
		return proof{}, err
	}
	installLockUsesWorkspace, err := admit.Bool(record["installLockUsesWorkspace"], "proofkit registry-consumer proof installLockUsesWorkspace")
	if err != nil {
		return proof{}, err
	}
	frozenLockContainsPackage, err := admit.Bool(record["frozenLockContainsPackage"], "proofkit registry-consumer proof frozenLockContainsPackage")
	if err != nil {
		return proof{}, err
	}
	frozenLockUsesWorkspace, err := admit.Bool(record["frozenLockUsesWorkspace"], "proofkit registry-consumer proof frozenLockUsesWorkspace")
	if err != nil {
		return proof{}, err
	}
	binarySmokeOutputSHA256, err := text(record["binarySmokeOutputSha256"], "proofkit registry-consumer proof binarySmokeOutputSha256")
	if err != nil {
		return proof{}, err
	}
	cliWitnessPlanOutputSHA256, err := text(record["cliWitnessPlanOutputSha256"], "proofkit registry-consumer proof cliWitnessPlanOutputSha256")
	if err != nil {
		return proof{}, err
	}
	releaseAuthorityKind, err := text(record["releaseAuthorityReportKind"], "proofkit registry-consumer proof releaseAuthorityReportKind")
	if err != nil {
		return proof{}, err
	}
	releaseAuthorityState, err := text(record["releaseAuthorityState"], "proofkit registry-consumer proof releaseAuthorityState")
	if err != nil {
		return proof{}, err
	}
	releaseAuthorityOutputSHA256, err := text(record["releaseAuthorityOutputSha256"], "proofkit registry-consumer proof releaseAuthorityOutputSha256")
	if err != nil {
		return proof{}, err
	}
	rollbackLockContainsPackage, err := admit.Bool(record["rollbackLockContainsPackage"], "proofkit registry-consumer proof rollbackLockContainsPackage")
	if err != nil {
		return proof{}, err
	}
	return proof{
		CLIWitnessPlanOutputSHA256:   cliWitnessPlanOutputSHA256,
		DependencySpec:               dependencySpec,
		FrozenLockContainsPackage:    frozenLockContainsPackage,
		FrozenLockUsesWorkspace:      frozenLockUsesWorkspace,
		InstallLockContainsPackage:   installLockContainsPackage,
		InstallLockUsesWorkspace:     installLockUsesWorkspace,
		RegistryPackIntegrityMatch:   registryPackIntegrityMatches,
		RegistryPackNameMatches:      registryPackNameMatches,
		RegistryPackShasumMatches:    registryPackShasumMatches,
		RegistryPackVersionMatches:   registryPackVersionMatches,
		ReleaseAuthorityKind:         releaseAuthorityKind,
		ReleaseAuthorityOutputSHA256: releaseAuthorityOutputSHA256,
		ReleaseAuthorityState:        releaseAuthorityState,
		RollbackLockContainsPackage:  rollbackLockContainsPackage,
		BinarySmokeOutputSHA256:      binarySmokeOutputSHA256,
		TempConsumerLocation:         "os-temp",
	}, nil
}

func inputFailures(input input) []string {
	failures := []string{}
	if input.DependencyName != input.PackageName {
		failures = append(failures, "registry consumer dependencyName must match packageName")
	}
	if input.DependencySpec != input.PackageVersion {
		failures = append(failures, "registry consumer dependencySpec must be the exact packageVersion")
	}
	if !hexSHA1Pattern.MatchString(input.TarballShasum) {
		failures = append(failures, "registry consumer tarballShasum must be lowercase sha1 hex")
	}
	if !strings.HasPrefix(input.TarballIntegrity, "sha512-") {
		failures = append(failures, "registry consumer tarballIntegrity must be an npm sha512 integrity string")
	}
	if !npmSHA512IntegrityPattern.MatchString(input.TarballIntegrity) {
		failures = append(failures, "registry consumer tarballIntegrity must be base64 sha512 npm integrity text")
	}
	if input.TarballFileName != expectedTarballFileName(input.PackageName, input.PackageVersion) {
		failures = append(failures, "registry consumer tarballFileName must match package name and version")
	}
	return failures
}

func releaseAuthorityFailures(input input) []string {
	failures := []string{}
	if input.ReleaseAuthority.Err != nil {
		return []string{fmt.Sprintf("releaseAuthorityInput: %s", input.ReleaseAuthority.Err.Error())}
	}
	if input.ReleaseAuthority.Record.State != "passed" {
		for _, result := range input.ReleaseAuthority.Record.RuleResults {
			failures = append(failures, "releaseAuthorityInput: "+result.Message)
		}
	}
	releaseProjection := input.ReleaseAuthority.Projection
	if releaseProjection.SchemaVersion != 3 {
		failures = append(failures, "releaseAuthorityInput.schemaVersion must be 3 for registry consumer proof")
	}
	if releaseProjection.Channel != string(releasechannel.RegistryRelease) {
		failures = append(failures, "releaseAuthorityInput.channel must be registry_release")
	}
	if !releaseProjection.Package.HasPublishConfigRegistry || releaseProjection.Package.PublishConfigRegistry != input.RegistryURL {
		failures = append(failures, "releaseAuthorityInput.package.publishConfigRegistry must match registryUrl")
	}
	if !releaseProjection.HasRegistryAuthority || releaseProjection.RegistryAuthority.RegistryURL != input.RegistryURL {
		failures = append(failures, "releaseAuthorityInput.registryAuthority.registryUrl must match registryUrl")
	}
	if releaseProjection.RolloutClaim {
		failures = append(failures, "releaseAuthorityInput.rolloutClaim must be false")
	}
	if releaseProjection.Package.Name != input.PackageName {
		failures = append(failures, "releaseAuthorityInput.package.name must match packageName")
	}
	if releaseProjection.Package.Version != input.PackageVersion {
		failures = append(failures, "releaseAuthorityInput.package.version must match packageVersion")
	}
	if basename(releaseProjection.Package.ArtifactPath) != input.TarballFileName {
		failures = append(failures, "releaseAuthorityInput.package.artifactPath basename must match tarballFileName")
	}
	if releaseProjection.Rollback.VersionPin != input.RollbackVersionPin {
		failures = append(failures, "releaseAuthorityInput.rollback.versionPin must match rollbackVersionPin")
	}
	return failures
}

func consumerProofFailures(input input, proofValue *proof) []string {
	if proofValue == nil {
		return []string{"registry consumer proof evidence must be provided"}
	}
	failures := []string{}
	if proofValue.DependencySpec != input.DependencySpec {
		failures = append(failures, "registry consumer proof dependencySpec must match input dependencySpec")
	}
	if !proofValue.RegistryPackNameMatches || !proofValue.RegistryPackVersionMatches || !proofValue.RegistryPackShasumMatches || !proofValue.RegistryPackIntegrityMatch {
		failures = append(failures, "registry consumer proof registry pack artifact must match admitted name, version, shasum, and integrity")
	}
	if !proofValue.InstallLockContainsPackage || !proofValue.FrozenLockContainsPackage {
		failures = append(failures, "registry consumer proof lockfiles must contain the prepared registry package tarball")
	}
	if proofValue.InstallLockUsesWorkspace || proofValue.FrozenLockUsesWorkspace {
		failures = append(failures, "registry consumer proof lockfiles must not use workspace resolution")
	}
	if proofValue.RollbackLockContainsPackage {
		failures = append(failures, "registry consumer proof rollback lock must not contain the package")
	}
	if !hexSHA256Pattern.MatchString(proofValue.BinarySmokeOutputSHA256) {
		failures = append(failures, "registry consumer proof binarySmokeOutputSha256 must be lowercase sha256 hex")
	}
	if !hexSHA256Pattern.MatchString(proofValue.CLIWitnessPlanOutputSHA256) {
		failures = append(failures, "registry consumer proof cliWitnessPlanOutputSha256 must be lowercase sha256 hex")
	}
	if !hexSHA256Pattern.MatchString(proofValue.ReleaseAuthorityOutputSHA256) {
		failures = append(failures, "registry consumer proof releaseAuthorityOutputSha256 must be lowercase sha256 hex")
	}
	if proofValue.ReleaseAuthorityKind != "proofkit.release-authority" {
		failures = append(failures, "registry consumer proof releaseAuthorityReportKind must be proofkit.release-authority")
	}
	if proofValue.ReleaseAuthorityState != "passed" {
		failures = append(failures, "registry consumer proof releaseAuthorityState must be passed")
	}
	expectedReleaseHash := expectedReleaseAuthorityOutputSHA256(input)
	if expectedReleaseHash != "" && proofValue.ReleaseAuthorityOutputSHA256 != expectedReleaseHash {
		failures = append(failures, "registry consumer proof releaseAuthorityOutputSha256 must match package API output")
	}
	return failures
}

func expectedReleaseAuthorityOutputSHA256(input input) string {
	if input.ReleaseAuthority.Err != nil {
		return ""
	}
	return input.ReleaseAuthority.OutputSHA256
}

func consumerProofDiagnostic(proofValue *proof) any {
	if proofValue == nil {
		return map[string]any{"executed": false}
	}
	return map[string]any{
		"cliWitnessPlanOutputSha256":   proofValue.CLIWitnessPlanOutputSHA256,
		"frozenLockContainsPackage":    proofValue.FrozenLockContainsPackage,
		"frozenLockUsesWorkspace":      proofValue.FrozenLockUsesWorkspace,
		"installLockContainsPackage":   proofValue.InstallLockContainsPackage,
		"installLockUsesWorkspace":     proofValue.InstallLockUsesWorkspace,
		"releaseAuthorityOutputSha256": proofValue.ReleaseAuthorityOutputSHA256,
		"releaseAuthorityReportKind":   proofValue.ReleaseAuthorityKind,
		"releaseAuthorityState":        proofValue.ReleaseAuthorityState,
		"rollbackLockContainsPackage":  proofValue.RollbackLockContainsPackage,
		"binarySmokeOutputSha256":      proofValue.BinarySmokeOutputSHA256,
		"tempConsumerLocation":         proofValue.TempConsumerLocation,
	}
}

func failedAdmissionReport(err error) report.Record {
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      "proofkit.registry-consumer.invalid-input",
		State:         "failed",
		Summary: map[string]any{
			"admission": "failed",
		},
		Diagnostics: []report.Diagnostic{},
		RuleResults: []report.RuleResult{
			{
				RuleID:      "proofkit.registry-consumer.failure.001",
				Status:      "failed",
				Message:     err.Error(),
				Diagnostics: []report.Diagnostic{},
			},
		},
		NonClaims: []any{"Invalid registry-consumer input is not proofkit consumption evidence."},
	}
}

func ruleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{
			{
				RuleID:      "proofkit.registry-consumer.accepted",
				Status:      "passed",
				Message:     "registry consumer install proof accepted",
				Diagnostics: []report.Diagnostic{},
			},
		}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.registry-consumer.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}

func packageName(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if !packageNamePattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an npm package name", context)
	}
	return value, nil
}

func packageVersion(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if !packageVersionPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an exact npm version", context)
	}
	return value, nil
}

func registryURL(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if !registryURLPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an https registry URL", context)
	}
	return value, nil
}

func tarballFileName(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if !tarballNamePattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an npm tarball filename", context)
	}
	return value, nil
}

func registryVersionPin(raw any, expectedPackageName string, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	marker := expectedPackageName + "@"
	if !strings.HasPrefix(value, marker) {
		return "", fmt.Errorf("%s must point to the same package name", context)
	}
	version := strings.TrimPrefix(value, marker)
	if !packageVersionPattern.MatchString(version) {
		return "", fmt.Errorf("%s must be an exact registry package version pin", context)
	}
	return value, nil
}

func sortedNonEmptyStrings(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a non-empty string array", context)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		textValue, err := text(value, context)
		if err != nil {
			return nil, fmt.Errorf("%s must be a non-empty string array", context)
		}
		result = append(result, textValue)
	}
	for index := 1; index < len(result); index++ {
		if result[index-1] >= result[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return result, nil
}

func text(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func commandNonClaims(caller []string) []string {
	values := append(append([]string{}, boundaryNonClaims...), caller...)
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func basename(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func expectedTarballFileName(packageNameValue string, version string) string {
	return fmt.Sprintf("%s-%s.tgz", strings.Replace(strings.Replace(packageNameValue, "@", "", 1), "/", "-", 1), version)
}
