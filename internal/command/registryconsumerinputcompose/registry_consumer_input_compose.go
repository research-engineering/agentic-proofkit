package registryconsumerinputcompose

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
)

const compositionKind = "proofkit.registry-consumer-proof-input-compose"

var (
	packageNamePattern        = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	packageVersionPattern     = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	registryURLPattern        = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]*)?$`)
	tarballNamePattern        = regexp.MustCompile(`^[A-Za-z0-9._@-]+-\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\.tgz$`)
	hexSHA1Pattern            = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexSHA256Pattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	npmSHA512IntegrityPattern = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]+={0,2}$`)
)

var requiredPreconditionIDs = []string{
	"binary.smoke",
	"cli.witness-plan",
	"frozen.lock",
	"install.lock",
	"registry.metadata",
	"release-authority.report",
	"rollback.lock",
}

var standardNonClaims = []string{
	"Registry consumer proof input composition does not fetch package registries or run package managers.",
	"Registry consumer proof input composition does not read manifests, lockfiles, or repository state.",
	"Registry consumer proof input composition does not authenticate producers, compute proof freshness, approve merge, approve release, approve rollout, or approve production readiness.",
	"Registry-consumer remains the final proof-schema owner and final consumption-evidence validator.",
}

type input struct {
	CompositionID          string
	ConsumerID             string
	DependencyName         string
	DependencySpec         string
	FrozenInstall          lockFacts
	Install                lockFacts
	NonClaims              []string
	PackageName            string
	PackageVersion         string
	Preconditions          []precondition
	RegistryMetadata       registryMetadata
	RegistryPackProof      registryPackProof
	RegistryURL            string
	ReleaseAuthority       releaseauthority.ConsumerProjectionAdmission
	ReleaseAuthorityReport releaseAuthorityReport
	Rollback               rollbackFacts
	RollbackVersionPin     string
	Smoke                  smokeFacts
}

type registryMetadata struct {
	PackageName      string
	PackageVersion   string
	TarballFileName  string
	TarballIntegrity string
	TarballShasum    string
}

type registryPackProof struct {
	IntegrityMatches bool
	NameMatches      bool
	ShasumMatches    bool
	VersionMatches   bool
}

type lockFacts struct {
	DependencySpec      string
	LockContainsPackage bool
	LockUsesWorkspace   bool
}

type smokeFacts struct {
	BinarySmokeOutputSHA256    string
	CLIWitnessPlanOutputSHA256 string
}

type releaseAuthorityReport struct {
	OutputSHA256 string
	ReportKind   string
	State        string
}

type rollbackFacts struct {
	LockContainsPackage bool
}

type precondition struct {
	ID     string
	Reason string
	State  string
}

func Build(raw any) (map[string]any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return invalidInputOutput(err), 1, nil
	}
	output, exitCode := buildOutput(input)
	return output, exitCode, nil
}

func buildOutput(input input) (map[string]any, int) {
	blockers, failures := findings(input)
	state := "passed"
	if len(blockers) > 0 {
		state = "blocked"
	} else if len(failures) > 0 {
		state = "failed"
	}
	var registryInput any
	if state == "passed" {
		composed := composeRegistryConsumerInput(input)
		record, exitCode, err := registryconsumer.Build(composed)
		if err != nil || exitCode != 0 || record.State != "passed" {
			state = "failed"
			failures = append(failures, "composed registry-consumer input must be accepted by registry-consumer")
			registryInput = nil
		} else {
			registryInput = composed
		}
	}
	output := map[string]any{
		"compositionId":         input.CompositionID,
		"compositionKind":       compositionKind,
		"nonClaims":             admit.StringSliceToAny(nonClaims(input.NonClaims)),
		"registryConsumerInput": registryInput,
		"ruleResults":           ruleResults(blockers, failures),
		"schemaVersion":         1,
		"state":                 state,
		"summary": map[string]any{
			"blockedPreconditionCount": len(blockers),
			"dependencySpec":           input.DependencySpec,
			"failureCount":             len(failures),
			"packageName":              input.PackageName,
			"packageVersion":           input.PackageVersion,
			"registryUrl":              input.RegistryURL,
		},
	}
	if state == "passed" {
		return output, 0
	}
	return output, 1
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("registry consumer proof input compose input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"compositionId", "consumerId", "dependencyName", "dependencySpec", "frozenInstall", "install", "nonClaims", "packageName", "packageVersion", "preconditions", "registryMetadata", "registryPackProof", "registryUrl", "releaseAuthorityInput", "releaseAuthorityReport", "rollback", "rollbackVersionPin", "schemaVersion", "smoke"}, "registry consumer proof input compose input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("registry consumer proof input compose schemaVersion must be 1")
	}
	compositionID, err := admit.RuleID(record["compositionId"], "registry consumer proof input compose compositionId")
	if err != nil {
		return input{}, err
	}
	consumerID, err := admit.RuleID(record["consumerId"], "registry consumer proof input compose consumerId")
	if err != nil {
		return input{}, err
	}
	packageNameValue, err := packageName(record["packageName"], "registry consumer proof input compose packageName")
	if err != nil {
		return input{}, err
	}
	packageVersionValue, err := packageVersion(record["packageVersion"], "registry consumer proof input compose packageVersion")
	if err != nil {
		return input{}, err
	}
	dependencyName, err := packageName(record["dependencyName"], "registry consumer proof input compose dependencyName")
	if err != nil {
		return input{}, err
	}
	dependencySpec, err := packageVersion(record["dependencySpec"], "registry consumer proof input compose dependencySpec")
	if err != nil {
		return input{}, err
	}
	registryURL, err := registryURL(record["registryUrl"], "registry consumer proof input compose registryUrl")
	if err != nil {
		return input{}, err
	}
	rollbackVersionPin, err := registryVersionPin(record["rollbackVersionPin"], packageNameValue, "registry consumer proof input compose rollbackVersionPin")
	if err != nil {
		return input{}, err
	}
	registry, err := admitRegistryMetadata(record["registryMetadata"])
	if err != nil {
		return input{}, err
	}
	registryPack, err := admitRegistryPackProof(record["registryPackProof"])
	if err != nil {
		return input{}, err
	}
	install, err := admitLockFacts(record["install"], "install")
	if err != nil {
		return input{}, err
	}
	frozen, err := admitLockFacts(record["frozenInstall"], "frozenInstall")
	if err != nil {
		return input{}, err
	}
	smoke, err := admitSmokeFacts(record["smoke"])
	if err != nil {
		return input{}, err
	}
	releaseReport, err := admitReleaseAuthorityReport(record["releaseAuthorityReport"])
	if err != nil {
		return input{}, err
	}
	rollback, err := admitRollbackFacts(record["rollback"])
	if err != nil {
		return input{}, err
	}
	preconditions, err := admitPreconditions(record["preconditions"])
	if err != nil {
		return input{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "registry consumer proof input compose nonClaims", true)
	if err != nil {
		return input{}, err
	}
	return input{
		CompositionID:          compositionID,
		ConsumerID:             consumerID,
		DependencyName:         dependencyName,
		DependencySpec:         dependencySpec,
		FrozenInstall:          frozen,
		Install:                install,
		NonClaims:              nonClaims,
		PackageName:            packageNameValue,
		PackageVersion:         packageVersionValue,
		Preconditions:          preconditions,
		RegistryMetadata:       registry,
		RegistryPackProof:      registryPack,
		RegistryURL:            registryURL,
		ReleaseAuthority:       releaseauthority.AdmitConsumerProjection(record["releaseAuthorityInput"]),
		ReleaseAuthorityReport: releaseReport,
		Rollback:               rollback,
		RollbackVersionPin:     rollbackVersionPin,
		Smoke:                  smoke,
	}, nil
}

func admitRegistryMetadata(raw any) (registryMetadata, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return registryMetadata{}, fmt.Errorf("registry consumer proof input compose registryMetadata must be an object")
	}
	if err := admit.KnownKeys(record, []string{"packageName", "packageVersion", "tarballFileName", "tarballIntegrity", "tarballShasum"}, "registry consumer proof input compose registryMetadata"); err != nil {
		return registryMetadata{}, err
	}
	name, err := packageName(record["packageName"], "registryMetadata.packageName")
	if err != nil {
		return registryMetadata{}, err
	}
	version, err := packageVersion(record["packageVersion"], "registryMetadata.packageVersion")
	if err != nil {
		return registryMetadata{}, err
	}
	tarball, err := tarballFileName(record["tarballFileName"], "registryMetadata.tarballFileName")
	if err != nil {
		return registryMetadata{}, err
	}
	integrity, err := admit.NonEmptyText(record["tarballIntegrity"], "registryMetadata.tarballIntegrity")
	if err != nil {
		return registryMetadata{}, err
	}
	shasum, err := admit.NonEmptyText(record["tarballShasum"], "registryMetadata.tarballShasum")
	if err != nil {
		return registryMetadata{}, err
	}
	return registryMetadata{PackageName: name, PackageVersion: version, TarballFileName: tarball, TarballIntegrity: integrity, TarballShasum: shasum}, nil
}

func admitRegistryPackProof(raw any) (registryPackProof, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return registryPackProof{}, fmt.Errorf("registry consumer proof input compose registryPackProof must be an object")
	}
	if err := admit.KnownKeys(record, []string{"integrityMatches", "nameMatches", "shasumMatches", "versionMatches"}, "registry consumer proof input compose registryPackProof"); err != nil {
		return registryPackProof{}, err
	}
	integrityMatches, err := admit.Bool(record["integrityMatches"], "registryPackProof.integrityMatches")
	if err != nil {
		return registryPackProof{}, err
	}
	nameMatches, err := admit.Bool(record["nameMatches"], "registryPackProof.nameMatches")
	if err != nil {
		return registryPackProof{}, err
	}
	shasumMatches, err := admit.Bool(record["shasumMatches"], "registryPackProof.shasumMatches")
	if err != nil {
		return registryPackProof{}, err
	}
	versionMatches, err := admit.Bool(record["versionMatches"], "registryPackProof.versionMatches")
	if err != nil {
		return registryPackProof{}, err
	}
	return registryPackProof{
		IntegrityMatches: integrityMatches,
		NameMatches:      nameMatches,
		ShasumMatches:    shasumMatches,
		VersionMatches:   versionMatches,
	}, nil
}

func admitLockFacts(raw any, label string) (lockFacts, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return lockFacts{}, fmt.Errorf("registry consumer proof input compose %s must be an object", label)
	}
	if err := admit.KnownKeys(record, []string{"dependencySpec", "lockContainsPackage", "lockUsesWorkspace"}, "registry consumer proof input compose "+label); err != nil {
		return lockFacts{}, err
	}
	dependencySpec, err := packageVersion(record["dependencySpec"], label+".dependencySpec")
	if err != nil {
		return lockFacts{}, err
	}
	lockContainsPackage, err := admit.Bool(record["lockContainsPackage"], label+".lockContainsPackage")
	if err != nil {
		return lockFacts{}, err
	}
	lockUsesWorkspace, err := admit.Bool(record["lockUsesWorkspace"], label+".lockUsesWorkspace")
	if err != nil {
		return lockFacts{}, err
	}
	return lockFacts{DependencySpec: dependencySpec, LockContainsPackage: lockContainsPackage, LockUsesWorkspace: lockUsesWorkspace}, nil
}

func admitSmokeFacts(raw any) (smokeFacts, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return smokeFacts{}, fmt.Errorf("registry consumer proof input compose smoke must be an object")
	}
	if err := admit.KnownKeys(record, []string{"binarySmokeOutputSha256", "cliWitnessPlanOutputSha256"}, "registry consumer proof input compose smoke"); err != nil {
		return smokeFacts{}, err
	}
	binarySmoke, err := sha256Text(record["binarySmokeOutputSha256"], "smoke.binarySmokeOutputSha256")
	if err != nil {
		return smokeFacts{}, err
	}
	cliWitness, err := sha256Text(record["cliWitnessPlanOutputSha256"], "smoke.cliWitnessPlanOutputSha256")
	if err != nil {
		return smokeFacts{}, err
	}
	return smokeFacts{BinarySmokeOutputSHA256: binarySmoke, CLIWitnessPlanOutputSHA256: cliWitness}, nil
}

func admitReleaseAuthorityReport(raw any) (releaseAuthorityReport, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return releaseAuthorityReport{}, fmt.Errorf("registry consumer proof input compose releaseAuthorityReport must be an object")
	}
	if err := admit.KnownKeys(record, []string{"outputSha256", "reportKind", "state"}, "registry consumer proof input compose releaseAuthorityReport"); err != nil {
		return releaseAuthorityReport{}, err
	}
	outputSHA, err := sha256Text(record["outputSha256"], "releaseAuthorityReport.outputSha256")
	if err != nil {
		return releaseAuthorityReport{}, err
	}
	kind, err := admit.NonEmptyText(record["reportKind"], "releaseAuthorityReport.reportKind")
	if err != nil {
		return releaseAuthorityReport{}, err
	}
	state, err := admit.NonEmptyText(record["state"], "releaseAuthorityReport.state")
	if err != nil {
		return releaseAuthorityReport{}, err
	}
	return releaseAuthorityReport{OutputSHA256: outputSHA, ReportKind: kind, State: state}, nil
}

func admitRollbackFacts(raw any) (rollbackFacts, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return rollbackFacts{}, fmt.Errorf("registry consumer proof input compose rollback must be an object")
	}
	if err := admit.KnownKeys(record, []string{"lockContainsPackage"}, "registry consumer proof input compose rollback"); err != nil {
		return rollbackFacts{}, err
	}
	lockContainsPackage, err := admit.Bool(record["lockContainsPackage"], "rollback.lockContainsPackage")
	if err != nil {
		return rollbackFacts{}, err
	}
	return rollbackFacts{LockContainsPackage: lockContainsPackage}, nil
}

func admitPreconditions(raw any) ([]precondition, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("registry consumer proof input compose preconditions must be an array")
	}
	result := make([]precondition, 0, len(values))
	ids := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("registry consumer proof input compose precondition #%d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"preconditionId", "reason", "state"}, "registry consumer proof input compose precondition"); err != nil {
			return nil, err
		}
		id, err := admit.RuleID(record["preconditionId"], "registry consumer proof input compose preconditionId")
		if err != nil {
			return nil, err
		}
		state, err := admit.Enum(record["state"], map[string]struct{}{"available": {}, "unavailable": {}}, "registry consumer proof input compose precondition state")
		if err != nil {
			return nil, err
		}
		reason, err := admit.NonEmptyText(record["reason"], "registry consumer proof input compose precondition reason")
		if err != nil {
			return nil, err
		}
		result = append(result, precondition{ID: id, Reason: reason, State: state})
		ids = append(ids, id)
	}
	if _, err := admit.PreserveSortedText(ids, "registry consumer proof input compose precondition ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func findings(input input) ([]string, []string) {
	blockers, failures := preconditionFindings(input.Preconditions)
	failures = append(failures, packageFailures(input)...)
	failures = append(failures, registryMetadataFailures(input)...)
	failures = append(failures, lockFailures(input)...)
	failures = append(failures, releaseAuthorityFailures(input)...)
	return blockers, failures
}

func preconditionFindings(preconditions []precondition) ([]string, []string) {
	seen := map[string]precondition{}
	for _, item := range preconditions {
		seen[item.ID] = item
	}
	blockers := []string{}
	failures := []string{}
	for _, id := range requiredPreconditionIDs {
		item, ok := seen[id]
		if !ok {
			failures = append(failures, "registry consumer proof input compose missing required precondition: "+id)
			continue
		}
		if item.State == "unavailable" {
			blockers = append(blockers, "registry consumer proof input compose precondition unavailable: "+id)
		}
	}
	return blockers, failures
}

func packageFailures(input input) []string {
	failures := []string{}
	if input.DependencyName != input.PackageName {
		failures = append(failures, "dependencyName must match packageName")
	}
	if input.DependencySpec != input.PackageVersion {
		failures = append(failures, "dependencySpec must be the exact packageVersion")
	}
	return failures
}

func registryMetadataFailures(input input) []string {
	failures := []string{}
	if input.RegistryMetadata.PackageName != input.PackageName {
		failures = append(failures, "registry metadata packageName must match packageName")
	}
	if input.RegistryMetadata.PackageVersion != input.PackageVersion {
		failures = append(failures, "registry metadata packageVersion must match packageVersion")
	}
	if input.RegistryMetadata.TarballFileName != expectedTarballFileName(input.PackageName, input.PackageVersion) {
		failures = append(failures, "registry metadata tarballFileName must match package name and version")
	}
	if !hexSHA1Pattern.MatchString(input.RegistryMetadata.TarballShasum) {
		failures = append(failures, "registry metadata tarballShasum must be lowercase sha1 hex")
	}
	if !npmSHA512IntegrityPattern.MatchString(input.RegistryMetadata.TarballIntegrity) {
		failures = append(failures, "registry metadata tarballIntegrity must be npm sha512 integrity text")
	}
	if !input.RegistryPackProof.IntegrityMatches {
		failures = append(failures, "registry pack integrity comparison must match admitted metadata")
	}
	if !input.RegistryPackProof.NameMatches {
		failures = append(failures, "registry pack name comparison must match packageName")
	}
	if !input.RegistryPackProof.ShasumMatches {
		failures = append(failures, "registry pack shasum comparison must match admitted metadata")
	}
	if !input.RegistryPackProof.VersionMatches {
		failures = append(failures, "registry pack version comparison must match packageVersion")
	}
	return failures
}

func lockFailures(input input) []string {
	failures := []string{}
	if input.Install.DependencySpec != input.DependencySpec {
		failures = append(failures, "install dependencySpec must match dependencySpec")
	}
	if input.FrozenInstall.DependencySpec != input.DependencySpec {
		failures = append(failures, "frozenInstall dependencySpec must match dependencySpec")
	}
	if !input.Install.LockContainsPackage {
		failures = append(failures, "install lock must contain the package")
	}
	if input.Install.LockUsesWorkspace {
		failures = append(failures, "install lock must not resolve through workspace")
	}
	if !input.FrozenInstall.LockContainsPackage {
		failures = append(failures, "frozen install lock must contain the package")
	}
	if input.FrozenInstall.LockUsesWorkspace {
		failures = append(failures, "frozen install lock must not resolve through workspace")
	}
	if input.Rollback.LockContainsPackage {
		failures = append(failures, "rollback lock must not contain the package")
	}
	return failures
}

func releaseAuthorityFailures(input input) []string {
	failures := []string{}
	if input.ReleaseAuthority.Err != nil {
		return []string{"releaseAuthorityInput: " + input.ReleaseAuthority.Err.Error()}
	}
	if input.ReleaseAuthority.Record.State != "passed" {
		for _, result := range input.ReleaseAuthority.Record.RuleResults {
			failures = append(failures, "releaseAuthorityInput: "+result.Message)
		}
	}
	projection := input.ReleaseAuthority.Projection
	if projection.SchemaVersion != 3 {
		failures = append(failures, "releaseAuthorityInput.schemaVersion must be 3 for registry consumer proof")
	}
	if projection.Channel != string(releasechannel.RegistryRelease) {
		failures = append(failures, "releaseAuthorityInput.channel must be registry_release")
	}
	if !projection.Package.HasPublishConfigRegistry || projection.Package.PublishConfigRegistry != input.RegistryURL {
		failures = append(failures, "releaseAuthorityInput.package.publishConfigRegistry must match registryUrl")
	}
	if !projection.HasRegistryAuthority || projection.RegistryAuthority.RegistryURL != input.RegistryURL {
		failures = append(failures, "releaseAuthorityInput.registryAuthority.registryUrl must match registryUrl")
	}
	if projection.Package.Name != input.PackageName {
		failures = append(failures, "releaseAuthorityInput.package.name must match packageName")
	}
	if projection.Package.Version != input.PackageVersion {
		failures = append(failures, "releaseAuthorityInput.package.version must match packageVersion")
	}
	if projection.RolloutClaim {
		failures = append(failures, "releaseAuthorityInput.rolloutClaim must be false")
	}
	if projection.Rollback.VersionPin != input.RollbackVersionPin {
		failures = append(failures, "releaseAuthorityInput.rollback.versionPin must match rollbackVersionPin")
	}
	if input.ReleaseAuthorityReport.ReportKind != "proofkit.release-authority" {
		failures = append(failures, "releaseAuthorityReport.reportKind must be proofkit.release-authority")
	}
	if input.ReleaseAuthorityReport.State != "passed" {
		failures = append(failures, "releaseAuthorityReport.state must be passed")
	}
	if input.ReleaseAuthorityReport.OutputSHA256 != input.ReleaseAuthority.OutputSHA256 {
		failures = append(failures, "releaseAuthorityReport.outputSha256 must match admitted release-authority report digest")
	}
	return failures
}

func composeRegistryConsumerInput(input input) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"input": map[string]any{
			"consumerId":            input.ConsumerID,
			"dependencyName":        input.DependencyName,
			"dependencySpec":        input.DependencySpec,
			"nonClaims":             admit.StringSliceToAny(nonClaims(input.NonClaims)),
			"packageName":           input.PackageName,
			"packageVersion":        input.PackageVersion,
			"registryUrl":           input.RegistryURL,
			"releaseAuthorityInput": input.ReleaseAuthority.InputJSON,
			"rollbackVersionPin":    input.RollbackVersionPin,
			"schemaVersion":         json.Number("1"),
			"tarballFileName":       input.RegistryMetadata.TarballFileName,
			"tarballIntegrity":      input.RegistryMetadata.TarballIntegrity,
			"tarballShasum":         input.RegistryMetadata.TarballShasum,
		},
		"proof": map[string]any{
			"binarySmokeOutputSha256":      input.Smoke.BinarySmokeOutputSHA256,
			"cliWitnessPlanOutputSha256":   input.Smoke.CLIWitnessPlanOutputSHA256,
			"dependencySpec":               input.DependencySpec,
			"frozenLockContainsPackage":    input.FrozenInstall.LockContainsPackage,
			"frozenLockUsesWorkspace":      input.FrozenInstall.LockUsesWorkspace,
			"installLockContainsPackage":   input.Install.LockContainsPackage,
			"installLockUsesWorkspace":     input.Install.LockUsesWorkspace,
			"registryPackIntegrityMatches": input.RegistryPackProof.IntegrityMatches,
			"registryPackNameMatches":      input.RegistryPackProof.NameMatches,
			"registryPackShasumMatches":    input.RegistryPackProof.ShasumMatches,
			"registryPackVersionMatches":   input.RegistryPackProof.VersionMatches,
			"releaseAuthorityOutputSha256": input.ReleaseAuthorityReport.OutputSHA256,
			"releaseAuthorityReportKind":   input.ReleaseAuthorityReport.ReportKind,
			"releaseAuthorityState":        input.ReleaseAuthorityReport.State,
			"rollbackLockContainsPackage":  input.Rollback.LockContainsPackage,
			"tempConsumerLocation":         "os-temp",
		},
	}
}

func ruleResults(blockers []string, failures []string) []any {
	results := []any{}
	preconditionStatus := "passed"
	preconditionMessage := "registry consumer proof input compose preconditions are available"
	if len(blockers) > 0 {
		preconditionStatus = "blocked"
		preconditionMessage = strings.Join(blockers, "; ")
	} else if matches := matchingFailures(failures, "precondition"); len(matches) > 0 {
		preconditionStatus = "failed"
		preconditionMessage = strings.Join(matches, "; ")
	}
	results = append(results, map[string]any{
		"diagnostics": []any{},
		"message":     preconditionMessage,
		"ruleId":      "proofkit.registry-consumer-proof-input-compose.preconditions",
		"status":      preconditionStatus,
	})
	semanticFailures := nonMatchingFailures(failures, "precondition")
	if len(semanticFailures) == 0 && len(blockers) == 0 {
		results = append(results, map[string]any{
			"diagnostics": []any{},
			"message":     "registry-consumer input composition is accepted by registry-consumer",
			"ruleId":      "proofkit.registry-consumer-proof-input-compose.accepted",
			"status":      "passed",
		})
		return results
	}
	for index, failure := range semanticFailures {
		results = append(results, map[string]any{
			"diagnostics": []any{},
			"message":     failure,
			"ruleId":      fmt.Sprintf("proofkit.registry-consumer-proof-input-compose.failure.%03d", index+1),
			"status":      "failed",
		})
	}
	return results
}

func invalidInputOutput(err error) map[string]any {
	return map[string]any{
		"compositionId":         "proofkit.registry-consumer-proof-input-compose.invalid-input",
		"compositionKind":       compositionKind,
		"nonClaims":             admit.StringSliceToAny(standardNonClaims),
		"registryConsumerInput": nil,
		"ruleResults": []any{
			map[string]any{
				"diagnostics": []any{},
				"message":     admit.RedactDiagnosticValue(err.Error()),
				"ruleId":      "proofkit.registry-consumer-proof-input-compose.failure.001",
				"status":      "failed",
			},
		},
		"schemaVersion": 1,
		"state":         "failed",
		"summary": map[string]any{
			"admission": "failed",
		},
	}
}

func matchingFailures(failures []string, marker string) []string {
	result := []string{}
	for _, failure := range failures {
		if strings.Contains(failure, marker) {
			result = append(result, failure)
		}
	}
	return result
}

func nonMatchingFailures(failures []string, marker string) []string {
	result := []string{}
	for _, failure := range failures {
		if !strings.Contains(failure, marker) {
			result = append(result, failure)
		}
	}
	return result
}

func nonClaims(values []string) []string {
	out := append([]string{}, standardNonClaims...)
	out = append(out, values...)
	sort.Strings(out)
	deduped := out[:0]
	for _, value := range out {
		if len(deduped) == 0 || deduped[len(deduped)-1] != value {
			deduped = append(deduped, value)
		}
	}
	return deduped
}

func packageName(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !packageNamePattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an npm package name", context)
	}
	return value, nil
}

func packageVersion(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !packageVersionPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an exact npm package version", context)
	}
	return value, nil
}

func registryURL(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !registryURLPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an https registry URL", context)
	}
	return value, nil
}

func registryVersionPin(raw any, expectedPackageName string, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
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

func tarballFileName(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !tarballNamePattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an npm tarball filename", context)
	}
	return value, nil
}

func sha256Text(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !hexSHA256Pattern.MatchString(value) {
		return "", fmt.Errorf("%s must be lowercase sha256 hex", context)
	}
	return value, nil
}

func expectedTarballFileName(packageNameValue string, version string) string {
	return fmt.Sprintf("%s-%s.tgz", strings.Replace(strings.Replace(packageNameValue, "@", "", 1), "/", "-", 1), version)
}
