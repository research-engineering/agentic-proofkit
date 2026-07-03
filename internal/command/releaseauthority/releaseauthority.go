package releaseauthority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const reportKind = "proofkit.release-authority"

var dependencyPinTypes = map[string]struct{}{
	"file_tarball":     {},
	"registry_version": {},
}

var registryKinds = map[string]struct{}{
	"github_packages": {},
	"npm_registry":    {},
}

var releaseVisibilities = map[string]struct{}{
	"internal":   {},
	"private":    {},
	"public":     {},
	"restricted": {},
}

var provenanceModes = map[string]struct{}{
	"npm_provenance":     {},
	"trusted_publishing": {},
}

var publisherAuthorityModes = map[string]struct{}{
	"github_actions_github_token": {},
	"npm_provenance":              {},
	"npm_trusted_publishing":      {},
}

var sourceRepositoryVisibilities = map[string]struct{}{
	"internal": {},
	"private":  {},
	"public":   {},
}

var (
	npmPackageNamePattern       = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)
	packageScopePattern         = regexp.MustCompile(`^@[a-z0-9][a-z0-9._-]*$`)
	packageVersionPattern       = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	httpsURLPattern             = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~/-]*)?$`)
	githubOwnerPattern          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$`)
	githubRepositoryNamePattern = regexp.MustCompile(`^[a-z0-9._-]+$`)
)

const (
	npmRegistryURL            = releasechannel.NPMRegistryURL
	githubPackagesRegistryURL = releasechannel.GitHubPackagesRegistryURL
)

var boundaryNonClaims = []string{
	"Release authority does not publish packages, authenticate registry credentials, execute consumer installs, approve rollout, or prove registry freshness.",
	"Release authority validates caller-owned release-channel declarations only.",
}

type releasePackage struct {
	ArtifactPath           string
	ManifestPrivate        bool
	Name                   string
	PackageManagerLockfile string
	PackManifestPath       string
	PublishConfigRegistry  *string
	Version                string
}

type artifactProof struct {
	CLISmokeProofID             string
	DeepImportRejectionProofID  string
	OutsideConsumerInstallProof string
	PackageArtifactCommandID    string
	PackDryRunCommandID         string
	RegistryPublishDryRunID     *string
	BinarySmokeProofID          string
}

type consumerContract struct {
	DependencyPinType                 string
	InputLockfileRequired             bool
	InputBinarySmokeOnly              bool
	InputSiblingSourceCheckoutAllowed bool
}

type sourceRepository struct {
	Name       string
	Owner      string
	URL        string
	Visibility string
}

type registryAuthority struct {
	ConsumerMigrationPath string
	PackageScope          string
	PublishAuthorityMode  string
	PublishWorkflowPath   string
	RegistryKind          string
	RegistryURL           string
	ReleaseTagPattern     string
	RollbackPolicy        string
	SourceRepository      *sourceRepository
	Visibility            string
}

type rollback struct {
	Owner      string
	Procedure  string
	VersionPin string
}

type admittedInput struct {
	ArtifactProof     artifactProof
	Channel           string
	ConsumerContract  consumerContract
	InputRolloutClaim bool
	NonClaims         []string
	Package           releasePackage
	RegistryAuthority *registryAuthority
	ReleaseID         string
	Rollback          rollback
	SchemaVersion     int
}

type ConsumerProjectionAdmission struct {
	Err          error
	InputJSON    map[string]any
	OutputSHA256 string
	Projection   ConsumerProjection
	Record       report.Record
}

type ConsumerProjection struct {
	ArtifactProof        ConsumerProjectionArtifactProof
	Channel              string
	HasRegistryAuthority bool
	Package              ConsumerProjectionPackage
	RegistryAuthority    ConsumerProjectionRegistryAuthority
	Rollback             ConsumerProjectionRollback
	RolloutClaim         bool
	SchemaVersion        int
}

type ConsumerProjectionPackage struct {
	ArtifactPath             string
	HasPublishConfigRegistry bool
	Name                     string
	PackageManagerLockfile   string
	PackManifestPath         string
	PublishConfigRegistry    string
	Version                  string
}

type ConsumerProjectionArtifactProof struct {
	BinarySmokeProofID          string
	CLISmokeProofID             string
	DeepImportRejectionProofID  string
	OutsideConsumerInstallProof string
	PackageArtifactCommandID    string
	PackDryRunCommandID         string
}

type ConsumerProjectionRegistryAuthority struct {
	RegistryURL string
}

type ConsumerProjectionRollback struct {
	VersionPin string
}

func Build(raw any) (report.Record, int, error) {
	_, record, exitCode, err := build(raw)
	return record, exitCode, err
}

func AdmitConsumerProjection(raw any) ConsumerProjectionAdmission {
	input, record, _, err := build(raw)
	if err != nil {
		return ConsumerProjectionAdmission{Err: err}
	}
	return ConsumerProjectionAdmission{
		InputJSON:    admittedInputJSON(input),
		OutputSHA256: stableSHA256(record.JSONValue()),
		Projection:   consumerProjectionFrom(input),
		Record:       record,
	}
}

func admittedInputJSON(input admittedInput) map[string]any {
	return map[string]any{
		"artifactProof":     artifactProofJSON(input.ArtifactProof),
		"channel":           input.Channel,
		"consumerContract":  consumerContractJSON(input.ConsumerContract),
		"nonClaims":         admit.StringSliceToAny(input.NonClaims),
		"package":           releasePackageJSON(input.Package),
		"registryAuthority": registryAuthorityJSON(input.RegistryAuthority, input.SchemaVersion),
		"releaseId":         input.ReleaseID,
		"rollback": map[string]any{
			"owner":      input.Rollback.Owner,
			"procedure":  input.Rollback.Procedure,
			"versionPin": input.Rollback.VersionPin,
		},
		"rolloutClaim":  input.InputRolloutClaim,
		"schemaVersion": json.Number(fmt.Sprintf("%d", input.SchemaVersion)),
	}
}

func releasePackageJSON(input releasePackage) map[string]any {
	var publishConfig any
	if input.PublishConfigRegistry != nil {
		publishConfig = *input.PublishConfigRegistry
	}
	return map[string]any{
		"artifactPath":           input.ArtifactPath,
		"manifestPrivate":        input.ManifestPrivate,
		"name":                   input.Name,
		"packageManagerLockfile": input.PackageManagerLockfile,
		"packManifestPath":       input.PackManifestPath,
		"publishConfigRegistry":  publishConfig,
		"version":                input.Version,
	}
}

func artifactProofJSON(input artifactProof) map[string]any {
	value := map[string]any{
		"binarySmokeProofId":            input.BinarySmokeProofID,
		"cliSmokeProofId":               input.CLISmokeProofID,
		"deepImportRejectionProofId":    input.DeepImportRejectionProofID,
		"outsideConsumerInstallProofId": input.OutsideConsumerInstallProof,
		"packageArtifactCommandId":      input.PackageArtifactCommandID,
		"packDryRunCommandId":           input.PackDryRunCommandID,
	}
	if input.RegistryPublishDryRunID != nil {
		value["registryPublishDryRunProofId"] = *input.RegistryPublishDryRunID
	}
	return value
}

func consumerContractJSON(input consumerContract) map[string]any {
	return map[string]any{
		"binarySmokeOnly":              input.InputBinarySmokeOnly,
		"dependencyPinType":            input.DependencyPinType,
		"lockfileRequired":             input.InputLockfileRequired,
		"siblingSourceCheckoutAllowed": input.InputSiblingSourceCheckoutAllowed,
	}
}

func registryAuthorityJSON(input *registryAuthority, schemaVersion int) any {
	if input == nil {
		return nil
	}
	if schemaVersion == 1 {
		provenanceMode := "npm_provenance"
		if input.PublishAuthorityMode == "npm_trusted_publishing" {
			provenanceMode = "trusted_publishing"
		}
		return map[string]any{
			"consumerMigrationPath": input.ConsumerMigrationPath,
			"packageScope":          input.PackageScope,
			"provenanceMode":        provenanceMode,
			"publishWorkflowPath":   input.PublishWorkflowPath,
			"registryKind":          input.RegistryKind,
			"registryUrl":           input.RegistryURL,
			"releaseTagPattern":     input.ReleaseTagPattern,
			"rollbackPolicy":        input.RollbackPolicy,
			"visibility":            input.Visibility,
		}
	}
	value := map[string]any{
		"consumerMigrationPath": input.ConsumerMigrationPath,
		"packageScope":          input.PackageScope,
		"publishAuthorityMode":  input.PublishAuthorityMode,
		"publishWorkflowPath":   input.PublishWorkflowPath,
		"registryKind":          input.RegistryKind,
		"registryUrl":           input.RegistryURL,
		"releaseTagPattern":     input.ReleaseTagPattern,
		"rollbackPolicy":        input.RollbackPolicy,
		"sourceRepository":      nil,
		"visibility":            input.Visibility,
	}
	if input.SourceRepository != nil {
		value["sourceRepository"] = map[string]any{
			"name":       input.SourceRepository.Name,
			"owner":      input.SourceRepository.Owner,
			"url":        input.SourceRepository.URL,
			"visibility": input.SourceRepository.Visibility,
		}
	}
	return value
}

func build(raw any) (admittedInput, report.Record, int, error) {
	failures := []string{}
	input, err := admitInput(raw, &failures)
	if err != nil {
		return admittedInput{}, report.Record{}, 1, err
	}
	enforceChannelRules(input, &failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.ReleaseID,
		State:         state,
		Summary: map[string]any{
			"channel":                   input.Channel,
			"dependencyPinType":         input.ConsumerContract.DependencyPinType,
			"manifestPrivate":           input.Package.ManifestPrivate,
			"packageName":               input.Package.Name,
			"packageVersion":            input.Package.Version,
			"registryAuthorityDeclared": input.RegistryAuthority != nil,
			"rolloutClaim":              input.InputRolloutClaim,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "artifactProof", Value: artifactProofDiagnostic(input.ArtifactProof)},
			{Key: "consumerContract", Value: map[string]any{
				"dependencyPinType":                 input.ConsumerContract.DependencyPinType,
				"inputLockfileRequired":             input.ConsumerContract.InputLockfileRequired,
				"inputBinarySmokeOnly":              input.ConsumerContract.InputBinarySmokeOnly,
				"inputSiblingSourceCheckoutAllowed": input.ConsumerContract.InputSiblingSourceCheckoutAllowed,
			}},
			{Key: "packageArtifact", Value: map[string]any{
				"artifactPath":           input.Package.ArtifactPath,
				"packageManagerLockfile": input.Package.PackageManagerLockfile,
				"packManifestPath":       input.Package.PackManifestPath,
			}},
			{Key: "registryAuthority", Value: registryAuthorityDiagnostic(input.RegistryAuthority)},
			{Key: "rollback", Value: map[string]any{
				"owner":      input.Rollback.Owner,
				"procedure":  input.Rollback.Procedure,
				"versionPin": input.Rollback.VersionPin,
			}},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(commandNonClaims(input.NonClaims)),
	}
	if state == "passed" {
		return input, record, 0, nil
	}
	return input, record, 1, nil
}

func consumerProjectionFrom(input admittedInput) ConsumerProjection {
	projection := ConsumerProjection{
		ArtifactProof: ConsumerProjectionArtifactProof{
			BinarySmokeProofID:          input.ArtifactProof.BinarySmokeProofID,
			CLISmokeProofID:             input.ArtifactProof.CLISmokeProofID,
			DeepImportRejectionProofID:  input.ArtifactProof.DeepImportRejectionProofID,
			OutsideConsumerInstallProof: input.ArtifactProof.OutsideConsumerInstallProof,
			PackageArtifactCommandID:    input.ArtifactProof.PackageArtifactCommandID,
			PackDryRunCommandID:         input.ArtifactProof.PackDryRunCommandID,
		},
		Channel: input.Channel,
		Package: ConsumerProjectionPackage{
			ArtifactPath:           input.Package.ArtifactPath,
			Name:                   input.Package.Name,
			PackageManagerLockfile: input.Package.PackageManagerLockfile,
			PackManifestPath:       input.Package.PackManifestPath,
			Version:                input.Package.Version,
		},
		Rollback:      ConsumerProjectionRollback{VersionPin: input.Rollback.VersionPin},
		RolloutClaim:  input.InputRolloutClaim,
		SchemaVersion: input.SchemaVersion,
	}
	if input.Package.PublishConfigRegistry != nil {
		projection.Package.HasPublishConfigRegistry = true
		projection.Package.PublishConfigRegistry = *input.Package.PublishConfigRegistry
	}
	if input.RegistryAuthority != nil {
		projection.HasRegistryAuthority = true
		projection.RegistryAuthority = ConsumerProjectionRegistryAuthority{RegistryURL: input.RegistryAuthority.RegistryURL}
	}
	return projection
}

func stableSHA256(value any) string {
	stable, err := stablejson.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(stable)
	return hex.EncodeToString(sum[:])
}

func admitInput(raw any, failures *[]string) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("release authority input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"artifactProof", "channel", "consumerContract", "nonClaims", "package", "registryAuthority", "releaseId", "rollback", "rolloutClaim", "schemaVersion"}, "release authority input"); err != nil {
		return admittedInput{}, err
	}
	schemaVersion, err := schemaVersion(record["schemaVersion"])
	if err != nil {
		return admittedInput{}, err
	}
	channel, err := admit.Enum(record["channel"], releasechannel.IDSet(), "release authority channel")
	if err != nil {
		return admittedInput{}, err
	}
	rolloutClaim, err := admit.Bool(record["rolloutClaim"], "release authority rolloutClaim")
	if err != nil {
		return admittedInput{}, err
	}
	if rolloutClaim {
		*failures = append(*failures, "rolloutClaim must remain false; release authority is not organization rollout approval")
	}
	releaseID, err := admit.RuleID(record["releaseId"], "release authority releaseId")
	if err != nil {
		return admittedInput{}, err
	}
	pkg, err := admitPackage(record["package"])
	if err != nil {
		return admittedInput{}, err
	}
	proof, err := admitArtifactProof(record["artifactProof"])
	if err != nil {
		return admittedInput{}, err
	}
	contract, err := admitConsumerContract(record["consumerContract"], failures)
	if err != nil {
		return admittedInput{}, err
	}
	authority, err := admitRegistryAuthorityForSchema(record["registryAuthority"], schemaVersion, channel)
	if err != nil {
		return admittedInput{}, err
	}
	rollback, err := admitRollback(record["rollback"])
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "release authority nonClaims")
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		ArtifactProof:     proof,
		Channel:           channel,
		ConsumerContract:  contract,
		InputRolloutClaim: rolloutClaim,
		NonClaims:         nonClaims,
		Package:           pkg,
		RegistryAuthority: authority,
		ReleaseID:         releaseID,
		Rollback:          rollback,
		SchemaVersion:     schemaVersion,
	}, nil
}

func schemaVersion(raw any) (int, error) {
	for _, value := range []int64{1, 2, 3} {
		if admit.JSONNumberEquals(raw, value) {
			return int(value), nil
		}
	}
	return 0, fmt.Errorf("release authority schemaVersion must be one of: 1, 2, 3")
}

func admitPackage(raw any) (releasePackage, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return releasePackage{}, fmt.Errorf("release authority package must be an object")
	}
	if err := admit.KnownKeys(record, []string{"artifactPath", "manifestPrivate", "name", "packageManagerLockfile", "packManifestPath", "publishConfigRegistry", "version"}, "release authority package"); err != nil {
		return releasePackage{}, err
	}
	name, err := text(record["name"], "package name")
	if err != nil {
		return releasePackage{}, err
	}
	if !npmPackageNamePattern.MatchString(name) {
		return releasePackage{}, fmt.Errorf("package name must be a valid npm package name")
	}
	version, err := text(record["version"], "package version")
	if err != nil {
		return releasePackage{}, err
	}
	if !packageVersionPattern.MatchString(version) {
		return releasePackage{}, fmt.Errorf("package version must be an exact npm version")
	}
	publishConfigRegistry, err := nullableHTTPSURL(record["publishConfigRegistry"], "package publishConfigRegistry")
	if err != nil {
		return releasePackage{}, err
	}
	manifestPrivate, err := admit.Bool(record["manifestPrivate"], "package manifestPrivate")
	if err != nil {
		return releasePackage{}, err
	}
	lockfile, err := pathField(record["packageManagerLockfile"], "package packageManagerLockfile")
	if err != nil {
		return releasePackage{}, err
	}
	artifactPath, err := pathField(record["artifactPath"], "package artifactPath")
	if err != nil {
		return releasePackage{}, err
	}
	packManifestPath, err := pathField(record["packManifestPath"], "package packManifestPath")
	if err != nil {
		return releasePackage{}, err
	}
	return releasePackage{
		ArtifactPath:           artifactPath,
		ManifestPrivate:        manifestPrivate,
		Name:                   name,
		PackageManagerLockfile: lockfile,
		PackManifestPath:       packManifestPath,
		PublishConfigRegistry:  publishConfigRegistry,
		Version:                version,
	}, nil
}

func admitArtifactProof(raw any) (artifactProof, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return artifactProof{}, fmt.Errorf("release authority artifactProof must be an object")
	}
	if err := admit.KnownKeys(record, []string{"cliSmokeProofId", "deepImportRejectionProofId", "outsideConsumerInstallProofId", "packageArtifactCommandId", "packDryRunCommandId", "registryPublishDryRunProofId", "binarySmokeProofId"}, "release authority artifactProof"); err != nil {
		return artifactProof{}, err
	}
	packDryRunCommandID, err := admit.RuleID(record["packDryRunCommandId"], "artifactProof packDryRunCommandId")
	if err != nil {
		return artifactProof{}, err
	}
	packageArtifactCommandID, err := admit.RuleID(record["packageArtifactCommandId"], "artifactProof packageArtifactCommandId")
	if err != nil {
		return artifactProof{}, err
	}
	outsideConsumerInstallProofID, err := admit.RuleID(record["outsideConsumerInstallProofId"], "artifactProof outsideConsumerInstallProofId")
	if err != nil {
		return artifactProof{}, err
	}
	binarySmokeProofID, err := admit.RuleID(record["binarySmokeProofId"], "artifactProof binarySmokeProofId")
	if err != nil {
		return artifactProof{}, err
	}
	cliSmokeProofID, err := admit.RuleID(record["cliSmokeProofId"], "artifactProof cliSmokeProofId")
	if err != nil {
		return artifactProof{}, err
	}
	deepImportRejectionProofID, err := admit.RuleID(record["deepImportRejectionProofId"], "artifactProof deepImportRejectionProofId")
	if err != nil {
		return artifactProof{}, err
	}
	var registryPublishDryRunProofID *string
	if rawValue, ok := record["registryPublishDryRunProofId"]; ok {
		value, err := admit.RuleID(rawValue, "artifactProof registryPublishDryRunProofId")
		if err != nil {
			return artifactProof{}, err
		}
		registryPublishDryRunProofID = &value
	}
	return artifactProof{
		CLISmokeProofID:             cliSmokeProofID,
		DeepImportRejectionProofID:  deepImportRejectionProofID,
		OutsideConsumerInstallProof: outsideConsumerInstallProofID,
		PackageArtifactCommandID:    packageArtifactCommandID,
		PackDryRunCommandID:         packDryRunCommandID,
		RegistryPublishDryRunID:     registryPublishDryRunProofID,
		BinarySmokeProofID:          binarySmokeProofID,
	}, nil
}

func admitConsumerContract(raw any, failures *[]string) (consumerContract, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return consumerContract{}, fmt.Errorf("release authority consumerContract must be an object")
	}
	if err := admit.KnownKeys(record, []string{"dependencyPinType", "lockfileRequired", "binarySmokeOnly", "siblingSourceCheckoutAllowed"}, "release authority consumerContract"); err != nil {
		return consumerContract{}, err
	}
	dependencyPinType, err := admit.Enum(record["dependencyPinType"], dependencyPinTypes, "consumerContract dependencyPinType")
	if err != nil {
		return consumerContract{}, err
	}
	binarySmokeOnly, err := admit.Bool(record["binarySmokeOnly"], "consumerContract binarySmokeOnly")
	if err != nil {
		return consumerContract{}, err
	}
	lockfileRequired, err := admit.Bool(record["lockfileRequired"], "consumerContract lockfileRequired")
	if err != nil {
		return consumerContract{}, err
	}
	siblingSourceCheckoutAllowed, err := admit.Bool(record["siblingSourceCheckoutAllowed"], "consumerContract siblingSourceCheckoutAllowed")
	if err != nil {
		return consumerContract{}, err
	}
	if !binarySmokeOnly {
		*failures = append(*failures, "consumerContract binarySmokeOnly must be true")
	}
	if !lockfileRequired {
		*failures = append(*failures, "consumerContract lockfileRequired must be true")
	}
	if siblingSourceCheckoutAllowed {
		*failures = append(*failures, "consumerContract siblingSourceCheckoutAllowed must be false")
	}
	return consumerContract{
		DependencyPinType:                 dependencyPinType,
		InputLockfileRequired:             lockfileRequired,
		InputBinarySmokeOnly:              binarySmokeOnly,
		InputSiblingSourceCheckoutAllowed: siblingSourceCheckoutAllowed,
	}, nil
}

func admitRegistryAuthorityForSchema(raw any, schemaVersion int, channel string) (*registryAuthority, error) {
	if raw == nil {
		return nil, nil
	}
	if schemaVersion == 1 {
		return admitLegacyRegistryAuthority(raw)
	}
	if channel == string(releasechannel.TarballPilot) {
		return admitRegistryAuthorityV2(raw)
	}
	return admitRegistryAuthorityV2(raw)
}

func admitLegacyRegistryAuthority(raw any) (*registryAuthority, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("release authority registryAuthority must be an object or null")
	}
	if err := admit.KnownKeys(record, []string{"consumerMigrationPath", "packageScope", "provenanceMode", "publishWorkflowPath", "registryKind", "registryUrl", "releaseTagPattern", "rollbackPolicy", "visibility"}, "release authority registryAuthority"); err != nil {
		return nil, err
	}
	registryKind, err := admit.Enum(record["registryKind"], registryKinds, "registryAuthority registryKind")
	if err != nil {
		return nil, err
	}
	packageScope, err := optionalPackageScope(record["packageScope"], registryKind, "registryAuthority packageScope")
	if err != nil {
		return nil, err
	}
	provenanceMode, err := admit.Enum(record["provenanceMode"], provenanceModes, "registryAuthority provenanceMode")
	if err != nil {
		return nil, err
	}
	registryURL, err := httpsURL(record["registryUrl"], "registryAuthority registryUrl")
	if err != nil {
		return nil, err
	}
	visibility, err := admit.Enum(record["visibility"], releaseVisibilities, "registryAuthority visibility")
	if err != nil {
		return nil, err
	}
	publishWorkflowPath, err := pathField(record["publishWorkflowPath"], "registryAuthority publishWorkflowPath")
	if err != nil {
		return nil, err
	}
	releaseTagPattern, err := text(record["releaseTagPattern"], "registryAuthority releaseTagPattern")
	if err != nil {
		return nil, err
	}
	consumerMigrationPath, err := text(record["consumerMigrationPath"], "registryAuthority consumerMigrationPath")
	if err != nil {
		return nil, err
	}
	rollbackPolicy, err := text(record["rollbackPolicy"], "registryAuthority rollbackPolicy")
	if err != nil {
		return nil, err
	}
	publishAuthorityMode := "npm_provenance"
	if provenanceMode == "trusted_publishing" {
		publishAuthorityMode = "npm_trusted_publishing"
	}
	return &registryAuthority{
		ConsumerMigrationPath: consumerMigrationPath,
		PackageScope:          packageScope,
		PublishAuthorityMode:  publishAuthorityMode,
		PublishWorkflowPath:   publishWorkflowPath,
		RegistryKind:          registryKind,
		RegistryURL:           registryURL,
		ReleaseTagPattern:     releaseTagPattern,
		RollbackPolicy:        rollbackPolicy,
		SourceRepository:      nil,
		Visibility:            visibility,
	}, nil
}

func admitRegistryAuthorityV2(raw any) (*registryAuthority, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("release authority registryAuthority must be an object or null")
	}
	if err := admit.KnownKeys(record, []string{"consumerMigrationPath", "packageScope", "publishAuthorityMode", "publishWorkflowPath", "registryKind", "registryUrl", "releaseTagPattern", "rollbackPolicy", "sourceRepository", "visibility"}, "release authority registryAuthority"); err != nil {
		return nil, err
	}
	registryKind, err := admit.Enum(record["registryKind"], registryKinds, "registryAuthority registryKind")
	if err != nil {
		return nil, err
	}
	packageScope, err := optionalPackageScope(record["packageScope"], registryKind, "registryAuthority packageScope")
	if err != nil {
		return nil, err
	}
	registryURL, err := httpsURL(record["registryUrl"], "registryAuthority registryUrl")
	if err != nil {
		return nil, err
	}
	visibility, err := admit.Enum(record["visibility"], releaseVisibilities, "registryAuthority visibility")
	if err != nil {
		return nil, err
	}
	publishAuthorityMode, err := admit.Enum(record["publishAuthorityMode"], publisherAuthorityModes, "registryAuthority publishAuthorityMode")
	if err != nil {
		return nil, err
	}
	publishWorkflowPath, err := pathField(record["publishWorkflowPath"], "registryAuthority publishWorkflowPath")
	if err != nil {
		return nil, err
	}
	releaseTagPattern, err := text(record["releaseTagPattern"], "registryAuthority releaseTagPattern")
	if err != nil {
		return nil, err
	}
	sourceRepository, err := admitSourceRepository(record["sourceRepository"])
	if err != nil {
		return nil, err
	}
	consumerMigrationPath, err := text(record["consumerMigrationPath"], "registryAuthority consumerMigrationPath")
	if err != nil {
		return nil, err
	}
	rollbackPolicy, err := text(record["rollbackPolicy"], "registryAuthority rollbackPolicy")
	if err != nil {
		return nil, err
	}
	return &registryAuthority{
		ConsumerMigrationPath: consumerMigrationPath,
		PackageScope:          packageScope,
		PublishAuthorityMode:  publishAuthorityMode,
		PublishWorkflowPath:   publishWorkflowPath,
		RegistryKind:          registryKind,
		RegistryURL:           registryURL,
		ReleaseTagPattern:     releaseTagPattern,
		RollbackPolicy:        rollbackPolicy,
		SourceRepository:      &sourceRepository,
		Visibility:            visibility,
	}, nil
}

func admitSourceRepository(raw any) (sourceRepository, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return sourceRepository{}, fmt.Errorf("release authority sourceRepository must be an object")
	}
	if err := admit.KnownKeys(record, []string{"name", "owner", "url", "visibility"}, "release authority sourceRepository"); err != nil {
		return sourceRepository{}, err
	}
	owner, err := text(record["owner"], "sourceRepository owner")
	if err != nil {
		return sourceRepository{}, err
	}
	owner = strings.ToLower(owner)
	if !githubOwnerPattern.MatchString(owner) {
		return sourceRepository{}, fmt.Errorf("sourceRepository owner must be a GitHub owner name")
	}
	name, err := text(record["name"], "sourceRepository name")
	if err != nil {
		return sourceRepository{}, err
	}
	name = strings.ToLower(name)
	if !githubRepositoryNamePattern.MatchString(name) {
		return sourceRepository{}, fmt.Errorf("sourceRepository name must be a GitHub repository name")
	}
	visibility, err := admit.Enum(record["visibility"], sourceRepositoryVisibilities, "sourceRepository visibility")
	if err != nil {
		return sourceRepository{}, err
	}
	url, err := httpsURL(record["url"], "sourceRepository url")
	if err != nil {
		return sourceRepository{}, err
	}
	expectedURL := fmt.Sprintf("https://github.com/%s/%s", owner, name)
	if url != expectedURL {
		return sourceRepository{}, fmt.Errorf("sourceRepository url must match owner and name")
	}
	return sourceRepository{
		Name:       name,
		Owner:      owner,
		URL:        url,
		Visibility: visibility,
	}, nil
}

func admitRollback(raw any) (rollback, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return rollback{}, fmt.Errorf("release authority rollback must be an object")
	}
	if err := admit.KnownKeys(record, []string{"owner", "procedure", "versionPin"}, "release authority rollback"); err != nil {
		return rollback{}, err
	}
	owner, err := text(record["owner"], "rollback owner")
	if err != nil {
		return rollback{}, err
	}
	procedure, err := text(record["procedure"], "rollback procedure")
	if err != nil {
		return rollback{}, err
	}
	versionPin, err := text(record["versionPin"], "rollback versionPin")
	if err != nil {
		return rollback{}, err
	}
	return rollback{Owner: owner, Procedure: procedure, VersionPin: versionPin}, nil
}

func enforceChannelRules(input admittedInput, failures *[]string) {
	switch input.Channel {
	case string(releasechannel.TarballPilot):
		if input.RegistryAuthority != nil {
			*failures = append(*failures, "tarball_pilot channel must not declare registryAuthority")
		}
		if !input.Package.ManifestPrivate {
			*failures = append(*failures, "tarball_pilot channel requires package manifestPrivate=true")
		}
		if input.Package.PublishConfigRegistry != nil {
			*failures = append(*failures, "tarball_pilot channel must not declare publishConfigRegistry")
		}
		if input.ConsumerContract.DependencyPinType != "file_tarball" {
			*failures = append(*failures, "tarball_pilot channel requires file_tarball dependency pin")
		}
		if input.ArtifactProof.RegistryPublishDryRunID != nil {
			*failures = append(*failures, "tarball_pilot channel must not declare registryPublishDryRunProofId")
		}
		enforceTarballIdentity(input, failures)
		return
	case string(releasechannel.RegistryRelease):
	default:
		definition := releasechannel.Must(releasechannel.ID(input.Channel))
		*failures = append(*failures, fmt.Sprintf("%s channel is known, but release-authority owns only tarball_pilot and npm registry_release; use %s evidence for this channel", input.Channel, definition.AuthorityValidator))
		return
	}
	if input.RegistryAuthority == nil {
		*failures = append(*failures, "registry_release channel requires registryAuthority")
		return
	}
	if input.SchemaVersion >= 3 && input.ArtifactProof.RegistryPublishDryRunID == nil {
		*failures = append(*failures, "registry_release schemaVersion 3 requires registryPublishDryRunProofId")
	}
	if input.Package.ManifestPrivate {
		*failures = append(*failures, "registry_release channel requires package manifestPrivate=false")
	}
	if input.Package.PublishConfigRegistry == nil {
		*failures = append(*failures, "registry_release channel requires publishConfigRegistry")
	} else if *input.Package.PublishConfigRegistry != input.RegistryAuthority.RegistryURL {
		*failures = append(*failures, "registry_release publishConfigRegistry must match registryAuthority registryUrl")
	}
	if input.ConsumerContract.DependencyPinType != "registry_version" {
		*failures = append(*failures, "registry_release channel requires registry_version dependency pin")
	}
	declaredPackageScope := ""
	if strings.HasPrefix(input.Package.Name, "@") {
		declaredPackageScope = input.Package.Name[:strings.Index(input.Package.Name, "/")]
	}
	if declaredPackageScope != input.RegistryAuthority.PackageScope {
		*failures = append(*failures, "registry_release package name must match registryAuthority packageScope")
	}
	enforceRegistryKindURL(*input.RegistryAuthority, failures)
	enforceRegistryPublisherAuthority(*input.RegistryAuthority, failures)
}

func enforceTarballIdentity(input admittedInput, failures *[]string) {
	tarballName := fmt.Sprintf("%s-%s.tgz", strings.Replace(strings.Replace(input.Package.Name, "@", "", 1), "/", "-", 1), input.Package.Version)
	if !strings.HasSuffix(input.Package.ArtifactPath, "/"+tarballName) && input.Package.ArtifactPath != tarballName {
		*failures = append(*failures, "tarball_pilot artifactPath must end with the package name and version tarball filename")
	}
	if !strings.HasSuffix(input.Package.PackManifestPath, "npm-pack.json") {
		*failures = append(*failures, "tarball_pilot packManifestPath must point to npm-pack.json")
	}
	if !strings.HasPrefix(input.Rollback.VersionPin, "file:") {
		*failures = append(*failures, "tarball_pilot rollback versionPin must be an exact file: tarball pin")
	} else if !strings.HasSuffix(input.Rollback.VersionPin, tarballName) {
		*failures = append(*failures, "tarball_pilot rollback versionPin must reference the same package tarball filename")
	}
}

func enforceRegistryKindURL(authority registryAuthority, failures *[]string) {
	if authority.RegistryKind == "npm_registry" && authority.RegistryURL != npmRegistryURL {
		*failures = append(*failures, "npm_registry authority must use https://registry.npmjs.org")
	}
	if authority.RegistryKind == "github_packages" && authority.RegistryURL != githubPackagesRegistryURL {
		*failures = append(*failures, "github_packages authority must use https://npm.pkg.github.com")
	}
}

func enforceRegistryPublisherAuthority(authority registryAuthority, failures *[]string) {
	if authority.RegistryKind == "github_packages" {
		if authority.Visibility == "restricted" {
			*failures = append(*failures, "github_packages authority must not use npm restricted visibility")
		}
		if authority.PublishAuthorityMode != "github_actions_github_token" {
			*failures = append(*failures, "github_packages authority requires github_actions_github_token publish authority")
		}
		if authority.SourceRepository == nil {
			return
		}
		requiredScope := "@" + authority.SourceRepository.Owner
		if authority.PackageScope != requiredScope {
			*failures = append(*failures, "github_packages packageScope must match the source repository owner namespace")
		}
		return
	}
	if authority.PublishAuthorityMode == "github_actions_github_token" {
		*failures = append(*failures, "npm_registry authority must not use github_actions_github_token publish authority")
	}
	if authority.PublishAuthorityMode == "npm_provenance" &&
		(authority.Visibility != "public" || authority.SourceRepository == nil || authority.SourceRepository.Visibility != "public") {
		*failures = append(*failures, "npm provenance authority requires public source repository proof and public package visibility")
	}
	if authority.PublishAuthorityMode == "npm_trusted_publishing" && authority.Visibility != "public" {
		*failures = append(*failures, "npm trusted publishing authority requires public package visibility")
	}
}

func artifactProofDiagnostic(proof artifactProof) map[string]any {
	value := map[string]any{
		"cliSmokeProofId":               proof.CLISmokeProofID,
		"deepImportRejectionProofId":    proof.DeepImportRejectionProofID,
		"outsideConsumerInstallProofId": proof.OutsideConsumerInstallProof,
		"packageArtifactCommandId":      proof.PackageArtifactCommandID,
		"packDryRunCommandId":           proof.PackDryRunCommandID,
		"binarySmokeProofId":            proof.BinarySmokeProofID,
	}
	if proof.RegistryPublishDryRunID != nil {
		value["registryPublishDryRunProofId"] = *proof.RegistryPublishDryRunID
	}
	return value
}

func registryAuthorityDiagnostic(authority *registryAuthority) map[string]any {
	if authority == nil {
		return map[string]any{"declared": false}
	}
	var source any
	if authority.SourceRepository == nil {
		source = nil
	} else {
		source = map[string]any{
			"name":       authority.SourceRepository.Name,
			"owner":      authority.SourceRepository.Owner,
			"visibility": authority.SourceRepository.Visibility,
		}
	}
	return map[string]any{
		"declared":             true,
		"packageScope":         authority.PackageScope,
		"publishAuthorityMode": authority.PublishAuthorityMode,
		"publishWorkflowPath":  authority.PublishWorkflowPath,
		"registryKind":         authority.RegistryKind,
		"registryUrl":          authority.RegistryURL,
		"sourceRepository":     source,
		"visibility":           authority.Visibility,
	}
}

func nullableHTTPSURL(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := httpsURL(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func httpsURL(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if !httpsURLPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be an HTTPS URL", context)
	}
	return strings.TrimRight(value, "/"), nil
}

func optionalPackageScope(raw any, registryKind string, context string) (string, error) {
	if value, ok := raw.(string); ok && value == "" {
		if registryKind == "npm_registry" {
			return "", nil
		}
		return "", fmt.Errorf("%s must be an npm package scope for github_packages", context)
	}
	packageScope, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if !packageScopePattern.MatchString(packageScope) {
		return "", fmt.Errorf("%s must be an npm package scope", context)
	}
	return packageScope, nil
}

func pathField(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func sortedText(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a non-empty string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		textValue, err := text(value, context)
		if err != nil {
			return nil, fmt.Errorf("%s must be a non-empty string array", context)
		}
		result = append(result, textValue)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
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

func ruleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{
			{
				RuleID:      "proofkit.release-authority.accepted",
				Status:      "passed",
				Message:     "release authority is explicit and bounded to the selected channel",
				Diagnostics: []report.Diagnostic{},
			},
		}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.release-authority.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}
