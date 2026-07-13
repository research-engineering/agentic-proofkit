package externalconsumer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

const reportKind = "proofkit.external-consumer"
const expectedSourceRepository = "research-engineering/agentic-proofkit"

var boundaryNonClaims = []string{
	"External consumer does not publish packages, fetch registries, hold credentials, approve rollout, or prove production readiness.",
	"External consumer validates caller-owned tarball pilot evidence only.",
}

var (
	hexSHA1Pattern       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexSHA256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	decimalTextPattern   = regexp.MustCompile(`^\d+$`)
	packageVersionRegexp = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

var requiredPackedFiles = []string{
	"AGENTS.md",
	"CONTRIBUTING.md",
	"LICENSE",
	"NON_CLAIMS.md",
	"README.md",
	"SECURITY.md",
	"dist/agentic-proofkit",
	"package.json",
	"proofkit/cli-contract.v2.json",
	"proofkit/receipt-producer-policy.json",
	"proofkit/requirement-bindings.json",
	"proofkit/witness-plan.json",
}

var forbiddenPackedFiles = []string{
	"bun.lock",
	"dist/cli.js",
	"dist/index.js",
	"src/index.ts",
	"test/public-api.test.ts",
	"tsconfig.json",
}

type input struct {
	NonClaims              []string
	NPMSHASum              string
	NPMIntegrity           string
	PackageName            string
	PackageVersion         string
	PackMetadataPath       string
	PackMetadataSHA256     string
	PilotID                string
	ReleaseAuthority       releaseauthority.ConsumerProjectionAdmission
	Rollback               rollback
	BinarySmokeProbeRuleID string
	SourceArtifactName     string
	SourceCommit           string
	SourceRepository       string
	SourceWorkflowRun      string
	TarballPath            string
	TarballSHA256          string
	WitnessPlan            witnessPlan
}

type witnessPlan struct {
	Commands   []any
	Vocabulary any
}

type rollback struct {
	DependencyRemoval               string
	LocalWorkspaceFallbackPreserved bool
}

type tarballEvidence struct {
	Path   string
	SHA1   string
	SHA256 string
}

type packMetadataEvidence struct {
	Path    string
	Records []packMetadataRecord
	SHA256  string
}

type packMetadataRecord struct {
	Filename  string
	Files     []packMetadataFile
	Integrity string
	Name      string
	SHASum    string
	Version   string
}

type packMetadataFile struct {
	Path string
}

type consumerProof struct {
	CLIWitnessPlanOutputSHA256   string
	DependencySpec               string
	FrozenLockContainsPackage    bool
	FrozenLockContainsTarball    bool
	FrozenLockUsesWorkspace      bool
	InstallLockContainsPackage   bool
	InstallLockContainsTarball   bool
	InstallLockUsesWorkspace     bool
	ReleaseAuthorityOutputSHA256 string
	ReleaseAuthorityReportKind   string
	ReleaseAuthorityState        string
	RollbackLockContainsPackage  bool
	BinarySmokeOutputSHA256      string
	TempConsumerLocation         string
}

type evidence struct {
	ConsumerProof *consumerProof
	PackMetadata  packMetadataEvidence
	Tarball       tarballEvidence
}

type reportInput struct {
	Evidence evidence
	Input    input
}

func Build(raw any) (report.Record, int, error) {
	admitted, err := admitReportInput(raw)
	if err != nil {
		return failedAdmissionReport(err), 1, nil
	}
	failures := []string{}
	failures = append(failures, inputFailures(admitted.Input)...)
	failures = append(failures, witnessPlanFailures(admitted.Input)...)
	failures = append(failures, artifactEvidenceFailures(admitted.Input, admitted.Evidence)...)
	failures = append(failures, packMetadataFailures(admitted.Input, admitted.Evidence.PackMetadata)...)
	failures = append(failures, releaseAuthorityFailures(admitted.Input)...)
	failures = append(failures, consumerProofFailures(admitted.Input, admitted.Evidence.ConsumerProof)...)

	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      admitted.Input.PilotID,
		State:         state,
		Summary: map[string]any{
			"consumerProofExecuted":           admitted.Evidence.ConsumerProof != nil,
			"localWorkspaceFallbackPreserved": admitted.Input.Rollback.LocalWorkspaceFallbackPreserved,
			"packageName":                     admitted.Input.PackageName,
			"packageVersion":                  admitted.Input.PackageVersion,
			"pilotMode":                       "non_blocking",
			"provenanceArtifactNameHint":      admitted.Input.SourceArtifactName,
			"provenanceCommitHint":            admitted.Input.SourceCommit,
			"provenanceRepositoryHint":        admitted.Input.SourceRepository,
			"provenanceWorkflowRunHint":       admitted.Input.SourceWorkflowRun,
			"releaseAuthorityChannel":         releaseAuthorityChannel(admitted.Input),
			"tarballPath":                     admitted.Input.TarballPath,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "artifactEvidence", Value: map[string]any{
				"npmIntegrity":       admitted.Input.NPMIntegrity,
				"npmShasum":          admitted.Input.NPMSHASum,
				"packMetadataPath":   admitted.Input.PackMetadataPath,
				"packMetadataSha256": admitted.Input.PackMetadataSHA256,
				"tarballPath":        admitted.Input.TarballPath,
				"tarballSha256":      admitted.Input.TarballSHA256,
			}},
			{Key: "consumerProof", Value: consumerProofDiagnostic(admitted.Evidence.ConsumerProof)},
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
		return reportInput{}, fmt.Errorf("proofkit external-consumer report input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"evidence", "input", "schemaVersion"}, "proofkit external-consumer report input"); err != nil {
		return reportInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return reportInput{}, fmt.Errorf("proofkit external-consumer report input schemaVersion must be 1")
	}
	inputValue, err := admitInput(record["input"])
	if err != nil {
		return reportInput{}, err
	}
	evidenceValue, err := admitEvidence(record["evidence"])
	if err != nil {
		return reportInput{}, err
	}
	return reportInput{Evidence: evidenceValue, Input: inputValue}, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("proofkit external-consumer input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"npmIntegrity", "npmShasum", "nonClaims", "packageName", "packageVersion", "packMetadataPath", "packMetadataSha256", "pilotId", "pilotMode", "releaseAuthorityInput", "rollback", "binarySmokeProbeRuleId", "schemaVersion", "sourceArtifactName", "sourceCommit", "sourceRepository", "sourceWorkflowRun", "tarballPath", "tarballSha256", "witnessPlan"}, "proofkit external-consumer input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("proofkit external-consumer input schemaVersion must be 1")
	}
	if record["pilotMode"] != "non_blocking" {
		return input{}, fmt.Errorf("proofkit external-consumer input pilotMode must be non_blocking")
	}
	packageNameValue, err := packageName(record["packageName"])
	if err != nil {
		return input{}, err
	}
	packageVersionValue, err := versionText(record["packageVersion"], "proofkit external-consumer packageVersion")
	if err != nil {
		return input{}, err
	}
	tarballPath, err := pathText(record["tarballPath"], "proofkit external-consumer tarballPath")
	if err != nil {
		return input{}, err
	}
	packMetadataPath, err := pathText(record["packMetadataPath"], "proofkit external-consumer packMetadataPath")
	if err != nil {
		return input{}, err
	}
	pilotID, err := admit.RuleID(record["pilotId"], "proofkit external-consumer pilotId")
	if err != nil {
		return input{}, err
	}
	binarySmokeProbeRuleID, err := admit.RuleID(record["binarySmokeProbeRuleId"], "proofkit external-consumer binarySmokeProbeRuleId")
	if err != nil {
		return input{}, err
	}
	witnessPlanValue, err := admitWitnessPlan(record["witnessPlan"])
	if err != nil {
		return input{}, err
	}
	rollbackValue, err := admitRollback(record["rollback"])
	if err != nil {
		return input{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "proofkit external-consumer nonClaims")
	if err != nil {
		return input{}, err
	}
	sourceRepository, err := text(record["sourceRepository"], "proofkit external-consumer sourceRepository")
	if err != nil {
		return input{}, err
	}
	sourceCommit, err := text(record["sourceCommit"], "proofkit external-consumer sourceCommit")
	if err != nil {
		return input{}, err
	}
	sourceWorkflowRun, err := text(record["sourceWorkflowRun"], "proofkit external-consumer sourceWorkflowRun")
	if err != nil {
		return input{}, err
	}
	sourceArtifactName, err := text(record["sourceArtifactName"], "proofkit external-consumer sourceArtifactName")
	if err != nil {
		return input{}, err
	}
	tarballSHA256, err := text(record["tarballSha256"], "proofkit external-consumer tarballSha256")
	if err != nil {
		return input{}, err
	}
	packMetadataSHA256, err := text(record["packMetadataSha256"], "proofkit external-consumer packMetadataSha256")
	if err != nil {
		return input{}, err
	}
	npmIntegrity, err := text(record["npmIntegrity"], "proofkit external-consumer npmIntegrity")
	if err != nil {
		return input{}, err
	}
	npmSHASum, err := text(record["npmShasum"], "proofkit external-consumer npmShasum")
	if err != nil {
		return input{}, err
	}
	return input{
		NonClaims:              nonClaims,
		NPMSHASum:              npmSHASum,
		NPMIntegrity:           npmIntegrity,
		PackageName:            packageNameValue,
		PackageVersion:         packageVersionValue,
		PackMetadataPath:       packMetadataPath,
		PackMetadataSHA256:     packMetadataSHA256,
		PilotID:                pilotID,
		ReleaseAuthority:       releaseauthority.AdmitConsumerProjection(record["releaseAuthorityInput"]),
		Rollback:               rollbackValue,
		BinarySmokeProbeRuleID: binarySmokeProbeRuleID,
		SourceArtifactName:     sourceArtifactName,
		SourceCommit:           sourceCommit,
		SourceRepository:       sourceRepository,
		SourceWorkflowRun:      sourceWorkflowRun,
		TarballPath:            tarballPath,
		TarballSHA256:          tarballSHA256,
		WitnessPlan:            witnessPlanValue,
	}, nil
}

func admitWitnessPlan(raw any) (witnessPlan, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return witnessPlan{}, fmt.Errorf("proofkit external-consumer witnessPlan must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commands", "vocabulary"}, "proofkit external-consumer witnessPlan"); err != nil {
		return witnessPlan{}, err
	}
	if _, ok := record["vocabulary"].(map[string]any); !ok {
		return witnessPlan{}, fmt.Errorf("proofkit external-consumer witnessPlan.vocabulary must be an object")
	}
	commands, ok := record["commands"].([]any)
	if !ok || len(commands) == 0 {
		return witnessPlan{}, fmt.Errorf("proofkit external-consumer witnessPlan.commands must be a non-empty array")
	}
	return witnessPlan{Commands: commands, Vocabulary: record["vocabulary"]}, nil
}

func admitRollback(raw any) (rollback, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return rollback{}, fmt.Errorf("proofkit external-consumer rollback must be an object")
	}
	if err := admit.KnownKeys(record, []string{"dependencyRemoval", "localWorkspaceFallbackPreserved"}, "proofkit external-consumer rollback"); err != nil {
		return rollback{}, err
	}
	if record["dependencyRemoval"] != "temp_consumer_package_and_lockfile" {
		return rollback{}, fmt.Errorf("proofkit external-consumer rollback.dependencyRemoval must be temp_consumer_package_and_lockfile")
	}
	localWorkspaceFallbackPreserved, err := admit.Bool(record["localWorkspaceFallbackPreserved"], "proofkit external-consumer rollback.localWorkspaceFallbackPreserved")
	if err != nil {
		return rollback{}, err
	}
	if !localWorkspaceFallbackPreserved {
		return rollback{}, fmt.Errorf("proofkit external-consumer rollback.localWorkspaceFallbackPreserved must be true")
	}
	return rollback{DependencyRemoval: "temp_consumer_package_and_lockfile", LocalWorkspaceFallbackPreserved: true}, nil
}

func admitEvidence(raw any) (evidence, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return evidence{}, fmt.Errorf("proofkit external-consumer evidence must be an object")
	}
	if err := admit.KnownKeys(record, []string{"consumerProof", "packMetadata", "schemaVersion", "tarball"}, "proofkit external-consumer evidence"); err != nil {
		return evidence{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return evidence{}, fmt.Errorf("proofkit external-consumer evidence schemaVersion must be 1")
	}
	if _, ok := record["consumerProof"]; !ok {
		return evidence{}, fmt.Errorf("proofkit external-consumer proof evidence must be an object or null")
	}
	tarball, err := admitTarballEvidence(record["tarball"])
	if err != nil {
		return evidence{}, err
	}
	packMetadata, err := admitPackMetadataEvidence(record["packMetadata"])
	if err != nil {
		return evidence{}, err
	}
	var consumerProofValue *consumerProof
	if record["consumerProof"] != nil {
		value, err := admitConsumerProof(record["consumerProof"])
		if err != nil {
			return evidence{}, err
		}
		consumerProofValue = &value
	}
	return evidence{ConsumerProof: consumerProofValue, PackMetadata: packMetadata, Tarball: tarball}, nil
}

func admitTarballEvidence(raw any) (tarballEvidence, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return tarballEvidence{}, fmt.Errorf("proofkit external-consumer tarball evidence must be an object")
	}
	if err := admit.KnownKeys(record, []string{"path", "sha1", "sha256"}, "proofkit external-consumer tarball evidence"); err != nil {
		return tarballEvidence{}, err
	}
	path, err := pathText(record["path"], "tarball evidence path")
	if err != nil {
		return tarballEvidence{}, err
	}
	sha1, err := text(record["sha1"], "tarball evidence sha1")
	if err != nil {
		return tarballEvidence{}, err
	}
	sha256, err := text(record["sha256"], "tarball evidence sha256")
	if err != nil {
		return tarballEvidence{}, err
	}
	return tarballEvidence{Path: path, SHA1: sha1, SHA256: sha256}, nil
}

func admitPackMetadataEvidence(raw any) (packMetadataEvidence, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return packMetadataEvidence{}, fmt.Errorf("proofkit external-consumer pack metadata evidence must be an object")
	}
	if err := admit.KnownKeys(record, []string{"path", "records", "sha256"}, "proofkit external-consumer pack metadata evidence"); err != nil {
		return packMetadataEvidence{}, err
	}
	path, err := pathText(record["path"], "pack metadata evidence path")
	if err != nil {
		return packMetadataEvidence{}, err
	}
	sha256Value, err := text(record["sha256"], "pack metadata evidence sha256")
	if err != nil {
		return packMetadataEvidence{}, err
	}
	rawRecords, ok := record["records"].([]any)
	if !ok {
		return packMetadataEvidence{}, fmt.Errorf("proofkit external-consumer pack metadata records must be an array")
	}
	records := make([]packMetadataRecord, 0, len(rawRecords))
	for _, rawRecord := range rawRecords {
		record, err := admitPackMetadataRecord(rawRecord)
		if err != nil {
			return packMetadataEvidence{}, err
		}
		records = append(records, record)
	}
	return packMetadataEvidence{Path: path, Records: records, SHA256: sha256Value}, nil
}

func admitPackMetadataRecord(raw any) (packMetadataRecord, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return packMetadataRecord{}, fmt.Errorf("proofkit external-consumer pack metadata record must be an object")
	}
	if err := admit.KnownKeys(record, []string{"filename", "files", "integrity", "name", "shasum", "version"}, "proofkit external-consumer pack metadata record"); err != nil {
		return packMetadataRecord{}, err
	}
	filesRaw, ok := record["files"].([]any)
	if !ok {
		return packMetadataRecord{}, fmt.Errorf("proofkit external-consumer pack metadata files must be an array")
	}
	files := make([]packMetadataFile, 0, len(filesRaw))
	for _, rawFile := range filesRaw {
		file, err := admitPackMetadataFile(rawFile)
		if err != nil {
			return packMetadataRecord{}, err
		}
		files = append(files, file)
	}
	name, err := text(record["name"], "pack metadata name")
	if err != nil {
		return packMetadataRecord{}, err
	}
	version, err := text(record["version"], "pack metadata version")
	if err != nil {
		return packMetadataRecord{}, err
	}
	integrity, err := text(record["integrity"], "pack metadata integrity")
	if err != nil {
		return packMetadataRecord{}, err
	}
	shasum, err := text(record["shasum"], "pack metadata shasum")
	if err != nil {
		return packMetadataRecord{}, err
	}
	filename, err := text(record["filename"], "pack metadata filename")
	if err != nil {
		return packMetadataRecord{}, err
	}
	return packMetadataRecord{Filename: filename, Files: files, Integrity: integrity, Name: name, SHASum: shasum, Version: version}, nil
}

func admitPackMetadataFile(raw any) (packMetadataFile, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return packMetadataFile{}, fmt.Errorf("proofkit external-consumer pack metadata file must be an object")
	}
	if err := admit.KnownKeys(record, []string{"path"}, "proofkit external-consumer pack metadata file"); err != nil {
		return packMetadataFile{}, err
	}
	path, err := pathText(record["path"], "pack metadata file path")
	if err != nil {
		return packMetadataFile{}, err
	}
	return packMetadataFile{Path: path}, nil
}

func admitConsumerProof(raw any) (consumerProof, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return consumerProof{}, fmt.Errorf("proofkit external-consumer proof evidence must be an object or null")
	}
	if err := admit.KnownKeys(record, []string{"cliWitnessPlanOutputSha256", "dependencySpec", "frozenLockContainsPackage", "frozenLockContainsTarball", "frozenLockUsesWorkspace", "installLockContainsPackage", "installLockContainsTarball", "installLockUsesWorkspace", "releaseAuthorityOutputSha256", "releaseAuthorityReportKind", "releaseAuthorityState", "rollbackLockContainsPackage", "binarySmokeOutputSha256", "tempConsumerLocation"}, "proofkit external-consumer proof evidence"); err != nil {
		return consumerProof{}, err
	}
	tempConsumerLocation, err := text(record["tempConsumerLocation"], "consumer proof tempConsumerLocation")
	if err != nil {
		return consumerProof{}, err
	}
	if tempConsumerLocation != "os-temp" {
		return consumerProof{}, fmt.Errorf("proofkit external-consumer tempConsumerLocation must be os-temp")
	}
	dependencySpec, err := text(record["dependencySpec"], "consumer proof dependencySpec")
	if err != nil {
		return consumerProof{}, err
	}
	binarySmokeOutputSHA256, err := text(record["binarySmokeOutputSha256"], "consumer proof binarySmokeOutputSha256")
	if err != nil {
		return consumerProof{}, err
	}
	cliWitnessPlanOutputSHA256, err := text(record["cliWitnessPlanOutputSha256"], "consumer proof cliWitnessPlanOutputSha256")
	if err != nil {
		return consumerProof{}, err
	}
	releaseAuthorityReportKind, err := text(record["releaseAuthorityReportKind"], "consumer proof releaseAuthorityReportKind")
	if err != nil {
		return consumerProof{}, err
	}
	releaseAuthorityState, err := text(record["releaseAuthorityState"], "consumer proof releaseAuthorityState")
	if err != nil {
		return consumerProof{}, err
	}
	releaseAuthorityOutputSHA256, err := text(record["releaseAuthorityOutputSha256"], "consumer proof releaseAuthorityOutputSha256")
	if err != nil {
		return consumerProof{}, err
	}
	installLockContainsPackage, err := admit.Bool(record["installLockContainsPackage"], "consumer proof installLockContainsPackage")
	if err != nil {
		return consumerProof{}, err
	}
	installLockUsesWorkspace, err := admit.Bool(record["installLockUsesWorkspace"], "consumer proof installLockUsesWorkspace")
	if err != nil {
		return consumerProof{}, err
	}
	installLockContainsTarball, err := admit.Bool(record["installLockContainsTarball"], "consumer proof installLockContainsTarball")
	if err != nil {
		return consumerProof{}, err
	}
	frozenLockContainsPackage, err := admit.Bool(record["frozenLockContainsPackage"], "consumer proof frozenLockContainsPackage")
	if err != nil {
		return consumerProof{}, err
	}
	frozenLockUsesWorkspace, err := admit.Bool(record["frozenLockUsesWorkspace"], "consumer proof frozenLockUsesWorkspace")
	if err != nil {
		return consumerProof{}, err
	}
	frozenLockContainsTarball, err := admit.Bool(record["frozenLockContainsTarball"], "consumer proof frozenLockContainsTarball")
	if err != nil {
		return consumerProof{}, err
	}
	rollbackLockContainsPackage, err := admit.Bool(record["rollbackLockContainsPackage"], "consumer proof rollbackLockContainsPackage")
	if err != nil {
		return consumerProof{}, err
	}
	return consumerProof{
		CLIWitnessPlanOutputSHA256:   cliWitnessPlanOutputSHA256,
		DependencySpec:               dependencySpec,
		FrozenLockContainsPackage:    frozenLockContainsPackage,
		FrozenLockContainsTarball:    frozenLockContainsTarball,
		FrozenLockUsesWorkspace:      frozenLockUsesWorkspace,
		InstallLockContainsPackage:   installLockContainsPackage,
		InstallLockContainsTarball:   installLockContainsTarball,
		InstallLockUsesWorkspace:     installLockUsesWorkspace,
		ReleaseAuthorityOutputSHA256: releaseAuthorityOutputSHA256,
		ReleaseAuthorityReportKind:   releaseAuthorityReportKind,
		ReleaseAuthorityState:        releaseAuthorityState,
		RollbackLockContainsPackage:  rollbackLockContainsPackage,
		BinarySmokeOutputSHA256:      binarySmokeOutputSHA256,
		TempConsumerLocation:         "os-temp",
	}, nil
}

func inputFailures(input input) []string {
	failures := []string{}
	if !hexSHA1Pattern.MatchString(input.SourceCommit) {
		failures = append(failures, "sourceCommit must be a 40-character lowercase hex commit")
	}
	if !decimalTextPattern.MatchString(input.SourceWorkflowRun) {
		failures = append(failures, "sourceWorkflowRun must be decimal workflow run id text")
	}
	if input.SourceRepository != expectedSourceRepository {
		failures = append(failures, fmt.Sprintf("sourceRepository must be %s", expectedSourceRepository))
	}
	if input.SourceArtifactName != "agentic-proofkit-npm-package-"+input.SourceCommit {
		failures = append(failures, "sourceArtifactName must bind to sourceCommit")
	}
	if !hexSHA256Pattern.MatchString(input.TarballSHA256) {
		failures = append(failures, "tarballSha256 must be lowercase sha256 hex")
	}
	if !hexSHA256Pattern.MatchString(input.PackMetadataSHA256) {
		failures = append(failures, "packMetadataSha256 must be lowercase sha256 hex")
	}
	if !hexSHA1Pattern.MatchString(input.NPMSHASum) {
		failures = append(failures, "npmShasum must be lowercase sha1 hex")
	}
	return failures
}

func witnessPlanFailures(input input) []string {
	if _, err := expectedWitnessPlan(input); err != nil {
		return []string{"witnessPlan: " + err.Error()}
	}
	return []string{}
}

func artifactEvidenceFailures(input input, evidence evidence) []string {
	failures := []string{}
	if evidence.Tarball.Path != input.TarballPath {
		failures = append(failures, "tarball evidence path must match input tarballPath")
	}
	if evidence.Tarball.SHA256 != input.TarballSHA256 {
		failures = append(failures, "tarball evidence sha256 must match input tarballSha256")
	}
	if evidence.Tarball.SHA1 != input.NPMSHASum {
		failures = append(failures, "tarball evidence sha1 must match input npmShasum")
	}
	if evidence.PackMetadata.Path != input.PackMetadataPath {
		failures = append(failures, "pack metadata evidence path must match input packMetadataPath")
	}
	if evidence.PackMetadata.SHA256 != input.PackMetadataSHA256 {
		failures = append(failures, "pack metadata evidence sha256 must match input packMetadataSha256")
	}
	return failures
}

func packMetadataFailures(input input, evidence packMetadataEvidence) []string {
	if len(evidence.Records) != 1 {
		return []string{"npm pack metadata must describe exactly one package"}
	}
	record := evidence.Records[0]
	failures := []string{}
	if record.Name != input.PackageName {
		failures = append(failures, "npm pack metadata name must match packageName")
	}
	if record.Version != input.PackageVersion {
		failures = append(failures, "npm pack metadata version must match packageVersion")
	}
	if record.Integrity != input.NPMIntegrity {
		failures = append(failures, "npm pack metadata integrity must match npmIntegrity")
	}
	if record.SHASum != input.NPMSHASum {
		failures = append(failures, "npm pack metadata shasum must match npmShasum")
	}
	if record.Filename != packageTarballName(input) {
		failures = append(failures, "npm pack metadata filename must match package name and version")
	}
	filePaths := map[string]struct{}{}
	for _, file := range record.Files {
		filePaths[file.Path] = struct{}{}
	}
	for _, required := range requiredPackedFiles {
		if _, ok := filePaths[required]; !ok {
			failures = append(failures, "npm pack metadata missing required packed file: "+required)
		}
	}
	for _, forbidden := range forbiddenPackedFiles {
		if _, ok := filePaths[forbidden]; ok {
			failures = append(failures, "npm pack metadata must not include source or workspace file: "+forbidden)
		}
	}
	orderedPaths := make([]string, 0, len(filePaths))
	for path := range filePaths {
		orderedPaths = append(orderedPaths, path)
	}
	sort.Strings(orderedPaths)
	for _, path := range orderedPaths {
		if strings.HasPrefix(path, "src/") || strings.HasPrefix(path, "test/") || strings.HasSuffix(path, ".d.ts") || strings.HasSuffix(path, ".map") {
			failures = append(failures, "npm pack metadata must not include non-runtime file: "+path)
		}
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
	releaseProjection := input.ReleaseAuthority.Projection
	if releaseProjection.Package.Name != input.PackageName {
		failures = append(failures, "releaseAuthorityInput.package.name must match packageName")
	}
	if releaseProjection.Package.Version != input.PackageVersion {
		failures = append(failures, "releaseAuthorityInput.package.version must match packageVersion")
	}
	if releaseProjection.Package.ArtifactPath != input.TarballPath {
		failures = append(failures, "releaseAuthorityInput.package.artifactPath must match tarballPath")
	}
	if releaseProjection.Package.PackManifestPath != input.PackMetadataPath {
		failures = append(failures, "releaseAuthorityInput.package.packManifestPath must match packMetadataPath")
	}
	if releaseProjection.Package.PackageManagerLockfile != "go.mod" {
		failures = append(failures, "releaseAuthorityInput.package.packageManagerLockfile must be go.mod")
	}
	if releaseProjection.Channel != string(releasechannel.TarballPilot) {
		failures = append(failures, "releaseAuthorityInput.channel must be tarball_pilot")
	}
	if releaseProjection.RolloutClaim {
		failures = append(failures, "releaseAuthorityInput.rolloutClaim must be false")
	}
	if releaseProjection.HasRegistryAuthority {
		failures = append(failures, "releaseAuthorityInput.registryAuthority must be null for tarball pilot")
	}
	if releaseProjection.Rollback.VersionPin != "file:"+input.TarballPath {
		failures = append(failures, "releaseAuthorityInput.rollback.versionPin must reference the exact file tarball path")
	}
	expectedProofIDs := map[string]string{
		"packDryRunCommandId":           releaseProjection.ArtifactProof.PackDryRunCommandID,
		"packageArtifactCommandId":      releaseProjection.ArtifactProof.PackageArtifactCommandID,
		"outsideConsumerInstallProofId": releaseProjection.ArtifactProof.OutsideConsumerInstallProof,
		"binarySmokeProofId":            releaseProjection.ArtifactProof.BinarySmokeProofID,
		"cliSmokeProofId":               releaseProjection.ArtifactProof.CLISmokeProofID,
		"deepImportRejectionProofId":    releaseProjection.ArtifactProof.DeepImportRejectionProofID,
	}
	for key, actual := range expectedProofIDs {
		expected := expectedExternalProofID(key)
		if actual != expected {
			failures = append(failures, "releaseAuthorityInput.artifactProof."+key+" must be "+expected)
		}
	}
	return failures
}

func expectedExternalProofID(key string) string {
	return map[string]string{
		"packDryRunCommandId":           "proofkit.external-consumer.pack-dry-run",
		"packageArtifactCommandId":      "proofkit.external-consumer.package-artifact",
		"outsideConsumerInstallProofId": "proofkit.external-consumer.install",
		"binarySmokeProofId":            "proofkit.external-consumer.binary-smoke",
		"cliSmokeProofId":               "proofkit.external-consumer.cli-smoke",
		"deepImportRejectionProofId":    "proofkit.external-consumer.deep-import-rejection",
	}[key]
}

func consumerProofFailures(input input, proofValue *consumerProof) []string {
	if proofValue == nil {
		return []string{"consumer proof evidence must be provided"}
	}
	failures := []string{}
	if proofValue.DependencySpec != "file:"+input.TarballPath {
		failures = append(failures, "consumer proof dependencySpec must reference the exact input tarballPath")
	}
	if !proofValue.InstallLockContainsPackage {
		failures = append(failures, "consumer proof install lock must contain the package")
	}
	if proofValue.InstallLockUsesWorkspace {
		failures = append(failures, "consumer proof install lock must not resolve through workspace")
	}
	if !proofValue.InstallLockContainsTarball {
		failures = append(failures, "consumer proof install lock must mention the exact tarball")
	}
	if !proofValue.FrozenLockContainsPackage {
		failures = append(failures, "consumer proof frozen lock must contain the package")
	}
	if proofValue.FrozenLockUsesWorkspace {
		failures = append(failures, "consumer proof frozen lock must not resolve through workspace")
	}
	if !proofValue.FrozenLockContainsTarball {
		failures = append(failures, "consumer proof frozen lock must mention the exact tarball")
	}
	if !hexSHA256Pattern.MatchString(proofValue.BinarySmokeOutputSHA256) {
		failures = append(failures, "consumer proof binarySmokeOutputSha256 must be lowercase sha256 hex")
	} else if expected := expectedBinarySmokeOutputSHA256(input); expected != "" && proofValue.BinarySmokeOutputSHA256 != expected {
		failures = append(failures, "consumer proof binarySmokeOutputSha256 must match expected binary smoke output")
	}
	if !hexSHA256Pattern.MatchString(proofValue.CLIWitnessPlanOutputSHA256) {
		failures = append(failures, "consumer proof cliWitnessPlanOutputSha256 must be lowercase sha256 hex")
	} else if expected := expectedCLIWitnessPlanOutputSHA256(input); expected != "" && proofValue.CLIWitnessPlanOutputSHA256 != expected {
		failures = append(failures, "consumer proof cliWitnessPlanOutputSha256 must match expected witness-plan CLI output")
	}
	if !hexSHA256Pattern.MatchString(proofValue.ReleaseAuthorityOutputSHA256) {
		failures = append(failures, "consumer proof releaseAuthorityOutputSha256 must be lowercase sha256 hex")
	} else if expected := expectedReleaseAuthorityOutputSHA256(input); expected != "" && proofValue.ReleaseAuthorityOutputSHA256 != expected {
		failures = append(failures, "consumer proof releaseAuthorityOutputSha256 must match expected release-authority report output")
	}
	if proofValue.ReleaseAuthorityReportKind != "proofkit.release-authority" {
		failures = append(failures, "consumer proof releaseAuthorityReportKind must be proofkit.release-authority")
	}
	if proofValue.ReleaseAuthorityState != "passed" {
		failures = append(failures, "consumer proof releaseAuthorityState must be passed")
	}
	if proofValue.RollbackLockContainsPackage {
		failures = append(failures, "consumer proof rollback lock must not contain the package")
	}
	return failures
}

func expectedWitnessPlan(input input) (map[string]any, error) {
	vocabulary, err := witnesscommand.AdmitVocabulary(input.WitnessPlan.Vocabulary)
	if err != nil {
		return nil, err
	}
	commands := make([]witnesscommand.Command, 0, len(input.WitnessPlan.Commands))
	for _, rawCommand := range input.WitnessPlan.Commands {
		command, err := witnesscommand.AdmitWithVocabulary(rawCommand, vocabulary)
		if err != nil {
			return nil, err
		}
		commands = append(commands, command)
	}
	plan, err := witnesscommand.PlanCommands(commands)
	if err != nil {
		return nil, err
	}
	return plan.JSONValue(), nil
}

func expectedBinarySmokeOutputSHA256(input input) string {
	plan, err := expectedWitnessPlan(input)
	if err != nil {
		return ""
	}
	value := map[string]any{
		"plan":   plan,
		"ruleId": input.BinarySmokeProbeRuleID,
	}
	return stableSHA256(value)
}

func expectedCLIWitnessPlanOutputSHA256(input input) string {
	plan, err := expectedWitnessPlan(input)
	if err != nil {
		return ""
	}
	return stableSHA256(plan)
}

func expectedReleaseAuthorityOutputSHA256(input input) string {
	if input.ReleaseAuthority.Err != nil {
		return ""
	}
	return input.ReleaseAuthority.OutputSHA256
}

func stableSHA256(value any) string {
	stable, err := stablejson.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(stable)
	return hex.EncodeToString(sum[:])
}

func failedAdmissionReport(err error) report.Record {
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      "proofkit.external-consumer.invalid-input",
		State:         "failed",
		Summary:       map[string]any{"admission": "failed"},
		Diagnostics:   []report.Diagnostic{},
		RuleResults: []report.RuleResult{
			{
				RuleID:      "proofkit.external-consumer.failure.001",
				Status:      "failed",
				Message:     err.Error(),
				Diagnostics: []report.Diagnostic{},
			},
		},
		NonClaims: []any{"Invalid external-consumer input is not proofkit consumption evidence."},
	}
}

func ruleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{
			{
				RuleID:      "proofkit.external-consumer.accepted",
				Status:      "passed",
				Message:     "external consumer evidence is explicit and bounded to the tarball pilot channel",
				Diagnostics: []report.Diagnostic{},
			},
		}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.external-consumer.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}

func consumerProofDiagnostic(proofValue *consumerProof) any {
	if proofValue == nil {
		return map[string]any{"executed": false}
	}
	return map[string]any{
		"cliWitnessPlanOutputSha256":   proofValue.CLIWitnessPlanOutputSHA256,
		"dependencySpec":               proofValue.DependencySpec,
		"frozenLockContainsPackage":    proofValue.FrozenLockContainsPackage,
		"frozenLockContainsTarball":    proofValue.FrozenLockContainsTarball,
		"frozenLockUsesWorkspace":      proofValue.FrozenLockUsesWorkspace,
		"installLockContainsPackage":   proofValue.InstallLockContainsPackage,
		"installLockContainsTarball":   proofValue.InstallLockContainsTarball,
		"installLockUsesWorkspace":     proofValue.InstallLockUsesWorkspace,
		"releaseAuthorityOutputSha256": proofValue.ReleaseAuthorityOutputSHA256,
		"releaseAuthorityReportKind":   proofValue.ReleaseAuthorityReportKind,
		"releaseAuthorityState":        proofValue.ReleaseAuthorityState,
		"rollbackLockContainsPackage":  proofValue.RollbackLockContainsPackage,
		"binarySmokeOutputSha256":      proofValue.BinarySmokeOutputSHA256,
		"tempConsumerLocation":         proofValue.TempConsumerLocation,
	}
}

func releaseAuthorityChannel(input input) any {
	if input.ReleaseAuthority.Err != nil {
		return "invalid"
	}
	return input.ReleaseAuthority.Projection.Channel
}

func packageTarballName(input input) string {
	return strings.Replace(strings.Replace(input.PackageName, "@", "", 1), "/", "-", 1) + "-" + input.PackageVersion + ".tgz"
}

func packageName(raw any) (string, error) {
	value, err := text(raw, "proofkit external-consumer input packageName")
	if err != nil {
		return "", err
	}
	if value != "@research-engineering/agentic-proofkit" {
		return "", fmt.Errorf("proofkit external-consumer input packageName must be @research-engineering/agentic-proofkit")
	}
	return value, nil
}

func versionText(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if !packageVersionRegexp.MatchString(value) {
		return "", fmt.Errorf("%s must be an exact npm version", context)
	}
	return value, nil
}

func pathText(raw any, context string) (string, error) {
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
