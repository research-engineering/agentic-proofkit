package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/specproofbundleadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/diagnostic"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasepublisher"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/trustedpublisher"
	"github.com/research-engineering/agentic-proofkit/internal/tools/commandoracle"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
	"github.com/research-engineering/agentic-proofkit/internal/tools/retainedevidence"
)

var commandOracleValidateCurrent = commandoracle.ValidateCurrent

const (
	completionID                      = "proofkit.release_closeout.current_package_gate"
	ciProvenancePath                  = "artifacts/proofkit/ci-provenance.json"
	cliContractPath                   = "proofkit/cli-contract.v2.json"
	coverageMetricsPath               = "artifacts/proofkit/coverage-metrics.json"
	commandOracleRecordPath           = commandoracle.RecordPath
	proofReceiptReportPath            = "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json"
	proofReceiptsPath                 = "artifacts/proofkit/self-hosting-proof-receipts.json"
	producerReportPath                = "artifacts/proofkit/self-hosting-receipt-producer-admission-report.json"
	producerPolicyPath                = "artifacts/proofkit/self-hosting-receipt-producer-admission.json"
	specProofBundleReportPath         = "artifacts/proofkit/self-hosting-spec-proof-bundle-admission-report.json"
	specProofBundlePath               = "artifacts/proofkit/self-hosting-spec-proof-bundle.json"
	npmCandidateNonClaim              = "Local npm package artifacts are candidate tarball evidence; they do not prove npm registry publication, registry install authority, or consumer adoption."
	pypiPlannedNonClaim               = "PyPI is not a dependency authority for this version until PyPI package evidence exists."
	packageGateEnvironmentClass       = "local-go-python"
	pythonPackageName                 = "agentic-proofkit"
	pythonWheelBinaryEntry            = "agentic_proofkit/bin/agentic-proofkit"
	maxPythonWheelBytes         int64 = 256 << 20
	maxPythonBinaryBytes        int64 = 64 << 20
	maxPythonWheelEntries             = 4096
)

type completionInput struct {
	SchemaVersion int         `json:"schemaVersion"`
	CompletionID  string      `json:"completionId"`
	Criteria      []criterion `json:"criteria"`
	NonClaims     []string    `json:"nonClaims"`
}

type criterion struct {
	Blocker                *string  `json:"blocker"`
	Criterion              string   `json:"criterion"`
	CriterionClass         string   `json:"criterionClass"`
	CriterionID            string   `json:"criterionId"`
	EvidenceRefs           []string `json:"evidenceRefs"`
	FailsWhen              []string `json:"failsWhen"`
	NonClaims              []string `json:"nonClaims"`
	Owner                  string   `json:"owner"`
	ProofRefs              []string `json:"proofRefs"`
	Status                 string   `json:"status"`
	StructuredDecisionRefs []string `json:"structuredDecisionRefs"`
	ValidatorRefs          []string `json:"validatorRefs"`
}

type packageJSON struct {
	Name       string         `json:"name"`
	Repository repositoryJSON `json:"repository"`
	Version    string         `json:"version"`
}

type repositoryJSON struct {
	URL string `json:"url"`
}

type packRecord struct {
	Filename  string `json:"filename"`
	Integrity string `json:"integrity"`
	Name      string `json:"name"`
	Shasum    string `json:"shasum"`
	Version   string `json:"version"`
}

type pythonPackageSet struct {
	PackageName    string        `json:"packageName"`
	PackageVersion string        `json:"packageVersion"`
	Packages       []pythonWheel `json:"packages"`
}

type pythonWheel struct {
	BinarySha256 string `json:"binarySha256"`
	Filename     string `json:"filename"`
	Name         string `json:"name"`
	Sha256       string `json:"sha256"`
	Version      string `json:"version"`
}

type releaseManifest struct {
	ArtifactKind string           `json:"artifactKind"`
	Channels     []releaseChannel `json:"channels"`
	NonClaims    []string         `json:"nonClaims"`
	Package      packageJSON      `json:"package"`
}

type releaseChannel struct {
	AuthorityChannel string                     `json:"authorityChannel"`
	NonClaims        []string                   `json:"nonClaims"`
	PublicationMode  string                     `json:"publicationMode"`
	Status           string                     `json:"status"`
	TrustedPublisher *trustedpublisher.Identity `json:"trustedPublisher"`
}

type cyclonedxBOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
}

type coverageMetricsEvidence struct {
	ArtifactKind  string                      `json:"artifactKind"`
	CLIContract   coverageCLIContractMetrics  `json:"cliContract"`
	CommandRoutes coverageCommandRouteMetrics `json:"commandRoutes"`
	DeadZones     coverageDeadZoneMetrics     `json:"deadZones"`
	NonClaims     []string                    `json:"nonClaims"`
	ProofBindings map[string]any              `json:"proofBindings"`
	Provenance    coverageMetricsProvenance   `json:"provenance"`
	Requirements  map[string]any              `json:"requirements"`
	SchemaVersion int                         `json:"schemaVersion"`
	WitnessPlan   map[string]any              `json:"witnessPlan"`
}

type coverageCLIContractMetrics struct {
	CommandCount *int      `json:"commandCount"`
	Commands     *[]string `json:"commands"`
}

type cliContractEvidence struct {
	Commands []cliContractCommandEvidence `json:"commands"`
}

type cliContractCommandEvidence struct {
	Command string `json:"command"`
}

type coverageMetricsProvenance struct {
	GeneratedAt          string `json:"generatedAt"`
	ProducerCommandID    string `json:"producerCommandId"`
	SourceRevision       string `json:"sourceRevision"`
	SourceSnapshotDigest string `json:"sourceSnapshotDigest"`
}

type coverageCommandRouteMetrics struct {
	AdmittedInventoryEntryCount                        *int      `json:"admittedInventoryEntryCount"`
	CommandCount                                       *int      `json:"commandCount"`
	Commands                                           *[]string `json:"commands"`
	CommandWithoutProofRouteCandidateCount             *int      `json:"commandWithoutProofRouteCandidateCount"`
	CommandsWithoutProofRouteCandidate                 *[]string `json:"commandsWithoutProofRouteCandidate"`
	ContractOnlyCommandCount                           *int      `json:"contractOnlyCommandCount"`
	ContractOnlyCommands                               *[]string `json:"contractOnlyCommands"`
	CommandWithoutDeclaredSemanticFalsifierRouteCount  *int      `json:"commandWithoutDeclaredSemanticFalsifierRouteCount"`
	CommandsWithoutDeclaredSemanticFalsifierRoute      *[]string `json:"commandsWithoutDeclaredSemanticFalsifierRoute"`
	RouteCount                                         *int      `json:"routeCount"`
	RouteOnlyCommandCount                              *int      `json:"routeOnlyCommandCount"`
	RouteOnlyCommands                                  *[]string `json:"routeOnlyCommands"`
	RouteSmokeCount                                    *int      `json:"routeSmokeCount"`
	ProofRouteCandidateInventoryEntryCount             *int      `json:"proofRouteCandidateInventoryEntryCount"`
	ProofRouteCandidateRouteCount                      *int      `json:"proofRouteCandidateRouteCount"`
	DeclaredSemanticFalsifierRouteEntryCount           *int      `json:"declaredSemanticFalsifierRouteEntryCount"`
	UnknownProofRouteCandidateRefCount                 *int      `json:"unknownProofRouteCandidateRefCount"`
	UnknownProofRouteCandidateRefs                     *[]string `json:"unknownProofRouteCandidateRefs"`
	UnknownDeclaredSemanticRouteCommandRefCount        *int      `json:"unknownDeclaredSemanticRouteCommandRefCount"`
	UnknownDeclaredSemanticRouteCommandRefs            *[]string `json:"unknownDeclaredSemanticRouteCommandRefs"`
	CommandOracleCandidateSetDigest                    string    `json:"commandOracleCandidateSetDigest"`
	CommandOracleCounterfeitCorpusDigest               string    `json:"commandOracleCounterfeitCorpusDigest"`
	CommandOracleRecordDigest                          string    `json:"commandOracleRecordDigest"`
	CommandOracleSourceSnapshotDigest                  string    `json:"commandOracleSourceSnapshotDigest"`
	CommandWithoutExecutionBackedSemanticRouteCount    *int      `json:"commandWithoutExecutionBackedSemanticRouteCount"`
	CommandsWithoutExecutionBackedSemanticRoute        *[]string `json:"commandsWithoutExecutionBackedSemanticRoute"`
	ExecutionBackedSemanticRouteEntryCount             *int      `json:"executionBackedSemanticRouteEntryCount"`
	UnknownExecutionBackedSemanticRouteCommandRefCount *int      `json:"unknownExecutionBackedSemanticRouteCommandRefCount"`
	UnknownExecutionBackedSemanticRouteCommandRefs     *[]string `json:"unknownExecutionBackedSemanticRouteCommandRefs"`
}

type coverageDeadZoneMetrics struct {
	BindingWithoutRequirementIDs  *[]string `json:"bindingWithoutRequirementIds"`
	RequirementWithoutBindingIDs  *[]string `json:"requirementWithoutBindingIds"`
	ScenarioWithoutCommandIDs     *[]string `json:"scenarioWithoutCommandIds"`
	ScenarioWithoutRequirementIDs *[]string `json:"scenarioWithoutRequirementIds"`
}

type selfEvidenceReport struct {
	Diagnostics   []any                    `json:"diagnostics"`
	NonClaims     []string                 `json:"nonClaims"`
	ReportID      string                   `json:"reportId"`
	ReportKind    string                   `json:"reportKind"`
	RuleResults   []selfEvidenceRuleResult `json:"ruleResults"`
	SchemaVersion int                      `json:"schemaVersion"`
	State         string                   `json:"state"`
	Summary       map[string]any           `json:"summary"`
}

type selfEvidenceRuleResult struct {
	RuleID string `json:"ruleId"`
	Status string `json:"status"`
}

type proofReceiptSetEvidence struct {
	NonClaims     []string               `json:"nonClaims"`
	ReceiptSetID  string                 `json:"receiptSetId"`
	Receipts      []proofReceiptEvidence `json:"receipts"`
	SchemaVersion int                    `json:"schemaVersion"`
}

type proofReceiptEvidence struct {
	ArtifactRefs           []any    `json:"artifactRefs"`
	CommandDigest          string   `json:"commandDigest"`
	DependencyDigest       string   `json:"dependencyDigest"`
	EnvironmentClass       string   `json:"environmentClass"`
	EnvironmentDigest      string   `json:"environmentDigest"`
	EvidenceRefs           []string `json:"evidenceRefs"`
	ExitCode               int      `json:"exitCode"`
	FinishedAt             string   `json:"finishedAt"`
	LockfileDigest         *string  `json:"lockfileDigest"`
	NonClaims              []string `json:"nonClaims"`
	ProducerAdmissionClass string   `json:"producerAdmissionClass"`
	ProducerID             string   `json:"producerId"`
	PreconditionDigest     string   `json:"preconditionDigest"`
	ProofBindingDigest     string   `json:"proofBindingDigest"`
	ProofPlanID            string   `json:"proofPlanId"`
	ProvenanceRef          string   `json:"provenanceRef"`
	ReceiptID              string   `json:"receiptId"`
	ReceiptKind            string   `json:"receiptKind"`
	RunnerClass            string   `json:"runnerClass"`
	RunnerIdentity         string   `json:"runnerIdentity"`
	SourceRevision         string   `json:"sourceRevision"`
	StartedAt              string   `json:"startedAt"`
	Status                 string   `json:"status"`
	ToolchainDigest        string   `json:"toolchainDigest"`
	WitnessSelectorDigest  string   `json:"witnessSelectorDigest"`
	WitnessSelectors       []string `json:"witnessSelectors"`
}

type selfEvidenceDocument[T any] struct {
	raw   any
	value T
}

// SelfEvidenceSnapshot is constructed once and exposes no mutable document state.
type SelfEvidenceSnapshot struct {
	root                  string
	cliContractCommands   []string
	ciProvenance          selfEvidenceDocument[map[string]any]
	coverageMetrics       selfEvidenceDocument[coverageMetricsEvidence]
	commandOracle         commandoracle.Evidence
	execution             packageartifactrecord.Record
	proofReceiptReport    selfEvidenceDocument[selfEvidenceReport]
	proofReceipts         selfEvidenceDocument[proofReceiptSetEvidence]
	producerReport        selfEvidenceDocument[selfEvidenceReport]
	producerPolicy        selfEvidenceDocument[receiptProducerPolicyEvidence]
	specProofBundleReport selfEvidenceDocument[selfEvidenceReport]
	specProofBundle       selfEvidenceDocument[specProofBundleEvidence]
}

type receiptProducerPolicyEvidence struct {
	EnvironmentClasses []string                  `json:"environmentClasses"`
	NonClaims          []string                  `json:"nonClaims"`
	PolicyID           string                    `json:"policyId"`
	Producers          []receiptProducerEvidence `json:"producers"`
	ReceiptKinds       []string                  `json:"receiptKinds"`
	Receipts           []receiptProducerReceipt  `json:"receipts"`
	SchemaVersion      int                       `json:"schemaVersion"`
}

type receiptProducerEvidence struct {
	AdmissionLevel     string   `json:"admissionLevel"`
	EnvironmentClasses []string `json:"environmentClasses"`
	EvidenceRefs       []string `json:"evidenceRefs"`
	NonClaim           string   `json:"nonClaim"`
	Owner              string   `json:"owner"`
	ProducerID         string   `json:"producerId"`
	ReceiptKinds       []string `json:"receiptKinds"`
}

type receiptProducerReceipt struct {
	ArtifactRefs             []string `json:"artifactRefs"`
	EnvironmentClass         string   `json:"environmentClass"`
	EvidenceRef              string   `json:"evidenceRef"`
	NonClaim                 string   `json:"nonClaim"`
	ProducerID               string   `json:"producerId"`
	ProvenanceRef            string   `json:"provenanceRef"`
	ReceiptID                string   `json:"receiptId"`
	ReceiptKind              string   `json:"receiptKind"`
	SatisfiesMergeObligation bool     `json:"satisfiesMergeObligation"`
	Status                   string   `json:"status"`
	SubjectRef               string   `json:"subjectRef"`
}

type specProofBundleEvidence struct {
	BundleID                 string                             `json:"bundleId"`
	MergeRequiredReceiptIDs  []string                           `json:"mergeRequiredReceiptIds"`
	NonClaims                []string                           `json:"nonClaims"`
	ReceiptAdmission         specBundleReceiptAdmission         `json:"receiptAdmission"`
	ReceiptProducerAdmission specBundleReceiptProducerAdmission `json:"receiptProducerAdmission"`
	RequirementBindings      specBundleRequirementBindings      `json:"requirementBindings"`
	SchemaVersion            int                                `json:"schemaVersion"`
	WitnessPlan              specBundleWitnessPlan              `json:"witnessPlan"`
}

type specBundleReceiptAdmission struct {
	ExitCode  int                    `json:"exitCode"`
	Failures  []any                  `json:"failures"`
	NonClaims []string               `json:"nonClaims"`
	Receipts  []proofReceiptEvidence `json:"receipts"`
	Report    selfEvidenceReport     `json:"report"`
}

type specBundleReceiptProducerAdmission struct {
	EnvironmentClasses []string                  `json:"environmentClasses"`
	ExitCode           int                       `json:"exitCode"`
	Failures           []any                     `json:"failures"`
	NonClaims          []string                  `json:"nonClaims"`
	Producers          []receiptProducerEvidence `json:"producers"`
	ReceiptKinds       []string                  `json:"receiptKinds"`
	Receipts           []receiptProducerReceipt  `json:"receipts"`
	Report             selfEvidenceReport        `json:"report"`
}

type specBundleRequirementBindings struct {
	BindingID       string                     `json:"bindingId"`
	Bindings        []specBundleBinding        `json:"bindings"`
	NonClaims       []string                   `json:"nonClaims"`
	Requirements    []specBundleRequirement    `json:"requirements"`
	SchemaVersion   int                        `json:"schemaVersion"`
	WitnessCommands []specBundleWitnessCommand `json:"witnessCommands"`
}

type specBundleRequirement struct {
	OwnerID       string `json:"ownerId"`
	ProofState    string `json:"proofState"`
	RequirementID string `json:"requirementId"`
	SpecPath      string `json:"specPath"`
}

type specBundleBinding struct {
	CommandIDs         []string `json:"commandIds"`
	EnvironmentClasses []string `json:"environmentClasses"`
	RequirementID      string   `json:"requirementId"`
	ScenarioID         string   `json:"scenarioId"`
	WitnessID          string   `json:"witnessId"`
	WitnessKind        string   `json:"witnessKind"`
	WitnessPath        string   `json:"witnessPath"`
}

type specBundleWitnessCommand struct {
	Command          string `json:"command"`
	CommandID        string `json:"commandId"`
	EnvironmentClass string `json:"environmentClass"`
}

type specBundleWitnessPlan struct {
	Commands        []specBundlePlanCommand `json:"commands"`
	NonClaims       []string                `json:"nonClaims"`
	Policies        []specBundlePlanPolicy  `json:"policies"`
	SchedulerPlanID string                  `json:"schedulerPlanId"`
	SchemaVersion   int                     `json:"schemaVersion"`
	Vocabulary      specBundleVocabulary    `json:"vocabulary"`
}

type specBundlePlanCommand struct {
	ExpectedArtifacts []specBundleExpectedArtifact `json:"expectedArtifacts"`
	ID                string                       `json:"id"`
}

type specBundleExpectedArtifact struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Required bool   `json:"required"`
}

type specBundlePlanPolicy struct {
	CommandID          string   `json:"commandId"`
	EnvironmentClasses []string `json:"environmentClasses"`
	SideEffectClass    string   `json:"sideEffectClass"`
}

type specBundleVocabulary struct {
	EnvironmentClasses []string `json:"environmentClasses"`
}

func main() {
	if err := run(os.Stdout); err != nil {
		diagnostic.WriteError(os.Stderr, err)
		os.Exit(1)
	}
}

func run(out io.Writer) error {
	input, err := buildInput(".")
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return err
	}
	_, err = out.Write(append(encoded, '\n'))
	return err
}

func buildInput(root string) (completionInput, error) {
	manifest, err := readTypedJSON[packageJSON](root, "package.json")
	if err != nil {
		return completionInput{}, err
	}
	criteria := []criterion{
		packageArtifactCriterion(root, manifest),
		pythonArtifactCriterion(root, manifest),
		releaseManifestCriterion(root, manifest),
		releaseChannelClassificationCriterion(root, manifest),
		selfEvidenceCriterion(root),
		registryPublicationNonClaimCriterion(),
	}
	sort.Slice(criteria, func(left int, right int) bool {
		return criteria[left].CriterionID < criteria[right].CriterionID
	})
	return completionInput{
		SchemaVersion: 1,
		CompletionID:  completionID,
		Criteria:      criteria,
		NonClaims: []string{
			"Release closeout input is generated from local candidate artifacts only.",
			"Release closeout input does not publish packages, authenticate providers, prove registry availability, approve release, approve rollout, or prove production readiness.",
		},
	}, nil
}

func packageArtifactCriterion(root string, manifest packageJSON) criterion {
	packPath := "artifacts/package/npm-pack.json"
	tarballPath := filepath.Join("artifacts", "package", npmTarballName(manifest.Name, manifest.Version))
	ok := fileExists(root, tarballPath) && validPackRecords(root, packPath, manifest)
	return blockingCriterion(
		"proofkit.release_closeout.package_artifacts",
		"Local npm package artifact and npm pack metadata must exist for the current package version.",
		ok,
		[]string{"package.json", packPath, filepath.ToSlash(tarballPath)},
		[]string{"npm:package:artifact", "internal/tools/packageverify"},
		[]string{"npm pack metadata is missing, invalid, or does not describe the current package.", "The current package tarball is missing or empty."},
		[]string{"This criterion does not claim npm registry publication or consumer installation."},
	)
}

func pythonArtifactCriterion(root string, manifest packageJSON) criterion {
	path := "artifacts/pypi/python-packages.json"
	packages, ok := readPythonPackageSet(root, path, manifest)
	evidence := []string{path}
	for _, item := range packages {
		evidence = append(evidence, filepath.ToSlash(filepath.Join("artifacts", "pypi", item.Filename)))
	}
	sort.Strings(evidence)
	return blockingCriterion(
		"proofkit.release_closeout.python_wrappers",
		"Python wheel candidate artifacts and package metadata must exist for the current package version.",
		ok,
		evidence,
		[]string{"npm:python:package", "npm:python:verify"},
		[]string{"Python package metadata is missing or invalid.", "One or more declared Python wheel artifacts are missing or empty."},
		[]string{"This criterion does not claim PyPI publication, Python SDK stability, or consumer adoption."},
	)
}

func releaseManifestCriterion(root string, manifest packageJSON) criterion {
	evidence := []string{
		ciProvenancePath,
		releasechange.RecordPath,
		"artifacts/release/checksums.sha256",
		"artifacts/release/metadata-checksums.sha256",
		"artifacts/release/release-manifest.json",
		"artifacts/release/release-notes.md",
		"artifacts/release/sbom-subjects.sha256",
		"artifacts/release/sbom.cdx.json",
	}
	evidence = append(evidence, retainedReleaseEvidenceRefs(root)...)
	ok := releaseManifestMatches(root, manifest) &&
		validSBOM(root, "artifacts/release/sbom.cdx.json") &&
		releaseNotesMatchChangeRecord(root, "artifacts/release/release-notes.md", manifest) &&
		releaseChecksumInventoriesMatch(root, manifest) &&
		retainedReleaseEvidenceMatches(root) &&
		allFilesExist(root, evidence)
	return blockingCriterion(
		"proofkit.release_closeout.manifest_and_sbom",
		"Release manifest, version-bound change-record notes, package checksums, metadata checksums, SBOM, and SBOM subject digests must exist for the current package version.",
		ok,
		evidence,
		[]string{"npm:release:manifest", "npm:release:sbom"},
		[]string{"Release manifest, change record, release notes projection, checksum inventory, metadata checksum inventory, SBOM, or SBOM subject digest is missing or invalid."},
		[]string{"This criterion does not claim vulnerability absence, license approval, GitHub Release publication, or registry publication."},
	)
}

func releaseChannelClassificationCriterion(root string, packageManifest packageJSON) criterion {
	path := "artifacts/release/release-manifest.json"
	manifest, err := readTypedJSON[releaseManifest](root, path)
	ok := err == nil &&
		hasNPMRegistryChannelScope(manifest) &&
		hasChannelStatus(manifest, string(releasechannel.GitHubReleaseArchive), "candidate", "published") &&
		hasChannelStatus(manifest, string(releasechannel.PythonWheelCandidate), "candidate", "published") &&
		hasPlannedPyPIWithNonClaim(manifest) &&
		publishedWorkflowIdentitiesValid(manifest, packageManifest)
	return blockingCriterion(
		"proofkit.release_closeout.channel_scope",
		"Release manifest must classify npm, PyPI, GitHub archive, and wheel evidence as candidate, planned, or published without upgrading planned channels to authority, and workflow-published registry channels must retain Trusted Publisher identity.",
		ok,
		[]string{path},
		[]string{"internal/tools/releasemanifest"},
		[]string{"Release manifest omits a required channel, upgrades planned evidence without registry proof, lacks a non-claim for npm or PyPI candidate authority, or claims workflow publication without an admitted Trusted Publisher identity tuple."},
		[]string{"This criterion does not claim post-publish registry identity, provider attestation, or archive publication."},
	)
}

func selfEvidenceCriterion(root string) criterion {
	evidence := []string{
		commandOracleRecordPath,
		coverageMetricsPath,
		packageartifactrecord.RecordPath,
		proofReceiptReportPath,
		proofReceiptsPath,
		producerReportPath,
		producerPolicyPath,
		specProofBundleReportPath,
		specProofBundlePath,
	}
	ok := selfEvidenceValid(root)
	return blockingCriterion(
		"proofkit.release_closeout.self_evidence",
		"Current package-artifact execution, command-oracle diagnostic, self-hosting receipt, producer admission, spec-proof bundle, and coverage metrics evidence must form one coherent local advisory closeout snapshot.",
		ok,
		evidence,
		[]string{"npm:self:receipt", "npm:self:coverage"},
		[]string{"Package-artifact execution is missing, stale, invalid, or mismatched with the self receipt.", "Self-hosting receipt, producer admission, spec-proof bundle, or coverage metrics evidence is missing or invalid."},
		[]string{"This criterion does not make local advisory receipts merge-satisfying or release-satisfying provider evidence."},
	)
}

func selfEvidenceValid(root string) bool {
	snapshot, err := readSelfEvidenceSnapshot(root)
	if err != nil {
		return false
	}
	return snapshot.valid()
}

func readSelfEvidenceSnapshot(root string) (SelfEvidenceSnapshot, error) {
	cliContract, err := readTypedJSON[cliContractEvidence](root, cliContractPath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	cliContractCommands, err := admittedCLIContractCommands(cliContract)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	ciProvenance, err := readSelfEvidenceDocument[map[string]any](root, ciProvenancePath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	coverageMetrics, err := readSelfEvidenceDocument[coverageMetricsEvidence](root, coverageMetricsPath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	commandOracle, err := commandoracle.ReadDiagnostic(root)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	if err := commandOracleValidateCurrent(context.Background(), root, commandOracle); err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	proofReceiptReport, err := readSelfEvidenceDocument[selfEvidenceReport](root, proofReceiptReportPath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	proofReceipts, err := readSelfEvidenceDocument[proofReceiptSetEvidence](root, proofReceiptsPath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	producerReport, err := readSelfEvidenceDocument[selfEvidenceReport](root, producerReportPath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	producerPolicy, err := readSelfEvidenceDocument[receiptProducerPolicyEvidence](root, producerPolicyPath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	specProofBundleReport, err := readSelfEvidenceDocument[selfEvidenceReport](root, specProofBundleReportPath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	specProofBundle, err := readSelfEvidenceDocument[specProofBundleEvidence](root, specProofBundlePath)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	execution, err := packageartifactrecord.Read(root)
	if err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	if err := packageartifactrecord.ValidateCurrent(root, execution); err != nil {
		return SelfEvidenceSnapshot{}, err
	}
	return SelfEvidenceSnapshot{
		root:                  root,
		cliContractCommands:   cliContractCommands,
		ciProvenance:          ciProvenance,
		coverageMetrics:       coverageMetrics,
		commandOracle:         commandOracle,
		execution:             execution,
		proofReceiptReport:    proofReceiptReport,
		proofReceipts:         proofReceipts,
		producerReport:        producerReport,
		producerPolicy:        producerPolicy,
		specProofBundleReport: specProofBundleReport,
		specProofBundle:       specProofBundle,
	}, nil
}

func readSelfEvidenceDocument[T any](root string, path string) (selfEvidenceDocument[T], error) {
	raw, err := readAdmittedJSON(root, path)
	if err != nil {
		return selfEvidenceDocument[T]{}, err
	}
	value, err := projectAdmittedJSON[T](raw)
	if err != nil {
		return selfEvidenceDocument[T]{}, err
	}
	return selfEvidenceDocument[T]{raw: raw, value: value}, nil
}

func (snapshot SelfEvidenceSnapshot) valid() bool {
	return coverageMetricsRecordMatches(snapshot.coverageMetrics.value, snapshot.cliContractCommands) &&
		coverageMetricsMatchExecution(snapshot.coverageMetrics.value, snapshot.execution) &&
		coverageMetricsMatchCommandOracle(snapshot.coverageMetrics.value, snapshot.commandOracle, snapshot.cliContractCommands) &&
		proofReceiptReportMatchesDocument(snapshot.proofReceiptReport, snapshot.proofReceipts) &&
		proofReceiptDocumentMatches(snapshot.proofReceipts) &&
		receiptProducerReportMatchesDocument(snapshot.producerReport, snapshot.producerPolicy) &&
		receiptProducerDocumentMatches(snapshot.producerPolicy) &&
		specProofBundleReportMatchesDocument(snapshot.specProofBundleReport, snapshot.specProofBundle) &&
		specProofBundleDocumentMatches(snapshot.specProofBundle) &&
		snapshot.identityConsistent(snapshot.execution) &&
		snapshot.receiptDigestsConsistent(snapshot.execution)
}

func coverageMetricsMatchCommandOracle(metrics coverageMetricsEvidence, evidence commandoracle.Evidence, cliContractCommands []string) bool {
	oracle := evidence.Record
	routes := metrics.CommandRoutes
	expectedCommandRefs := make([]string, 0, len(cliContractCommands))
	for _, command := range cliContractCommands {
		expectedCommandRefs = append(expectedCommandRefs, "proofkit.cli."+command)
	}
	sort.Strings(expectedCommandRefs)
	oracleCommandRefs := commandoracle.ExecutionCommandRefs(evidence)
	return oracle.ArtifactKind == commandoracle.ArtifactKind &&
		oracle.CommandID == commandoracle.CommandID &&
		oracle.SchemaVersion == commandoracle.SchemaVersion &&
		oracle.State == "passed" &&
		len(oracle.Entries) > 0 &&
		len(oracle.ExecutionCommands) > 0 &&
		len(oracle.NonClaims) > 0 &&
		reflect.DeepEqual(oracleCommandRefs, expectedCommandRefs) &&
		isSHA256(oracle.CandidateSetDigest) &&
		isSHA256(oracle.CounterfeitCorpusDigest) &&
		isSHA256(oracle.SourceSnapshotDigest) &&
		isSHA256(evidence.RecordDigest) &&
		routes.ExecutionBackedSemanticRouteEntryCount != nil &&
		*routes.ExecutionBackedSemanticRouteEntryCount == len(oracle.Entries) &&
		routes.CommandOracleCandidateSetDigest == oracle.CandidateSetDigest &&
		routes.CommandOracleCounterfeitCorpusDigest == oracle.CounterfeitCorpusDigest &&
		routes.CommandOracleRecordDigest == evidence.RecordDigest &&
		routes.CommandOracleSourceSnapshotDigest == oracle.SourceSnapshotDigest &&
		metrics.Provenance.SourceRevision == oracle.SourceRevision &&
		metrics.Provenance.SourceSnapshotDigest == oracle.SourceSnapshotDigest
}

func coverageMetricsMatchExecution(record coverageMetricsEvidence, execution packageartifactrecord.Record) bool {
	generatedAt, err := time.Parse(time.RFC3339Nano, record.Provenance.GeneratedAt)
	if err != nil {
		return false
	}
	finishedAt, err := time.Parse(time.RFC3339Nano, execution.FinishedAt)
	return err == nil && !generatedAt.Before(finishedAt) &&
		record.Provenance.ProducerCommandID == "proofkit.coverage-metrics" &&
		record.Provenance.SourceRevision == execution.SourceRevision &&
		record.Provenance.SourceSnapshotDigest == execution.SourceSnapshotDigest
}

func proofReceiptReportMatchesDocument(reportDocument selfEvidenceDocument[selfEvidenceReport], inputDocument selfEvidenceDocument[proofReceiptSetEvidence]) bool {
	ownerReport, exitCode, err := proofreceiptadmission.Build(inputDocument.raw)
	return err == nil && exitCode == 0 && ownerReport.State == "passed" && reportDocumentMatchesOwner(reportDocument.raw, ownerReport.JSONValue())
}

func receiptProducerReportMatchesDocument(reportDocument selfEvidenceDocument[selfEvidenceReport], inputDocument selfEvidenceDocument[receiptProducerPolicyEvidence]) bool {
	ownerReport, exitCode, err := receiptproduceradmission.Build(inputDocument.raw)
	return err == nil && exitCode == 0 && ownerReport.State == "passed" && reportDocumentMatchesOwner(reportDocument.raw, ownerReport.JSONValue())
}

func specProofBundleReportMatchesDocument(reportDocument selfEvidenceDocument[selfEvidenceReport], inputDocument selfEvidenceDocument[specProofBundleEvidence]) bool {
	ownerReport, exitCode, err := specproofbundleadmission.Build(inputDocument.raw)
	return err == nil && exitCode == 0 && ownerReport.State == "passed" && reportDocumentMatchesOwner(reportDocument.raw, ownerReport.JSONValue())
}

func reportDocumentMatchesOwner(stored any, owner any) bool {
	storedDigest, err := digest.StableJSONSHA256Ref(stored)
	if err != nil {
		return false
	}
	ownerDigest, err := digest.StableJSONSHA256Ref(owner)
	return err == nil && storedDigest == ownerDigest
}

type selfHostingReceiptIdentity struct {
	ProducerID string
	ReceiptID  string
}

func (snapshot SelfEvidenceSnapshot) identityConsistent(execution packageartifactrecord.Record) bool {
	receiptSet := snapshot.proofReceipts.value
	if len(receiptSet.Receipts) != 1 {
		return false
	}
	proofIdentity, ok := proofReceiptIdentity(receiptSet.Receipts[0])
	if !ok || !proofReceiptMatchesExecution(receiptSet.Receipts[0], execution) {
		return false
	}
	producerPolicy := snapshot.producerPolicy.value
	if len(producerPolicy.Receipts) != 1 {
		return false
	}
	producerIdentity, ok := producerReceiptIdentity(producerPolicy.Receipts[0])
	if !ok || producerIdentity != proofIdentity {
		return false
	}
	bundle := snapshot.specProofBundle.value
	if len(bundle.ReceiptAdmission.Receipts) != 1 ||
		len(bundle.ReceiptProducerAdmission.Receipts) != 1 {
		return false
	}
	receiptRaw, receiptRawOK := firstNestedRecord(snapshot.proofReceipts.raw, "receipts")
	bundleReceiptRaw, bundleReceiptRawOK := firstNestedRecord(snapshot.specProofBundle.raw, "receiptAdmission", "receipts")
	producerRaw, producerRawOK := firstNestedRecord(snapshot.producerPolicy.raw, "receipts")
	bundleProducerRaw, bundleProducerRawOK := firstNestedRecord(snapshot.specProofBundle.raw, "receiptProducerAdmission", "receipts")
	if !receiptRawOK || !bundleReceiptRawOK || !producerRawOK || !bundleProducerRawOK ||
		!canonicalRecordsEqual(receiptRaw, bundleReceiptRaw) || !canonicalRecordsEqual(producerRaw, bundleProducerRaw) {
		return false
	}
	bundleProofIdentity, ok := proofReceiptIdentity(bundle.ReceiptAdmission.Receipts[0])
	if !ok || bundleProofIdentity != proofIdentity ||
		!reflect.DeepEqual(bundle.ReceiptAdmission.Receipts[0], receiptSet.Receipts[0]) ||
		!proofReceiptMatchesExecution(bundle.ReceiptAdmission.Receipts[0], execution) {
		return false
	}
	bundleProducerIdentity, ok := producerReceiptIdentity(bundle.ReceiptProducerAdmission.Receipts[0])
	return ok && bundleProducerIdentity == proofIdentity &&
		reflect.DeepEqual(bundle.ReceiptProducerAdmission.Receipts[0], producerPolicy.Receipts[0])
}

func firstNestedRecord(raw any, objectPath ...string) (any, bool) {
	current := raw
	for _, key := range objectPath {
		record, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = record[key]
		if !ok {
			return nil, false
		}
	}
	values, ok := current.([]any)
	if !ok || len(values) != 1 {
		return nil, false
	}
	return values[0], true
}

func canonicalRecordsEqual(left any, right any) bool {
	leftDigest, err := digest.StableJSONSHA256Ref(left)
	if err != nil {
		return false
	}
	rightDigest, err := digest.StableJSONSHA256Ref(right)
	return err == nil && leftDigest == rightDigest
}

func proofReceiptIdentity(record proofReceiptEvidence) (selfHostingReceiptIdentity, bool) {
	if !selfHostingReceiptIdentityMatches(record.ReceiptID, record.ProducerID, record.RunnerClass) {
		return selfHostingReceiptIdentity{}, false
	}
	return selfHostingReceiptIdentity{ProducerID: record.ProducerID, ReceiptID: record.ReceiptID}, true
}

func producerReceiptIdentity(record receiptProducerReceipt) (selfHostingReceiptIdentity, bool) {
	if !selfHostingReceiptProducerMatches(record.ReceiptID, record.ProducerID) {
		return selfHostingReceiptIdentity{}, false
	}
	return selfHostingReceiptIdentity{ProducerID: record.ProducerID, ReceiptID: record.ReceiptID}, true
}

func proofReceiptMatchesExecution(receipt proofReceiptEvidence, execution packageartifactrecord.Record) bool {
	commandDigest, err := packageArtifactCommandDigest(execution)
	if err != nil || receipt.SourceRevision != execution.SourceRevision ||
		receipt.StartedAt != execution.StartedAt ||
		receipt.FinishedAt != execution.FinishedAt ||
		receipt.CommandDigest != commandDigest {
		return false
	}
	if execution.EnvironmentDigest != "" {
		expected, err := admit.SHA256HexRef(execution.EnvironmentDigest, "package execution environmentDigest")
		if err != nil || receipt.EnvironmentDigest != expected {
			return false
		}
	}
	if execution.ToolchainDigest != "" {
		expected, err := admit.SHA256HexRef(execution.ToolchainDigest, "package execution toolchainDigest")
		if err != nil || receipt.ToolchainDigest != expected {
			return false
		}
	}
	return true
}

func (snapshot SelfEvidenceSnapshot) receiptDigestsConsistent(execution packageartifactrecord.Record) bool {
	if len(snapshot.proofReceipts.value.Receipts) != 1 {
		return false
	}
	receipt := snapshot.proofReceipts.value.Receipts[0]
	proofBindingDigest, err := fileDigestRef(snapshot.root, "proofkit/requirement-bindings.json")
	if err != nil {
		return false
	}
	goModDigest, err := fileDigestRef(snapshot.root, "go.mod")
	if err != nil {
		return false
	}
	goSumDigest, err := fileDigestRef(snapshot.root, "go.sum")
	if err != nil {
		return false
	}
	packageJSONDigest, err := fileDigestRef(snapshot.root, "package.json")
	if err != nil {
		return false
	}
	witnessPlanDigest, err := fileDigestRef(snapshot.root, "proofkit/witness-plan.json")
	if err != nil {
		return false
	}
	trustInputs, ok := snapshot.ciProvenance.value["ciTrustInputs"]
	if !ok {
		return false
	}
	ciTrustInputDigest, err := digest.StableJSONSHA256Ref(trustInputs)
	if err != nil {
		return false
	}
	dependencyDigest, err := digest.StableJSONSHA256Ref(map[string]any{
		"goModDigest": goModDigest,
		"goSumDigest": goSumDigest,
	})
	if err != nil {
		return false
	}
	preconditionDigest, err := digest.StableJSONSHA256Ref(map[string]any{
		"artifactSnapshotDigest": execution.ArtifactSnapshotDigest,
		"ciTrustInputDigest":     ciTrustInputDigest,
		"goModDigest":            goModDigest,
		"goSumDigest":            goSumDigest,
		"packageJsonDigest":      packageJSONDigest,
		"sourceSnapshotDigest":   execution.SourceSnapshotDigest,
		"witnessPlanDigest":      witnessPlanDigest,
	})
	if err != nil {
		return false
	}
	selectorValues := make([]any, 0, len(receipt.WitnessSelectors))
	for _, selector := range receipt.WitnessSelectors {
		selectorValues = append(selectorValues, selector)
	}
	witnessSelectorDigest, err := digest.StableJSONSHA256Ref(selectorValues)
	if err != nil {
		return false
	}
	return receipt.DependencyDigest == dependencyDigest &&
		receipt.PreconditionDigest == preconditionDigest &&
		receipt.ProofBindingDigest == proofBindingDigest &&
		receipt.WitnessSelectorDigest == witnessSelectorDigest &&
		provenanceMatchesExecution(snapshot.ciProvenance.value, execution)
}

func provenanceMatchesExecution(record map[string]any, execution packageartifactrecord.Record) bool {
	if record["sourceRevision"] != execution.SourceRevision {
		return false
	}
	generatedAt, ok := record["generatedAt"].(string)
	if !ok {
		return false
	}
	generated, err := time.Parse(time.RFC3339Nano, generatedAt)
	if err != nil {
		return false
	}
	finished, err := time.Parse(time.RFC3339Nano, execution.FinishedAt)
	return err == nil && !generated.Before(finished)
}

func fileDigestRef(root string, path string) (string, error) {
	value, err := fileSHA256(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return "", err
	}
	return "sha256:" + value, nil
}

func packageArtifactCommandDigest(execution packageartifactrecord.Record) (string, error) {
	argv := make([]any, 0, len(execution.Argv))
	for _, argument := range execution.Argv {
		argv = append(argv, argument)
	}
	return digest.StableJSONSHA256Ref(map[string]any{
		"argv": argv,
		"id":   execution.CommandID,
	})
}

func coverageMetricsRecordMatches(record coverageMetricsEvidence, cliContractCommands []string) bool {
	return record.SchemaVersion == 2 &&
		record.ArtifactKind == "proofkit.coverage-metrics.v2" &&
		coverageCLIContractMatches(record.CLIContract, cliContractCommands) &&
		len(record.NonClaims) > 0 &&
		len(record.ProofBindings) > 0 &&
		len(record.Requirements) > 0 &&
		len(record.WitnessPlan) > 0 &&
		coverageDeadZonesEmpty(record.DeadZones) &&
		commandRouteDefectsEmpty(record.CommandRoutes, cliContractCommands)
}

func coverageCLIContractMatches(metrics coverageCLIContractMetrics, expected []string) bool {
	return metrics.CommandCount != nil && metrics.Commands != nil &&
		*metrics.CommandCount == len(expected) &&
		reflect.DeepEqual(*metrics.Commands, expected) &&
		sortedUniqueStringSlice(metrics.Commands)
}

func reportRecordMatches(record selfEvidenceReport, wantKind string, wantID string, wantState string, wantRuleIDs []string) bool {
	return record.SchemaVersion == 1 &&
		record.ReportKind == wantKind &&
		record.ReportID == wantID &&
		record.State == wantState &&
		len(record.Diagnostics) > 0 &&
		len(record.NonClaims) > 0 &&
		len(record.RuleResults) > 0 &&
		len(record.Summary) > 0 &&
		ruleResultsMatch(record.RuleResults, wantRuleIDs) &&
		summaryFailureCountIsZero(record.Summary) &&
		diagnosticsHaveNoFailures(record.Diagnostics)
}

func ruleResultsMatch(results []selfEvidenceRuleResult, wantRuleIDs []string) bool {
	if len(results) != len(wantRuleIDs) || len(results) == 0 {
		return false
	}
	gotIDs := make([]string, 0, len(results))
	for _, item := range results {
		if item.RuleID == "" || item.Status != "passed" {
			return false
		}
		gotIDs = append(gotIDs, item.RuleID)
	}
	sort.Strings(gotIDs)
	wantIDs := append([]string{}, wantRuleIDs...)
	sort.Strings(wantIDs)
	for index := range gotIDs {
		if gotIDs[index] != wantIDs[index] {
			return false
		}
	}
	return true
}

func summaryFailureCountIsZero(summary map[string]any) bool {
	value, exists := summary["failureCount"]
	if !exists {
		return false
	}
	return numericValueIsZero(value)
}

func diagnosticsHaveNoFailures(diagnostics []any) bool {
	for _, diagnostic := range diagnostics {
		record, ok := diagnostic.(map[string]any)
		if !ok {
			continue
		}
		if !diagnosticFailureFieldsEmpty(record) {
			return false
		}
	}
	return true
}

func diagnosticFailureFieldsEmpty(record map[string]any) bool {
	if value, exists := record["failureCount"]; exists && !numericValueIsZero(value) {
		return false
	}
	if value, exists := record["failures"]; exists && !arrayValueIsEmpty(value) {
		return false
	}
	key, hasKey := record["key"].(string)
	if !hasKey {
		return true
	}
	value, exists := record["value"]
	if !exists {
		return true
	}
	switch key {
	case "failureCount":
		return numericValueIsZero(value)
	case "failures":
		return arrayValueIsEmpty(value)
	default:
		return true
	}
}

func coverageDeadZonesEmpty(deadZones coverageDeadZoneMetrics) bool {
	return emptyStringSlice(deadZones.BindingWithoutRequirementIDs) &&
		emptyStringSlice(deadZones.RequirementWithoutBindingIDs) &&
		emptyStringSlice(deadZones.ScenarioWithoutCommandIDs) &&
		emptyStringSlice(deadZones.ScenarioWithoutRequirementIDs)
}

func commandRouteDefectsEmpty(routes coverageCommandRouteMetrics, cliContractCommands []string) bool {
	return positiveInt(routes.AdmittedInventoryEntryCount) &&
		positiveInt(routes.CommandCount) &&
		positiveInt(routes.RouteCount) &&
		nonNegativeInt(routes.RouteSmokeCount) &&
		positiveInt(routes.ProofRouteCandidateInventoryEntryCount) &&
		positiveInt(routes.ProofRouteCandidateRouteCount) &&
		nonNegativeInt(routes.DeclaredSemanticFalsifierRouteEntryCount) &&
		positiveInt(routes.ExecutionBackedSemanticRouteEntryCount) &&
		commandRouteMetricsProducerReachable(routes, cliContractCommands) &&
		countMatchesStringSlice(routes.CommandWithoutDeclaredSemanticFalsifierRouteCount, routes.CommandsWithoutDeclaredSemanticFalsifierRoute) &&
		zeroInt(routes.CommandWithoutExecutionBackedSemanticRouteCount) &&
		zeroInt(routes.UnknownExecutionBackedSemanticRouteCommandRefCount) &&
		zeroInt(routes.CommandWithoutProofRouteCandidateCount) &&
		zeroInt(routes.ContractOnlyCommandCount) &&
		zeroInt(routes.RouteOnlyCommandCount) &&
		zeroInt(routes.UnknownProofRouteCandidateRefCount) &&
		zeroInt(routes.UnknownDeclaredSemanticRouteCommandRefCount) &&
		emptyStringSlice(routes.CommandsWithoutProofRouteCandidate) &&
		emptyStringSlice(routes.ContractOnlyCommands) &&
		emptyStringSlice(routes.RouteOnlyCommands) &&
		emptyStringSlice(routes.UnknownProofRouteCandidateRefs) &&
		emptyStringSlice(routes.UnknownDeclaredSemanticRouteCommandRefs) &&
		emptyStringSlice(routes.CommandsWithoutExecutionBackedSemanticRoute) &&
		emptyStringSlice(routes.UnknownExecutionBackedSemanticRouteCommandRefs) &&
		isSHA256(routes.CommandOracleCandidateSetDigest) &&
		isSHA256(routes.CommandOracleCounterfeitCorpusDigest) &&
		isSHA256(routes.CommandOracleRecordDigest) &&
		isSHA256(routes.CommandOracleSourceSnapshotDigest)
}

func commandRouteMetricsProducerReachable(routes coverageCommandRouteMetrics, cliContractCommands []string) bool {
	if routes.AdmittedInventoryEntryCount == nil ||
		routes.CommandCount == nil ||
		routes.Commands == nil ||
		routes.CommandWithoutProofRouteCandidateCount == nil ||
		routes.CommandsWithoutDeclaredSemanticFalsifierRoute == nil ||
		routes.RouteCount == nil ||
		routes.RouteSmokeCount == nil ||
		routes.ProofRouteCandidateInventoryEntryCount == nil ||
		routes.ProofRouteCandidateRouteCount == nil ||
		routes.DeclaredSemanticFalsifierRouteEntryCount == nil ||
		routes.CommandWithoutDeclaredSemanticFalsifierRouteCount == nil ||
		routes.ExecutionBackedSemanticRouteEntryCount == nil ||
		routes.CommandWithoutExecutionBackedSemanticRouteCount == nil ||
		routes.CommandsWithoutExecutionBackedSemanticRoute == nil ||
		routes.UnknownExecutionBackedSemanticRouteCommandRefCount == nil ||
		routes.UnknownExecutionBackedSemanticRouteCommandRefs == nil {
		return false
	}
	admitted := *routes.AdmittedInventoryEntryCount
	commands := *routes.CommandCount
	routeCount := *routes.RouteCount
	routeSmokeCount := *routes.RouteSmokeCount
	candidateEntries := *routes.ProofRouteCandidateInventoryEntryCount
	candidateRoutes := *routes.ProofRouteCandidateRouteCount
	declaredEntries := *routes.DeclaredSemanticFalsifierRouteEntryCount
	missingCandidates := *routes.CommandWithoutProofRouteCandidateCount
	missingDeclared := *routes.CommandWithoutDeclaredSemanticFalsifierRouteCount
	executionBacked := *routes.ExecutionBackedSemanticRouteEntryCount
	missingExecutionBacked := *routes.CommandWithoutExecutionBackedSemanticRouteCount
	unknownExecutionBacked := *routes.UnknownExecutionBackedSemanticRouteCommandRefCount
	if admitted < 0 || commands < 0 || routeCount < 0 || routeSmokeCount < 0 ||
		candidateEntries < 0 || candidateRoutes < 0 || declaredEntries < 0 ||
		missingCandidates < 0 || missingDeclared < 0 || executionBacked < 0 || missingExecutionBacked < 0 || unknownExecutionBacked < 0 ||
		admitted != routeCount || candidateEntries != candidateRoutes ||
		candidateEntries > admitted || routeSmokeCount != admitted-candidateEntries ||
		declaredEntries != 0 || missingCandidates > commands || missingDeclared != commands ||
		executionBacked != candidateEntries || missingExecutionBacked != 0 || unknownExecutionBacked != 0 ||
		candidateRoutes < commands-missingCandidates || len(*routes.Commands) != commands ||
		!reflect.DeepEqual(*routes.Commands, *routes.CommandsWithoutDeclaredSemanticFalsifierRoute) ||
		!reflect.DeepEqual(*routes.Commands, cliContractCommands) {
		return false
	}
	return sortedUniqueStringSlice(routes.Commands) &&
		sortedUniqueStringSlice(routes.CommandsWithoutDeclaredSemanticFalsifierRoute) &&
		sortedUniqueStringSlice(routes.CommandsWithoutProofRouteCandidate) &&
		sortedUniqueStringSlice(routes.ContractOnlyCommands) &&
		sortedUniqueStringSlice(routes.RouteOnlyCommands) &&
		sortedUniqueStringSlice(routes.UnknownProofRouteCandidateRefs) &&
		sortedUniqueStringSlice(routes.UnknownDeclaredSemanticRouteCommandRefs) &&
		sortedUniqueStringSlice(routes.CommandsWithoutExecutionBackedSemanticRoute) &&
		sortedUniqueStringSlice(routes.UnknownExecutionBackedSemanticRouteCommandRefs)
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func admittedCLIContractCommands(contract cliContractEvidence) ([]string, error) {
	if len(contract.Commands) == 0 {
		return nil, fmt.Errorf("%s must declare at least one command", cliContractPath)
	}
	commands := make([]string, 0, len(contract.Commands))
	for index, command := range contract.Commands {
		value, err := admit.RuleID(command.Command, fmt.Sprintf("%s commands[%d] command", cliContractPath, index))
		if err != nil {
			return nil, err
		}
		commands = append(commands, value)
	}
	sort.Strings(commands)
	for index := 1; index < len(commands); index++ {
		if commands[index-1] == commands[index] {
			return nil, fmt.Errorf("%s commands must be unique", cliContractPath)
		}
	}
	return commands, nil
}

func sortedUniqueStringSlice(values *[]string) bool {
	if values == nil {
		return false
	}
	for index, value := range *values {
		if value == "" || (index > 0 && (*values)[index-1] >= value) {
			return false
		}
	}
	return true
}

func countMatchesStringSlice(count *int, values *[]string) bool {
	return count != nil && values != nil && *count >= 0 && *count == len(*values)
}

func positiveInt(value *int) bool {
	return value != nil && *value > 0
}

func zeroInt(value *int) bool {
	return value != nil && *value == 0
}

func nonNegativeInt(value *int) bool {
	return value != nil && *value >= 0
}

func emptyStringSlice(value *[]string) bool {
	return value != nil && len(*value) == 0
}

func numericValueIsZero(value any) bool {
	switch typed := value.(type) {
	case json.Number:
		return typed == "0"
	case float64:
		return typed == 0
	case int:
		return typed == 0
	case int64:
		return typed == 0
	default:
		return false
	}
}

func arrayValueIsEmpty(value any) bool {
	array, ok := value.([]any)
	return ok && len(array) == 0
}

func proofReceiptSetMatches(root string, path string) bool {
	document, err := readSelfEvidenceDocument[proofReceiptSetEvidence](root, path)
	if err != nil {
		return false
	}
	return proofReceiptDocumentMatches(document)
}

func proofReceiptDocumentMatches(document selfEvidenceDocument[proofReceiptSetEvidence]) bool {
	ownerReport, ownerExitCode, err := proofreceiptadmission.Build(document.raw)
	if err != nil || ownerExitCode != 0 || ownerReport.State != "passed" {
		return false
	}
	return proofReceiptSetRecordMatches(document.value)
}

func proofReceiptSetRecordMatches(record proofReceiptSetEvidence) bool {
	return record.SchemaVersion == 1 &&
		record.ReceiptSetID == "proofkit.self-hosting.proof-receipts" &&
		len(record.NonClaims) > 0 &&
		len(record.Receipts) == 1 &&
		proofReceiptMatches(record.Receipts[0])
}

func proofReceiptMatches(record proofReceiptEvidence) bool {
	return selfHostingReceiptIdentityMatches(record.ReceiptID, record.ProducerID, record.RunnerClass) &&
		record.ReceiptKind == "proofkit.package-artifact" &&
		record.ProducerAdmissionClass == "advisory" &&
		record.EnvironmentClass == packageGateEnvironmentClass &&
		record.Status == "passed" &&
		record.ExitCode == 0 &&
		record.ProofPlanID == "proofkit.self-hosting.witness-plan" &&
		record.ProvenanceRef == "artifacts/proofkit/ci-provenance.json" &&
		len(record.ArtifactRefs) > 0 &&
		len(record.EvidenceRefs) > 0 &&
		len(record.NonClaims) > 0 &&
		len(record.WitnessSelectors) > 0
}

func receiptProducerPolicyMatches(root string, path string) bool {
	document, err := readSelfEvidenceDocument[receiptProducerPolicyEvidence](root, path)
	if err != nil {
		return false
	}
	return receiptProducerDocumentMatches(document)
}

func receiptProducerDocumentMatches(document selfEvidenceDocument[receiptProducerPolicyEvidence]) bool {
	ownerReport, ownerExitCode, err := receiptproduceradmission.Build(document.raw)
	if err != nil || ownerExitCode != 0 || ownerReport.State != "passed" {
		return false
	}
	return receiptProducerPolicyRecordMatches(document.value)
}

func receiptProducerPolicyRecordMatches(record receiptProducerPolicyEvidence) bool {
	return record.SchemaVersion == 1 &&
		record.PolicyID == "proofkit.receipt-producer-policy" &&
		len(record.EnvironmentClasses) > 0 &&
		len(record.NonClaims) > 0 &&
		len(record.Producers) > 0 &&
		len(record.ReceiptKinds) > 0 &&
		len(record.Receipts) == 1 &&
		receiptProducerPolicyCoversReceipt(record)
}

func receiptProducerPolicyCoversReceipt(record receiptProducerPolicyEvidence) bool {
	receipt := record.Receipts[0]
	if !receiptProducerReceiptMatches(receipt) {
		return false
	}
	for _, producer := range record.Producers {
		if receiptProducerMatches(producer, receipt) {
			return true
		}
	}
	return false
}

func receiptProducerReceiptMatches(receipt receiptProducerReceipt) bool {
	return selfHostingReceiptProducerMatches(receipt.ReceiptID, receipt.ProducerID) &&
		receipt.ReceiptKind == "proofkit.package-artifact" &&
		receipt.EnvironmentClass == packageGateEnvironmentClass &&
		receipt.Status == "passed" &&
		!receipt.SatisfiesMergeObligation &&
		receipt.EvidenceRef == "artifacts/proofkit/self-hosting-proof-receipts.json" &&
		receipt.ProvenanceRef == "artifacts/proofkit/ci-provenance.json" &&
		receipt.SubjectRef == "proofkit.package-boundary.self-hosting" &&
		receipt.NonClaim != "" &&
		len(receipt.ArtifactRefs) > 0
}

func selfHostingReceiptIdentityMatches(receiptID string, producerID string, runnerClass string) bool {
	switch producerID {
	case "local.developer":
		return receiptID == "receipt.local.package-artifact" && runnerClass == "local"
	case "github.actions.package":
		return receiptID == "receipt.github.actions.package-artifact" && runnerClass == "github.actions.hosted"
	default:
		return false
	}
}

func selfHostingReceiptProducerMatches(receiptID string, producerID string) bool {
	switch producerID {
	case "local.developer":
		return receiptID == "receipt.local.package-artifact"
	case "github.actions.package":
		return receiptID == "receipt.github.actions.package-artifact"
	default:
		return false
	}
}

func receiptProducerMatches(producer receiptProducerEvidence, receipt receiptProducerReceipt) bool {
	return producer.ProducerID == receipt.ProducerID &&
		producer.AdmissionLevel == "advisory" &&
		producer.Owner != "" &&
		producer.NonClaim != "" &&
		stringSliceContains(producer.EnvironmentClasses, receipt.EnvironmentClass) &&
		stringSliceContains(producer.ReceiptKinds, receipt.ReceiptKind) &&
		len(producer.EvidenceRefs) > 0
}

func specProofBundleMatches(root string, path string) bool {
	document, err := readSelfEvidenceDocument[specProofBundleEvidence](root, path)
	if err != nil {
		return false
	}
	return specProofBundleDocumentMatches(document)
}

func specProofBundleDocumentMatches(document selfEvidenceDocument[specProofBundleEvidence]) bool {
	ownerReport, ownerExitCode, err := specproofbundleadmission.Build(document.raw)
	if err != nil || ownerExitCode != 0 || ownerReport.State != "passed" {
		return false
	}
	return specProofBundleRecordMatches(document.value)
}

func specProofBundleRecordMatches(record specProofBundleEvidence) bool {
	return record.SchemaVersion == 1 &&
		record.BundleID == "proofkit.self-hosting.spec-proof-bundle" &&
		len(record.NonClaims) > 0 &&
		len(record.MergeRequiredReceiptIDs) == 0 &&
		specBundleReceiptAdmissionMatches(record.ReceiptAdmission) &&
		specBundleReceiptProducerAdmissionMatches(record.ReceiptProducerAdmission) &&
		specBundleRequirementBindingsMatch(record.RequirementBindings) &&
		specBundleWitnessPlanMatches(record.WitnessPlan)
}

func readAdmittedJSON(root string, path string) (any, error) {
	file, err := os.Open(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return admission.DecodeJSON(file, 16<<20)
}

func projectAdmittedJSON[T any](raw any) (T, error) {
	var output T
	encoded, err := json.Marshal(raw)
	if err != nil {
		return output, err
	}
	if err := json.Unmarshal(encoded, &output); err != nil {
		return output, err
	}
	return output, nil
}

func specBundleReceiptAdmissionMatches(record specBundleReceiptAdmission) bool {
	return record.ExitCode == 0 &&
		len(record.Failures) == 0 &&
		len(record.NonClaims) > 0 &&
		len(record.Receipts) == 1 &&
		proofReceiptMatches(record.Receipts[0]) &&
		reportRecordMatches(record.Report, "proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "passed", []string{"proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts"})
}

func specBundleReceiptProducerAdmissionMatches(record specBundleReceiptProducerAdmission) bool {
	return record.ExitCode == 0 &&
		len(record.Failures) == 0 &&
		len(record.NonClaims) > 0 &&
		len(record.EnvironmentClasses) > 0 &&
		len(record.Producers) > 0 &&
		len(record.ReceiptKinds) > 0 &&
		len(record.Receipts) == 1 &&
		receiptProducerPolicyCoversReceipt(receiptProducerPolicyEvidence{
			EnvironmentClasses: record.EnvironmentClasses,
			NonClaims:          record.NonClaims,
			PolicyID:           "proofkit.receipt-producer-policy",
			Producers:          record.Producers,
			ReceiptKinds:       record.ReceiptKinds,
			Receipts:           record.Receipts,
			SchemaVersion:      1,
		}) &&
		reportRecordMatches(record.Report, "proofkit.receipt-producer-admission", "proofkit.receipt-producer-policy", "passed", []string{"proofkit.receipt-producer-admission.boundary", "proofkit.receipt-producer-admission.coverage", "proofkit.receipt-producer-admission.receipts"})
}

func specBundleRequirementBindingsMatch(record specBundleRequirementBindings) bool {
	return record.SchemaVersion == 1 &&
		record.BindingID == "proofkit.package-boundary.requirement-bindings" &&
		len(record.NonClaims) > 0 &&
		specBundleHasRequirement(record.Requirements, "REQ-PROOFKIT-PACKAGE-003") &&
		specBundleHasBinding(record.Bindings, "REQ-PROOFKIT-PACKAGE-003", "proofkit.package-artifact", packageGateEnvironmentClass) &&
		specBundleHasWitnessCommand(record.WitnessCommands, "proofkit.package-artifact", packageGateEnvironmentClass)
}

func specBundleWitnessPlanMatches(record specBundleWitnessPlan) bool {
	return record.SchemaVersion == 1 &&
		record.SchedulerPlanID == "proofkit.self-hosting.witness-plan" &&
		len(record.NonClaims) > 0 &&
		specBundleHasPlanCommandArtifact(record.Commands, "proofkit.package-artifact", "artifacts/package/npm-pack.json") &&
		specBundleHasPlanPolicy(record.Policies, "proofkit.package-artifact") &&
		stringSliceContains(record.Vocabulary.EnvironmentClasses, packageGateEnvironmentClass)
}

func specBundleHasRequirement(records []specBundleRequirement, requirementID string) bool {
	for _, record := range records {
		if record.RequirementID == requirementID &&
			record.OwnerID != "" &&
			record.ProofState != "" &&
			record.SpecPath != "" {
			return true
		}
	}
	return false
}

func specBundleHasBinding(records []specBundleBinding, requirementID string, commandID string, environmentClass string) bool {
	for _, record := range records {
		if record.RequirementID == requirementID &&
			record.ScenarioID != "" &&
			record.WitnessID != "" &&
			record.WitnessKind != "" &&
			record.WitnessPath != "" &&
			stringSliceContains(record.CommandIDs, commandID) &&
			stringSliceContains(record.EnvironmentClasses, environmentClass) {
			return true
		}
	}
	return false
}

func specBundleHasWitnessCommand(records []specBundleWitnessCommand, commandID string, environmentClass string) bool {
	for _, record := range records {
		if record.CommandID == commandID &&
			record.Command != "" &&
			record.EnvironmentClass == environmentClass {
			return true
		}
	}
	return false
}

func specBundleHasPlanCommandArtifact(records []specBundlePlanCommand, commandID string, path string) bool {
	for _, record := range records {
		if record.ID != commandID {
			continue
		}
		for _, artifact := range record.ExpectedArtifacts {
			if artifact.Path == path && artifact.Kind != "" && artifact.Required {
				return true
			}
		}
	}
	return false
}

func specBundleHasPlanPolicy(records []specBundlePlanPolicy, commandID string) bool {
	for _, record := range records {
		if record.CommandID == commandID &&
			record.SideEffectClass != "" {
			return true
		}
	}
	return false
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func registryPublicationNonClaimCriterion() criterion {
	return criterion{
		Blocker:        nil,
		Criterion:      "Provider registry publication and artifact attestation remain separate evidence classes outside local candidate closeout.",
		CriterionClass: "advisory",
		CriterionID:    "proofkit.release_closeout.provider_publication_advisory",
		EvidenceRefs:   []string{},
		FailsWhen: []string{
			"Local closeout text claims registry publication, provider attestation, release approval, rollout approval, or production readiness.",
		},
		NonClaims: []string{
			"This advisory criterion records publication and attestation non-claims; it does not block local candidate package closeout.",
		},
		Owner:                  "proofkit.release-closeout",
		ProofRefs:              []string{"docs/specs/proofkit-supply-chain-quality/requirements.v1.json#REQ-PROOFKIT-QUALITY-018"},
		Status:                 "advisory_skipped",
		StructuredDecisionRefs: []string{},
		ValidatorRefs:          []string{"provider:npm-registry", "provider:pypi-registry", "provider:github-artifact-attestation"},
	}
}

func blockingCriterion(id string, text string, ok bool, evidenceRefs []string, validatorRefs []string, failsWhen []string, nonClaims []string) criterion {
	status := "missing_evidence"
	if ok {
		status = "satisfied"
	}
	sort.Strings(evidenceRefs)
	sort.Strings(validatorRefs)
	sort.Strings(failsWhen)
	sort.Strings(nonClaims)
	return criterion{
		Blocker:                nil,
		Criterion:              text,
		CriterionClass:         "blocking",
		CriterionID:            id,
		EvidenceRefs:           evidenceRefsIfSatisfied(status, evidenceRefs),
		FailsWhen:              failsWhen,
		NonClaims:              nonClaims,
		Owner:                  "proofkit.release-closeout",
		ProofRefs:              []string{},
		Status:                 status,
		StructuredDecisionRefs: []string{},
		ValidatorRefs:          validatorRefs,
	}
}

func evidenceRefsIfSatisfied(status string, refs []string) []string {
	if status == "satisfied" {
		return refs
	}
	return []string{}
}

func npmTarballName(name string, version string) string {
	return strings.Replace(strings.Replace(name, "@", "", 1), "/", "-", 1) + "-" + version + ".tgz"
}

func validPackRecords(root string, path string, manifest packageJSON) bool {
	records, err := readTypedJSON[[]packRecord](root, path)
	if err != nil || len(records) != 1 {
		return false
	}
	record := records[0]
	return record.Name == manifest.Name &&
		record.Version == manifest.Version &&
		record.Filename == npmTarballName(manifest.Name, manifest.Version) &&
		packRecordBytesMatch(root, record)
}

func packRecordBytesMatch(root string, record packRecord) bool {
	content, err := os.ReadFile(filepath.Join(root, "artifacts", "package", record.Filename))
	if err != nil || len(content) == 0 {
		return false
	}
	sha1Sum := sha1.Sum(content)
	if hex.EncodeToString(sha1Sum[:]) != record.Shasum {
		return false
	}
	hash := sha512.New()
	_, _ = hash.Write(content)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return integrity == record.Integrity
}

func readPythonPackageSet(root string, path string, manifest packageJSON) ([]pythonWheel, bool) {
	packages, err := readTypedJSON[pythonPackageSet](root, path)
	if err != nil || packages.PackageName != pythonPackageName || packages.PackageVersion != manifest.Version || len(packages.Packages) == 0 {
		return nil, false
	}
	for _, item := range packages.Packages {
		if item.Name != pythonPackageName || item.Version != manifest.Version || item.Filename == "" || !isSHA256(item.Sha256) || !isSHA256(item.BinarySha256) {
			return packages.Packages, false
		}
		if !pythonWheelBytesMatch(root, item) {
			return packages.Packages, false
		}
	}
	return packages.Packages, true
}

func pythonWheelBytesMatch(rootPath string, wheel pythonWheel) bool {
	if filepath.Base(wheel.Filename) != wheel.Filename || filepath.Clean(wheel.Filename) != wheel.Filename || !filepath.IsLocal(wheel.Filename) {
		return false
	}
	relativePath := filepath.Join("artifacts", "pypi", wheel.Filename)
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return false
	}
	defer root.Close()
	before, err := root.Lstat(relativePath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxPythonWheelBytes {
		return false
	}
	file, err := root.Open(relativePath)
	if err != nil {
		return false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return false
	}
	wheelHash := sha256.New()
	written, err := io.Copy(wheelHash, io.LimitReader(file, maxPythonWheelBytes+1))
	if err != nil || written != before.Size() || hex.EncodeToString(wheelHash.Sum(nil)) != wheel.Sha256 {
		return false
	}
	reader, err := zip.NewReader(file, before.Size())
	if err != nil || len(reader.File) > maxPythonWheelEntries {
		return false
	}
	seen := make(map[string]struct{}, len(reader.File))
	found := false
	for _, entry := range reader.File {
		if _, duplicate := seen[entry.Name]; duplicate {
			return false
		}
		seen[entry.Name] = struct{}{}
		if entry.Name != pythonWheelBinaryEntry {
			continue
		}
		if found || entry.Mode()&os.ModeSymlink != 0 || !entry.FileInfo().Mode().IsRegular() || entry.UncompressedSize64 > uint64(maxPythonBinaryBytes) {
			return false
		}
		found = true
		member, err := entry.Open()
		if err != nil {
			return false
		}
		binaryHash := sha256.New()
		binarySize, copyErr := io.Copy(binaryHash, io.LimitReader(member, maxPythonBinaryBytes+1))
		closeErr := member.Close()
		if copyErr != nil || closeErr != nil || binarySize != int64(entry.UncompressedSize64) || hex.EncodeToString(binaryHash.Sum(nil)) != wheel.BinarySha256 {
			return false
		}
	}
	after, statErr := file.Stat()
	pathAfter, pathErr := root.Lstat(relativePath)
	return found && statErr == nil && pathErr == nil && pathAfter.Mode()&os.ModeSymlink == 0 && os.SameFile(before, after) && os.SameFile(after, pathAfter) && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func releaseChecksumInventoriesMatch(root string, manifest packageJSON) bool {
	packRecords, err := readTypedJSON[[]packRecord](root, "artifacts/package/npm-pack.json")
	if err != nil || len(packRecords) != 1 {
		return false
	}
	packRecord := packRecords[0]
	if packRecord.Name != manifest.Name || packRecord.Version != manifest.Version || packRecord.Filename != npmTarballName(manifest.Name, manifest.Version) {
		return false
	}
	wheels, ok := readPythonPackageSet(root, "artifacts/pypi/python-packages.json", manifest)
	if !ok {
		return false
	}
	packageTargets := []string{filepath.ToSlash(filepath.Join("artifacts", "package", packRecord.Filename))}
	for _, wheel := range wheels {
		packageTargets = append(packageTargets, filepath.ToSlash(filepath.Join("artifacts", "pypi", wheel.Filename)))
	}
	checksumTargets := append(append([]string{}, packageTargets...), "artifacts/release/sbom.cdx.json")
	metadataTargets := []string{"artifacts/release/release-manifest.json", "artifacts/release/release-notes.md"}
	return checksumFileMatches(root, "artifacts/release/checksums.sha256", checksumTargets) &&
		checksumFileMatches(root, "artifacts/release/sbom-subjects.sha256", packageTargets) &&
		checksumFileMatches(root, "artifacts/release/metadata-checksums.sha256", metadataTargets)
}

func retainedReleaseEvidenceRefs(root string) []string {
	targets := retainedReleaseEvidenceTargets(root)
	if len(targets) == 0 {
		return []string{}
	}
	return append([]string{"artifacts/" + retainedevidence.ManifestPath}, targets...)
}

func retainedReleaseEvidenceMatches(root string) bool {
	paths := []string{
		"artifacts/" + retainedevidence.ManifestPath,
		"artifacts/attestations",
	}
	paths = append(paths, retainedReleaseEvidenceRepositoryPaths()...)
	for _, path := range paths {
		if pathEntryExists(root, path) {
			return retainedevidence.Verify(filepath.Join(root, "artifacts")) == nil
		}
	}
	return true
}

func retainedReleaseEvidenceTargets(root string) []string {
	targets := []string{}
	for _, repositoryPath := range retainedReleaseEvidenceRepositoryPaths() {
		if fileExists(root, repositoryPath) {
			targets = append(targets, repositoryPath)
		}
	}
	sort.Strings(targets)
	return targets
}

func retainedReleaseEvidenceRepositoryPaths() []string {
	paths := make([]string, 0, len(retainedevidence.EvidencePaths()))
	for _, path := range retainedevidence.EvidencePaths() {
		paths = append(paths, filepath.ToSlash(filepath.Join("artifacts", filepath.FromSlash(path))))
	}
	return paths
}

func checksumFileMatches(root string, checksumPath string, targetPaths []string) bool {
	expected, err := checksumLines(root, targetPaths)
	if err != nil {
		return false
	}
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(checksumPath)))
	if err != nil {
		return false
	}
	return bytes.Equal(content, []byte(strings.Join(expected, "\n")+"\n"))
}

func checksumLines(root string, targetPaths []string) ([]string, error) {
	targets := append([]string{}, targetPaths...)
	sort.Strings(targets)
	lines := make([]string, 0, len(targets))
	for _, path := range targets {
		sum, err := fileSHA256(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return nil, err
		}
		lines = append(lines, fmt.Sprintf("%s  %s", sum, filepath.Base(path)))
	}
	return lines, nil
}

func fileSHA256(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

func releaseManifestMatches(root string, manifest packageJSON) bool {
	release, err := readTypedJSON[releaseManifest](root, "artifacts/release/release-manifest.json")
	if err != nil {
		return false
	}
	return release.ArtifactKind == "proofkit.release-manifest.v1" &&
		release.Package.Name == manifest.Name &&
		release.Package.Version == manifest.Version &&
		len(release.NonClaims) > 0
}

func validSBOM(root string, path string) bool {
	sbom, err := readTypedJSON[cyclonedxBOM](root, path)
	return err == nil && sbom.BOMFormat == "CycloneDX" && sbom.SpecVersion != ""
}

func releaseNotesMatchChangeRecord(root string, path string, manifest packageJSON) bool {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return false
	}
	record, err := releasechange.Read(filepath.Join(root, filepath.FromSlash(releasechange.RecordPath)))
	if err != nil || releasechange.RequireVersion(record, manifest.Version) != nil {
		return false
	}
	pypiPublished := fileExists(root, "artifacts/pypi-registry/pypi-release.json")
	expected := releasechange.RenderMarkdown(record, manifest.Name, pythonPackageName, pypiPublished)
	return bytes.Equal(content, []byte(expected))
}

func hasChannelStatus(manifest releaseManifest, authority string, allowed ...string) bool {
	for _, channel := range manifest.Channels {
		if channel.AuthorityChannel != authority {
			continue
		}
		for _, status := range allowed {
			if channel.Status == status {
				return true
			}
		}
		return false
	}
	return false
}

func hasNPMRegistryChannelScope(manifest releaseManifest) bool {
	for _, channel := range manifest.Channels {
		if channel.AuthorityChannel != string(releasechannel.RegistryRelease) {
			continue
		}
		switch channel.Status {
		case "candidate":
			return hasNPMCandidateNonClaim(channel.NonClaims)
		case "published":
			return true
		default:
			return false
		}
	}
	return false
}

func hasNPMCandidateNonClaim(nonClaims []string) bool {
	for _, nonClaim := range nonClaims {
		if nonClaim == npmCandidateNonClaim {
			return true
		}
	}
	return false
}

func hasPlannedPyPIWithNonClaim(manifest releaseManifest) bool {
	for _, channel := range manifest.Channels {
		if channel.AuthorityChannel != string(releasechannel.PyPIRegistryRelease) {
			continue
		}
		if channel.Status == "published" {
			return true
		}
		return channel.Status == "planned" && containsExact(channel.NonClaims, pypiPlannedNonClaim)
	}
	return false
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func publishedWorkflowIdentitiesValid(manifest releaseManifest, packageManifest packageJSON) bool {
	repository, err := trustedpublisher.RepositorySlugFromGitHubURL(packageManifest.Repository.URL)
	if err != nil {
		return false
	}
	for _, channel := range manifest.Channels {
		if !isTrustedPublisherChannel(channel.AuthorityChannel) {
			if channel.PublicationMode != "" || channel.TrustedPublisher != nil {
				return false
			}
			continue
		}
		if channel.Status != "published" {
			if channel.PublicationMode != "" || channel.TrustedPublisher != nil {
				return false
			}
			continue
		}
		requiresIdentity, err := trustedpublisher.PublicationModeRequiresIdentity(channel.PublicationMode, channel.AuthorityChannel+" publicationMode")
		if err != nil {
			return false
		}
		if !requiresIdentity {
			if channel.TrustedPublisher != nil {
				return false
			}
			continue
		}
		if channel.TrustedPublisher == nil {
			return false
		}
		projectName := packageManifest.Name
		if channel.AuthorityChannel == string(releasechannel.PyPIRegistryRelease) {
			projectName = pythonPackageName
		}
		if _, err := releasepublisher.AdmitForAuthorityChannel(*channel.TrustedPublisher, channel.AuthorityChannel, projectName, packageManifest.Version, repository); err != nil {
			return false
		}
	}
	return true
}

func isTrustedPublisherChannel(authorityChannel string) bool {
	return authorityChannel == string(releasechannel.RegistryRelease) ||
		authorityChannel == string(releasechannel.PyPIRegistryRelease)
}

func allFilesExist(root string, paths []string) bool {
	for _, path := range paths {
		if !fileExists(root, path) {
			return false
		}
	}
	return true
}

func fileExists(root string, path string) bool {
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(path)))
	return err == nil && !info.IsDir() && info.Size() > 0
}

func pathEntryExists(root string, path string) bool {
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
	return err == nil
}

func readTypedJSON[T any](root string, path string) (T, error) {
	file, err := os.Open(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		var zero T
		return zero, err
	}
	defer file.Close()
	return admission.DecodeTypedJSON[T](file, 16<<20)
}
