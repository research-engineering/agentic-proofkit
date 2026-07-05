package main

import (
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
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasepublisher"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/trustedpublisher"
)

const (
	completionID                = "proofkit.release_closeout.current_package_gate"
	npmCandidateNonClaim        = "Local npm package artifacts are candidate tarball evidence; they do not prove npm registry publication, registry install authority, or consumer adoption."
	packageGateEnvironmentClass = "local-go-python"
	pythonPackageName           = "agentic-proofkit"
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
	Filename string `json:"filename"`
	Name     string `json:"name"`
	Version  string `json:"version"`
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
	CLIContract   map[string]any              `json:"cliContract"`
	CommandRoutes coverageCommandRouteMetrics `json:"commandRoutes"`
	DeadZones     coverageDeadZoneMetrics     `json:"deadZones"`
	NonClaims     []string                    `json:"nonClaims"`
	ProofBindings map[string]any              `json:"proofBindings"`
	Requirements  map[string]any              `json:"requirements"`
	SchemaVersion int                         `json:"schemaVersion"`
	WitnessPlan   map[string]any              `json:"witnessPlan"`
}

type coverageCommandRouteMetrics struct {
	AdmittedInventoryEntryCount               *int      `json:"admittedInventoryEntryCount"`
	CommandCount                              *int      `json:"commandCount"`
	ContractOnlyCommandCount                  *int      `json:"contractOnlyCommandCount"`
	ContractOnlyCommands                      *[]string `json:"contractOnlyCommands"`
	CommandWithoutSemanticFalsifierRouteCount *int      `json:"commandWithoutSemanticFalsifierRouteCount"`
	CommandsWithoutSemanticFalsifierRoute     *[]string `json:"commandsWithoutSemanticFalsifierRoute"`
	RouteCount                                *int      `json:"routeCount"`
	RouteOnlyCommandCount                     *int      `json:"routeOnlyCommandCount"`
	RouteOnlyCommands                         *[]string `json:"routeOnlyCommands"`
	RouteSmokeCount                           *int      `json:"routeSmokeCount"`
	SemanticInventoryEntryCount               *int      `json:"semanticInventoryEntryCount"`
	SemanticRouteCount                        *int      `json:"semanticRouteCount"`
	UnknownSemanticCommandRefCount            *int      `json:"unknownSemanticCommandRefCount"`
	UnknownSemanticCommandRefs                *[]string `json:"unknownSemanticCommandRefs"`
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
	EnvironmentClass       string   `json:"environmentClass"`
	EvidenceRefs           []string `json:"evidenceRefs"`
	ExitCode               int      `json:"exitCode"`
	NonClaims              []string `json:"nonClaims"`
	ProducerAdmissionClass string   `json:"producerAdmissionClass"`
	ProducerID             string   `json:"producerId"`
	ProofPlanID            string   `json:"proofPlanId"`
	ProvenanceRef          string   `json:"provenanceRef"`
	ReceiptID              string   `json:"receiptId"`
	ReceiptKind            string   `json:"receiptKind"`
	RunnerClass            string   `json:"runnerClass"`
	Status                 string   `json:"status"`
	WitnessSelectors       []string `json:"witnessSelectors"`
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
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
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
		releaseNotesIncludeRollback(root, "artifacts/release/release-notes.md") &&
		releaseChecksumInventoriesMatch(root, manifest) &&
		retainedReleaseEvidenceMatches(root) &&
		allFilesExist(root, evidence)
	return blockingCriterion(
		"proofkit.release_closeout.manifest_and_sbom",
		"Release manifest, rollback-capable release notes, package checksums, metadata checksums, SBOM, and SBOM subject digests must exist for the current package version.",
		ok,
		evidence,
		[]string{"npm:release:manifest", "npm:release:sbom"},
		[]string{"Release manifest, rollback-capable notes, checksum inventory, metadata checksum inventory, SBOM, or SBOM subject digest is missing or invalid."},
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
		"artifacts/proofkit/coverage-metrics.json",
		"artifacts/proofkit/self-hosting-proof-receipt-admission-report.json",
		"artifacts/proofkit/self-hosting-proof-receipts.json",
		"artifacts/proofkit/self-hosting-receipt-producer-admission-report.json",
		"artifacts/proofkit/self-hosting-receipt-producer-admission.json",
		"artifacts/proofkit/self-hosting-spec-proof-bundle-admission-report.json",
		"artifacts/proofkit/self-hosting-spec-proof-bundle.json",
	}
	ok := selfEvidenceValid(root)
	return blockingCriterion(
		"proofkit.release_closeout.self_evidence",
		"Self-hosting receipt, producer admission, spec-proof bundle, and coverage metrics evidence must exist as local advisory closeout evidence.",
		ok,
		evidence,
		[]string{"npm:self:receipt", "npm:self:coverage"},
		[]string{"Self-hosting receipt, producer admission, spec-proof bundle, or coverage metrics evidence is missing or invalid."},
		[]string{"This criterion does not make local advisory receipts merge-satisfying or release-satisfying provider evidence."},
	)
}

func selfEvidenceValid(root string) bool {
	return coverageMetricsMatches(root, "artifacts/proofkit/coverage-metrics.json") &&
		selfEvidenceIdentityConsistent(root) &&
		reportMatches(root, "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json", "proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "passed", []string{"proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts"}) &&
		proofReceiptSetMatches(root, "artifacts/proofkit/self-hosting-proof-receipts.json") &&
		reportMatches(root, "artifacts/proofkit/self-hosting-receipt-producer-admission-report.json", "proofkit.receipt-producer-admission", "proofkit.receipt-producer-policy", "passed", []string{"proofkit.receipt-producer-admission.boundary", "proofkit.receipt-producer-admission.coverage", "proofkit.receipt-producer-admission.receipts"}) &&
		receiptProducerPolicyMatches(root, "artifacts/proofkit/self-hosting-receipt-producer-admission.json") &&
		reportMatches(root, "artifacts/proofkit/self-hosting-spec-proof-bundle-admission-report.json", "proofkit.spec-proof-bundle-admission", "proofkit.self-hosting.spec-proof-bundle", "passed", []string{"proofkit.spec-proof-bundle-admission.accepted"}) &&
		specProofBundleMatches(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json")
}

type selfHostingReceiptIdentity struct {
	ProducerID string
	ReceiptID  string
}

func selfEvidenceIdentityConsistent(root string) bool {
	receiptSet, err := readTypedJSON[proofReceiptSetEvidence](root, "artifacts/proofkit/self-hosting-proof-receipts.json")
	if err != nil || len(receiptSet.Receipts) != 1 {
		return false
	}
	proofIdentity, ok := proofReceiptIdentity(receiptSet.Receipts[0])
	if !ok {
		return false
	}
	producerPolicy, err := readTypedJSON[receiptProducerPolicyEvidence](root, "artifacts/proofkit/self-hosting-receipt-producer-admission.json")
	if err != nil || len(producerPolicy.Receipts) != 1 {
		return false
	}
	producerIdentity, ok := producerReceiptIdentity(producerPolicy.Receipts[0])
	if !ok || producerIdentity != proofIdentity {
		return false
	}
	bundle, err := readTypedJSON[specProofBundleEvidence](root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json")
	if err != nil ||
		len(bundle.ReceiptAdmission.Receipts) != 1 ||
		len(bundle.ReceiptProducerAdmission.Receipts) != 1 {
		return false
	}
	bundleProofIdentity, ok := proofReceiptIdentity(bundle.ReceiptAdmission.Receipts[0])
	if !ok || bundleProofIdentity != proofIdentity {
		return false
	}
	bundleProducerIdentity, ok := producerReceiptIdentity(bundle.ReceiptProducerAdmission.Receipts[0])
	return ok && bundleProducerIdentity == proofIdentity
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

func coverageMetricsMatches(root string, path string) bool {
	record, err := readTypedJSON[coverageMetricsEvidence](root, path)
	return err == nil &&
		record.SchemaVersion == 1 &&
		record.ArtifactKind == "proofkit.coverage-metrics.v1" &&
		len(record.CLIContract) > 0 &&
		len(record.NonClaims) > 0 &&
		len(record.ProofBindings) > 0 &&
		len(record.Requirements) > 0 &&
		len(record.WitnessPlan) > 0 &&
		coverageDeadZonesEmpty(record.DeadZones) &&
		commandRouteDefectsEmpty(record.CommandRoutes)
}

func reportMatches(root string, path string, wantKind string, wantID string, wantState string, wantRuleIDs []string) bool {
	record, err := readTypedJSON[selfEvidenceReport](root, path)
	return err == nil && reportRecordMatches(record, wantKind, wantID, wantState, wantRuleIDs)
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

func commandRouteDefectsEmpty(routes coverageCommandRouteMetrics) bool {
	return positiveInt(routes.AdmittedInventoryEntryCount) &&
		positiveInt(routes.CommandCount) &&
		positiveInt(routes.RouteCount) &&
		nonNegativeInt(routes.RouteSmokeCount) &&
		positiveInt(routes.SemanticInventoryEntryCount) &&
		positiveInt(routes.SemanticRouteCount) &&
		zeroInt(routes.CommandWithoutSemanticFalsifierRouteCount) &&
		zeroInt(routes.ContractOnlyCommandCount) &&
		zeroInt(routes.RouteOnlyCommandCount) &&
		zeroInt(routes.UnknownSemanticCommandRefCount) &&
		emptyStringSlice(routes.CommandsWithoutSemanticFalsifierRoute) &&
		emptyStringSlice(routes.ContractOnlyCommands) &&
		emptyStringSlice(routes.RouteOnlyCommands) &&
		emptyStringSlice(routes.UnknownSemanticCommandRefs)
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
	record, err := readTypedJSON[proofReceiptSetEvidence](root, path)
	return err == nil &&
		record.SchemaVersion == 1 &&
		record.ReceiptSetID == "proofkit.self-hosting.proof-receipts" &&
		len(record.NonClaims) > 0 &&
		len(record.Receipts) == 1 &&
		proofReceiptMatches(record.Receipts[0])
}

func proofReceiptMatches(record proofReceiptEvidence) bool {
	return selfHostingReceiptIdentityMatches(record.ReceiptID, record.ProducerID, record.RunnerClass) &&
		record.ReceiptKind == "proofkit.package-gate" &&
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
	record, err := readTypedJSON[receiptProducerPolicyEvidence](root, path)
	return err == nil &&
		record.SchemaVersion == 1 &&
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
		receipt.ReceiptKind == "proofkit.package-gate" &&
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
		return receiptID == "receipt.local.package-gate" && runnerClass == "local"
	case "github.actions.package":
		return receiptID == "receipt.github.actions.package-gate" && runnerClass == "github.actions.hosted"
	default:
		return false
	}
}

func selfHostingReceiptProducerMatches(receiptID string, producerID string) bool {
	switch producerID {
	case "local.developer":
		return receiptID == "receipt.local.package-gate"
	case "github.actions.package":
		return receiptID == "receipt.github.actions.package-gate"
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
	record, err := readTypedJSON[specProofBundleEvidence](root, path)
	return err == nil &&
		record.SchemaVersion == 1 &&
		record.BundleID == "proofkit.self-hosting.spec-proof-bundle" &&
		len(record.NonClaims) > 0 &&
		len(record.MergeRequiredReceiptIDs) == 0 &&
		specBundleReceiptAdmissionMatches(record.ReceiptAdmission) &&
		specBundleReceiptProducerAdmissionMatches(record.ReceiptProducerAdmission) &&
		specBundleRequirementBindingsMatch(record.RequirementBindings) &&
		specBundleWitnessPlanMatches(record.WitnessPlan)
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
		specBundleHasRequirement(record.Requirements, "REQ-PROOFKIT-PACKAGE-004") &&
		specBundleHasBinding(record.Bindings, "REQ-PROOFKIT-PACKAGE-004", "proofkit.ci-receipt-anchor", packageGateEnvironmentClass) &&
		specBundleHasWitnessCommand(record.WitnessCommands, "proofkit.ci-receipt-anchor", packageGateEnvironmentClass)
}

func specBundleWitnessPlanMatches(record specBundleWitnessPlan) bool {
	return record.SchemaVersion == 1 &&
		record.SchedulerPlanID == "proofkit.self-hosting.witness-plan" &&
		len(record.NonClaims) > 0 &&
		specBundleHasPlanCommandArtifact(record.Commands, "proofkit.ci-receipt-anchor", "artifacts/proofkit/self-hosting-spec-proof-bundle.json") &&
		specBundleHasPlanPolicy(record.Policies, "proofkit.ci-receipt-anchor") &&
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
		if item.Name != pythonPackageName || item.Version != manifest.Version || item.Filename == "" {
			return packages.Packages, false
		}
		if !fileExists(root, filepath.Join("artifacts", "pypi", item.Filename)) {
			return packages.Packages, false
		}
	}
	return packages.Packages, true
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
	return append([]string{"artifacts/release/retained-evidence-checksums.sha256"}, targets...)
}

func retainedReleaseEvidenceMatches(root string) bool {
	targets := retainedReleaseEvidenceTargets(root)
	if len(targets) == 0 {
		return true
	}
	return checksumFileMatches(root, "artifacts/release/retained-evidence-checksums.sha256", targets)
}

func retainedReleaseEvidenceTargets(root string) []string {
	targets := []string{}
	if fileExists(root, "artifacts/release/github-release.json") {
		targets = append(targets, "artifacts/release/github-release.json")
	}
	attestationRoot := filepath.Join(root, "artifacts", "attestations")
	_ = filepath.WalkDir(attestationRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		targets = append(targets, filepath.ToSlash(relative))
		return nil
	})
	sort.Strings(targets)
	return targets
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
	return string(content) == strings.Join(expected, "\n")+"\n"
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

func releaseNotesIncludeRollback(root string, path string) bool {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil || len(content) == 0 {
		return false
	}
	normalized := strings.ToLower(string(content))
	return strings.Contains(normalized, "rollback") && strings.Contains(normalized, "npm install")
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
		return channel.Status == "planned" && len(channel.NonClaims) > 0
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
		if _, err := releasepublisher.AdmitForAuthorityChannel(*channel.TrustedPublisher, channel.AuthorityChannel, packageManifest.Name, packageManifest.Version, repository); err != nil {
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

func readTypedJSON[T any](root string, path string) (T, error) {
	file, err := os.Open(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		var zero T
		return zero, err
	}
	defer file.Close()
	return admission.DecodeTypedJSON[T](file, 16<<20)
}
