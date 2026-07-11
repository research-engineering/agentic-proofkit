package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
)

const (
	artifactRoot                = "artifacts/proofkit"
	packageArtifactRoot         = "artifacts/package"
	packageGateEnvironmentClass = "local-go-python"
	pythonArtifactRoot          = "artifacts/pypi"
	maxJSONBytes                = 8 << 20
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	if err := os.MkdirAll(artifactRoot, 0o755); err != nil {
		return err
	}
	isGitHubActions := os.Getenv("GITHUB_ACTIONS") == "true"
	admission := producerAdmissionFromEnvironment(isGitHubActions, os.Getenv("GITHUB_REF_PROTECTED"), os.Getenv("PROOFKIT_MERGE_SATISFYING_PRODUCER"))
	trustInputs := ciTrustInputs()
	trustInputDigest := digestJSON(trustInputs)
	executionRecord, err := packageartifactrecord.Read(".")
	if err != nil {
		return fmt.Errorf("read package artifact execution record: %w", err)
	}
	if err := packageartifactrecord.ValidateCurrent(".", executionRecord); err != nil {
		return err
	}

	packageJSON, err := readJSONObject("package.json")
	if err != nil {
		return err
	}
	policyInput, err := readJSONObject("proofkit/receipt-producer-policy.json")
	if err != nil {
		return err
	}
	requirementBindingsInput, err := readJSONObject("proofkit/requirement-bindings.json")
	if err != nil {
		return err
	}
	witnessPlanInput, err := readJSONObject("proofkit/witness-plan.json")
	if err != nil {
		return err
	}

	sourceRevision := executionRecord.SourceRevision
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	provenance := map[string]any{
		"ciTrustInputs":          trustInputs,
		"generatedAt":            timestamp,
		"producerAdmissionClass": admission.ProducerAdmissionClass,
		"producerId":             admission.ProducerID,
		"runAttempt":             nullableEnv("GITHUB_RUN_ATTEMPT"),
		"runId":                  nullableEnv("GITHUB_RUN_ID"),
		"runUrl":                 runURL(isGitHubActions),
		"sourceRevision":         sourceRevision,
	}
	if err := writeJSON(filepath.Join(artifactRoot, "ci-provenance.json"), provenance); err != nil {
		return err
	}

	artifactRefs, err := packageArtifactRefs(packageJSON)
	if err != nil {
		return err
	}
	proofBindingDigest := digestFile("proofkit/requirement-bindings.json")
	witnessPlanDigest := digestFile("proofkit/witness-plan.json")
	packageJSONDigest := digestFile("package.json")
	goModDigest := digestFile("go.mod")
	goSumDigest := digestFile("go.sum")
	dependencyDigest := digestJSON(map[string]any{
		"goModDigest": goModDigest,
		"goSumDigest": goSumDigest,
	})
	commandDigest := digestJSON(map[string]any{
		"argv": stringsToAny(executionRecord.Argv),
		"id":   executionRecord.CommandID,
	})
	environmentDigest := "sha256:" + executionRecord.EnvironmentDigest
	preconditionDigest := digestJSON(map[string]any{
		"artifactSnapshotDigest": executionRecord.ArtifactSnapshotDigest,
		"ciTrustInputDigest":     trustInputDigest,
		"goModDigest":            goModDigest,
		"goSumDigest":            goSumDigest,
		"packageJsonDigest":      packageJSONDigest,
		"sourceSnapshotDigest":   executionRecord.SourceSnapshotDigest,
		"witnessPlanDigest":      witnessPlanDigest,
	})
	witnessSelectors, err := requirementIDsForCommand(requirementBindingsInput, "proofkit.package-artifact")
	if err != nil {
		return err
	}
	receipt := map[string]any{
		"artifactRefs":           artifactRefs,
		"commandDigest":          commandDigest,
		"dependencyDigest":       dependencyDigest,
		"environmentClass":       packageGateEnvironmentClass,
		"environmentDigest":      environmentDigest,
		"evidenceRefs":           packageGateEvidenceRefs(),
		"exitCode":               0,
		"finishedAt":             executionRecord.FinishedAt,
		"lockfileDigest":         nil,
		"nonClaims":              aggregatePackageGateNonClaims(),
		"preconditionDigest":     preconditionDigest,
		"producerAdmissionClass": admission.ProducerAdmissionClass,
		"producerId":             admission.ProducerID,
		"proofBindingDigest":     proofBindingDigest,
		"proofPlanId":            stringField(witnessPlanInput, "schedulerPlanId"),
		"provenanceRef":          filepath.Join(artifactRoot, "ci-provenance.json"),
		"receiptId":              receiptID(admission.IsGitHubActions),
		"receiptKind":            "proofkit.package-artifact",
		"runnerClass":            admission.RunnerClass,
		"runnerIdentity":         admission.RunnerIdentity,
		"sourceRevision":         sourceRevision,
		"startedAt":              executionRecord.StartedAt,
		"status":                 "passed",
		"toolchainDigest":        "sha256:" + executionRecord.ToolchainDigest,
		"witnessSelectorDigest":  digestJSON(stringsToAny(witnessSelectors)),
		"witnessSelectors":       stringsToAny(witnessSelectors),
	}
	proofReceiptInput := map[string]any{
		"schemaVersion": 1,
		"receiptSetId":  "proofkit.self-hosting.proof-receipts",
		"receipts":      []any{receipt},
		"nonClaims": sortedStrings([]string{
			"Proofkit self-hosting receipt input projects one completed package-artifact execution record and its current source and artifact snapshots.",
			"Proofkit self-hosting receipt input does not replace native package gate execution.",
			"Proofkit self-hosting receipt input does not attest later self-coverage or release-closeout steps.",
		}),
	}
	if err := writeJSON(filepath.Join(artifactRoot, "self-hosting-proof-receipts.json"), proofReceiptInput); err != nil {
		return err
	}
	decodedProofReceiptInput, err := decodeStableJSON(proofReceiptInput)
	if err != nil {
		return err
	}
	proofReceiptRecord, proofReceiptExit, err := proofreceiptadmission.Build(decodedProofReceiptInput)
	if err != nil {
		return err
	}

	producerReceipt := map[string]any{
		"artifactRefs":             artifactPaths(artifactRefs),
		"environmentClass":         packageGateEnvironmentClass,
		"evidenceRef":              filepath.Join(artifactRoot, "self-hosting-proof-receipts.json"),
		"nonClaim":                 producerNonClaim(admission),
		"producerId":               admission.ProducerID,
		"provenanceRef":            filepath.Join(artifactRoot, "ci-provenance.json"),
		"receiptId":                receipt["receiptId"],
		"receiptKind":              receipt["receiptKind"],
		"satisfiesMergeObligation": admission.SatisfiesMergeObligation,
		"status":                   "passed",
		"subjectRef":               "proofkit.package-boundary.self-hosting",
	}
	receiptProducerInput := cloneObject(policyInput)
	receiptProducerInput["receipts"] = []any{producerReceipt}
	if err := writeJSON(filepath.Join(artifactRoot, "self-hosting-receipt-producer-admission.json"), receiptProducerInput); err != nil {
		return err
	}
	decodedReceiptProducerInput, err := decodeStableJSON(receiptProducerInput)
	if err != nil {
		return err
	}
	receiptProducerRecord, receiptProducerExit, err := receiptproduceradmission.Build(decodedReceiptProducerInput)
	if err != nil {
		return err
	}

	if err := runProofkit("proof-receipt-admission", filepath.Join(artifactRoot, "self-hosting-proof-receipts.json"), filepath.Join(artifactRoot, "self-hosting-proof-receipt-admission-report.json")); err != nil {
		return err
	}
	if err := runProofkit("receipt-producer-admission", filepath.Join(artifactRoot, "self-hosting-receipt-producer-admission.json"), filepath.Join(artifactRoot, "self-hosting-receipt-producer-admission-report.json")); err != nil {
		return err
	}

	bundleInput := map[string]any{
		"schemaVersion":            1,
		"bundleId":                 "proofkit.self-hosting.spec-proof-bundle",
		"requirementBindings":      requirementBindingsInput,
		"witnessPlan":              witnessPlanInput,
		"receiptAdmission":         childReport(proofReceiptRecord, proofReceiptExit, []any{receipt}, nil, proofReceiptInput),
		"receiptProducerAdmission": childReport(receiptProducerRecord, receiptProducerExit, []any{producerReceipt}, receiptProducerInput["producers"], receiptProducerInput),
		"mergeRequiredReceiptIds":  mergeRequiredReceiptIDs(admission.SatisfiesMergeObligation, receipt),
		"nonClaims": sortedStrings([]string{
			"Self-hosting spec-proof bundle input does not approve package release, registry publication, consumer rollout, or production readiness.",
			"Self-hosting spec-proof bundle input is generated from caller-owned tracked records and current run reports.",
		}),
	}
	if err := writeJSON(filepath.Join(artifactRoot, "self-hosting-spec-proof-bundle.json"), bundleInput); err != nil {
		return err
	}
	if err := runProofkit("spec-proof-bundle-admission", filepath.Join(artifactRoot, "self-hosting-spec-proof-bundle.json"), filepath.Join(artifactRoot, "self-hosting-spec-proof-bundle-admission-report.json")); err != nil {
		return err
	}
	fmt.Printf("self-hosting receipt producer=%s admission=%s\n", admission.ProducerID, admission.ProducerAdmissionClass)
	return nil
}

func packageGateEvidenceRefs() []any {
	return sortedStrings([]string{
		filepath.Join(artifactRoot, "ci-provenance.json"),
		filepath.Join(artifactRoot, "self-hosting-proof-receipts.json"),
		filepath.FromSlash(packageartifactrecord.RecordPath),
		filepath.Join(packageArtifactRoot, "npm-pack.json"),
		filepath.Join(pythonArtifactRoot, "python-packages.json"),
	})
}

func aggregatePackageGateNonClaims() []any {
	return sortedStrings([]string{
		"Self-hosting package receipts aggregate Go and Python package-gate evidence and do not provide independent local-go and local-python receipt classes.",
		"Self-hosting proof receipts do not authenticate the producer inside Proofkit.",
		"Self-hosting proof receipts do not claim registry publication or consumer rollout.",
		"Self-hosting proof receipts do not prove freshness after the bound local execution-record snapshot, external-provider freshness, or merge approval.",
	})
}

type producerAdmission struct {
	IsGitHubActions          bool
	ProducerAdmissionClass   string
	ProducerID               string
	RunnerClass              string
	RunnerIdentity           string
	SatisfiesMergeObligation bool
}

var ciTrustInputNames = []string{
	"GITHUB_ACTIONS",
	"GITHUB_EVENT_NAME",
	"GITHUB_REF",
	"GITHUB_REF_NAME",
	"GITHUB_REF_PROTECTED",
	"GITHUB_REF_TYPE",
	"GITHUB_REPOSITORY",
	"GITHUB_RUN_ATTEMPT",
	"GITHUB_RUN_ID",
	"GITHUB_SERVER_URL",
	"GITHUB_SHA",
	"GITHUB_WORKFLOW",
	"PROOFKIT_MERGE_SATISFYING_PRODUCER",
}

func ciTrustInputs() map[string]any {
	return ciTrustInputsFromLookup(os.Getenv)
}

func ciTrustInputsFromLookup(lookup func(string) string) map[string]any {
	result := make(map[string]any, len(ciTrustInputNames))
	for _, name := range ciTrustInputNames {
		value := lookup(name)
		if value == "" {
			result[name] = nil
			continue
		}
		result[name] = value
	}
	return result
}

func producerAdmissionFromEnvironment(isGitHubActions bool, refProtected string, explicitMergeSatisfying string) producerAdmission {
	if !isGitHubActions {
		return producerAdmission{
			IsGitHubActions:          false,
			ProducerAdmissionClass:   "advisory",
			ProducerID:               "local.developer",
			RunnerClass:              "local",
			RunnerIdentity:           "local.developer",
			SatisfiesMergeObligation: false,
		}
	}
	_ = refProtected
	_ = explicitMergeSatisfying
	producerID := "github.actions.package"
	return producerAdmission{
		IsGitHubActions:          true,
		ProducerAdmissionClass:   "advisory",
		ProducerID:               producerID,
		RunnerClass:              "github.actions.hosted",
		RunnerIdentity:           producerID,
		SatisfiesMergeObligation: false,
	}
}

func runProofkit(command string, inputPath string, outputPath string) error {
	binaryPath, err := currentPlatformBinary()
	if err != nil {
		return err
	}
	result := exec.Command(binaryPath, command, "--input", inputPath)
	output, err := result.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w\n%s", command, err, string(output))
	}
	if err := os.WriteFile(outputPath, output, 0o644); err != nil {
		return err
	}
	reportOutput, err := admission.DecodeJSON(bytes.NewReader(output), maxJSONBytes)
	if err != nil {
		return err
	}
	record, ok := reportOutput.(map[string]any)
	if !ok || record["state"] != "passed" {
		return fmt.Errorf("%s did not pass", command)
	}
	return nil
}

func currentPlatformBinary() (string, error) {
	osName := runtime.GOOS
	cpuName := runtime.GOARCH
	if cpuName == "amd64" {
		cpuName = "x64"
	}
	path := filepath.Join("dist", "platform", osName+"-"+cpuName, "agentic-proofkit")
	if stat, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("current platform binary is unavailable at %s: %w", path, err)
	} else if stat.IsDir() {
		return "", fmt.Errorf("current platform binary path is a directory: %s", path)
	}
	return path, nil
}

func packageArtifactRefs(packageJSON map[string]any) ([]any, error) {
	raw, err := readJSON(filepath.Join(packageArtifactRoot, "npm-pack.json"))
	if err != nil {
		return nil, err
	}
	records, ok := raw.([]any)
	if !ok || len(records) == 0 {
		return nil, fmt.Errorf("artifacts/package/npm-pack.json must describe the package artifact set")
	}
	version := stringField(packageJSON, "version")
	expected := map[string]struct{}{stringField(packageJSON, "name"): {}}
	refs := []map[string]any{
		{"kind": "report", "path": filepath.Join(packageArtifactRoot, "npm-pack.json"), "sha256": digestFile(filepath.Join(packageArtifactRoot, "npm-pack.json"))},
	}
	seen := map[string]struct{}{}
	for _, item := range records {
		record, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("artifacts/package/npm-pack.json record must be an object")
		}
		name := stringField(record, "name")
		if _, ok := expected[name]; !ok {
			return nil, fmt.Errorf("unexpected package artifact %s", name)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate package artifact %s", name)
		}
		seen[name] = struct{}{}
		if stringField(record, "version") != version {
			return nil, fmt.Errorf("package artifact %s version must match package.json", name)
		}
		filename := stringField(record, "filename")
		if filename == "" {
			return nil, fmt.Errorf("package artifact %s must include filename", name)
		}
		tarballPath := filepath.Join(packageArtifactRoot, filename)
		if _, err := os.Stat(tarballPath); err != nil {
			return nil, err
		}
		refs = append(refs, map[string]any{"kind": "artifact", "path": tarballPath, "sha256": digestFile(tarballPath)})
	}
	if len(seen) != len(expected) {
		return nil, fmt.Errorf("package artifact set has %d packages, expected %d", len(seen), len(expected))
	}
	pythonRefs, err := pythonArtifactRefs(version)
	if err != nil {
		return nil, err
	}
	refs = append(refs, pythonRefs...)
	sort.Slice(refs, func(left, right int) bool {
		return refs[left]["path"].(string) < refs[right]["path"].(string)
	})
	result := make([]any, 0, len(refs))
	for _, ref := range refs {
		result = append(result, ref)
	}
	return result, nil
}

func pythonArtifactRefs(version string) ([]map[string]any, error) {
	path := filepath.Join(pythonArtifactRoot, "python-packages.json")
	raw, err := readJSONObject(path)
	if err != nil {
		return nil, err
	}
	if stringField(raw, "packageVersion") != version {
		return nil, fmt.Errorf("%s packageVersion must match package.json", path)
	}
	refs := []map[string]any{
		{"kind": "report", "path": path, "sha256": digestFile(path)},
	}
	rawPackages, ok := raw["packages"].([]any)
	if !ok || len(rawPackages) == 0 {
		return nil, fmt.Errorf("%s must contain wheel packages", path)
	}
	seen := map[string]struct{}{}
	for _, item := range rawPackages {
		record, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s package record must be an object", path)
		}
		filename := stringField(record, "filename")
		if filename == "" {
			return nil, fmt.Errorf("%s package record must include filename", path)
		}
		if _, exists := seen[filename]; exists {
			return nil, fmt.Errorf("duplicate Python wheel artifact %s", filename)
		}
		seen[filename] = struct{}{}
		wheelPath := filepath.Join(pythonArtifactRoot, filename)
		if _, err := os.Stat(wheelPath); err != nil {
			return nil, err
		}
		if expected := stringField(record, "sha256"); expected != "" {
			if actual := strings.TrimPrefix(digestFile(wheelPath), "sha256:"); actual != expected {
				return nil, fmt.Errorf("python wheel sha256 mismatch for %s", filename)
			}
		}
		refs = append(refs, map[string]any{"kind": "artifact", "path": wheelPath, "sha256": digestFile(wheelPath)})
	}
	return refs, nil
}

func childReport(record report.Record, exitCode int, receipts []any, producers any, childInput map[string]any) map[string]any {
	if producers == nil {
		producers = []any{}
	}
	child := map[string]any{
		"exitCode":  exitCode,
		"failures":  []any{},
		"nonClaims": childInput["nonClaims"],
		"producers": producers,
		"receipts":  receipts,
		"report":    record.JSONValue(),
	}
	if childInput["environmentClasses"] != nil || childInput["receiptKinds"] != nil {
		child["environmentClasses"] = childInput["environmentClasses"]
		child["receiptKinds"] = childInput["receiptKinds"]
	}
	return child
}

func readJSON(path string) (any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := admission.DecodeJSON(file, maxJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return value, nil
}

func readJSONObject(path string) (map[string]any, error) {
	value, err := readJSON(path)
	if err != nil {
		return nil, err
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON object", path)
	}
	return record, nil
}

func writeJSON(path string, value any) error {
	output, err := stablejson.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, output, 0o644)
}

func decodeStableJSON(value any) (any, error) {
	output, err := stablejson.Marshal(value)
	if err != nil {
		return nil, err
	}
	return admission.DecodeJSON(bytes.NewReader(output), maxJSONBytes)
}

func digestFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestJSON(value any) string {
	output, err := stablejson.Marshal(value)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(output)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func nullableEnv(name string) any {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return nil
}

func runURL(isGitHubActions bool) any {
	if !isGitHubActions || os.Getenv("GITHUB_SERVER_URL") == "" || os.Getenv("GITHUB_REPOSITORY") == "" || os.Getenv("GITHUB_RUN_ID") == "" {
		return nil
	}
	return fmt.Sprintf("%s/%s/actions/runs/%s", os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID"))
}

func receiptID(isGitHubActions bool) string {
	if isGitHubActions {
		return "receipt.github.actions.package-artifact"
	}
	return "receipt.local.package-artifact"
}

func producerNonClaim(admission producerAdmission) string {
	if admission.SatisfiesMergeObligation {
		return "GitHub Actions merge-satisfying receipt admission depends on repository-owned workflow, protected-ref evidence, and explicit workflow opt-in."
	}
	if admission.IsGitHubActions {
		return "GitHub Actions advisory receipts do not satisfy merge obligations without a CI-owned producer admission wrapper."
	}
	return "Local advisory receipts do not satisfy merge obligations."
}

func mergeRequiredReceiptIDs(satisfiesMergeObligation bool, receipt map[string]any) []any {
	if !satisfiesMergeObligation {
		return []any{}
	}
	return []any{receipt["receiptId"]}
}

func requirementIDsForCommand(raw any, commandID string) ([]string, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("requirement bindings input must be an object")
	}
	bindings, ok := record["bindings"].([]any)
	if !ok {
		return nil, fmt.Errorf("requirement bindings input must include bindings")
	}
	selectorSet := map[string]struct{}{}
	for _, item := range bindings {
		binding, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement binding must be an object")
		}
		for _, command := range stringArrayField(binding, "commandIds") {
			if command == commandID {
				selectorSet[stringField(binding, "requirementId")] = struct{}{}
			}
		}
	}
	if len(selectorSet) == 0 {
		return nil, fmt.Errorf("requirement bindings contain no selectors for command %s", commandID)
	}
	result := make([]string, 0, len(selectorSet))
	for selector := range selectorSet {
		result = append(result, selector)
	}
	sort.Strings(result)
	return result, nil
}

func artifactPaths(artifactRefs []any) []any {
	paths := make([]string, 0, len(artifactRefs))
	for _, item := range artifactRefs {
		record, ok := item.(map[string]any)
		if !ok {
			panic("artifact ref must be an object")
		}
		paths = append(paths, stringField(record, "path"))
	}
	sort.Strings(paths)
	return stringsToAny(paths)
}

func cloneObject(raw any) map[string]any {
	record, ok := raw.(map[string]any)
	if !ok {
		panic("value must be an object")
	}
	result := make(map[string]any, len(record))
	for key, value := range record {
		result[key] = value
	}
	return result
}

func stringField(raw any, key string) string {
	record, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	value, _ := record[key].(string)
	return value
}

func stringArrayField(raw any, key string) []string {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	values, ok := record[key].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil
		}
		result = append(result, text)
	}
	return result
}

func sortedStrings(values []string) []any {
	sort.Strings(values)
	return stringsToAny(values)
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
