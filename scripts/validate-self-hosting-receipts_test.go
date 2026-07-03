package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"go.yaml.in/yaml/v3"
)

func TestProducerAdmissionFromEnvironmentDoesNotMintMergeSatisfyingReceipts(t *testing.T) {
	cases := []struct {
		name                    string
		isGitHubActions         bool
		refProtected            string
		explicitMergeSatisfying string
		wantAdmission           producerAdmission
	}{
		{
			name: "local receipts are advisory",
			wantAdmission: producerAdmission{
				IsGitHubActions:          false,
				ProducerAdmissionClass:   "advisory",
				ProducerID:               "local.developer",
				RunnerClass:              "local",
				RunnerIdentity:           "local.developer",
				SatisfiesMergeObligation: false,
			},
		},
		{
			name:                    "github actions without protected ref is advisory",
			isGitHubActions:         true,
			explicitMergeSatisfying: "true",
			wantAdmission: producerAdmission{
				IsGitHubActions:          true,
				ProducerAdmissionClass:   "advisory",
				ProducerID:               "github.actions.package",
				RunnerClass:              "github.actions.hosted",
				RunnerIdentity:           "github.actions.package",
				SatisfiesMergeObligation: false,
			},
		},
		{
			name:            "github actions without explicit opt-in is advisory",
			isGitHubActions: true,
			refProtected:    "true",
			wantAdmission: producerAdmission{
				IsGitHubActions:          true,
				ProducerAdmissionClass:   "advisory",
				ProducerID:               "github.actions.package",
				RunnerClass:              "github.actions.hosted",
				RunnerIdentity:           "github.actions.package",
				SatisfiesMergeObligation: false,
			},
		},
		{
			name:                    "protected github actions with explicit opt-in remains advisory without CI-owned wrapper",
			isGitHubActions:         true,
			refProtected:            "true",
			explicitMergeSatisfying: "true",
			wantAdmission: producerAdmission{
				IsGitHubActions:          true,
				ProducerAdmissionClass:   "advisory",
				ProducerID:               "github.actions.package",
				RunnerClass:              "github.actions.hosted",
				RunnerIdentity:           "github.actions.package",
				SatisfiesMergeObligation: false,
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			admission := producerAdmissionFromEnvironment(item.isGitHubActions, item.refProtected, item.explicitMergeSatisfying)
			if !reflect.DeepEqual(admission, item.wantAdmission) {
				t.Fatalf("producerAdmissionFromEnvironment() = %#v", admission)
			}
		})
	}
}

func TestProducerAdmissionDerivedReceiptHelpers(t *testing.T) {
	advisory := producerAdmissionFromEnvironment(true, "false", "true")
	if got := producerNonClaim(advisory); got != "GitHub Actions advisory receipts do not satisfy merge obligations without a CI-owned producer admission wrapper." {
		t.Fatalf("producerNonClaim(advisory) = %q", got)
	}
	if ids := mergeRequiredReceiptIDs(advisory.SatisfiesMergeObligation, map[string]any{"receiptId": "receipt.test"}); len(ids) != 0 {
		t.Fatalf("mergeRequiredReceiptIDs(advisory) = %#v", ids)
	}

	envOnly := producerAdmissionFromEnvironment(true, "true", "true")
	if got := producerNonClaim(envOnly); got != "GitHub Actions advisory receipts do not satisfy merge obligations without a CI-owned producer admission wrapper." {
		t.Fatalf("producerNonClaim(envOnly) = %q", got)
	}
	if ids := mergeRequiredReceiptIDs(envOnly.SatisfiesMergeObligation, map[string]any{"receiptId": "receipt.test"}); len(ids) != 0 {
		t.Fatalf("mergeRequiredReceiptIDs(envOnly) = %#v", ids)
	}
}

func TestCITrustInputsBindProducerAdmissionContext(t *testing.T) {
	base := map[string]string{
		"GITHUB_ACTIONS":                     "true",
		"GITHUB_EVENT_NAME":                  "pull_request",
		"GITHUB_REF":                         "refs/pull/1/merge",
		"GITHUB_REF_NAME":                    "1/merge",
		"GITHUB_REF_PROTECTED":               "false",
		"GITHUB_REF_TYPE":                    "branch",
		"GITHUB_REPOSITORY":                  "research-engineering/agentic-proofkit",
		"GITHUB_RUN_ATTEMPT":                 "1",
		"GITHUB_RUN_ID":                      "123",
		"GITHUB_SERVER_URL":                  "https://github.com",
		"GITHUB_SHA":                         "abc",
		"GITHUB_WORKFLOW":                    "CI",
		"PROOFKIT_MERGE_SATISFYING_PRODUCER": "true",
	}
	lookup := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	advisoryDigest := digestJSON(ciTrustInputsFromLookup(lookup(base)))
	protected := map[string]string{}
	for key, value := range base {
		protected[key] = value
	}
	protected["GITHUB_REF_PROTECTED"] = "true"
	protected["GITHUB_REF"] = "refs/heads/main"
	protected["GITHUB_REF_NAME"] = "main"
	protected["GITHUB_REF_TYPE"] = "branch"
	protectedDigest := digestJSON(ciTrustInputsFromLookup(lookup(protected)))
	if advisoryDigest == protectedDigest {
		t.Fatal("CI trust input digest must change when protected-ref admission inputs change")
	}
}

func TestCITrustInputNamesMatchFixedOracle(t *testing.T) {
	expected := expectedCITrustInputNames()
	if !reflect.DeepEqual(ciTrustInputNames, expected) {
		t.Fatalf("ciTrustInputNames=%#v, want %#v", ciTrustInputNames, expected)
	}
}

func TestCITrustInputDigestChangesForEachTrustInput(t *testing.T) {
	base := map[string]string{}
	for _, name := range expectedCITrustInputNames() {
		base[name] = "base-" + name
	}
	baseDigest := digestJSON(ciTrustInputsFromLookup(func(name string) string { return base[name] }))

	for _, name := range expectedCITrustInputNames() {
		t.Run(name, func(t *testing.T) {
			mutated := map[string]string{}
			for key, value := range base {
				mutated[key] = value
			}
			mutated[name] = "mutated-" + name
			mutatedDigest := digestJSON(ciTrustInputsFromLookup(func(name string) string { return mutated[name] }))
			if mutatedDigest == baseDigest {
				t.Fatalf("CI trust input digest did not change after mutating %s", name)
			}
		})
	}
}

func TestWitnessPlanAllowsEveryCITrustInput(t *testing.T) {
	raw := readRepoJSON(t, "proofkit/witness-plan.json")
	plan := raw.(map[string]any)
	commands := plan["commands"].([]any)
	var allowlist []any
	for _, item := range commands {
		command := item.(map[string]any)
		if command["id"] == "proofkit.ci-receipt-anchor" {
			allowlist = command["environment"].(map[string]any)["allowlist"].([]any)
			break
		}
	}
	if allowlist == nil {
		t.Fatal("proofkit.ci-receipt-anchor command not found")
	}
	actual := make([]string, 0, len(allowlist))
	for _, item := range allowlist {
		actual = append(actual, item.(string))
	}
	expected := expectedCITrustInputNames()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("witness plan environment allowlist=%#v, want %#v", actual, expected)
	}
}

func TestReceiptProducerPolicyDoesNotAdmitProtectedOptInProducer(t *testing.T) {
	policy := receiptProducerPolicy(t)
	policy["receipts"] = []any{
		map[string]any{
			"artifactRefs":             []any{"artifacts/proofkit/self-hosting-proof-receipts.json"},
			"environmentClass":         packageGateEnvironmentClass,
			"evidenceRef":              "artifacts/proofkit/self-hosting-proof-receipts.json",
			"nonClaim":                 "Test receipt does not prove live workflow identity.",
			"producerId":               "github.actions.package.protected",
			"receiptId":                "proofkit.test.protected-receipt",
			"receiptKind":              "proofkit.package-gate",
			"satisfiesMergeObligation": true,
			"status":                   "passed",
			"subjectRef":               "proofkit.package-boundary.self-hosting",
		},
	}

	record, exitCode, err := receiptproduceradmission.Build(policy)
	if err != nil {
		t.Fatalf("receipt producer admission: %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("receipt producer admission exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertReceiptProducerDiagnostic(t, record, "unknown producer: github.actions.package.protected")
}

func TestReceiptProducerPolicyRejectsPlainGitHubActionsMergeObligation(t *testing.T) {
	policy := receiptProducerPolicy(t)
	policy["receipts"] = []any{
		map[string]any{
			"artifactRefs":             []any{"artifacts/proofkit/self-hosting-proof-receipts.json"},
			"environmentClass":         packageGateEnvironmentClass,
			"evidenceRef":              "artifacts/proofkit/self-hosting-proof-receipts.json",
			"nonClaim":                 "Test receipt does not prove live workflow identity.",
			"producerId":               "github.actions.package",
			"receiptId":                "proofkit.test.plain-github-receipt",
			"receiptKind":              "proofkit.package-gate",
			"satisfiesMergeObligation": true,
			"status":                   "passed",
			"subjectRef":               "proofkit.package-boundary.self-hosting",
		},
	}

	record, exitCode, err := receiptproduceradmission.Build(policy)
	if err != nil {
		t.Fatalf("receipt producer admission: %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("receipt producer admission exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertReceiptProducerDiagnostic(t, record, "claims merge obligation with advisory producer: github.actions.package")
}

func receiptProducerPolicy(t *testing.T) map[string]any {
	t.Helper()
	decoded := readRepoJSON(t, "proofkit/receipt-producer-policy.json")
	policy, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("receipt producer policy must decode to object: %#v", decoded)
	}
	return policy
}

func readRepoJSON(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.Open(filepath.Join("..", path))
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := raw.Close(); err != nil {
			t.Fatalf("close %s: %v", path, err)
		}
	})
	decoded, err := admission.DecodeJSON(raw, maxJSONBytes)
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return decoded
}

func TestCIWorkflowPackageGateRemainsAdvisory(t *testing.T) {
	assertPackageGateWorkflowFile(t, filepath.Join("..", ".github", "workflows", "ci.yml"), packageGateWorkflowExpectation{
		label:                              "ci workflow",
		jobID:                              "source-quality",
		stepName:                           "Verify release closeout",
		runCommand:                         "npm run release:closeout",
		mustFollowSteps:                    ciSourceQualityProofSteps(),
		mustPrecedeStepNames:               []string{"Upload package tarball artifact"},
		requireReadOnlyWorkflowPermissions: true,
		requiredTriggers: []workflowTriggerExpectation{
			{event: "pull_request"},
			{event: "push", path: []string{"branches"}, value: "main"},
		},
	})
}

func ciSourceQualityProofSteps() []workflowStepExpectation {
	return []workflowStepExpectation{
		{name: "Verify npm version", runCommand: "npm run npm:version"},
		{name: "Verify source hygiene", runCommand: "npm run source-hygiene"},
		{name: "Verify text policy", runCommand: "npm run text-policy"},
		{name: "Verify Go formatting", runCommand: "npm run go:fmt"},
		{name: "Run Go tests for app", runCommand: "go test ./cmd/agentic-proofkit ./internal/app"},
		{name: "Run Go tests for kernel", runCommand: "go test ./internal/kernel/..."},
		{name: "Run Go tests for commands", runCommand: "go test ./internal/command/..."},
		{name: "Run Go tests for coverage and package tools", runCommand: "go test ./internal/tools/coveragemetrics ./internal/tools/packagebuild ./internal/tools/packagepack ./internal/tools/packageverify"},
		{name: "Run Go tests for registry and Python tools", runCommand: "go test ./internal/tools/pypiregistry ./internal/tools/pythonpackage"},
		{name: "Run Go tests for release tools", runCommand: "go test ./internal/tools/releasecloseoutinput ./internal/tools/releasemanifest ./internal/tools/releasepreflight ./internal/tools/releasesbom ./internal/tools/textpolicyinput"},
		{name: "Run Go tests for scripts", runCommand: "go test ./scripts"},
		{name: "Run Go vet", runCommand: "npm run go:vet"},
		{name: "Run staticcheck", runCommand: "npm run go:staticcheck"},
		{name: "Run actionlint", runCommand: "npm run go:actionlint"},
		{name: "Run govulncheck", runCommand: "npm run go:vulncheck"},
		{name: "Build and verify package artifacts", runCommand: "npm run package:artifact"},
		{name: "Verify self-hosting receipts", runCommand: "npm run self:receipt"},
		{name: "Verify self-hosting coverage", runCommand: "npm run self:coverage"},
	}
}

func TestReleaseWorkflowPackageGateRemainsAdvisory(t *testing.T) {
	assertPackageGateWorkflowFile(t, filepath.Join("..", ".github", "workflows", "release.yml"), packageGateWorkflowExpectation{
		label:                              "release workflow",
		jobID:                              "candidate",
		stepName:                           "Run package gate",
		runCommand:                         "npm run check",
		mustPrecedeStepNames:               []string{"Build publish dry-run evidence", "Upload release candidate evidence"},
		requireReadOnlyWorkflowPermissions: true,
		requiredNeeds: map[string][]string{
			"publish-readiness":    []string{"candidate"},
			"publish":              []string{"publish-readiness"},
			"publish-pypi":         []string{"publish-readiness"},
			"release-metadata":     []string{"candidate", "publish", "publish-pypi"},
			"release-attestations": []string{"candidate", "publish", "publish-pypi", "release-metadata"},
			"release-assets":       []string{"candidate", "publish", "publish-pypi", "release-metadata", "release-attestations"},
		},
		requiredTriggers: []workflowTriggerExpectation{
			{event: "push", path: []string{"tags"}, value: "v*"},
			{event: "workflow_dispatch"},
		},
	})
}

func TestReleaseWorkflowCandidateEvidenceAllowsExistingNPMByteMatch(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	var workflow githubWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse release workflow: %v", err)
	}
	stepIndex, err := uniqueStepIndex(workflow.Jobs["candidate"].Steps, "Build publish dry-run evidence")
	if err != nil {
		t.Fatalf("find candidate evidence step: %v", err)
	}
	if stepIndex < 0 {
		t.Fatal("Build publish dry-run evidence step not found")
	}
	run := workflow.Jobs["candidate"].Steps[stepIndex].Run
	required := []string{
		"npm view \"${package_name}@${package_version}\"",
		"go run ./internal/tools/releasepreflight npm-existing",
		"writeFileSync(report",
		"continue",
		"npm publish \"artifacts/package/${filename}\"",
		"--dry-run",
	}
	for _, item := range required {
		if !strings.Contains(run, item) {
			t.Fatalf("candidate evidence step missing %q", item)
		}
	}
	existingIndex := strings.Index(run, "go run ./internal/tools/releasepreflight npm-existing")
	dryRunIndex := strings.Index(run, "npm publish \"artifacts/package/${filename}\"")
	if existingIndex < 0 || dryRunIndex < 0 || existingIndex > dryRunIndex {
		t.Fatalf("candidate evidence must validate existing-byte-match before npm publish dry-run")
	}
}

func expectedCITrustInputNames() []string {
	return []string{
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
}

func assertReceiptProducerDiagnostic(t *testing.T, record report.Record, want string) {
	t.Helper()
	for _, rule := range record.RuleResults {
		if rule.RuleID != "proofkit.receipt-producer-admission.receipts" {
			continue
		}
		for _, diagnostic := range rule.Diagnostics {
			if text, ok := diagnostic.Value.(string); ok && strings.Contains(text, want) {
				return
			}
		}
		t.Fatalf("receipt producer diagnostics do not contain %q: %#v", want, rule.Diagnostics)
	}
	t.Fatalf("receipt producer receipt rule not found: %#v", record.RuleResults)
}

func TestReadJSONReturnsErrorsForAmbiguousInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"schemaVersion":2}`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	_, err := readJSON(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("readJSON() error = %v, want duplicate-key rejection", err)
	}
}

func TestRequirementIDsForCommandReturnsShapeErrors(t *testing.T) {
	_, err := requirementIDsForCommand(map[string]any{"bindings": []any{"not-an-object"}}, "proofkit.package-gate")
	if err == nil || !strings.Contains(err.Error(), "requirement binding must be an object") {
		t.Fatalf("requirementIDsForCommand() error = %v, want object-shape error", err)
	}
}
