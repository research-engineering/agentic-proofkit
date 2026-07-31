package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"go.yaml.in/yaml/v3"
)

const testRootPackageName = "@research-engineering/agentic-proofkit"

func TestRunProofkitVerdictCases(t *testing.T) {
	cases := []struct {
		name       string
		processErr error
		output     string
		wantError  string
	}{
		{name: "process exit", processErr: errors.New("exit status 7"), output: `{"state":"passed"}`, wantError: "exit status 7"},
		{name: "invalid JSON", output: `{"state":`, wantError: "emitted invalid JSON"},
		{name: "wrong state", output: `{"state":"failed"}`, wantError: "did not pass"},
		{name: "passed", output: `{"state":"passed"}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := proofkitVerdict("fixture", test.processErr, []byte(test.output))
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("proofkitVerdict() error=%v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("proofkitVerdict() error=%v, want %q", err, test.wantError)
			}
		})
	}
}

func TestRunInvokesEveryRequiredSelfHostingAdmissionBoundary(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "validate-self-hosting-receipts.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"proof-receipt-admission":     1,
		"receipt-producer-admission":  1,
		"spec-proof-bundle-admission": 1,
	}
	got := map[string]int{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "run" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 3 {
				return true
			}
			callee, ok := call.Fun.(*ast.Ident)
			if !ok || callee.Name != "runProofkit" {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			command, err := strconv.Unquote(literal.Value)
			if err == nil {
				got[command]++
			}
			return true
		})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("run() admission command inventory=%v, want exact %v", got, want)
	}
}

func TestCurrentPlatformBinaryUsesReleasePlatformOwner(t *testing.T) {
	target, err := releaseplatform.CurrentTarget()
	if err != nil {
		t.Skipf("current platform is outside the release matrix: %v", err)
	}
	root := t.TempDir()
	t.Chdir(root)
	path := filepath.FromSlash(target.BinaryPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := currentPlatformBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("currentPlatformBinary()=%q, release platform owner=%q", got, path)
	}
}

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
			"receiptKind":              "proofkit.package-artifact",
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
			"receiptKind":              "proofkit.package-artifact",
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

func TestReceiptProducerPolicyRetainsAggregatePackageGateOnly(t *testing.T) {
	policy := receiptProducerPolicy(t)
	if got := anyStrings(policy["receiptKinds"]); !reflect.DeepEqual(got, []string{"proofkit.package-artifact"}) {
		t.Fatalf("receiptKinds=%#v, want package-artifact only", got)
	}
	if got := anyStrings(policy["environmentClasses"]); !reflect.DeepEqual(got, []string{packageGateEnvironmentClass}) {
		t.Fatalf("environmentClasses=%#v, want aggregate %s only", got, packageGateEnvironmentClass)
	}
	nonClaims := strings.Join(anyStrings(policy["nonClaims"]), "\n")
	if !strings.Contains(nonClaims, "does not provide independent local-go and local-python receipt classes") {
		t.Fatalf("policy nonClaims do not deny split receipt readiness: %s", nonClaims)
	}
	for _, raw := range policy["producers"].([]any) {
		producer := raw.(map[string]any)
		if got := anyStrings(producer["receiptKinds"]); !reflect.DeepEqual(got, []string{"proofkit.package-artifact"}) {
			t.Fatalf("producer %s receiptKinds=%#v, want package-artifact only", producer["producerId"], got)
		}
		if got := anyStrings(producer["environmentClasses"]); !reflect.DeepEqual(got, []string{packageGateEnvironmentClass}) {
			t.Fatalf("producer %s environmentClasses=%#v, want aggregate %s only", producer["producerId"], got, packageGateEnvironmentClass)
		}
	}
}

func TestSelfHostingPackageGateReceiptKeepsAggregateEvidenceModel(t *testing.T) {
	evidenceRefs := anyStrings(packageGateEvidenceRefs())
	for _, want := range []string{
		"artifacts/package/npm-pack.json",
		"artifacts/pypi/python-packages.json",
		"artifacts/proofkit/ci-provenance.json",
		"artifacts/proofkit/self-hosting-proof-receipts.json",
	} {
		if !stringSliceContains(evidenceRefs, want) {
			t.Fatalf("packageGateEvidenceRefs() missing %q: %#v", want, evidenceRefs)
		}
	}
	nonClaims := strings.Join(anyStrings(aggregatePackageGateNonClaims()), "\n")
	if !strings.Contains(nonClaims, "aggregate Go and Python package-gate evidence") ||
		!strings.Contains(nonClaims, "do not provide independent local-go and local-python receipt classes") {
		t.Fatalf("aggregate package gate nonClaims do not preserve split-readiness denial: %s", nonClaims)
	}
}

func TestPackageArtifactRefsRejectEachPackageIdentityDefect(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, records []any)
		want   string
	}{
		{
			name: "name",
			mutate: func(_ *testing.T, records []any) {
				records[0].(map[string]any)["name"] = "@research-engineering/other"
			},
			want: "unexpected package artifact",
		},
		{
			name: "version",
			mutate: func(_ *testing.T, records []any) {
				records[0].(map[string]any)["version"] = "9.9.9"
			},
			want: "version must match package.json",
		},
		{
			name: "duplicate",
			mutate: func(_ *testing.T, records []any) {
				records = append(records, cloneObject(records[0].(map[string]any)))
				mustWriteJSON(t, filepath.Join(packageArtifactRoot, "npm-pack.json"), records)
			},
			want: "duplicate package artifact",
		},
		{
			name: "missing artifact",
			mutate: func(t *testing.T, records []any) {
				filename := records[0].(map[string]any)["filename"].(string)
				if err := os.Remove(filepath.Join(packageArtifactRoot, filename)); err != nil {
					t.Fatal(err)
				}
			},
			want: "no such file or directory",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			packageJSON, records := writeArtifactRefFixture(t)
			test.mutate(t, records)
			if test.name != "duplicate" {
				mustWriteJSON(t, filepath.Join(packageArtifactRoot, "npm-pack.json"), records)
			}
			_, err := packageArtifactRefs(packageJSON)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("packageArtifactRefs() error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestPythonArtifactRefsRejectEachWheelIdentityDefect(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, packageSet map[string]any)
		want   string
	}{
		{
			name: "version",
			mutate: func(_ *testing.T, packageSet map[string]any) {
				packageSet["packageVersion"] = "9.9.9"
			},
			want: "packageVersion must match",
		},
		{
			name: "duplicate",
			mutate: func(_ *testing.T, packageSet map[string]any) {
				packages := packageSet["packages"].([]any)
				packageSet["packages"] = append(packages, cloneObject(packages[0].(map[string]any)))
			},
			want: "duplicate Python wheel artifact",
		},
		{
			name: "missing file",
			mutate: func(t *testing.T, packageSet map[string]any) {
				filename := packageSet["packages"].([]any)[0].(map[string]any)["filename"].(string)
				if err := os.Remove(filepath.Join(pythonArtifactRoot, filename)); err != nil {
					t.Fatal(err)
				}
			},
			want: "no such file or directory",
		},
		{
			name: "SHA mismatch",
			mutate: func(_ *testing.T, packageSet map[string]any) {
				packageSet["packages"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
			},
			want: "sha256 mismatch",
		},
		{
			name: "missing SHA",
			mutate: func(_ *testing.T, packageSet map[string]any) {
				delete(packageSet["packages"].([]any)[0].(map[string]any), "sha256")
			},
			want: "must include sha256",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			packageJSON, _ := writeArtifactRefFixture(t)
			packageSet := readRepoArtifactObject(t, filepath.Join(pythonArtifactRoot, "python-packages.json"))
			test.mutate(t, packageSet)
			mustWriteJSON(t, filepath.Join(pythonArtifactRoot, "python-packages.json"), packageSet)
			_, err := pythonArtifactRefs(packageJSON["version"].(string))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("pythonArtifactRefs() error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestReceiptIDKeepsLocalAndCIIdentitiesDistinct(t *testing.T) {
	local := receiptID(false)
	ci := receiptID(true)
	if local != "receipt.local.package-artifact" ||
		ci != "receipt.github.actions.package-artifact" ||
		local == ci {
		t.Fatalf("receipt identities local=%q ci=%q", local, ci)
	}
}

func writeArtifactRefFixture(t *testing.T) (map[string]any, []any) {
	t.Helper()
	t.Chdir(t.TempDir())
	if err := os.MkdirAll(packageArtifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pythonArtifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	const (
		version = "1.2.3"
		tarball = "agentic-proofkit-1.2.3.tgz"
		wheel   = "agentic_proofkit-1.2.3-py3-none-any.whl"
	)
	if err := os.WriteFile(filepath.Join(packageArtifactRoot, tarball), []byte("tarball"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pythonArtifactRoot, wheel), []byte("wheel"), 0o644); err != nil {
		t.Fatal(err)
	}
	records := []any{map[string]any{
		"name":     testRootPackageName,
		"version":  version,
		"filename": tarball,
	}}
	mustWriteJSON(t, filepath.Join(packageArtifactRoot, "npm-pack.json"), records)
	mustWriteJSON(t, filepath.Join(pythonArtifactRoot, "python-packages.json"), map[string]any{
		"packageVersion": version,
		"packages": []any{map[string]any{
			"filename": wheel,
			"sha256":   strings.TrimPrefix(digestFile(filepath.Join(pythonArtifactRoot, wheel)), "sha256:"),
		}},
	})
	return map[string]any{"name": testRootPackageName, "version": version}, records
}

func mustWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := writeJSON(path, value); err != nil {
		t.Fatal(err)
	}
}

func readRepoArtifactObject(t *testing.T, path string) map[string]any {
	t.Helper()
	value, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
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

func anyStrings(raw any) []string {
	items := raw.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.(string))
	}
	return result
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
	assertPackageGateWorkflowFile(
		t,
		filepath.Join("..", ".github", "workflows", "ci.yml"),
		ciPackageGateWorkflowExpectation(),
	)
}

func ciPackageGateWorkflowExpectation() packageGateWorkflowExpectation {
	return packageGateWorkflowExpectation{
		label:        "ci workflow",
		workflowName: "ci",
		workflowConcurrency: &workflowConcurrencyExpectation{
			group:            "ci-${{ github.event.pull_request.number || github.ref }}",
			cancelInProgress: true,
		},
		jobID:                              "source-quality",
		stepName:                           "Verify release closeout",
		runCommand:                         "npm run release:closeout",
		mustFollowSteps:                    ciSourceQualityProofSteps(),
		mustPrecedeStepNames:               []string{"Upload package tarball artifact"},
		requireReadOnlyWorkflowPermissions: true,
		stepInventorySHA256:                ciSourceQualityStepInventorySHA256,
		requiredTriggers: []workflowTriggerExpectation{
			{event: "pull_request"},
			{event: "push", path: []string{"branches"}, value: "main"},
		},
	}
}

func ciSourceQualityProofSteps() []workflowStepExpectation {
	return []workflowStepExpectation{
		{name: "Verify npm version", runCommand: "npm run npm:version"},
		{name: "Verify source hygiene", runCommand: "npm run source-hygiene"},
		{name: "Verify text policy", runCommand: "npm run text-policy"},
		{name: "Verify Mermaid diagrams", runCommand: "npm run mermaid:check"},
		{name: "Verify Go formatting", runCommand: "npm run go:fmt"},
		{name: "Verify generated command contracts", runCommand: "npm run command-contract:check"},
		{name: "Verify generated command family catalog", runCommand: "npm run command-family:check"},
		{name: "Run all Go tests", runCommand: "npm run go:test"},
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
	assertPackageGateWorkflowFile(
		t,
		filepath.Join("..", ".github", "workflows", "release.yml"),
		releasePackageGateWorkflowExpectation(),
	)
}

func releasePackageGateWorkflowExpectation() packageGateWorkflowExpectation {
	return packageGateWorkflowExpectation{
		label:        "release workflow",
		workflowName: "release",
		workflowConcurrency: &workflowConcurrencyExpectation{
			group:            "release-${{ github.ref }}",
			cancelInProgress: false,
		},
		jobID:       "candidate",
		stepName:    "Run package gate",
		runCommand:  "npm run check",
		workflowEnv: map[string]any{"REGISTRY_URL": "https://registry.npmjs.org"},
		allowedStepEnv: map[string]map[string]any{
			"Verify source package identity": {
				"EXPECTED_VERSION": "${{ inputs.expected_version }}",
				"MODE":             "${{ inputs.mode }}",
			},
		},
		mustPrecedeStepNames:               []string{"Build publish dry-run evidence", "Upload release candidate evidence"},
		requireReadOnlyWorkflowPermissions: true,
		requireReleaseExpressionInventory:  true,
		stepInventorySHA256:                releaseCandidateStepInventorySHA256,
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
	}
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
	if err := validateReleaseCandidateLineageRun(run); err != nil {
		t.Fatal(err)
	}

	lateOverride := strings.Replace(
		run,
		"npm view \"${package_name}@latest\" name version --json",
		"lineage_state=\"unpublished\"\n            npm view \"${package_name}@latest\" name version --json",
		1,
	)
	if err := validateReleaseCandidateLineageRun(lateOverride); err == nil || !strings.Contains(err.Error(), "exactly two") {
		t.Fatalf("late candidate-state override error=%v, want exact assignment-count rejection", err)
	}

	const existingState = "lineage_state=\"existing_byte_match\""
	const unpublishedState = "lineage_state=\"unpublished\""
	swapped := strings.Replace(run, existingState, "__EXISTING_LINEAGE_STATE__", 1)
	swapped = strings.Replace(swapped, unpublishedState, existingState, 1)
	swapped = strings.Replace(swapped, "__EXISTING_LINEAGE_STATE__", unpublishedState, 1)
	if err := validateReleaseCandidateLineageRun(swapped); err == nil || !strings.Contains(err.Error(), "only after") {
		t.Fatalf("swapped candidate-state assignments error=%v, want branch-origin rejection", err)
	}
}

func validateReleaseCandidateLineageRun(run string) error {
	required := []string{
		"npm view \"${package_name}@${package_version}\"",
		"go run ./internal/tools/releasepreflight npm-existing",
		"lineage_state=\"existing_byte_match\"",
		"node - \"$metadata\" \"$filename\" \"$report\" <<'NODE'",
		"writeFileSync(report",
		"npm publish \"artifacts/package/${filename}\"",
		"--dry-run",
		"lineage_state=\"unpublished\"",
		"npm view \"${package_name}@latest\" name version --json",
		"go run ./internal/tools/releasepreflight npm-lineage",
		"--change-record-file release/change-record.v2.json",
		"--candidate-version \"$package_version\"",
		"--candidate-state \"$lineage_state\"",
	}
	for _, item := range required {
		if !strings.Contains(run, item) {
			return fmt.Errorf("candidate evidence step missing %q", item)
		}
	}
	if count := strings.Count(run, "lineage_state="); count != 2 {
		return fmt.Errorf("candidate evidence must contain exactly two lineage_state assignments, got %d", count)
	}
	existingIndex := strings.Index(run, "go run ./internal/tools/releasepreflight npm-existing")
	existingStateIndex := strings.Index(run, "lineage_state=\"existing_byte_match\"")
	dryRunIndex := strings.Index(run, "npm publish \"artifacts/package/${filename}\"")
	unpublishedStateIndex := strings.Index(run, "lineage_state=\"unpublished\"")
	latestIndex := strings.Index(run, "npm view \"${package_name}@latest\" name version --json")
	lineageIndex := strings.Index(run, "go run ./internal/tools/releasepreflight npm-lineage")
	if existingIndex < 0 || dryRunIndex < 0 || existingIndex > dryRunIndex {
		return fmt.Errorf("candidate evidence must validate existing-byte-match before npm publish dry-run")
	}
	if existingStateIndex < existingIndex || unpublishedStateIndex < dryRunIndex {
		return fmt.Errorf("candidate state must be assigned only after its branch evidence succeeds")
	}
	if latestIndex < existingStateIndex || latestIndex < unpublishedStateIndex || lineageIndex < latestIndex {
		return fmt.Errorf("candidate evidence must validate registry lineage after the exact-byte or dry-run branch")
	}
	return nil
}

func TestReleaseWorkflowRetainsReleaseAssetAndPostCreateEvidenceClosure(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	var workflow githubWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse release workflow: %v", err)
	}
	assetJob := workflow.Jobs["release-assets"]
	createIndex, err := uniqueStepIndex(assetJob.Steps, "Create GitHub Release")
	if err != nil {
		t.Fatalf("find release create step: %v", err)
	}
	if createIndex < 0 {
		t.Fatal("Create GitHub Release step not found")
	}
	createRun := assetJob.Steps[createIndex].Run
	for _, item := range []string{
		"artifacts/release/release-notes.md",
		"artifacts/release/github-release.json",
		"go run ./internal/tools/releasepreflight retained-evidence --artifact-root artifacts",
		"go run ./internal/tools/releasepreflight retained-evidence-verify --artifact-root artifacts",
	} {
		if !strings.Contains(createRun, item) {
			t.Fatalf("Create GitHub Release step missing retained evidence token %q", item)
		}
	}
	if strings.Contains(createRun, "$(basename \"$evidence\")") || strings.Contains(createRun, "sha256sum \"$evidence\"") {
		t.Fatal("Create GitHub Release step must delegate retained evidence topology to its repository owner")
	}
	if err := validateRetainedEvidenceBranchClosure(createRun); err != nil {
		t.Fatal(err)
	}
	uploadIndex, err := uniqueStepIndex(assetJob.Steps, "Upload release evidence")
	if err != nil {
		t.Fatalf("find release evidence upload step: %v", err)
	}
	if uploadIndex < 0 {
		t.Fatal("Upload release evidence step not found")
	}
	uploadPath := strings.Join(stringValues(assetJob.Steps[uploadIndex].With["path"]), "\n")
	for _, item := range []string{
		"artifacts/attestations/*.json",
		"artifacts/release/github-release.json",
		"artifacts/retained-evidence-checksums.sha256",
		"artifacts/release/release-notes.md",
	} {
		if !strings.Contains(uploadPath, item) {
			t.Fatalf("Upload release evidence path missing %q: %#v", item, uploadPath)
		}
	}
}

func TestRetainedEvidenceBranchClosureRejectsUnreachableExistingReleaseVerification(t *testing.T) {
	writeCommand := "go run ./internal/tools/releasepreflight retained-evidence --artifact-root artifacts"
	verifyCommand := "go run ./internal/tools/releasepreflight retained-evidence-verify --artifact-root artifacts"
	mutated := strings.Join([]string{
		`if gh release view "$GITHUB_REF_NAME" >/dev/null 2>&1; then`,
		"  exit 0",
		"fi",
		writeCommand,
		verifyCommand,
		`gh release create "$GITHUB_REF_NAME"`,
		writeCommand,
		verifyCommand,
	}, "\n")
	if err := validateRetainedEvidenceBranchClosure(mutated); err == nil {
		t.Fatal("retained evidence verification after the existing-release branch was accepted")
	}
}

func validateRetainedEvidenceBranchClosure(run string) error {
	writeCommand := "go run ./internal/tools/releasepreflight retained-evidence --artifact-root artifacts"
	verifyCommand := "go run ./internal/tools/releasepreflight retained-evidence-verify --artifact-root artifacts"
	writeOffsets := trimmedLineOffsets(run, writeCommand)
	verifyOffsets := trimmedLineOffsets(run, verifyCommand)
	exitOffsets := trimmedLineOffsets(run, "exit 0")
	branchEndOffsets := trimmedLineOffsets(run, "fi")
	existingBranchIndex := strings.Index(run, `if gh release view "$GITHUB_REF_NAME"`)
	createReleaseIndex := strings.Index(run, `gh release create "$GITHUB_REF_NAME"`)
	if len(writeOffsets) != 2 || len(verifyOffsets) != 2 || len(exitOffsets) != 1 || existingBranchIndex < 0 || createReleaseIndex < 0 {
		return fmt.Errorf("retained evidence branch inventory write=%v verify=%v exit=%v existing=%d create=%d", writeOffsets, verifyOffsets, exitOffsets, existingBranchIndex, createReleaseIndex)
	}
	branchEndIndex := -1
	for _, offset := range branchEndOffsets {
		if offset > exitOffsets[0] {
			branchEndIndex = offset
			break
		}
	}
	if !(existingBranchIndex < writeOffsets[0] &&
		writeOffsets[0] < verifyOffsets[0] &&
		verifyOffsets[0] < exitOffsets[0] &&
		exitOffsets[0] < branchEndIndex &&
		branchEndIndex < createReleaseIndex &&
		createReleaseIndex < writeOffsets[1] &&
		writeOffsets[1] < verifyOffsets[1]) {
		return fmt.Errorf("retained evidence write=%v verify=%v exit=%v branch end=%d existing=%d create=%d; want reachable write-then-verify before existing-release exit and after release creation", writeOffsets, verifyOffsets, exitOffsets, branchEndIndex, existingBranchIndex, createReleaseIndex)
	}
	return nil
}

func trimmedLineOffsets(content, target string) []int {
	offsets := []int{}
	offset := 0
	for _, line := range strings.SplitAfter(content, "\n") {
		if strings.TrimSpace(line) == target {
			offsets = append(offsets, offset)
		}
		offset += len(line)
	}
	return offsets
}

func TestReleaseWorkflowDelegatesNPMRegistryEvidenceToRepositoryOwner(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	var workflow githubWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse release workflow: %v", err)
	}
	publish := workflow.Jobs["publish"]
	stepIndex, err := uniqueStepIndex(publish.Steps, "Capture published registry artifact identity")
	if err != nil || stepIndex < 0 {
		t.Fatalf("find npm registry evidence step: index=%d error=%v", stepIndex, err)
	}
	run := publish.Steps[stepIndex].Run
	if strings.Count(run, "npm run npm:registry-evidence") != 1 {
		t.Fatalf("npm registry evidence step must invoke its repository owner exactly once: %s", run)
	}
	for _, forbidden := range []string{"proofkit.published-registry-artifact-set.v1", "authorityValidator", "registry_release"} {
		if strings.Contains(run, forbidden) {
			t.Fatalf("workflow duplicates typed npm registry authority field %q", forbidden)
		}
	}
}

func TestReleaseWorkflowRegistryInstallUsesRootPackageName(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	var workflow githubWorkflow
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse release workflow: %v", err)
	}
	stepIndex, err := uniqueStepIndex(workflow.Jobs["publish"].Steps, "Verify root-only registry install and signatures")
	if err != nil {
		t.Fatalf("find registry install step: %v", err)
	}
	if stepIndex < 0 {
		t.Fatal("Verify root-only registry install and signatures step not found")
	}
	run := workflow.Jobs["publish"].Steps[stepIndex].Run
	rootNameIndex := strings.Index(run, "package_name=\"$(node -p \"require('./package.json').name\")\"")
	pushdIndex := strings.Index(run, "pushd \"$consumer\"")
	if rootNameIndex < 0 {
		t.Fatal("registry install step must read package_name from root package.json")
	}
	if pushdIndex < 0 {
		t.Fatal("registry install step must enter a temporary consumer directory")
	}
	if rootNameIndex > pushdIndex {
		t.Fatal("registry install step must read package_name before entering the temporary consumer directory")
	}
	if strings.Count(run, "package_name=\"$(node -p \"require('./package.json').name\")\"") != 1 {
		t.Fatal("registry install step must not recompute package_name from temporary consumer package.json")
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
