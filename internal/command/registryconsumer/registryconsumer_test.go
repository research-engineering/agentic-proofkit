package registryconsumer

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestRegistryConsumerAcceptsRegistryReleaseProof(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.078570628200989177884060697900986161263859706648466286899141113980107918828824")
	record, exitCode, err := Build(validRegistryConsumerInput(t))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}
	assertRuleMessage(t, record.RuleResults, "proofkit.registry-consumer.accepted", "registry consumer install proof accepted")
}

func TestRegistryConsumerAddsMandatoryBoundaryNonClaims(t *testing.T) {
	record, exitCode, err := Build(validRegistryConsumerInput(t))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}
	nonClaims := anyStrings(record.NonClaims)
	for _, want := range []string{
		"Registry consumer does not fetch registry metadata, hold credentials, execute native consumer tests, approve rollback, approve rollout, or prove registry freshness.",
		"Registry consumer test input does not claim release readiness.",
	} {
		if !containsString(nonClaims, want) {
			t.Fatalf("NonClaims missing %q: %#v", want, nonClaims)
		}
	}
}

func TestRegistryConsumerRejectsSecretLikeCallerOwnedText(t *testing.T) {
	secretLike := "Authorization: Bearer abcdefghijklmnop"
	input := validRegistryConsumerInput(t)
	input["input"].(map[string]any)["consumerId"] = secretLike

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "secret-like values") {
		t.Fatalf("Build() accepted secret-like caller text: exit=%d record=%s", exitCode, string(encoded))
	}
	if strings.Contains(string(encoded), secretLike) {
		t.Fatalf("Build() leaked secret-like caller text: %s", string(encoded))
	}
}

func TestRegistryConsumerRejectsWorkspaceInstallLock(t *testing.T) {
	input := validRegistryConsumerInput(t)
	proof := input["proof"].(map[string]any)
	proof["installLockUsesWorkspace"] = true

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertFailureMessage(t, record.RuleResults, "lockfiles must not use workspace resolution")
}

func TestRegistryConsumerRejectsReleaseAuthorityStateDrift(t *testing.T) {
	input := validRegistryConsumerInput(t)
	proof := input["proof"].(map[string]any)
	proof["releaseAuthorityState"] = "failed"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertFailureMessage(t, record.RuleResults, "releaseAuthorityState must be passed")
}

func TestRegistryConsumerRejectsReleaseAuthorityDigestDrift(t *testing.T) {
	input := validRegistryConsumerInput(t)
	proof := input["proof"].(map[string]any)
	proof["releaseAuthorityOutputSha256"] = strings.Repeat("f", 64)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertFailureMessage(t, record.RuleResults, "releaseAuthorityOutputSha256 must match package API output")
}

func TestRegistryConsumerUsesAdmittedReleaseAuthorityProjection(t *testing.T) {
	input := validRegistryConsumerInput(t)
	consumerInput := input["input"].(map[string]any)
	releaseInput := consumerInput["releaseAuthorityInput"].(map[string]any)
	releaseInput["package"].(map[string]any)["publishConfigRegistry"] = "https://registry.npmjs.org/"
	releaseInput["registryAuthority"].(map[string]any)["registryUrl"] = "https://registry.npmjs.org/"
	input["proof"].(map[string]any)["releaseAuthorityOutputSha256"] = releaseAuthorityOutputSHA256(t, releaseInput)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s rules=%#v, want passed", exitCode, record.State, record.RuleResults)
	}
}

func TestRegistryConsumerRejectsTarballPilotReleaseAuthority(t *testing.T) {
	input := validRegistryConsumerInput(t)
	consumerInput := input["input"].(map[string]any)
	releaseInput := validTarballPilotReleaseInput()
	consumerInput["releaseAuthorityInput"] = releaseInput
	input["proof"].(map[string]any)["releaseAuthorityOutputSha256"] = releaseAuthorityOutputSHA256(t, releaseInput)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertFailureMessage(t, record.RuleResults, "releaseAuthorityInput.channel must be registry_release")
}

func TestRegistryConsumerReleaseAuthorityBoundaryUsesOwnerProjectionOnly(t *testing.T) {
	sourceBytes, err := os.ReadFile("registryconsumer.go")
	if err != nil {
		t.Fatalf("read registryconsumer.go: %v", err)
	}
	source := string(sourceBytes)
	if strings.Count(source, `record["releaseAuthorityInput"]`) != 1 {
		t.Fatalf("registry consumer must read releaseAuthorityInput only at the admission edge")
	}
	if !strings.Contains(source, `releaseauthority.AdmitConsumerProjection(record["releaseAuthorityInput"])`) {
		t.Fatalf("registry consumer must delegate release authority admission to releaseauthority.AdmitConsumerProjection")
	}
	for _, forbidden := range []string{
		"ReleaseAuthorityInput",
		"BuildProjection(",
		"releaseauthority.Build(",
		"stablejson",
		"crypto/sha256",
		"encoding/hex",
		"objectField(",
		"stringField(",
		"boolField(",
		"func admitReleaseAuthority",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("registry consumer must not own release-authority raw parsing or digest helper %q", forbidden)
		}
	}
}

func TestRegistryExpectedReleaseAuthorityOutputUsesOwnerDigest(t *testing.T) {
	sentinel := strings.Repeat("e", 64)
	got := expectedReleaseAuthorityOutputSHA256(input{
		ReleaseAuthority: releaseauthority.ConsumerProjectionAdmission{
			OutputSHA256: sentinel,
		},
	})
	if got != sentinel {
		t.Fatalf("expectedReleaseAuthorityOutputSHA256()=%q, want owner digest %q", got, sentinel)
	}
}

func TestRegistryConsumerRejectsLegacyRootImportProof(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.039930770239161369599321884905894984519351217077585815477648288469771222069580")
	input := validRegistryConsumerInput(t)
	proof := input["proof"].(map[string]any)
	proof["rootImportOutputSha256"] = sha256Hex()

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("Build() exit=%d, want admission failure", exitCode)
	}
	if record.ReportID != "proofkit.registry-consumer.invalid-input" {
		t.Fatalf("Build() reportID=%s, want invalid input report", record.ReportID)
	}
	assertFailureMessage(t, record.RuleResults, "rootImportOutputSha256")
}

func anyStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validRegistryConsumerInput(t *testing.T) map[string]any {
	t.Helper()
	releaseInput := validRegistryReleaseInput()
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"input": map[string]any{
			"schemaVersion":         json.Number("1"),
			"consumerId":            "proofkit.registry.consumer.test",
			"dependencyName":        "agentic-proofkit",
			"dependencySpec":        "1.2.3",
			"nonClaims":             []any{"Registry consumer test input does not claim release readiness."},
			"packageName":           "agentic-proofkit",
			"packageVersion":        "1.2.3",
			"registryUrl":           "https://registry.npmjs.org",
			"releaseAuthorityInput": releaseInput,
			"rollbackVersionPin":    "agentic-proofkit@1.2.2",
			"tarballFileName":       "agentic-proofkit-1.2.3.tgz",
			"tarballIntegrity":      "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"tarballShasum":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		"proof": map[string]any{
			"binarySmokeOutputSha256":      sha256Hex(),
			"cliWitnessPlanOutputSha256":   sha256Hex(),
			"dependencySpec":               "1.2.3",
			"frozenLockContainsPackage":    true,
			"frozenLockUsesWorkspace":      false,
			"installLockContainsPackage":   true,
			"installLockUsesWorkspace":     false,
			"registryPackIntegrityMatches": true,
			"registryPackNameMatches":      true,
			"registryPackShasumMatches":    true,
			"registryPackVersionMatches":   true,
			"releaseAuthorityOutputSha256": releaseAuthorityOutputSHA256(t, releaseInput),
			"releaseAuthorityReportKind":   "proofkit.release-authority",
			"releaseAuthorityState":        "passed",
			"rollbackLockContainsPackage":  false,
			"tempConsumerLocation":         "os-temp",
		},
	}
}

func validTarballPilotReleaseInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("3"),
		"releaseId":     "proofkit.test.tarball-pilot",
		"channel":       "tarball_pilot",
		"rolloutClaim":  false,
		"package": map[string]any{
			"artifactPath":           "artifacts/package/agentic-proofkit-1.2.3.tgz",
			"manifestPrivate":        true,
			"name":                   "agentic-proofkit",
			"packageManagerLockfile": "package-lock.json",
			"packManifestPath":       "artifacts/package/npm-pack.json",
			"publishConfigRegistry":  nil,
			"version":                "1.2.3",
		},
		"artifactProof": map[string]any{
			"binarySmokeProofId":            "proofkit.test.binary-smoke",
			"cliSmokeProofId":               "proofkit.test.cli-smoke",
			"deepImportRejectionProofId":    "proofkit.test.deep-import",
			"outsideConsumerInstallProofId": "proofkit.test.outside-consumer",
			"packageArtifactCommandId":      "proofkit.test.package-artifact",
			"packDryRunCommandId":           "proofkit.test.pack-dry-run",
		},
		"consumerContract": map[string]any{
			"binarySmokeOnly":              true,
			"dependencyPinType":            "file_tarball",
			"lockfileRequired":             true,
			"siblingSourceCheckoutAllowed": false,
		},
		"registryAuthority": nil,
		"rollback": map[string]any{
			"owner":      "proofkit.release",
			"procedure":  "Delete the temporary consumer and pin no published version.",
			"versionPin": "file:artifacts/package/agentic-proofkit-1.2.3.tgz",
		},
		"nonClaims": []any{"Tarball pilot test input is not registry publication proof."},
	}
}

func validRegistryReleaseInput() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("3"),
		"releaseId":     "proofkit.test.release",
		"channel":       "registry_release",
		"rolloutClaim":  false,
		"package": map[string]any{
			"artifactPath":           "artifacts/package/agentic-proofkit-1.2.3.tgz",
			"manifestPrivate":        false,
			"name":                   "agentic-proofkit",
			"packageManagerLockfile": "package-lock.json",
			"packManifestPath":       "artifacts/package/npm-pack.json",
			"publishConfigRegistry":  "https://registry.npmjs.org",
			"version":                "1.2.3",
		},
		"artifactProof": map[string]any{
			"binarySmokeProofId":            "proofkit.test.binary-smoke",
			"cliSmokeProofId":               "proofkit.test.cli-smoke",
			"deepImportRejectionProofId":    "proofkit.test.deep-import",
			"outsideConsumerInstallProofId": "proofkit.test.outside-consumer",
			"packageArtifactCommandId":      "proofkit.test.package-artifact",
			"packDryRunCommandId":           "proofkit.test.pack-dry-run",
			"registryPublishDryRunProofId":  "proofkit.test.registry-dry-run",
		},
		"consumerContract": map[string]any{
			"binarySmokeOnly":              true,
			"dependencyPinType":            "registry_version",
			"lockfileRequired":             true,
			"siblingSourceCheckoutAllowed": false,
		},
		"registryAuthority": map[string]any{
			"consumerMigrationPath": "Consumers pin the exact published version and run their native gates.",
			"packageScope":          "",
			"publishAuthorityMode":  "npm_trusted_publishing",
			"publishWorkflowPath":   ".github/workflows/release.yml",
			"registryKind":          "npm_registry",
			"registryUrl":           "https://registry.npmjs.org",
			"releaseTagPattern":     "v1.2.3",
			"rollbackPolicy":        "Rollback pins consumers to the previous admitted version.",
			"sourceRepository": map[string]any{
				"name":       "agentic-proofkit",
				"owner":      "research-engineering",
				"url":        "https://github.com/research-engineering/agentic-proofkit",
				"visibility": "public",
			},
			"visibility": "public",
		},
		"rollback": map[string]any{
			"owner":      "proofkit.release",
			"procedure":  "Pin consumers back to the previous admitted registry version.",
			"versionPin": "agentic-proofkit@1.2.2",
		},
		"nonClaims": []any{"Release authority test input does not claim consumer rollout."},
	}
}

func releaseAuthorityOutputSHA256(t *testing.T, input map[string]any) string {
	t.Helper()
	admission := releaseauthority.AdmitConsumerProjection(input)
	if admission.Err != nil {
		t.Fatalf("releaseauthority.AdmitConsumerProjection() error = %v", admission.Err)
	}
	if admission.Record.State != "passed" {
		t.Fatalf("releaseauthority.AdmitConsumerProjection() state=%s rules=%#v", admission.Record.State, admission.Record.RuleResults)
	}
	return admission.OutputSHA256
}

func assertFailureMessage(t *testing.T, rules []report.RuleResult, want string) {
	t.Helper()
	for _, result := range rules {
		if strings.Contains(result.Message, want) {
			return
		}
	}
	t.Fatalf("rule message containing %q not found: %#v", want, rules)
}

func assertRuleMessage(t *testing.T, rules []report.RuleResult, ruleID string, want string) {
	t.Helper()
	for _, result := range rules {
		if result.RuleID == ruleID && result.Status == "passed" && strings.Contains(result.Message, want) {
			return
		}
	}
	t.Fatalf("passed rule %s containing %q not found: %#v", ruleID, want, rules)
}

func sha256Hex() string {
	return strings.Repeat("a", 64)
}
