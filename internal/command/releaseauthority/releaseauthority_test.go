package releaseauthority

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func TestBuildAcceptsPrivateSourceTrustedPublisherRelease(t *testing.T) {
	input := validRegistryReleaseInput("npm_trusted_publishing", "private")

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s", exitCode, record.State)
	}
}

func TestBuildAddsMandatoryBoundaryNonClaims(t *testing.T) {
	input := validRegistryReleaseInput("npm_trusted_publishing", "private")

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s", exitCode, record.State)
	}
	nonClaims := anyStrings(record.NonClaims)
	for _, want := range []string{
		"Release authority does not publish packages, authenticate registry credentials, execute consumer installs, approve rollout, or prove registry freshness.",
		"Release authority test input does not claim consumer rollout.",
	} {
		if !containsString(nonClaims, want) {
			t.Fatalf("NonClaims missing %q: %#v", want, nonClaims)
		}
	}
}

func TestAdmitConsumerProjectionReturnsAdmittedNormalizedFields(t *testing.T) {
	input := validRegistryReleaseInput("npm_trusted_publishing", "public")
	input["package"].(map[string]any)["publishConfigRegistry"] = npmRegistryURL + "/"
	input["registryAuthority"].(map[string]any)["registryUrl"] = npmRegistryURL + "/"

	admission := AdmitConsumerProjection(input)
	if admission.Err != nil {
		t.Fatalf("AdmitConsumerProjection() error = %v", admission.Err)
	}
	if admission.Record.State != "passed" {
		t.Fatalf("AdmitConsumerProjection() state=%s, want passed", admission.Record.State)
	}
	if admission.OutputSHA256 == "" {
		t.Fatalf("AdmitConsumerProjection() OutputSHA256 is empty")
	}
	if !admission.Projection.Package.HasPublishConfigRegistry || admission.Projection.Package.PublishConfigRegistry != npmRegistryURL {
		t.Fatalf("projection package registry=%q has=%v, want %q", admission.Projection.Package.PublishConfigRegistry, admission.Projection.Package.HasPublishConfigRegistry, npmRegistryURL)
	}
	if !admission.Projection.HasRegistryAuthority || admission.Projection.RegistryAuthority.RegistryURL != npmRegistryURL {
		t.Fatalf("projection registry authority=%q has=%v, want %q", admission.Projection.RegistryAuthority.RegistryURL, admission.Projection.HasRegistryAuthority, npmRegistryURL)
	}
}

func TestAdmitConsumerProjectionInputJSONRoundTripsThroughOwner(t *testing.T) {
	first := AdmitConsumerProjection(validRegistryReleaseInput("npm_trusted_publishing", "public"))
	if first.Err != nil {
		t.Fatalf("first AdmitConsumerProjection() error = %v", first.Err)
	}
	if first.InputJSON == nil {
		t.Fatalf("first AdmitConsumerProjection() InputJSON is nil")
	}
	if first.InputJSON["schemaVersion"] != json.Number("3") {
		t.Fatalf("InputJSON schemaVersion=%#v, want json.Number(3)", first.InputJSON["schemaVersion"])
	}
	registryAuthority := first.InputJSON["registryAuthority"].(map[string]any)
	if _, ok := registryAuthority["publishAuthorityMode"]; !ok {
		t.Fatalf("InputJSON registryAuthority missing schema-v3 publishAuthorityMode: %#v", registryAuthority)
	}
	if _, ok := registryAuthority["provenanceMode"]; ok {
		t.Fatalf("InputJSON registryAuthority must not emit schema-v1 provenanceMode for schema v3: %#v", registryAuthority)
	}
	second := AdmitConsumerProjection(first.InputJSON)
	if second.Err != nil {
		t.Fatalf("second AdmitConsumerProjection() error = %v", second.Err)
	}
	if second.Record.State != "passed" {
		t.Fatalf("second AdmitConsumerProjection() state=%s, want passed", second.Record.State)
	}
	if second.OutputSHA256 != first.OutputSHA256 {
		t.Fatalf("InputJSON round-trip digest drifted: first=%s second=%s", first.OutputSHA256, second.OutputSHA256)
	}
}

func TestBuildRejectsPrivateSourceNPMProvenanceClaim(t *testing.T) {
	input := validRegistryReleaseInput("npm_provenance", "private")

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertFailedRuleMessage(t, record.RuleResults, "proofkit.release-authority.failure.", "public source repository proof")
}

func TestBuildRejectsPrivatePackageTrustedPublisherRelease(t *testing.T) {
	input := validRegistryReleaseInput("npm_trusted_publishing", "private")
	registryAuthority := input["registryAuthority"].(map[string]any)
	registryAuthority["visibility"] = "private"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	assertFailedRuleMessage(t, record.RuleResults, "proofkit.release-authority.failure.", "trusted publishing authority requires public package visibility")
}

func TestBuildReportsKnownExternalReleaseChannelsAsOutOfScope(t *testing.T) {
	cases := map[releasechannel.ID]string{
		releasechannel.GitHubReleaseArchive: "releasepreflight.github-release",
		releasechannel.PyPIRegistryRelease:  "pypiregistry",
		releasechannel.PythonWheelCandidate: "pythonpackage",
	}

	for channel, validator := range cases {
		t.Run(string(channel), func(t *testing.T) {
			input := validRegistryReleaseInput("npm_trusted_publishing", "public")
			input["channel"] = string(channel)

			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
			}
			assertFailedRuleMessage(t, record.RuleResults, "proofkit.release-authority.failure.", "release-authority owns only tarball_pilot and npm registry_release")
			assertFailedRuleMessage(t, record.RuleResults, "proofkit.release-authority.failure.", validator)
		})
	}
}

func TestBuildRejectsDisplayLabelAsReleaseChannelAuthority(t *testing.T) {
	for _, channel := range []string{"github-release", "public-npm", "pypi"} {
		t.Run(channel, func(t *testing.T) {
			input := validRegistryReleaseInput("npm_trusted_publishing", "public")
			input["channel"] = channel

			_, exitCode, err := Build(input)
			if err == nil || exitCode == 0 {
				t.Fatalf("Build() error=%v exit=%d, want admission rejection", err, exitCode)
			}
			if !strings.Contains(err.Error(), "release authority channel") {
				t.Fatalf("Build() error=%v, want release authority channel rejection", err)
			}
		})
	}
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

func assertFailedRuleMessage(t *testing.T, rules []report.RuleResult, rulePrefix string, want string) {
	t.Helper()
	for _, rule := range rules {
		if !strings.HasPrefix(rule.RuleID, rulePrefix) {
			continue
		}
		if rule.Status != "failed" {
			t.Fatalf("%s status=%s, want failed", rule.RuleID, rule.Status)
		}
		if strings.Contains(rule.Message, want) {
			return
		}
	}
	t.Fatalf("failed rule with prefix %q does not contain %q: %#v", rulePrefix, want, rules)
}

func validRegistryReleaseInput(publishAuthorityMode string, sourceVisibility string) map[string]any {
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
			"publishConfigRegistry":  npmRegistryURL,
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
			"publishAuthorityMode":  publishAuthorityMode,
			"publishWorkflowPath":   ".github/workflows/release.yml",
			"registryKind":          "npm_registry",
			"registryUrl":           npmRegistryURL,
			"releaseTagPattern":     "v1.2.3",
			"rollbackPolicy":        "Rollback pins consumers to the previous admitted version.",
			"sourceRepository": map[string]any{
				"name":       "agentic-proofkit",
				"owner":      "research-engineering",
				"url":        "https://github.com/research-engineering/agentic-proofkit",
				"visibility": sourceVisibility,
			},
			"visibility": "public",
		},
		"rollback": map[string]any{
			"owner":      "proofkit.release",
			"procedure":  "Pin consumers back to the previous admitted registry version.",
			"versionPin": "1.2.2",
		},
		"nonClaims": []any{"Release authority test input does not claim consumer rollout."},
	}
}
