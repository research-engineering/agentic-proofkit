package externalconsumer

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
)

func TestBuildAdmitsExternalConsumerProofAndRejectsWorkspaceLock(t *testing.T) {
	input := validExternalConsumerInput(t)
	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		encoded, _ := json.Marshal(record)
		t.Fatalf("Build() exit=%d record=%s, want passed", exitCode, string(encoded))
	}

	input = validExternalConsumerInput(t)
	input["evidence"].(map[string]any)["consumerProof"].(map[string]any)["installLockUsesWorkspace"] = true
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() workspace lock error=%v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "install lock must not resolve through workspace") {
		t.Fatalf("Build() accepted workspace lock: exit=%d record=%s", exitCode, string(encoded))
	}
}

func TestBuildAddsMandatoryBoundaryNonClaims(t *testing.T) {
	record, exitCode, err := Build(validExternalConsumerInput(t))
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}
	nonClaims := anyStrings(record.NonClaims)
	for _, want := range []string{
		"External consumer does not publish packages, fetch registries, hold credentials, approve rollout, or prove production readiness.",
		"External consumer test input is not publication proof.",
	} {
		if !containsString(nonClaims, want) {
			t.Fatalf("NonClaims missing %q: %#v", want, nonClaims)
		}
	}
}

func TestBuildRejectsSecretLikeCallerOwnedText(t *testing.T) {
	secretLike := "Authorization: Bearer abcdefghijklmnop"
	input := validExternalConsumerInput(t)
	input["input"].(map[string]any)["sourceRepository"] = secretLike

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "secret-like values") {
		t.Fatalf("Build() accepted secret-like caller text: exit=%d record=%s", exitCode, string(encoded))
	}
	if strings.Contains(string(encoded), secretLike) {
		t.Fatalf("Build() leaked secret-like caller text: %s", string(encoded))
	}
}

func TestBuildUsesAdmittedReleaseAuthorityProjection(t *testing.T) {
	input := validExternalConsumerInput(t)
	rootInput := input["input"].(map[string]any)
	releaseInput := rootInput["releaseAuthorityInput"].(map[string]any)
	releasePackage := releaseInput["package"].(map[string]any)
	releasePackage["artifactPath"] = "  " + rootInput["tarballPath"].(string) + "  "
	releasePackage["packManifestPath"] = "  " + rootInput["packMetadataPath"].(string) + "  "
	releaseInput["rollback"].(map[string]any)["versionPin"] = "  file:" + rootInput["tarballPath"].(string) + "  "

	admitted, err := admitReportInput(input)
	if err != nil {
		t.Fatalf("admit external-consumer fixture: %v", err)
	}
	input["evidence"].(map[string]any)["consumerProof"].(map[string]any)["releaseAuthorityOutputSha256"] = expectedReleaseAuthorityOutputSHA256(admitted.Input)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		encoded, _ := json.Marshal(record)
		t.Fatalf("Build() exit=%d record=%s, want passed", exitCode, string(encoded))
	}
}

func TestBuildRejectsRegistryReleaseAuthorityProjection(t *testing.T) {
	input := validExternalConsumerInput(t)
	rootInput := input["input"].(map[string]any)
	releaseInput := validExternalRegistryReleaseAuthorityInput(
		rootInput["packageVersion"].(string),
		rootInput["tarballPath"].(string),
		rootInput["packMetadataPath"].(string),
	)
	rootInput["releaseAuthorityInput"] = releaseInput
	admitted, err := admitReportInput(input)
	if err != nil {
		t.Fatalf("admit external-consumer fixture: %v", err)
	}
	input["evidence"].(map[string]any)["consumerProof"].(map[string]any)["releaseAuthorityOutputSha256"] = expectedReleaseAuthorityOutputSHA256(admitted.Input)

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "releaseAuthorityInput.channel must be tarball_pilot") {
		t.Fatalf("Build() accepted registry release authority: exit=%d record=%s", exitCode, string(encoded))
	}
}

func TestExternalConsumerReleaseAuthorityBoundaryUsesOwnerProjectionOnly(t *testing.T) {
	sourceBytes, err := os.ReadFile("externalconsumer.go")
	if err != nil {
		t.Fatalf("read externalconsumer.go: %v", err)
	}
	source := string(sourceBytes)
	if strings.Count(source, `record["releaseAuthorityInput"]`) != 1 {
		t.Fatalf("external consumer must read releaseAuthorityInput only at the admission edge")
	}
	if !strings.Contains(source, `releaseauthority.AdmitConsumerProjection(record["releaseAuthorityInput"])`) {
		t.Fatalf("external consumer must delegate release authority admission to releaseauthority.AdmitConsumerProjection")
	}
	for _, forbidden := range []string{
		"ReleaseAuthorityInput",
		"ReleaseAuthority.Record.JSONValue",
		"stableSHA256(input.ReleaseAuthority",
		"BuildProjection(",
		"releaseauthority.Build(",
		"objectField(",
		"stringField(",
		"boolField(",
		"func admitReleaseAuthority",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("external consumer must not own release-authority raw parsing helper %q", forbidden)
		}
	}
}

func TestExpectedReleaseAuthorityOutputUsesOwnerDigest(t *testing.T) {
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

func validExternalConsumerInput(t *testing.T) map[string]any {
	t.Helper()
	sourceCommit := strings.Repeat("a", 40)
	version := "1.2.3"
	tarballPath := "artifacts/package/agentic-proofkit-" + version + ".tgz"
	packPath := "artifacts/package/npm-pack.json"
	tarballSHA := strings.Repeat("b", 64)
	packSHA := strings.Repeat("c", 64)
	npmSHASum := strings.Repeat("d", 40)
	npmIntegrity := "sha512-testintegrity"
	root := map[string]any{
		"schemaVersion": json.Number("1"),
		"input": map[string]any{
			"schemaVersion":          json.Number("1"),
			"pilotId":                "proofkit.external-consumer.test",
			"pilotMode":              "non_blocking",
			"packageName":            "agentic-proofkit",
			"packageVersion":         version,
			"tarballPath":            tarballPath,
			"tarballSha256":          tarballSHA,
			"packMetadataPath":       packPath,
			"packMetadataSha256":     packSHA,
			"npmIntegrity":           npmIntegrity,
			"npmShasum":              npmSHASum,
			"sourceRepository":       expectedSourceRepository,
			"sourceCommit":           sourceCommit,
			"sourceWorkflowRun":      "12345",
			"sourceArtifactName":     "agentic-proofkit-npm-package-" + sourceCommit,
			"binarySmokeProbeRuleId": "proofkit.external-consumer.binary-smoke",
			"nonClaims":              []any{"External consumer test input is not publication proof."},
			"rollback":               map[string]any{"dependencyRemoval": "temp_consumer_package_and_lockfile", "localWorkspaceFallbackPreserved": true},
			"witnessPlan":            validExternalWitnessPlan(),
			"releaseAuthorityInput":  validExternalReleaseAuthorityInput(version, tarballPath, packPath),
		},
		"evidence": map[string]any{
			"schemaVersion": json.Number("1"),
			"tarball":       map[string]any{"path": tarballPath, "sha1": npmSHASum, "sha256": tarballSHA},
			"packMetadata": map[string]any{
				"path":   packPath,
				"sha256": packSHA,
				"records": []any{
					map[string]any{
						"name":      "agentic-proofkit",
						"version":   version,
						"filename":  "agentic-proofkit-" + version + ".tgz",
						"integrity": npmIntegrity,
						"shasum":    npmSHASum,
						"files":     packedFileRecords(),
					},
				},
			},
			"consumerProof": map[string]any{
				"dependencySpec":               "file:" + tarballPath,
				"installLockContainsPackage":   true,
				"installLockContainsTarball":   true,
				"installLockUsesWorkspace":     false,
				"frozenLockContainsPackage":    true,
				"frozenLockContainsTarball":    true,
				"frozenLockUsesWorkspace":      false,
				"rollbackLockContainsPackage":  false,
				"releaseAuthorityReportKind":   "proofkit.release-authority",
				"releaseAuthorityState":        "passed",
				"binarySmokeOutputSha256":      strings.Repeat("0", 64),
				"cliWitnessPlanOutputSha256":   strings.Repeat("0", 64),
				"releaseAuthorityOutputSha256": strings.Repeat("0", 64),
				"tempConsumerLocation":         "os-temp",
			},
		},
	}
	admitted, err := admitReportInput(root)
	if err != nil {
		t.Fatalf("admit external-consumer fixture: %v", err)
	}
	proof := root["evidence"].(map[string]any)["consumerProof"].(map[string]any)
	proof["binarySmokeOutputSha256"] = expectedBinarySmokeOutputSHA256(admitted.Input)
	proof["cliWitnessPlanOutputSha256"] = expectedCLIWitnessPlanOutputSHA256(admitted.Input)
	proof["releaseAuthorityOutputSha256"] = expectedReleaseAuthorityOutputSHA256(admitted.Input)
	return root
}

func validExternalWitnessPlan() map[string]any {
	return map[string]any{
		"vocabulary": map[string]any{
			"artifactKinds":                 []any{"report"},
			"credentialClasses":             []any{"none"},
			"environmentClasses":            []any{"local"},
			"nonCacheableCredentialClasses": []any{},
			"parallelGroups":                []any{"local"},
			"maxTimeoutMs":                  json.Number("10000"),
			"environmentClassPolicies": []any{
				map[string]any{
					"environmentClass":  "local",
					"networkPolicies":   []any{"none"},
					"credentialClasses": []any{"none"},
					"cachePolicies":     []any{"disabled"},
				},
			},
		},
		"commands": []any{
			map[string]any{
				"schemaVersion":   json.Number("1"),
				"id":              "proofkit.external-consumer.binary-smoke",
				"cwd":             ".",
				"argv":            []any{"agentic-proofkit", "--version"},
				"timeoutMs":       json.Number("1000"),
				"networkPolicy":   "none",
				"credentialClass": "none",
				"cachePolicy":     "disabled",
				"parallelGroup":   "local",
				"environment":     map[string]any{"inherit": "none", "allowlist": []any{}, "classes": []any{"local"}},
				"expectedArtifacts": []any{
					map[string]any{"kind": "report", "path": "artifacts/proofkit/binary-smoke.json", "required": true},
				},
				"exitCodePolicy": map[string]any{"kind": "zero", "successCodes": []any{json.Number("0")}},
			},
		},
	}
}

func validExternalReleaseAuthorityInput(version string, tarballPath string, packPath string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("3"),
		"releaseId":     "proofkit.external-consumer.release",
		"channel":       "tarball_pilot",
		"rolloutClaim":  false,
		"package": map[string]any{
			"artifactPath":           tarballPath,
			"manifestPrivate":        true,
			"name":                   "agentic-proofkit",
			"packageManagerLockfile": "go.mod",
			"packManifestPath":       packPath,
			"publishConfigRegistry":  nil,
			"version":                version,
		},
		"artifactProof": map[string]any{
			"packDryRunCommandId":           "proofkit.external-consumer.pack-dry-run",
			"packageArtifactCommandId":      "proofkit.external-consumer.package-artifact",
			"outsideConsumerInstallProofId": "proofkit.external-consumer.install",
			"binarySmokeProofId":            "proofkit.external-consumer.binary-smoke",
			"cliSmokeProofId":               "proofkit.external-consumer.cli-smoke",
			"deepImportRejectionProofId":    "proofkit.external-consumer.deep-import-rejection",
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
			"versionPin": "file:" + tarballPath,
		},
		"nonClaims": []any{"External consumer tarball pilot is not a registry release."},
	}
}

func validExternalRegistryReleaseAuthorityInput(version string, tarballPath string, packPath string) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("3"),
		"releaseId":     "proofkit.external-consumer.registry-release",
		"channel":       "registry_release",
		"rolloutClaim":  false,
		"package": map[string]any{
			"artifactPath":           tarballPath,
			"manifestPrivate":        false,
			"name":                   "agentic-proofkit",
			"packageManagerLockfile": "go.mod",
			"packManifestPath":       packPath,
			"publishConfigRegistry":  "https://registry.npmjs.org",
			"version":                version,
		},
		"artifactProof": map[string]any{
			"packDryRunCommandId":           "proofkit.external-consumer.pack-dry-run",
			"packageArtifactCommandId":      "proofkit.external-consumer.package-artifact",
			"outsideConsumerInstallProofId": "proofkit.external-consumer.install",
			"binarySmokeProofId":            "proofkit.external-consumer.binary-smoke",
			"cliSmokeProofId":               "proofkit.external-consumer.cli-smoke",
			"deepImportRejectionProofId":    "proofkit.external-consumer.deep-import-rejection",
			"registryPublishDryRunProofId":  "proofkit.external-consumer.registry-publish-dry-run",
		},
		"consumerContract": map[string]any{
			"binarySmokeOnly":              true,
			"dependencyPinType":            "registry_version",
			"lockfileRequired":             true,
			"siblingSourceCheckoutAllowed": false,
		},
		"registryAuthority": map[string]any{
			"consumerMigrationPath": "External consumer tests do not own registry migration.",
			"packageScope":          "",
			"publishAuthorityMode":  "npm_trusted_publishing",
			"publishWorkflowPath":   ".github/workflows/release.yml",
			"registryKind":          "npm_registry",
			"registryUrl":           "https://registry.npmjs.org",
			"releaseTagPattern":     "v" + version,
			"rollbackPolicy":        "Pin consumers to the previous admitted registry version.",
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
		"nonClaims": []any{"External consumer registry release fixture is a channel rejection witness."},
	}
}

func packedFileRecords() []any {
	records := make([]any, 0, len(requiredPackedFiles))
	for _, path := range requiredPackedFiles {
		records = append(records, map[string]any{"path": path})
	}
	return records
}
