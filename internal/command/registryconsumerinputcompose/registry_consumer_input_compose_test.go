package registryconsumerinputcompose

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

var testRequiredPreconditionIDs = []string{
	"binary.smoke",
	"cli.witness-plan",
	"frozen.lock",
	"install.lock",
	"registry.metadata",
	"release-authority.report",
	"rollback.lock",
}

func TestBuildComposesInputAcceptedByRegistryConsumer(t *testing.T) {
	input := validComposeInput(t)
	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || output["state"] != "passed" {
		t.Fatalf("Build() exit=%d state=%v output=%#v, want passed", exitCode, output["state"], output)
	}
	composed := composedRegistryInput(t, output)
	assertRegistryConsumerInputMatchesExpectedFacts(t, input, composed)
	record, consumerExit, err := registryconsumer.Build(composed)
	if err != nil {
		t.Fatalf("registryconsumer.Build() error=%v", err)
	}
	if consumerExit != 0 || record.State != "passed" {
		t.Fatalf("registryconsumer.Build() exit=%d state=%s rules=%#v, want passed", consumerExit, record.State, record.RuleResults)
	}
}

func TestBuildBlocksUnavailableRequiredPreconditionsWithoutAcceptedInput(t *testing.T) {
	for _, preconditionID := range testRequiredPreconditionIDs {
		t.Run(preconditionID, func(t *testing.T) {
			input := validComposeInput(t)
			setPreconditionState(t, input, preconditionID, "unavailable")

			output, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			if exitCode == 0 || output["state"] != "blocked" {
				t.Fatalf("Build() exit=%d state=%v, want blocked", exitCode, output["state"])
			}
			if output["registryConsumerInput"] != nil {
				t.Fatalf("blocked output must not emit registryConsumerInput")
			}
			assertRuleMessage(t, output, "precondition unavailable: "+preconditionID)
		})
	}
}

func TestBuildRejectsMissingRequiredPreconditionsWithoutAcceptedInput(t *testing.T) {
	for _, preconditionID := range testRequiredPreconditionIDs {
		t.Run(preconditionID, func(t *testing.T) {
			input := validComposeInput(t)
			input["preconditions"] = withoutPrecondition(t, input, preconditionID)

			output, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			if exitCode == 0 || output["state"] != "failed" {
				t.Fatalf("Build() exit=%d state=%v, want failed", exitCode, output["state"])
			}
			if output["registryConsumerInput"] != nil {
				t.Fatalf("failed output must not emit registryConsumerInput")
			}
			assertRuleMessage(t, output, "missing required precondition: "+preconditionID)
		})
	}
}

func TestBuildRejectsPrimitiveFactDrift(t *testing.T) {
	tests := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{
			name: "dependency spec drift",
			edit: func(input map[string]any) {
				input["dependencySpec"] = "1.2.4"
			},
			want: "dependencySpec must be the exact packageVersion",
		},
		{
			name: "registry package name drift",
			edit: func(input map[string]any) {
				input["registryMetadata"].(map[string]any)["packageName"] = "other-package"
			},
			want: "registry metadata packageName must match packageName",
		},
		{
			name: "registry package version drift",
			edit: func(input map[string]any) {
				input["registryMetadata"].(map[string]any)["packageVersion"] = "1.2.4"
			},
			want: "registry metadata packageVersion must match packageVersion",
		},
		{
			name: "registry shasum drift",
			edit: func(input map[string]any) {
				input["registryMetadata"].(map[string]any)["tarballShasum"] = strings.Repeat("A", 40)
			},
			want: "tarballShasum must be lowercase sha1 hex",
		},
		{
			name: "registry integrity drift",
			edit: func(input map[string]any) {
				input["registryMetadata"].(map[string]any)["tarballIntegrity"] = "sha1-AAAAAAAA"
			},
			want: "tarballIntegrity must be npm sha512 integrity text",
		},
		{
			name: "registry tarball filename drift",
			edit: func(input map[string]any) {
				input["registryMetadata"].(map[string]any)["tarballFileName"] = "agentic-proofkit-1.2.4.tgz"
			},
			want: "tarballFileName must match package name and version",
		},
		{
			name: "registry integrity comparison false",
			edit: func(input map[string]any) {
				input["registryPackProof"].(map[string]any)["integrityMatches"] = false
			},
			want: "registry pack integrity comparison must match admitted metadata",
		},
		{
			name: "registry name comparison false",
			edit: func(input map[string]any) {
				input["registryPackProof"].(map[string]any)["nameMatches"] = false
			},
			want: "registry pack name comparison must match packageName",
		},
		{
			name: "registry shasum comparison false",
			edit: func(input map[string]any) {
				input["registryPackProof"].(map[string]any)["shasumMatches"] = false
			},
			want: "registry pack shasum comparison must match admitted metadata",
		},
		{
			name: "registry version comparison false",
			edit: func(input map[string]any) {
				input["registryPackProof"].(map[string]any)["versionMatches"] = false
			},
			want: "registry pack version comparison must match packageVersion",
		},
		{
			name: "install lock missing package",
			edit: func(input map[string]any) {
				input["install"].(map[string]any)["lockContainsPackage"] = false
			},
			want: "install lock must contain the package",
		},
		{
			name: "frozen lock missing package",
			edit: func(input map[string]any) {
				input["frozenInstall"].(map[string]any)["lockContainsPackage"] = false
			},
			want: "frozen install lock must contain the package",
		},
		{
			name: "install workspace lock",
			edit: func(input map[string]any) {
				input["install"].(map[string]any)["lockUsesWorkspace"] = true
			},
			want: "install lock must not resolve through workspace",
		},
		{
			name: "frozen workspace lock",
			edit: func(input map[string]any) {
				input["frozenInstall"].(map[string]any)["lockUsesWorkspace"] = true
			},
			want: "frozen install lock must not resolve through workspace",
		},
		{
			name: "rollback contains package",
			edit: func(input map[string]any) {
				input["rollback"].(map[string]any)["lockContainsPackage"] = true
			},
			want: "rollback lock must not contain the package",
		},
		{
			name: "release authority kind drift",
			edit: func(input map[string]any) {
				input["releaseAuthorityReport"].(map[string]any)["reportKind"] = "proofkit.other"
			},
			want: "releaseAuthorityReport.reportKind must be proofkit.release-authority",
		},
		{
			name: "release authority state drift",
			edit: func(input map[string]any) {
				input["releaseAuthorityReport"].(map[string]any)["state"] = "failed"
			},
			want: "releaseAuthorityReport.state must be passed",
		},
		{
			name: "release authority digest drift",
			edit: func(input map[string]any) {
				input["releaseAuthorityReport"].(map[string]any)["outputSha256"] = strings.Repeat("f", 64)
			},
			want: "releaseAuthorityReport.outputSha256 must match admitted release-authority report digest",
		},
		{
			name: "release authority channel drift",
			edit: func(input map[string]any) {
				releaseInput := input["releaseAuthorityInput"].(map[string]any)
				releaseInput["channel"] = "tarball_pilot"
				releaseInput["registryAuthority"] = nil
				releaseInput["package"].(map[string]any)["manifestPrivate"] = true
				releaseInput["package"].(map[string]any)["publishConfigRegistry"] = nil
				releaseInput["consumerContract"].(map[string]any)["dependencyPinType"] = "file_tarball"
				delete(releaseInput["artifactProof"].(map[string]any), "registryPublishDryRunProofId")
				releaseInput["rollback"].(map[string]any)["versionPin"] = "file:artifacts/package/agentic-proofkit-1.2.3.tgz"
				input["releaseAuthorityReport"].(map[string]any)["outputSha256"] = releaseAuthorityOutputSHA256(t, releaseInput)
			},
			want: "releaseAuthorityInput.channel must be registry_release",
		},
		{
			name: "release authority schema version drift",
			edit: func(input map[string]any) {
				releaseInput := input["releaseAuthorityInput"].(map[string]any)
				releaseInput["schemaVersion"] = json.Number("2")
				input["releaseAuthorityReport"].(map[string]any)["outputSha256"] = releaseAuthorityOutputSHA256(t, releaseInput)
			},
			want: "releaseAuthorityInput.schemaVersion must be 3 for registry consumer proof",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validComposeInput(t)
			tt.edit(input)
			output, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() error=%v", err)
			}
			if exitCode == 0 || output["state"] != "failed" {
				t.Fatalf("Build() exit=%d state=%v, want failed", exitCode, output["state"])
			}
			if output["registryConsumerInput"] != nil {
				t.Fatalf("failed output must not emit registryConsumerInput")
			}
			assertRuleMessage(t, output, tt.want)
		})
	}
}

func TestBuildUsesAdmittedPrimitiveFactsAfterRawMutation(t *testing.T) {
	raw := validComposeInput(t)
	expected := expectedRegistryConsumerInput(t, raw)
	admitted, err := admitInput(raw)
	if err != nil {
		t.Fatalf("admitInput() error=%v", err)
	}
	mutateRawPrimitiveFacts(raw)

	output, exitCode := buildOutput(admitted)
	if exitCode != 0 || output["state"] != "passed" {
		t.Fatalf("buildOutput(admitted) exit=%d state=%v output=%#v, want passed", exitCode, output["state"], output)
	}
	assertStableJSONEqual(t, "registry consumer input after raw mutation", expected, composedRegistryInput(t, output))
}

func TestBuildPreservesSmokeDigestsExactly(t *testing.T) {
	input := validComposeInput(t)
	binary := strings.Repeat("1", 64)
	cli := strings.Repeat("2", 64)
	input["smoke"].(map[string]any)["binarySmokeOutputSha256"] = binary
	input["smoke"].(map[string]any)["cliWitnessPlanOutputSha256"] = cli

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || output["state"] != "passed" {
		t.Fatalf("Build() exit=%d state=%v, want passed", exitCode, output["state"])
	}
	proof := composedRegistryInput(t, output)["proof"].(map[string]any)
	if proof["binarySmokeOutputSha256"] != binary || proof["cliWitnessPlanOutputSha256"] != cli {
		t.Fatalf("smoke digests were not preserved exactly: %#v", proof)
	}
}

func TestBuildRejectsMalformedSmokeDigestAsInvalidInput(t *testing.T) {
	input := validComposeInput(t)
	input["smoke"].(map[string]any)["binarySmokeOutputSha256"] = strings.Repeat("A", 64)

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode == 0 || output["state"] != "failed" {
		t.Fatalf("Build() exit=%d state=%v, want failed", exitCode, output["state"])
	}
	if output["registryConsumerInput"] != nil {
		t.Fatalf("invalid input output must not emit registryConsumerInput")
	}
	assertRuleMessage(t, output, "must be lowercase sha256 hex")
}

func TestBuildRejectsSecretLikeReleaseAuthorityFreeTextWithoutComposedInput(t *testing.T) {
	input := validComposeInput(t)
	input["releaseAuthorityInput"].(map[string]any)["rollback"].(map[string]any)["procedure"] = "api_key=secret-value"

	output, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode == 0 || output["state"] != "failed" {
		t.Fatalf("Build() exit=%d state=%v, want failed", exitCode, output["state"])
	}
	if output["registryConsumerInput"] != nil {
		t.Fatalf("secret-like release authority text must not be emitted in registryConsumerInput")
	}
	assertRuleMessage(t, output, "must not contain secret-like values")
}

func TestBuildOutputIsStableForEquivalentPrimitiveFactMaps(t *testing.T) {
	left, _, err := Build(validComposeInput(t))
	if err != nil {
		t.Fatalf("Build(left) error=%v", err)
	}
	rightInput := validComposeInput(t)
	rightInput["registryMetadata"] = map[string]any{
		"tarballShasum":    strings.Repeat("a", 40),
		"tarballIntegrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"tarballFileName":  "agentic-proofkit-1.2.3.tgz",
		"packageVersion":   "1.2.3",
		"packageName":      "agentic-proofkit",
	}
	right, _, err := Build(rightInput)
	if err != nil {
		t.Fatalf("Build(right) error=%v", err)
	}
	leftJSON, err := stablejson.Marshal(left)
	if err != nil {
		t.Fatalf("marshal left: %v", err)
	}
	rightJSON, err := stablejson.Marshal(right)
	if err != nil {
		t.Fatalf("marshal right: %v", err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("equivalent primitive maps produced different output\nleft=%s\nright=%s", leftJSON, rightJSON)
	}
}

func TestRegistryConsumerInputComposeReleaseAuthorityBoundaryUsesOwnerProjectionOnly(t *testing.T) {
	sourceBytes, err := os.ReadFile("registry_consumer_input_compose.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	source := string(sourceBytes)
	if strings.Count(source, `record["releaseAuthorityInput"]`) != 1 {
		t.Fatalf("composer must read releaseAuthorityInput only at the admission edge")
	}
	if !strings.Contains(source, `releaseauthority.AdmitConsumerProjection(record["releaseAuthorityInput"])`) {
		t.Fatalf("composer must delegate release authority admission to releaseauthority.AdmitConsumerProjection")
	}
	if strings.Contains(source, `Record.JSONValue()`) {
		t.Fatalf("composer must not use release-authority report JSON as releaseAuthorityInput")
	}
	if !strings.Contains(source, `input.ReleaseAuthority.InputJSON`) {
		t.Fatalf("composer must consume release-authority owner-projected admitted input")
	}
}

func validComposeInput(t *testing.T) map[string]any {
	t.Helper()
	releaseInput := validRegistryReleaseInput()
	releaseDigest := releaseAuthorityOutputSHA256(t, releaseInput)
	return map[string]any{
		"schemaVersion":      json.Number("1"),
		"compositionId":      "proofkit.registry.consumer.input.compose.test",
		"consumerId":         "proofkit.registry.consumer.test",
		"dependencyName":     "agentic-proofkit",
		"dependencySpec":     "1.2.3",
		"packageName":        "agentic-proofkit",
		"packageVersion":     "1.2.3",
		"registryUrl":        "https://registry.npmjs.org",
		"rollbackVersionPin": "agentic-proofkit@1.2.2",
		"registryMetadata": map[string]any{
			"packageName":      "agentic-proofkit",
			"packageVersion":   "1.2.3",
			"tarballFileName":  "agentic-proofkit-1.2.3.tgz",
			"tarballIntegrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"tarballShasum":    strings.Repeat("a", 40),
		},
		"registryPackProof": map[string]any{
			"integrityMatches": true,
			"nameMatches":      true,
			"shasumMatches":    true,
			"versionMatches":   true,
		},
		"install": map[string]any{
			"dependencySpec":      "1.2.3",
			"lockContainsPackage": true,
			"lockUsesWorkspace":   false,
		},
		"frozenInstall": map[string]any{
			"dependencySpec":      "1.2.3",
			"lockContainsPackage": true,
			"lockUsesWorkspace":   false,
		},
		"smoke": map[string]any{
			"binarySmokeOutputSha256":    strings.Repeat("b", 64),
			"cliWitnessPlanOutputSha256": strings.Repeat("c", 64),
		},
		"releaseAuthorityInput": releaseInput,
		"releaseAuthorityReport": map[string]any{
			"outputSha256": releaseDigest,
			"reportKind":   "proofkit.release-authority",
			"state":        "passed",
		},
		"rollback": map[string]any{
			"lockContainsPackage": false,
		},
		"preconditions": availablePreconditions(),
		"nonClaims": []any{
			"Registry consumer input compose fixture does not claim registry publication.",
		},
	}
}

func availablePreconditions() []any {
	out := make([]any, 0, len(testRequiredPreconditionIDs))
	for _, id := range testRequiredPreconditionIDs {
		out = append(out, map[string]any{
			"preconditionId": id,
			"reason":         "fixture fact is available",
			"state":          "available",
		})
	}
	return out
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
		t.Fatalf("releaseauthority.AdmitConsumerProjection() error=%v", admission.Err)
	}
	if admission.Record.State != "passed" {
		t.Fatalf("releaseauthority.AdmitConsumerProjection() state=%s rules=%#v", admission.Record.State, admission.Record.RuleResults)
	}
	return admission.OutputSHA256
}

func composedRegistryInput(t *testing.T, output map[string]any) map[string]any {
	t.Helper()
	value, ok := output["registryConsumerInput"].(map[string]any)
	if !ok {
		t.Fatalf("registryConsumerInput missing or wrong type: %#v", output["registryConsumerInput"])
	}
	return value
}

func assertRegistryConsumerInputMatchesExpectedFacts(t *testing.T, input map[string]any, composed map[string]any) {
	t.Helper()
	assertStableJSONEqual(t, "registry consumer input", expectedRegistryConsumerInput(t, input), composed)
}

func expectedRegistryConsumerInput(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	registryMetadata := input["registryMetadata"].(map[string]any)
	smoke := input["smoke"].(map[string]any)
	packProof := input["registryPackProof"].(map[string]any)
	releaseAdmission := releaseauthority.AdmitConsumerProjection(input["releaseAuthorityInput"])
	if releaseAdmission.Err != nil {
		t.Fatalf("releaseauthority.AdmitConsumerProjection() error=%v", releaseAdmission.Err)
	}
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"input": map[string]any{
			"consumerId":            input["consumerId"],
			"dependencyName":        input["dependencyName"],
			"dependencySpec":        input["dependencySpec"],
			"nonClaims":             expectedRegistryConsumerNonClaims(),
			"packageName":           input["packageName"],
			"packageVersion":        input["packageVersion"],
			"registryUrl":           input["registryUrl"],
			"releaseAuthorityInput": releaseAdmission.InputJSON,
			"rollbackVersionPin":    input["rollbackVersionPin"],
			"schemaVersion":         json.Number("1"),
			"tarballFileName":       registryMetadata["tarballFileName"],
			"tarballIntegrity":      registryMetadata["tarballIntegrity"],
			"tarballShasum":         registryMetadata["tarballShasum"],
		},
		"proof": map[string]any{
			"binarySmokeOutputSha256":      smoke["binarySmokeOutputSha256"],
			"cliWitnessPlanOutputSha256":   smoke["cliWitnessPlanOutputSha256"],
			"dependencySpec":               input["dependencySpec"],
			"frozenLockContainsPackage":    true,
			"frozenLockUsesWorkspace":      false,
			"installLockContainsPackage":   true,
			"installLockUsesWorkspace":     false,
			"registryPackIntegrityMatches": packProof["integrityMatches"],
			"registryPackNameMatches":      packProof["nameMatches"],
			"registryPackShasumMatches":    packProof["shasumMatches"],
			"registryPackVersionMatches":   packProof["versionMatches"],
			"releaseAuthorityOutputSha256": input["releaseAuthorityReport"].(map[string]any)["outputSha256"],
			"releaseAuthorityReportKind":   "proofkit.release-authority",
			"releaseAuthorityState":        "passed",
			"rollbackLockContainsPackage":  false,
			"tempConsumerLocation":         "os-temp",
		},
	}
}

func expectedRegistryConsumerNonClaims() []any {
	return []any{
		"Registry consumer input compose fixture does not claim registry publication.",
		"Registry consumer proof input composition does not authenticate producers, compute proof freshness, approve merge, approve release, approve rollout, or approve production readiness.",
		"Registry consumer proof input composition does not fetch package registries or run package managers.",
		"Registry consumer proof input composition does not read manifests, lockfiles, or repository state.",
		"Registry-consumer remains the final proof-schema owner and final consumption-evidence validator.",
	}
}

func setPreconditionState(t *testing.T, input map[string]any, preconditionID string, state string) {
	t.Helper()
	for _, value := range input["preconditions"].([]any) {
		record := value.(map[string]any)
		if record["preconditionId"] == preconditionID {
			record["state"] = state
			record["reason"] = "test-owned precondition mutation for " + preconditionID
			return
		}
	}
	t.Fatalf("fixture missing precondition %s", preconditionID)
}

func withoutPrecondition(t *testing.T, input map[string]any, preconditionID string) []any {
	t.Helper()
	values := input["preconditions"].([]any)
	out := make([]any, 0, len(values)-1)
	found := false
	for _, value := range values {
		record := value.(map[string]any)
		if record["preconditionId"] == preconditionID {
			found = true
			continue
		}
		out = append(out, value)
	}
	if !found {
		t.Fatalf("fixture missing precondition %s", preconditionID)
	}
	return out
}

func mutateRawPrimitiveFacts(raw map[string]any) {
	raw["consumerId"] = "proofkit.registry.consumer.mutated"
	raw["dependencyName"] = "mutated-proofkit"
	raw["dependencySpec"] = "9.9.9"
	raw["packageName"] = "mutated-proofkit"
	raw["packageVersion"] = "9.9.9"
	raw["registryUrl"] = "https://example.invalid"
	raw["rollbackVersionPin"] = "mutated-proofkit@9.9.8"
	raw["registryMetadata"].(map[string]any)["packageName"] = "mutated-proofkit"
	raw["registryMetadata"].(map[string]any)["packageVersion"] = "9.9.9"
	raw["registryMetadata"].(map[string]any)["tarballFileName"] = "mutated-proofkit-9.9.9.tgz"
	raw["registryMetadata"].(map[string]any)["tarballIntegrity"] = "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	raw["registryMetadata"].(map[string]any)["tarballShasum"] = strings.Repeat("d", 40)
	raw["registryPackProof"].(map[string]any)["integrityMatches"] = false
	raw["registryPackProof"].(map[string]any)["nameMatches"] = false
	raw["registryPackProof"].(map[string]any)["shasumMatches"] = false
	raw["registryPackProof"].(map[string]any)["versionMatches"] = false
	raw["install"].(map[string]any)["dependencySpec"] = "9.9.9"
	raw["install"].(map[string]any)["lockContainsPackage"] = false
	raw["install"].(map[string]any)["lockUsesWorkspace"] = true
	raw["frozenInstall"].(map[string]any)["dependencySpec"] = "9.9.9"
	raw["frozenInstall"].(map[string]any)["lockContainsPackage"] = false
	raw["frozenInstall"].(map[string]any)["lockUsesWorkspace"] = true
	raw["smoke"].(map[string]any)["binarySmokeOutputSha256"] = strings.Repeat("e", 64)
	raw["smoke"].(map[string]any)["cliWitnessPlanOutputSha256"] = strings.Repeat("f", 64)
	raw["releaseAuthorityInput"].(map[string]any)["releaseId"] = "proofkit.test.release.mutated"
	raw["releaseAuthorityReport"].(map[string]any)["outputSha256"] = strings.Repeat("0", 64)
	raw["releaseAuthorityReport"].(map[string]any)["reportKind"] = "proofkit.mutated"
	raw["releaseAuthorityReport"].(map[string]any)["state"] = "failed"
	raw["rollback"].(map[string]any)["lockContainsPackage"] = true
	for _, value := range raw["preconditions"].([]any) {
		record := value.(map[string]any)
		record["reason"] = "mutated after admission"
		record["state"] = "unavailable"
	}
	raw["nonClaims"] = []any{"Mutated non-claim after admission."}
}

func assertStableJSONEqual(t *testing.T, label string, want any, got any) {
	t.Helper()
	wantJSON, err := stablejson.Marshal(want)
	if err != nil {
		t.Fatalf("marshal expected %s: %v", label, err)
	}
	gotJSON, err := stablejson.Marshal(got)
	if err != nil {
		t.Fatalf("marshal actual %s: %v", label, err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("%s drifted\nwant=%s\ngot =%s", label, wantJSON, gotJSON)
	}
}

func assertRuleMessage(t *testing.T, output map[string]any, want string) {
	t.Helper()
	encoded, _ := json.Marshal(output["ruleResults"])
	if !strings.Contains(string(encoded), want) {
		t.Fatalf("ruleResults missing %q: %s", want, encoded)
	}
}
