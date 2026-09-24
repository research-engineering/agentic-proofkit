package deploymentevidenceadmission

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestBuildAdmitsCandidateEvidenceAndRejectsUnpinnedImages(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.094704258305539434923641925385994047558037254453527095265999848506667453675409")
	record, exitCode, err := Build(validDeploymentEvidenceInput())
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		t.Fatalf("Build() exit=%d state=%s, want passed", exitCode, record.State)
	}

	input := validDeploymentEvidenceInput()
	fact := input["evidence"].(map[string]any)["facts"].([]any)[0].(map[string]any)
	fact["imageRefs"] = []any{"registry.example.test/proofkit:latest"}
	record, exitCode, err = Build(input)
	if err != nil {
		t.Fatalf("Build() unpinned image error=%v", err)
	}
	encoded, _ := json.Marshal(record)
	if exitCode == 0 || record.State != "failed" || !strings.Contains(string(encoded), "must be pinned by digest with @sha256") {
		t.Fatalf("Build() accepted unpinned image ref: exit=%d record=%s", exitCode, string(encoded))
	}
}

func TestBuildRedactsSecretLikeUnknownEvidenceFields(t *testing.T) {
	input := validDeploymentEvidenceInput()
	input["evidence"].(map[string]any)["api_key=ghp_secretvalue"] = "ignored"

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, "api_key") || strings.Contains(text, "ghp_secretvalue") {
		t.Fatalf("record leaked secret-like unsupported field name: %s", text)
	}
	if !strings.Contains(text, "redacted-unsupported-field-001") {
		t.Fatalf("record missing redacted unsupported field label: %s", text)
	}
}

func TestBuildRejectsSecretLikeNestedEvidenceThroughSharedScanner(t *testing.T) {
	input := validDeploymentEvidenceInput()
	input["rawOperatorEvidence"] = []any{
		map[string]any{
			"evidenceRef": "operator.note",
			"payload": map[string]any{
				"nested": []any{
					map[string]any{"token": "Authorization: Bearer abcdefghijklmnop"},
				},
			},
		},
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exit=%d state=%s, want failed", exitCode, record.State)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	text := string(encoded)
	if strings.Contains(text, "abcdefghijklmnop") || strings.Contains(text, "Authorization") {
		t.Fatalf("record leaked secret-shaped nested value: %s", text)
	}
	if !strings.Contains(text, "rawOperatorEvidence[0].payload.nested[0].token must not contain secret-shaped material") {
		t.Fatalf("record missing shared scanner path finding: %s", text)
	}
}

func TestBuildClassifiesTemporaryEndpointHosts(t *testing.T) {
	for _, test := range []struct {
		host      string
		temporary bool
	}{
		{"trycloudflare.com", true},
		{"demo.trycloudflare.com", true},
		{"demo.TRYCLOUDFLARE.COM", true},
		{"demo.trycloudflare.com.", true},
		{"demo.trycloudflare\u3002com", true},
		{"demo.trycloudflare\u3002com\u3002", true},
		{"demo.trycloudflare\uff0ecom", true},
		{"demo.\uff54\uff52\uff59cloudflare.com", true},
		{"nottrycloudflare.com", false},
		{"trycloudflare.com.example.test", false},
	} {
		input := validDeploymentEvidenceInput()
		fact := input["evidence"].(map[string]any)["facts"].([]any)[0].(map[string]any)
		fact["urls"] = []any{map[string]any{
			"endpointId":   "proofkit.test.endpoint",
			"endpointKind": "stable",
			"url":          "https://" + test.host + "/proof",
		}}
		record, exitCode, err := Build(input)
		if err != nil {
			t.Fatalf("Build(%q) error=%v", test.host, err)
		}
		if (exitCode != 0) != test.temporary {
			t.Fatalf("Build(%q) exit=%d state=%s, temporary=%t", test.host, exitCode, record.State, test.temporary)
		}
		if test.temporary {
			encoded, err := json.Marshal(record)
			if err != nil || !strings.Contains(string(encoded), "stable endpoint must not use a temporary endpoint host") {
				t.Fatalf("Build(%q) did not identify the temporary host: %s, error=%v", test.host, encoded, err)
			}
		}
	}
}

func TestCanonicalEndpointHostRejectsInvalidDNSLabels(t *testing.T) {
	for _, host := range []string{".", "bad..example.test"} {
		if value, err := canonicalEndpointHost(host); err == nil {
			t.Fatalf("canonicalEndpointHost(%q)=%q, want invalid host", host, value)
		}
	}
}

func TestPolicyRejectsDuplicateCanonicalTemporarySuffixes(t *testing.T) {
	for _, suffixes := range [][]any{
		{"TRYCLOUDFLARE.COM", "trycloudflare.com"},
		{"trycloudflare.com", "trycloudflare\u3002com"},
	} {
		input := validDeploymentEvidenceInput()
		input["policy"].(map[string]any)["temporaryEndpointHostSuffixes"] = suffixes
		if _, err := admitPolicy(input["policy"]); err == nil || !strings.Contains(err.Error(), "unique after DNS normalization") {
			t.Fatalf("admitPolicy(%v) error=%v, want canonical duplicate rejection", suffixes, err)
		}
	}
}

func TestBuildRejectsIDNAEquivalentLocalHost(t *testing.T) {
	input := validDeploymentEvidenceInput()
	fact := input["evidence"].(map[string]any)["facts"].([]any)[0].(map[string]any)
	fact["urls"] = []any{map[string]any{
		"endpointId":   "proofkit.test.endpoint",
		"endpointKind": "stable",
		"url":          "https://\uff4c\uff4f\uff43\uff41\uff4c\uff48\uff4f\uff53\uff54/proof",
	}}
	record, exitCode, err := Build(input)
	if err != nil || exitCode == 0 {
		t.Fatalf("Build() exit=%d error=%v, want local-host denial", exitCode, err)
	}
	encoded, err := json.Marshal(record)
	if err != nil || !strings.Contains(string(encoded), ".url must not be local or loopback") {
		t.Fatalf("Build() did not classify IDNA-equivalent localhost: %s, error=%v", encoded, err)
	}
}

func TestBuildRejectsCallerLocalIndicatorsAcrossDNSRepresentations(t *testing.T) {
	for _, test := range []struct {
		indicator string
		host      string
	}{
		{"b\u00fcro.example", "b\u00fcro.example"},
		{"b\u00fcro.example", "xn--bro-hoa.example"},
		{"xn--bro-hoa.example", "b\u00fcro.example"},
		{"internal.example.", "internal.example"},
	} {
		input := validDeploymentEvidenceInput()
		input["policy"].(map[string]any)["localRefIndicators"] = []any{test.indicator}
		fact := input["evidence"].(map[string]any)["facts"].([]any)[0].(map[string]any)
		fact["urls"] = []any{map[string]any{
			"endpointId": "proofkit.test.endpoint", "endpointKind": "stable",
			"url": "https://" + test.host + "/proof",
		}}
		record, exitCode, err := Build(input)
		if err != nil || exitCode == 0 {
			t.Fatalf("Build(%q, %q) exit=%d error=%v, want local-host denial", test.indicator, test.host, exitCode, err)
		}
		encoded, err := json.Marshal(record)
		if err != nil || !strings.Contains(string(encoded), ".url must not be local or loopback") {
			t.Fatalf("Build(%q, %q) failed for wrong reason: %s, error=%v", test.indicator, test.host, encoded, err)
		}
	}
}

func TestBuildAdmitsOnlyCalendarValidUTCExpiry(t *testing.T) {
	for _, test := range []struct {
		expiresAt string
		valid     bool
	}{
		{"2024-02-29T23:59:59Z", true},
		{"1990-12-31T23:59:60Z", true},
		{"2016-12-31T23:59:60.5Z", true},
		{"2025-02-29T23:59:59Z", false},
		{"1990-12-30T23:59:60Z", false},
		{"1990-12-31T22:59:60Z", false},
		{"2026-12-31T23:59:60Z", false},
		{"2026-02-31T25:61:61Z", false},
		{"2026-01-01T00:00:00+00:00", false},
	} {
		input := validDeploymentEvidenceInput()
		fact := input["evidence"].(map[string]any)["facts"].([]any)[0].(map[string]any)
		fact["urls"] = []any{map[string]any{
			"endpointId":                   "proofkit.test.endpoint",
			"endpointKind":                 "temporary",
			"url":                          "https://demo.trycloudflare.com/proof",
			"expiresAt":                    test.expiresAt,
			"temporaryEndpointApprovalRef": "proofkit.test.approval",
			"replacementPlanRef":           "proofkit.test.replacement",
		}}
		record, exitCode, err := Build(input)
		if err != nil {
			t.Fatalf("Build(%q) error=%v", test.expiresAt, err)
		}
		if (exitCode == 0) != test.valid {
			t.Fatalf("Build(%q) exit=%d state=%s, valid=%t", test.expiresAt, exitCode, record.State, test.valid)
		}
		if !test.valid {
			encoded, err := json.Marshal(record)
			if err != nil || !strings.Contains(string(encoded), ".expiresAt must be an RFC3339 UTC timestamp") {
				t.Fatalf("Build(%q) did not identify the invalid timestamp: %s, error=%v", test.expiresAt, encoded, err)
			}
		}
	}
}

func validDeploymentEvidenceInput() map[string]any {
	nonClaim := "Deployment evidence test fixture does not prove live deployment."
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"admissionId":   "proofkit.test.deployment",
		"evidence": map[string]any{
			"schema":          "deployment.evidence.v1",
			"proofScope":      "local",
			"deploymentClaim": "candidate",
			"evidenceId":      "proofkit.test.evidence",
			"facts": []any{
				map[string]any{
					"factId":        "proofkit.test.fact",
					"kind":          "release_artifact",
					"sourceCommits": []any{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
					"imageRefs":     []any{"registry.example.test/proofkit@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				},
			},
			"nonClaims": []any{nonClaim},
		},
		"policy": map[string]any{
			"expectedDeploymentClaim":       "candidate",
			"expectedEvidenceSchema":        "deployment.evidence.v1",
			"expectedProofScope":            "local",
			"forbiddenValueIndicators":      []any{},
			"localRefIndicators":            []any{"localhost", "127.0.0.1"},
			"requiredFactIds":               []any{"proofkit.test.fact"},
			"requiredFactKinds":             []any{"release_artifact"},
			"requiredNonClaims":             []any{nonClaim},
			"requireDigestPinnedImageRefs":  true,
			"requireLowercaseSourceCommits": true,
			"temporaryEndpointHostSuffixes": []any{"trycloudflare.com"},
		},
		"rawOperatorEvidence": []any{},
		"nonClaims":           []any{"Deployment evidence admission test fixture is not release proof."},
	}
}
