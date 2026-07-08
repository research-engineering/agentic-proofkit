package migrationplan

import (
	"encoding/json"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"strings"
	"testing"
)

func TestSortedFollowUpCommandsRejectsShellControlTokens(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.082298967063760496779599754309164283301628231265151485187770019052237054259416")
	_, err := sortedFollowUpCommands([]any{map[string]any{
		"command":   "go test ./... && curl example.test",
		"commandId": "proofkit.followup",
		"nonClaim":  "Test command is not executed by migration-plan.",
		"owner":     "consumer_repository",
		"phase":     "post-retirement-validation",
	}})
	if err == nil || !strings.Contains(err.Error(), "display-only command text") {
		t.Fatalf("sortedFollowUpCommands() error=%v, want display-only command rejection", err)
	}
}

func TestBuildRejectsSecretLikeCallerText(t *testing.T) {
	secretLike := "Authorization: Bearer abcdefghijklmnop"
	input := validMigrationPlanInput()
	input["retirementCandidates"].([]any)[0].(map[string]any)["reason"] = secretLike

	_, exitCode, err := Build(input)
	if exitCode != 1 || err == nil || !strings.Contains(err.Error(), "secret-like values") {
		t.Fatalf("Build() exit=%d error=%v, want secret-like rejection", exitCode, err)
	}
	if strings.Contains(err.Error(), secretLike) {
		t.Fatalf("Build() leaked secret-like caller text: %v", err)
	}
}

func TestMigrationNestedRecordsRejectUnknownFields(t *testing.T) {
	cases := []struct {
		name  string
		check func() error
	}{
		{
			name: "source owner",
			check: func() error {
				_, err := sortedSourceProofOwners([]any{map[string]any{
					"ownerId":          "old.owner",
					"ownerKind":        "local_manifest",
					"path":             "docs/old.json",
					"retirementPolicy": "candidate",
					"shadowPolicy":     true,
				}})
				return err
			},
		},
		{
			name: "target ref",
			check: func() error {
				_, err := sortedTargetRefs([]any{map[string]any{
					"path":        "proofkit/bindings.v1.json",
					"targetId":    "proofkit.binding",
					"targetKind":  "proofkit_input",
					"shadowProof": true,
				}})
				return err
			},
		},
		{
			name: "follow-up command",
			check: func() error {
				_, err := sortedFollowUpCommands([]any{map[string]any{
					"command":    "go test ./...",
					"commandId":  "proofkit.followup",
					"nonClaim":   "Test command is not executed by migration-plan.",
					"owner":      "consumer_repository",
					"phase":      "post-retirement-validation",
					"shadowMode": "merge",
				}})
				return err
			},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			err := item.check()
			if err == nil || !strings.Contains(err.Error(), "unsupported field") {
				t.Fatalf("nested parser error=%v, want unsupported field rejection", err)
			}
		})
	}
}

func validMigrationPlanInput() map[string]any {
	return map[string]any{
		"schemaVersion": jsonNumber("1"),
		"migrationId":   "proofkit.migration.test",
		"sourceProofOwners": []any{map[string]any{
			"ownerId":          "old.owner",
			"ownerKind":        "local_manifest",
			"path":             "docs/old.json",
			"retirementPolicy": "candidate",
		}},
		"targetProofkitRefs": []any{map[string]any{
			"path":       "proofkit/bindings.v1.json",
			"targetId":   "proofkit.binding",
			"targetKind": "proofkit_input",
		}},
		"parityEvidenceRefs": []any{map[string]any{
			"evidenceId":    "proofkit.parity",
			"evidenceRef":   "artifacts/parity.json",
			"nonClaim":      "Parity evidence is caller-owned.",
			"sourceOwnerId": "old.owner",
			"targetId":      "proofkit.binding",
		}},
		"retainedOwners": []any{},
		"retirementCandidates": []any{map[string]any{
			"ownerId":    "old.owner",
			"reason":     "Target proofkit binding has caller-owned parity evidence.",
			"removalRef": "docs/old.json",
		}},
		"followUpCommands": []any{map[string]any{
			"command":   "go test ./...",
			"commandId": "proofkit.followup",
			"nonClaim":  "Follow-up command is not executed by migration-plan.",
			"owner":     "consumer_repository",
			"phase":     "post-retirement-validation",
		}},
		"nonClaims": []any{"Migration plan test input is not merge approval."},
	}
}

func jsonNumber(value string) any {
	return json.Number(value)
}
