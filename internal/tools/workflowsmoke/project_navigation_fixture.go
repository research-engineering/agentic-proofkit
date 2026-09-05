package workflowsmoke

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func materializationSmokeInput(ctx context.Context, repositoryRoot string) (any, []byte, error) {
	if err := os.WriteFile(filepath.Join(repositoryRoot, "README.md"), []byte("# Installed workflow smoke\n"), 0o600); err != nil {
		return nil, nil, fmt.Errorf("write workflow smoke repository seed: %w", err)
	}
	inventory, err := repositoryinventory.Scan(ctx, repositoryRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("scan workflow smoke repository: %w", err)
	}
	sourcePlan, err := adoptionplan.Build(adoptionplan.IntentFresh, inventory, "")
	if err != nil {
		return nil, nil, fmt.Errorf("build workflow smoke adoption plan: %w", err)
	}
	requirementNonClaims := []any{"Installed workflow fixture does not prove rollout."}
	value := map[string]any{
		"schemaVersion": json.Number("1"), "requestKind": adoptionmaterialization.RequestKind,
		"requestId": "proofkit.workflow-smoke.materialization", "projectId": "proofkit.workflow-smoke", "sourcePlan": sourcePlan.JSONValue(),
		"requirementSources": []any{map[string]any{
			"schemaVersion": json.Number("1"), "sourceId": "proofkit.workflow-smoke.requirements", "specPackagePath": "docs/specs/workflow-smoke",
			"overviewPath": "docs/specs/workflow-smoke/overview.md", "requirementsPath": "docs/specs/workflow-smoke/requirements.v1.json",
			"nonClaims": []any{"Installed workflow source fixture does not prove production readiness."},
			"requirements": []any{map[string]any{
				"claimLevel": "blocking", "deferral": nil, "invariant": "Installed carriers preserve admitted materialized-project navigation.",
				"lifecycle":    map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"},
				"nonClaimRefs": []any{}, "nonClaims": requirementNonClaims, "ownerId": "proofkit.workflow-smoke.owner",
				"proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "requirementId": "REQ-PROOFKIT-WORKFLOW-SMOKE-001", "riskClass": "high",
				"updatePolicy": map[string]any{"requiresImpactDeclaration": true, "requiresProofBindingReview": true, "reviewOwnerId": "proofkit.workflow-smoke.owner"},
			}},
		}},
		"requirementProofBinding": map[string]any{
			"path": "proofkit/requirement-bindings.json",
			"record": map[string]any{
				"schemaVersion": json.Number("1"), "bindingId": "proofkit.workflow-smoke.bindings",
				"requirements": []any{map[string]any{
					"claimLevel": "blocking", "nonClaims": requirementNonClaims, "ownerId": "proofkit.workflow-smoke.owner",
					"proofState": "witness_backed", "requirementId": "REQ-PROOFKIT-WORKFLOW-SMOKE-001", "specPath": "docs/specs/workflow-smoke/requirements.v1.json",
				}},
				"bindings": []any{map[string]any{
					"commandIds": []any{"proofkit.workflow-smoke.test"}, "environmentClasses": []any{"local-go"}, "requirementId": "REQ-PROOFKIT-WORKFLOW-SMOKE-001",
					"scenarioId": "proofkit.workflow-smoke.materialization", "witnessId": "proofkit.workflow-smoke.witness",
					"witnessKind": "contract", "witnessPath": "internal/workflow_smoke/materialization_test.go",
				}},
				"witnessCommands": []any{map[string]any{
					"command": "go test ./internal/workflow_smoke", "commandId": "proofkit.workflow-smoke.test", "environmentClasses": []any{"local-go"},
				}},
				"selection": map[string]any{"changedPaths": []any{}, "ownerIds": []any{}, "requirementIds": []any{}},
				"nonClaims": []any{"Installed workflow binding fixture does not execute witnesses."},
			},
		},
		"testEvidenceInventory": map[string]any{
			"path": "proofkit/test-evidence-inventory.json",
			"record": map[string]any{
				"schemaVersion": json.Number("1"), "inventoryId": "proofkit.workflow-smoke.inventory", "authority": "caller_owned_inventory",
				"entries": []any{map[string]any{
					"testId": "proofkit.workflow-smoke.materialization", "selector": "go test ./internal/workflow_smoke -run TestMaterialization",
					"sourcePath": "internal/workflow_smoke/materialization_test.go", "ownerId": "proofkit.workflow-smoke.owner",
					"evidenceClass": "declared_semantic_falsifier_route", "requirementRefs": []any{"REQ-PROOFKIT-WORKFLOW-SMOKE-001"},
					"ownerInvariantRefs": []any{}, "commandRefs": []any{"proofkit.workflow-smoke.test"}, "witnessRefs": []any{"proofkit.workflow-smoke.witness"},
					"falsifier": map[string]any{
						"falsifierId": "proofkit.workflow-smoke.falsifier", "negativeCaseId": "proofkit.workflow-smoke.case",
						"wrongImplementationClassId": "proofkit.workflow-smoke.wrong", "dominanceGroup": "proofkit.workflow-smoke.materialization", "supersedes": []any{},
					},
					"oracle": map[string]any{
						"oracleId": "proofkit.workflow-smoke.oracle", "oracleKind": "negative_exit_and_diagnostic",
						"expectedPublicOutcome": "invalid materialization fails closed",
						"assertionSummary":      "A contradictory materialization request is rejected before mutation.",
					},
					"nonClaims": []any{},
				}},
				"nonClaims": []any{"Installed workflow inventory fixture does not execute native tests."},
			},
		},
		"nonClaims": []any{"Installed workflow materialization request is test-only."},
	}
	payload, err := stablejson.Marshal(value)
	if err != nil {
		return nil, nil, fmt.Errorf("encode workflow smoke materialization input: %w", err)
	}
	return value, payload, nil
}
