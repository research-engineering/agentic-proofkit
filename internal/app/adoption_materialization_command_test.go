package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestAdoptionMaterializationCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.103035476538948218041788724536099147997319815968356867564973644428335343301159")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.058152805399859601021037338453799485862969628463250390378105158011563433477370")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.024071864329639467033814284200388059833882159297164197606479032099605203702808")
	repositoryRoot := t.TempDir()
	input := adoptionMaterializationCLIInput(t, repositoryRoot)
	payload, err := stablejson.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	planArgs := []string{"adopt", "materialize", "plan", "--input", "-", "--repo-root", repositoryRoot}
	status, stdout, stderr := executeAgentWorkflowCLI(t, planArgs, bytes.NewReader(payload), PresentationCapabilities{})
	if status != 0 || stderr != "" || strings.Contains(stdout, repositoryRoot) || strings.Contains(stdout, "\x1b[") {
		t.Fatalf("plan status=%d stderr=%q stdout=%q", status, stderr, stdout)
	}
	plan := decodeCLIJSON(t, stdout).(map[string]any)
	if plan["planKind"] != adoptionmaterialization.PlanKind || plan["state"] != "ready" {
		t.Fatalf("unexpected plan identity: %#v", plan)
	}
	transaction := plan["transaction"].(map[string]any)
	transactionID := transaction["transactionId"].(string)
	desiredStateID := transaction["desiredStateId"].(string)
	if transactionID == desiredStateID {
		t.Fatal("transaction and desired-state identities unexpectedly alias")
	}

	applyArgs := []string{
		"adopt", "materialize", "apply",
		"--input", "-",
		"--repo-root", repositoryRoot,
		"--expect-transaction", transactionID,
		"--expect-desired-state", desiredStateID,
	}
	status, stdout, stderr = executeAgentWorkflowCLI(t, applyArgs, bytes.NewReader(payload), PresentationCapabilities{})
	if status != 0 || stderr != "" {
		t.Fatalf("apply status=%d stderr=%q stdout=%q", status, stderr, stdout)
	}
	receipt := decodeCLIJSON(t, stdout).(map[string]any)
	if receipt["receiptKind"] != adoptionmaterialization.ReceiptKind || receipt["state"] != adoptionmaterialization.ReceiptStatePassed {
		t.Fatalf("unexpected apply receipt: %#v", receipt)
	}
	for _, path := range []string{
		"docs/specs/pilot/requirements.v1.json",
		"proofkit/project.v1.json",
		"proofkit/requirement-bindings.json",
		"proofkit/test-evidence-inventory.json",
	} {
		info, err := os.Stat(filepath.Join(repositoryRoot, filepath.FromSlash(path)))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("materialized %s: info=%v err=%v", path, info, err)
		}
	}

	status, stdout, stderr = executeAgentWorkflowCLI(t, applyArgs, bytes.NewReader(payload), PresentationCapabilities{})
	if status != 0 || stderr != "" {
		t.Fatalf("idempotent apply status=%d stderr=%q stdout=%q", status, stderr, stdout)
	}
	retry := decodeCLIJSON(t, stdout).(map[string]any)
	result := retry["transactionResult"].(map[string]any)
	if retry["state"] != adoptionmaterialization.ReceiptStatePassed || result["state"] != "already_satisfied" {
		t.Fatalf("unexpected retry receipt: %#v", retry)
	}

	recoverArgs := []string{
		"adopt", "materialize", "recover",
		"--repo-root", repositoryRoot,
		"--transaction", transactionID,
		"--action", "resume",
	}
	status, stdout, stderr = executeAgentWorkflowCLI(t, recoverArgs, strings.NewReader(""), PresentationCapabilities{})
	if status != 0 || stderr != "" {
		t.Fatalf("recover status=%d stderr=%q stdout=%q", status, stderr, stdout)
	}
	recovered := decodeCLIJSON(t, stdout).(map[string]any)
	if recovered["operation"] != adoptionmaterialization.OperationRecover || recovered["state"] != adoptionmaterialization.ReceiptStatePassed {
		t.Fatalf("unexpected recovery receipt: %#v", recovered)
	}

	t.Run("human presentation is opt-in and capability-bound", func(t *testing.T) {
		textArgs := append(cloneStrings(planArgs), "--format", "text")
		plainStatus, plain, plainErr := executeAgentWorkflowCLI(t, textArgs, bytes.NewReader(payload), PresentationCapabilities{StdoutIsTTY: true})
		if plainStatus != 0 || plainErr != "" || strings.Contains(plain, "\x1b[") {
			t.Fatalf("plain status=%d stderr=%q stdout=%q", plainStatus, plainErr, plain)
		}
		colorArgs := append(cloneStrings(textArgs), "--color", "auto")
		colorStatus, colored, colorErr := executeAgentWorkflowCLI(t, colorArgs, bytes.NewReader(payload), PresentationCapabilities{StdoutIsTTY: true})
		if colorStatus != 0 || colorErr != "" || !strings.Contains(colored, "\x1b[") {
			t.Fatalf("color status=%d stderr=%q stdout=%q", colorStatus, colorErr, colored)
		}
		disabledStatus, disabled, disabledErr := executeAgentWorkflowCLI(t, colorArgs, bytes.NewReader(payload), PresentationCapabilities{StdoutIsTTY: true, NoColorPresent: true})
		if disabledStatus != 0 || disabledErr != "" || disabled != plain {
			t.Fatalf("NO_COLOR status=%d stderr=%q stdout=%q want=%q", disabledStatus, disabledErr, disabled, plain)
		}
	})

	t.Run("argument admission precedes input and repository access", func(t *testing.T) {
		missingRoot := filepath.Join(t.TempDir(), "missing")
		for _, item := range []struct {
			args []string
			want string
		}{
			{args: []string{"adopt", "materialize", "plan", "--input", "-", "--repo-root", missingRoot, "--input-pointer", "bad"}, want: "RFC 6901"},
			{args: []string{"adopt", "materialize", "apply", "--input", "-", "--repo-root", missingRoot, "--expect-transaction", "invalid", "--expect-desired-state", desiredStateID}, want: "sha256"},
			{args: []string{"adopt", "materialize", "recover", "--repo-root", missingRoot, "--transaction", transactionID, "--action", "force"}, want: "resume, rollback"},
			{args: []string{"adopt", "materialize", "recover", "--repo-root", missingRoot, "--transaction", transactionID, "--action", "resume", "--input", "-"}, want: "unsupported argument"},
		} {
			status, stdout, stderr := executeAgentWorkflowCLI(t, item.args, panicReader{}, PresentationCapabilities{})
			if status != 1 || stdout != "" || !strings.Contains(stderr, item.want) {
				t.Fatalf("args=%v status=%d stdout=%q stderr=%q want=%q", item.args, status, stdout, stderr, item.want)
			}
		}
	})

	t.Run("hierarchical routes and mutation scope are explicit", func(t *testing.T) {
		for _, command := range []string{"adopt-materialize-apply", "adopt-materialize-plan", "adopt-materialize-recover"} {
			descriptor, ok := commandDescriptorFor(command)
			if !ok {
				t.Fatalf("descriptor %s is unavailable", command)
			}
			if command == "adopt-materialize-plan" {
				if descriptor.scopeClass != commandScopeExplicitFileSystemScan {
					t.Fatalf("plan scope=%s", descriptor.scopeClass)
				}
			} else if descriptor.scopeClass != commandScopeExplicitFileSystemMutation {
				t.Fatalf("%s scope=%s", command, descriptor.scopeClass)
			}
			status, stdout, stderr := executeAgentWorkflowCLI(t, append(cloneStrings(descriptor.routeTokens), "--help"), panicReader{}, PresentationCapabilities{})
			if status != 0 || stderr != "" || !strings.Contains(stdout, "agentic-proofkit "+strings.Join(descriptor.routeTokens, " ")) {
				t.Fatalf("help %s status=%d stderr=%q stdout=%q", command, status, stderr, stdout)
			}
		}
	})
}

func adoptionMaterializationCLIInput(t *testing.T, root string) map[string]any {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# Pilot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory, err := repositoryinventory.Scan(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	sourcePlan, err := adoptionplan.Build(adoptionplan.IntentFresh, inventory, "")
	if err != nil {
		t.Fatal(err)
	}
	requirementNonClaims := []any{"Pilot requirement fixture does not prove rollout."}
	return map[string]any{
		"schemaVersion": json.Number("1"), "requestKind": adoptionmaterialization.RequestKind,
		"requestId": "pilot.materialization.cli-request", "projectId": "pilot.project", "sourcePlan": sourcePlan.JSONValue(),
		"requirementSources": []any{map[string]any{
			"schemaVersion": json.Number("1"), "sourceId": "pilot.requirements", "specPackagePath": "docs/specs/pilot",
			"overviewPath": "docs/specs/pilot/overview.md", "requirementsPath": "docs/specs/pilot/requirements.v1.json",
			"nonClaims": []any{"Pilot source fixture does not prove production readiness."},
			"requirements": []any{map[string]any{
				"claimLevel": "blocking", "deferral": nil, "invariant": "Pilot materialization preserves admitted requirement meaning.",
				"lifecycle":    map[string]any{"evidenceRefs": []any{}, "replacementRequirementIds": []any{}, "state": "active"},
				"nonClaimRefs": []any{}, "nonClaims": requirementNonClaims, "ownerId": "pilot.owner",
				"proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "requirementId": "REQ-PILOT-001", "riskClass": "high",
				"updatePolicy": map[string]any{"requiresImpactDeclaration": true, "requiresProofBindingReview": true, "reviewOwnerId": "pilot.owner"},
			}},
		}},
		"requirementProofBinding": map[string]any{
			"path": "proofkit/requirement-bindings.json",
			"record": map[string]any{
				"schemaVersion": json.Number("1"), "bindingId": "pilot.bindings",
				"requirements": []any{map[string]any{
					"claimLevel": "blocking", "nonClaims": requirementNonClaims, "ownerId": "pilot.owner",
					"proofState": "witness_backed", "requirementId": "REQ-PILOT-001", "specPath": "docs/specs/pilot/requirements.v1.json",
				}},
				"bindings": []any{map[string]any{
					"commandIds": []any{"pilot.command.test"}, "environmentClasses": []any{"local-go"}, "requirementId": "REQ-PILOT-001",
					"scenarioId": "pilot.scenario.materialization", "witnessId": "pilot.witness.materialization",
					"witnessKind": "contract", "witnessPath": "internal/pilot/materialization_test.go",
				}},
				"witnessCommands": []any{map[string]any{
					"command": "go test ./internal/pilot", "commandId": "pilot.command.test", "environmentClasses": []any{"local-go"},
				}},
				"selection": map[string]any{"changedPaths": []any{}, "ownerIds": []any{}, "requirementIds": []any{}},
				"nonClaims": []any{"Pilot binding fixture does not execute witnesses."},
			},
		},
		"testEvidenceInventory": map[string]any{
			"path": "proofkit/test-evidence-inventory.json",
			"record": map[string]any{
				"schemaVersion": json.Number("1"), "inventoryId": "pilot.inventory", "authority": "caller_owned_inventory",
				"entries": []any{map[string]any{
					"testId": "pilot.test.materialization", "selector": "go test ./internal/pilot -run TestMaterialization",
					"sourcePath": "internal/pilot/materialization_test.go", "ownerId": "pilot.owner",
					"evidenceClass": "declared_semantic_falsifier_route", "requirementRefs": []any{"REQ-PILOT-001"},
					"ownerInvariantRefs": []any{}, "commandRefs": []any{"pilot.command.test"}, "witnessRefs": []any{"pilot.witness.materialization"},
					"falsifier": map[string]any{
						"falsifierId": "pilot.falsifier.materialization", "negativeCaseId": "pilot.case.materialization",
						"wrongImplementationClassId": "pilot.wrong.materialization", "dominanceGroup": "pilot.materialization", "supersedes": []any{},
					},
					"oracle": map[string]any{
						"oracleId": "pilot.oracle.materialization", "oracleKind": "negative_exit_and_diagnostic",
						"expectedPublicOutcome": "invalid materialization fails closed",
						"assertionSummary":      "A contradictory materialization request is rejected before mutation.",
					},
					"nonClaims": []any{},
				}},
				"nonClaims": []any{"Pilot inventory fixture does not execute native tests."},
			},
		},
		"nonClaims": []any{"Pilot materialization request is test-only."},
	}
}
