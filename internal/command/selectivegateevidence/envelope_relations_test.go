package selectivegateevidence

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestEnvelopeUnexpectedStatusIsDiagnosticOnly(t *testing.T) {
	for _, status := range []string{"passed", "failed", "not_run", "blocked"} {
		for _, difference := range []string{"id", "command", "sourcePath"} {
			t.Run(status+"/"+difference, func(t *testing.T) {
				input := relationalInput()
				extra := relationalReceipt(plannedCommand(), status, "artifacts/unexpected.json")
				switch difference {
				case "id":
					extra["id"] = "extra.check"
				case "command":
					extra["command"] = "check extra"
				case "sourcePath":
					extra["sourcePath"] = "src/other.go"
				}
				input["receipts"] = append(input["receipts"].([]any), extra)
				result, envelope := relationalBuild(t, input)
				if result.Report.State != "failed" || result.ExitCode != 1 || len(result.UnexpectedReceipts) != 1 || len(result.MissingReceipts) != 0 {
					t.Fatal("unexpected receipt stopped being a failing observation")
				}
				counts := map[string]int{"failed": len(result.FailedReceipts), "not_run": len(result.NotRunReceipts), "blocked": len(result.BlockedReceipts)}
				for class, count := range counts {
					want := 0
					if class == status {
						want = 1
					}
					if count != want {
						t.Fatalf("observational %s count = %d, want %d", class, count, want)
					}
				}
				if len(relationalRecords(envelope, "commands")) != 0 || len(relationalRecords(envelope, "receiptRefs")) != 0 || len(relationalVerify(t, envelope)["commandIds"].([]any)) != 0 {
					t.Fatal("unplanned tuple became an actionable planned command or receipt")
				}
			})
		}
	}
}

func TestEnvelopeMatchedStatusRetainsItsRole(t *testing.T) {
	for _, status := range []string{"passed", "failed", "not_run", "blocked", "missing"} {
		t.Run(status, func(t *testing.T) {
			input := relationalInput()
			input["receipts"] = []any{}
			if status != "missing" {
				input["receipts"] = []any{relationalReceipt(plannedCommand(), status, "artifacts/matched.json")}
			}
			_, envelope := relationalBuild(t, input)
			commands := relationalRecords(envelope, "commands")
			receipts := relationalRecords(envelope, "receiptRefs")
			retries := relationalVerify(t, envelope)["commandIds"].([]any)
			wantCommands, wantRetries := 1, 1
			if status == "passed" {
				wantCommands, wantRetries = 0, 0
			} else if status == "blocked" {
				wantRetries = 0
			}
			if len(commands) != wantCommands || len(receipts) != wantCommands || len(retries) != wantRetries {
				t.Fatalf("matched role lost: commands=%d receipts=%d retries=%d", len(commands), len(receipts), len(retries))
			}
			if len(receipts) != 0 {
				if receipts[0]["commandId"] != commands[0]["commandId"] {
					t.Fatal("matched receipt does not resolve to its own command")
				}
				if status == "missing" && (receipts[0]["kind"] != "required_receipt_class" || receipts[0]["producerAdmission"] != "required") {
					t.Fatal("missing receipt was presented as an existing artifact")
				}
			}
		})
	}
}

func TestEnvelopeUnexpectedStatusCannotPromoteBlockedSiblingToRetry(t *testing.T) {
	for _, status := range []string{"failed", "not_run"} {
		for _, difference := range []string{"command", "sourcePath"} {
			t.Run(status+"/"+difference, func(t *testing.T) {
				input := relationalInput()
				blocked := relationalReceipt(plannedCommand(), "blocked", "artifacts/blocked.json")
				extra := relationalReceipt(plannedCommand(), status, "artifacts/unexpected.json")
				if difference == "command" {
					extra["command"] = "check extra"
				} else {
					extra["sourcePath"] = "src/other.go"
				}
				input["receipts"] = []any{blocked, extra}
				result, envelope := relationalBuild(t, input)
				if result.Report.State != "failed" || len(result.UnexpectedReceipts) != 1 || len(result.BlockedReceipts) != 1 {
					t.Fatal("mixed observation roles changed")
				}
				if len(relationalRecords(envelope, "commands")) != 1 || len(relationalRecords(envelope, "receiptRefs")) != 1 || len(relationalVerify(t, envelope)["commandIds"].([]any)) != 0 {
					t.Fatal("unexpected status promoted a blocked planned sibling to retry")
				}
			})
		}
	}
}

func TestEnvelopeFullTupleIdentityAndJoin(t *testing.T) {
	for _, difference := range []string{"command", "sourcePath"} {
		for _, status := range []string{"missing", "failed", "not_run", "blocked"} {
			t.Run(difference+"/"+status, func(t *testing.T) {
				first, second := plannedCommand(), plannedCommand()
				if difference == "command" {
					second["command"] = "check alternate"
				} else {
					second["sourcePath"] = "src/alternate.go"
				}
				input := relationalInput()
				evidencePlan(input)["requiredCommands"] = []any{first, second}
				input["receipts"] = []any{}
				if status != "missing" {
					input["receipts"] = []any{relationalReceipt(first, status, "artifacts/first.json"), relationalReceipt(second, status, "artifacts/second.json")}
				}
				_, envelope := relationalBuild(t, input)
				commands, receipts := relationalRecords(envelope, "commands"), relationalRecords(envelope, "receiptRefs")
				if len(commands) != 2 || len(receipts) != 2 || commands[0]["commandId"] == commands[1]["commandId"] {
					t.Fatal("two admitted tuples coalesced or lost their receipt roles")
				}
				// Singleton gaps provide an independent join oracle: changing a sibling's
				// receipt status must not change either planned tuple's local target.
				wantIDs := map[any]bool{}
				for index, command := range []map[string]any{first, second} {
					control := relationalInput()
					evidencePlan(control)["requiredCommands"] = []any{first, second}
					other := first
					if index == 0 {
						other = second
					}
					control["receipts"] = []any{relationalReceipt(other, "passed", "artifacts/passed.json")}
					if status != "missing" {
						control["receipts"] = append(control["receipts"].([]any), relationalReceipt(command, status, []string{"artifacts/first.json", "artifacts/second.json"}[index]))
					}
					_, single := relationalBuild(t, control)
					singleCommands := relationalRecords(single, "commands")
					if len(singleCommands) != 1 || singleCommands[0]["command"] != command["command"] {
						t.Fatal("singleton gap did not retain its tuple")
					}
					id := singleCommands[0]["commandId"]
					wantIDs[id] = true
					found := false
					for _, receipt := range receipts {
						if receipt["commandId"] == id {
							found = true
							if status != "missing" && relationalArtifactPath(t, envelope, receipt) != []string{"artifacts/first.json", "artifacts/second.json"}[index] {
								t.Fatal("receipt joined a sibling tuple's artifact")
							}
						}
					}
					if !found {
						t.Fatal("tuple has no own receipt reference")
					}
				}
				if len(wantIDs) != 2 || relationalOmitted(envelope, "proofkit.agent.omission.selective-evidence-commands") != 0 {
					t.Fatal("tuple identity is not stable and injective below the cap")
				}
			})
		}
	}
}

func TestEnvelopeCandidateConservationBeforeCommandFiltering(t *testing.T) {
	for _, count := range []int{24, 25} {
		for _, mode := range []string{"missing", "mixed", "duplicate_artifacts"} {
			t.Run(fmt.Sprintf("%d/%s", count, mode), func(t *testing.T) {
				input := relationalInput()
				commands, receipts := []any{plannedCommand()}, []any{}
				for index := 1; index < count; index++ {
					command := plannedCommand()
					command["id"] = fmt.Sprintf("zz.command.%03d", index)
					command["command"] = fmt.Sprintf("check item %03d", index)
					commands = append(commands, command)
				}
				candidateReceipts := 0
				for index, raw := range commands {
					command := raw.(map[string]any)
					status := "missing"
					if mode == "mixed" {
						status = []string{"missing", "failed", "not_run", "blocked"}[index%4]
					} else if mode == "duplicate_artifacts" && index == count-1 {
						status = "failed"
					}
					candidateReceipts++
					if status != "missing" {
						receipts = append(receipts, relationalReceipt(command, status, fmt.Sprintf("artifacts/item-%03d.json", index)))
						if mode == "duplicate_artifacts" {
							receipts = append(receipts, relationalReceipt(command, "not_run", "artifacts/second.json"), relationalReceipt(command, "blocked", "artifacts/third.json"))
							candidateReceipts += 2
						}
					}
				}
				evidencePlan(input)["requiredCommands"], input["receipts"] = commands, receipts
				_, envelope := relationalBuild(t, input)
				retainedCommands, retainedReceipts := relationalRecords(envelope, "commands"), relationalRecords(envelope, "receiptRefs")
				commandOmissions := relationalOmitted(envelope, "proofkit.agent.omission.selective-evidence-commands")
				receiptOmissions := relationalOmitted(envelope, "proofkit.agent.omission.selective-evidence-receipts")
				if count != len(retainedCommands)+commandOmissions || candidateReceipts != len(retainedReceipts)+receiptOmissions {
					t.Fatalf("class conservation failed: commands %d != %d+%d; receipts %d != %d+%d", count, len(retainedCommands), commandOmissions, candidateReceipts, len(retainedReceipts), receiptOmissions)
				}
				ids := map[any]bool{}
				for _, command := range retainedCommands {
					ids[command["commandId"]] = true
				}
				for _, receipt := range retainedReceipts {
					if !ids[receipt["commandId"]] {
						t.Fatal("retained receipt references an omitted command")
					}
				}
			})
		}
	}
}

func TestEnvelopeArtifactLocatorUsesExactLocalPathContext(t *testing.T) {
	prefix := strings.Repeat("segment/", 70)
	paths := []string{"inputs/task-requirements.json", "docs/risk-assessment.md", " artifacts/report.json", "artifacts/report.json ", prefix + "first.json", prefix + "second.json", "artifacts/caf\u00e9.json", "artifacts/decomposed-e\u0301.json"}
	for _, status := range []string{"failed", "not_run", "blocked"} {
		t.Run(status, func(t *testing.T) {
			input := relationalInput()
			receipts := []any{}
			for _, path := range paths {
				receipts = append(receipts, relationalReceipt(plannedCommand(), status, path))
			}
			input["receipts"] = receipts
			_, envelope := relationalBuild(t, input)
			seen := map[string]bool{}
			for _, receipt := range relationalRecords(envelope, "receiptRefs") {
				path := relationalArtifactPath(t, envelope, receipt)
				seen[path] = true
				if !relationalHas(receipt["evidenceRefs"].([]any), receipt["ref"]) {
					t.Fatal("artifact ref and evidence ref do not select the same local path context")
				}
			}
			for _, path := range paths {
				if !seen[path] {
					t.Fatal("significant path bytes or long-prefix identity were lost")
				}
			}
			if status == "blocked" {
				contexts := map[any]bool{}
				for _, context := range relationalRecords(envelope, "contextRefs") {
					if context["kind"] == "path" {
						contexts[context["refId"]] = true
					}
				}
				for _, blocked := range relationalRecords(envelope, "blockedPreconditions") {
					found := false
					for _, ref := range blocked["evidenceRefs"].([]any) {
						found = found || contexts[ref]
					}
					if !found {
						t.Fatal("blocked receipt lost its artifact context")
					}
				}
			}
		})
	}
}

func TestEnvelopeArtifactProjectionKeepsProtectedPathRefusals(t *testing.T) {
	fixtures := admit.ReportVisibleRedactionFixtures()
	if len(fixtures) == 0 {
		t.Fatal("protected fixture catalog is empty")
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			input := relationalInput()
			input["receipts"] = []any{relationalReceipt(plannedCommand(), "failed", "inputs/prefix"+fixture.Input+"suffix.json")}
			if _, err := Build(input); err == nil {
				t.Fatal("protected evidence path was admitted")
			}
		})
	}
}

func TestEnvelopeArtifactPathsReachReceiptCapWithoutLosingContexts(t *testing.T) {
	for _, count := range []int{24, 25} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			input := relationalInput()
			receipts := []any{}
			for index := 0; index < count; index++ {
				receipts = append(receipts, relationalReceipt(plannedCommand(), "failed", fmt.Sprintf("artifacts/item-%03d.json", index)))
			}
			input["receipts"] = receipts
			_, envelope := relationalBuild(t, input)
			retained := relationalRecords(envelope, "receiptRefs")
			if len(retained) != 24 || len(relationalRecords(envelope, "contextRefs")) != 26 || count != len(retained)+relationalOmitted(envelope, "proofkit.agent.omission.selective-evidence-receipts") {
				t.Fatal("artifact contexts or receipt conservation lost at the receipt cap")
			}
			seen := map[string]bool{}
			for _, receipt := range retained {
				seen[relationalArtifactPath(t, envelope, receipt)] = true
			}
			if len(seen) != 24 {
				t.Fatal("distinct artifact paths coalesced at the receipt cap")
			}
		})
	}
}

func TestEnvelopeWithholdsWireUnsafeArtifactRecordAndCountsLoss(t *testing.T) {
	for _, unsafe := range []string{"\u202e", "\u200b", "\u0085", "\u2028", "\ufeff"} {
		for _, status := range []string{"failed", "not_run", "blocked"} {
			t.Run(fmt.Sprintf("%x/%s", []byte(unsafe), status), func(t *testing.T) {
				path := "artifacts/a-unsafe-" + unsafe + ".json"
				if _, err := admit.SafeRepoRelativePath(path, "fixture path"); err != nil {
					t.Fatal("fixture is not an admitted canonical path")
				}
				input := relationalInput()
				input["receipts"] = []any{relationalReceipt(plannedCommand(), status, path), relationalReceipt(plannedCommand(), status, "artifacts/safe.json")}
				result, envelope := relationalBuild(t, input)
				if result.Report.Summary["receiptCount"] != 2 || result.Report.Summary["unexpectedReceiptCount"] != 0 {
					t.Fatal("presentation safety changed report observations")
				}
				retained := relationalRecords(envelope, "receiptRefs")
				if len(retained) != 1 || relationalOmitted(envelope, "proofkit.agent.omission.selective-evidence-receipts") != 1 {
					t.Fatal("wire-unsafe context left a dangling artifact record or uncounted loss")
				}
				if relationalArtifactPath(t, envelope, retained[0]) != "artifacts/safe.json" || len(relationalRecords(envelope, "contextRefs")) != 3 {
					t.Fatal("safe sibling lost its exact retained context")
				}
				if len(relationalRecords(envelope, "commands")) != 1 || envelope["costContract"].(map[string]any)["prunedLocalReferenceCount"] != 0 {
					t.Fatal("whole-record withholding degraded unrelated command or reference roles")
				}
			})
		}
	}
}

func TestEnvelopeUnsafeArtifactDoesNotConsumeRetainedReceiptBudget(t *testing.T) {
	input := relationalInput()
	receipts := []any{relationalReceipt(plannedCommand(), "failed", "artifacts/a-unsafe-\u202e.json")}
	for index := 0; index < 24; index++ {
		receipts = append(receipts, relationalReceipt(plannedCommand(), "failed", fmt.Sprintf("artifacts/safe-%03d.json", index)))
	}
	input["receipts"] = receipts
	_, envelope := relationalBuild(t, input)
	retained := relationalRecords(envelope, "receiptRefs")
	if len(retained) != 24 || len(relationalRecords(envelope, "contextRefs")) != 26 || relationalOmitted(envelope, "proofkit.agent.omission.selective-evidence-receipts") != 1 {
		t.Fatal("unsafe artifact consumed the safe retained-receipt or context budget")
	}
	for _, receipt := range retained {
		if !strings.HasPrefix(relationalArtifactPath(t, envelope, receipt), "artifacts/safe-") {
			t.Fatal("receipt retained a dangling or substituted unsafe locator")
		}
	}
}

func TestEnvelopeArtifactPathSpellingCannotCaptureLocalTarget(t *testing.T) {
	seed := relationalInput()
	seed["receipts"] = []any{relationalReceipt(plannedCommand(), "failed", "artifacts/seed.json")}
	_, seedEnvelope := relationalBuild(t, seed)
	spellings := []string{"proofkit.go-test", "proofkit.agent.receipt.required.selective-evidence.001"}
	for _, domain := range [][2]string{{"commands", "commandId"}, {"contextRefs", "refId"}, {"receiptRefs", "receiptRefId"}} {
		for _, target := range relationalRecords(seedEnvelope, domain[0]) {
			spellings = append(spellings, target[domain[1]].(string))
		}
	}
	for _, locator := range spellings {
		for _, source := range []string{"census.other-source", "proofkit.agent.context.selective-evidence.001", locator} {
			for _, status := range []string{"failed", "blocked"} {
				t.Run(locator+"/"+source+"/"+status, func(t *testing.T) {
					input := relationalInput()
					input["evidenceId"] = source
					input["receipts"] = []any{relationalReceipt(plannedCommand(), status, locator), relationalReceipt(plannedCommand(), status, locator)}
					_, envelope := relationalBuild(t, input)
					pathContexts := map[any]bool{}
					for _, context := range relationalRecords(envelope, "contextRefs") {
						if context["kind"] == "path" && context["ref"] == locator {
							pathContexts[context["refId"]] = true
						}
					}
					if len(pathContexts) != 1 || len(relationalRecords(envelope, "receiptRefs")) != 2 {
						t.Fatal("equal-spelling artifact locators lost their dedicated shared path context")
					}
					for _, receipt := range relationalRecords(envelope, "receiptRefs") {
						if relationalArtifactPath(t, envelope, receipt) != locator || !pathContexts[receipt["ref"]] || !relationalHas(receipt["evidenceRefs"].([]any), receipt["ref"]) {
							t.Fatal("artifact reference captured a different local target's role")
						}
						refs := receipt["evidenceRefs"].([]any)
						if len(refs) != 2 || refs[0] == refs[1] {
							t.Fatal("source hash and artifact locator collapsed into one untyped identity")
						}
					}
					for _, blocked := range relationalRecords(envelope, "blockedPreconditions") {
						found := false
						for _, ref := range blocked["evidenceRefs"].([]any) {
							found = found || pathContexts[ref]
						}
						if !found {
							t.Fatal("blocked receipt captured a source, command, or receipt target instead of its artifact context")
						}
					}
				})
			}
		}
	}
}

func TestEnvelopeExactTuplePathsSurviveSiblingAndCallerMutation(t *testing.T) {
	prefix := strings.Repeat("segment/", 70)
	paths := []string{"src/ check.go", "src/check.go", "src/check .go", prefix + "first.go", prefix + "second.go"}
	input := relationalInput()
	commands, receipts := []any{plannedCommand()}, []any{relationalReceipt(plannedCommand(), "passed", "artifacts/passed.json")}
	for index, path := range paths {
		command := plannedCommand()
		command["sourcePath"] = path
		commands = append(commands, command)
		receipts = append(receipts, relationalReceipt(command, "failed", fmt.Sprintf("artifacts/exact-%d.json", index)))
	}
	evidencePlan(input)["requiredCommands"], input["receipts"] = commands, receipts
	result, envelope := relationalBuild(t, input)
	ids := map[any]bool{}
	for _, receipt := range relationalRecords(envelope, "receiptRefs") {
		ids[receipt["commandId"]] = true
	}
	if len(ids) != len(paths) || len(relationalRecords(envelope, "commands")) != len(paths) {
		t.Fatal("exact tuple path identities coalesced")
	}
	for index := range paths {
		commands[index+1].(map[string]any)["sourcePath"] = "src/changed.go"
		receipts[index+1].(map[string]any)["sourcePath"] = "src/changed.go"
	}
	if after := AgentEnvelope(result); !reflect.DeepEqual(envelope, after) {
		t.Fatal("source-path caller mutation changed the sealed tuple projection")
	}
}

func TestEnvelopeLocalTargetsNeverAliasExternalReportID(t *testing.T) {
	for _, status := range []string{"failed", "missing"} {
		t.Run(status, func(t *testing.T) {
			input := relationalInput()
			input["receipts"] = []any{}
			if status != "missing" {
				input["receipts"] = []any{relationalReceipt(plannedCommand(), status, "inputs/task-requirements.json")}
			}
			_, envelope := relationalBuild(t, input)
			ids := []string{}
			for _, domain := range [][2]string{{"commands", "commandId"}, {"contextRefs", "refId"}, {"receiptRefs", "receiptRefId"}} {
				for _, target := range relationalRecords(envelope, domain[0]) {
					ids = append(ids, target[domain[1]].(string))
				}
			}
			for _, id := range ids {
				t.Run(id, func(t *testing.T) {
					input["evidenceId"] = id
					_, candidate := relationalBuild(t, input)
					for _, domain := range [][2]string{{"commands", "commandId"}, {"contextRefs", "refId"}, {"receiptRefs", "receiptRefId"}} {
						for _, target := range relationalRecords(candidate, domain[0]) {
							if target[domain[1]] == id {
								t.Fatal("external report identity aliases a local target")
							}
						}
					}
					if len(relationalRecords(candidate, "commands")) != 1 || len(relationalRecords(candidate, "receiptRefs")) != 1 {
						t.Fatal("reserving the external ID lost usable guidance")
					}
				})
			}
		})
	}
}

func TestEnvelopePlannedMembershipDetachedFromCallerMutation(t *testing.T) {
	input := relationalInput()
	input["receipts"] = []any{relationalReceipt(plannedCommand(), "failed", "artifacts/failed.json")}
	result, before := relationalBuild(t, input)
	plannedCommandInput(input)["id"] = "changed.id"
	plannedCommandInput(input)["command"] = "changed command"
	plannedCommandInput(input)["sourcePath"] = "src/changed.go"
	if after := AgentEnvelope(result); !reflect.DeepEqual(before, after) {
		t.Fatal("caller mutation changed sealed planned membership")
	}
}

func relationalInput() map[string]any {
	input := validEvidenceInput()
	input["evidenceClass"] = "advisory"
	delete(input, "producerAdmission")
	delete(selectiveReceipt(input), "producerReceiptId")
	return input
}

func relationalReceipt(command map[string]any, status, path string) map[string]any {
	receipt := map[string]any{"id": command["id"], "command": command["command"], "status": status, "exitCode": selectiveReceiptExitCode(status), "evidenceRef": path, "artifactRefs": []any{}}
	if source, exists := command["sourcePath"]; exists && source != nil {
		receipt["sourcePath"] = source
	}
	return receipt
}

func relationalBuild(t *testing.T, input map[string]any) (Result, map[string]any) {
	t.Helper()
	result, err := Build(input)
	if err != nil {
		t.Fatalf("admitted fixture failed: %v", err)
	}
	envelope := AgentEnvelope(result)
	if err := schemacheck.Validate(EnvelopeStructure(), envelope); err != nil {
		t.Fatalf("native envelope violates its structure: %v", err)
	}
	return result, envelope
}

func relationalRecords(envelope map[string]any, field string) []map[string]any {
	result := []map[string]any{}
	for _, value := range envelope[field].([]any) {
		result = append(result, value.(map[string]any))
	}
	return result
}

func relationalVerify(t *testing.T, envelope map[string]any) map[string]any {
	t.Helper()
	for _, action := range relationalRecords(envelope, "actionPlan") {
		if action["phase"] == "verify" {
			return action
		}
	}
	t.Fatal("missing verify action")
	return nil
}

func relationalArtifactPath(t *testing.T, envelope map[string]any, receipt map[string]any) string {
	t.Helper()
	if receipt["kind"] != "receipt_artifact" {
		t.Fatal("supplied receipt has a missing-class role")
	}
	for _, context := range relationalRecords(envelope, "contextRefs") {
		if context["refId"] == receipt["ref"] && context["kind"] == "path" {
			return context["ref"].(string)
		}
	}
	t.Fatal("artifact locator is not an exact local path context")
	return ""
}

func relationalOmitted(envelope map[string]any, id string) int {
	count := 0
	for _, omission := range relationalRecords(envelope, "omitted") {
		if omission["omissionId"] == id {
			count += omission["omittedCount"].(int)
		}
	}
	return count
}

func relationalHas(values []any, target any) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestEnvelopeTupleProjectionIndependentOfInputOrder(t *testing.T) {
	input := relationalInput()
	commands := []any{plannedCommand()}
	for _, path := range []string{"src/first.go", "src/second.go"} {
		command := plannedCommand()
		command["sourcePath"] = path
		commands = append(commands, command)
	}
	evidencePlan(input)["requiredCommands"], input["receipts"] = commands, []any{}
	_, before := relationalBuild(t, input)
	slices.Reverse(commands)
	_, after := relationalBuild(t, input)
	left, _ := json.Marshal(before)
	right, _ := json.Marshal(after)
	if string(left) != string(right) {
		t.Fatal("plan permutation changed canonical tuple projection")
	}
}
