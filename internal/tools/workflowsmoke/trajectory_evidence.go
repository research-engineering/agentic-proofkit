package workflowsmoke

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// The smoke plays the consuming repository's runner here. Its declared
// subject encoding is proofkit.trajectory.receipt-subjects.v1:
//
//	proofBindingDigest: canonical JSON of the requirement record and binding
//	  fragment from requirement-context-slice --profile proof for that edge;
//	commandDigest: canonical JSON of the witness-plan projected command;
//	dependencyDigest: exact native witness file bytes;
//	environmentDigest: canonical JSON of the environment-class policy;
//	witnessSelectorDigest: canonical JSON of the logical selector list.
//
// Native witnesses are never executed: every receipt is labelled as a fixture
// observation. Proofkit owns admission, linkage and currentness verdicts only.
type trajectorySubjects struct {
	Binding     string
	Command     string
	Dependency  string
	Environment string
	Selectors   string
	Edge        trajectoryEdge
}

const trajectorySubjectEncoding = "proofkit.trajectory.receipt-subjects.v1"

func trajectoryCheckClasses() []string {
	return []string{"binding", "command", "dependency", "environment", "selectors"}
}

func (subjects trajectorySubjects) digest(class string) string {
	switch class {
	case "binding":
		return subjects.Binding
	case "command":
		return subjects.Command
	case "dependency":
		return subjects.Dependency
	case "environment":
		return subjects.Environment
	default:
		return subjects.Selectors
	}
}

// subjects recomputes current subjects for one (requirementId, scenarioId)
// edge from a fresh proof slice, the current scheduler command and file bytes.
func (t *trajectory) subjects(context map[string]any, scheduler map[string]any, requirementID string) (trajectorySubjects, []byte, error) {
	slice, err := t.slice(context, requirementID)
	if err != nil {
		return trajectorySubjects{}, nil, err
	}
	requirement, okRequirement := pointerValue(slice, "/projections/requirementSources/0/requirements/0")
	fragment, okFragment := pointerValue(slice, "/projections/proofBinding")
	bindings, okBindings := pointerValue(slice, "/projections/proofBinding/bindings")
	rows, _ := bindings.([]any)
	if !okRequirement || !okFragment || !okBindings || len(rows) != 1 {
		return trajectorySubjects{}, nil, fmt.Errorf("proof slice for %s must select exactly one requirement and one binding row", requirementID)
	}
	row := rows[0].(map[string]any)
	commandIDs, _ := row["commandIds"].([]any)
	environments, _ := row["environmentClasses"].([]any)
	if len(commandIDs) != 1 || len(environments) != 1 {
		return trajectorySubjects{}, nil, fmt.Errorf("proof slice for %s must bind one command and environment", requirementID)
	}
	edge := trajectoryEdge{
		RequirementID: requirementID, ScenarioID: row["scenarioId"].(string), WitnessID: row["witnessId"].(string),
		WitnessPath: row["witnessPath"].(string), CommandID: commandIDs[0].(string), Environment: environments[0].(string),
	}
	fragmentRecord := fragment.(map[string]any)
	binding, err := digest.StableJSONSHA256Ref(map[string]any{
		"encoding": trajectorySubjectEncoding, "requirement": requirement,
		"bindings": fragmentRecord["bindings"], "requirements": fragmentRecord["requirements"], "witnessCommands": fragmentRecord["witnessCommands"],
	})
	if err != nil {
		return trajectorySubjects{}, nil, err
	}
	command, ok := trajectoryCommand(scheduler, edge.CommandID)
	if !ok {
		return trajectorySubjects{}, nil, fmt.Errorf("scheduler has no projected command %s", edge.CommandID)
	}
	commandDigest, err := digest.StableJSONSHA256Ref(map[string]any{"encoding": trajectorySubjectEncoding, "command": command})
	if err != nil {
		return trajectorySubjects{}, nil, err
	}
	witness, err := os.ReadFile(filepath.Join(t.root, filepath.FromSlash(edge.WitnessPath)))
	if err != nil {
		return trajectorySubjects{}, nil, fmt.Errorf("read native witness %s: %w", edge.WitnessPath, err)
	}
	environment, err := digest.StableJSONSHA256Ref(map[string]any{"encoding": trajectorySubjectEncoding, "environmentClass": edge.Environment, "policy": trajectoryEnvironmentPolicy(scheduler, edge.Environment)})
	if err != nil {
		return trajectorySubjects{}, nil, err
	}
	selectors, err := digest.StableJSONSHA256Ref([]any{edge.ScenarioID})
	if err != nil {
		return trajectorySubjects{}, nil, err
	}
	fragmentBytes, err := canonicalBytes(map[string]any{"requirement": requirement, "proofBinding": fragment})
	if err != nil {
		return trajectorySubjects{}, nil, err
	}
	return trajectorySubjects{
		Binding: binding, Command: commandDigest, Dependency: digest.SHA256BytesRef(witness),
		Environment: environment, Selectors: selectors, Edge: edge,
	}, fragmentBytes, nil
}

func trajectoryCommand(scheduler map[string]any, commandID string) (any, bool) {
	commands, _ := scheduler["commands"].([]any)
	for _, command := range commands {
		if record, ok := command.(map[string]any); ok && record["id"] == commandID {
			return record, true
		}
	}
	return nil, false
}

func trajectoryEnvironmentPolicy(scheduler map[string]any, class string) any {
	policies, _ := pointerValue(scheduler, "/vocabulary/environmentClassPolicies")
	values, _ := policies.([]any)
	for _, policy := range values {
		if record, ok := policy.(map[string]any); ok && record["environmentClass"] == class {
			return record
		}
	}
	return nil
}

// trajectoryReceipt records one fixture observation for exactly one edge and
// retains its subject manifest and log as consumer evidence files.
func (t *trajectory) receipt(receiptID, status string, subjects trajectorySubjects) (map[string]any, error) {
	logPath := "artifacts/receipts/" + receiptID + ".log"
	manifestPath := "artifacts/receipts/" + receiptID + ".subjects.json"
	log := []byte("fixture observation for " + subjects.Edge.CommandID + ": " + status + "\n")
	manifest, err := stablejson.Marshal(map[string]any{
		"encoding": trajectorySubjectEncoding, "requirementId": subjects.Edge.RequirementID, "scenarioId": subjects.Edge.ScenarioID,
		"binding": subjects.Binding, "command": subjects.Command, "dependency": subjects.Dependency,
		"environment": subjects.Environment, "selectors": subjects.Selectors,
	})
	if err != nil {
		return nil, err
	}
	if err := writeTrajectoryFiles(t.root, map[string]string{logPath: string(log), manifestPath: string(manifest)}); err != nil {
		return nil, err
	}
	var exitCode any
	artifacts := []any{}
	switch status {
	case "passed":
		exitCode = json.Number("0")
	case "failed":
		exitCode = json.Number("1")
	}
	if exitCode != nil {
		artifacts = []any{map[string]any{"kind": "log", "path": logPath, "sha256": digest.SHA256BytesRef(log)}}
	}
	nonClaims := []any{"Fixture receipt; the trajectory smoke does not execute native witnesses."}
	if exitCode == nil {
		nonClaims = append(nonClaims, "The native witness was not run for this attempt.")
	}
	return map[string]any{
		"receiptId": receiptID, "receiptKind": subjects.Edge.CommandID, "proofPlanId": trajectorySchedulerID,
		"sourceRevision": "fixture-working-tree", "proofBindingDigest": subjects.Binding, "commandDigest": subjects.Command,
		"environmentClass": subjects.Edge.Environment, "environmentDigest": subjects.Environment,
		"preconditionDigest": digest.SHA256TextRef("no recorded precondition blockers"),
		"witnessSelectors":   []any{subjects.Edge.ScenarioID}, "witnessSelectorDigest": subjects.Selectors,
		"toolchainDigest": digest.SHA256TextRef("fixture toolchain observation"), "dependencyDigest": subjects.Dependency, "lockfileDigest": nil,
		"runnerIdentity": "greeter.fixture-runner", "runnerClass": "local", "producerId": "greeter.fixture-producer",
		"producerAdmissionClass": "advisory", "provenanceRef": nil,
		"startedAt": "2026-10-11T00:00:00Z", "finishedAt": "2026-10-11T00:00:01Z",
		"status": status, "exitCode": exitCode, "artifactRefs": artifacts,
		"evidenceRefs": []any{manifestPath}, "nonClaims": nonClaims,
	}, nil
}

func trajectoryReceiptInput(setID string, receipts ...map[string]any) map[string]any {
	values := make([]any, len(receipts))
	for index, receipt := range receipts {
		values[index] = receipt
	}
	sortAnyMaps(values, "receiptId")
	return map[string]any{
		"schemaVersion": json.Number("1"), "receiptSetId": setID, "receipts": values,
		"nonClaims": []any{"Fixture receipts do not authenticate a producer."},
	}
}

// obligation pairs one retained receipt with freshly recomputed subjects.
func trajectoryObligation(receipt map[string]any, current trajectorySubjects) (map[string]any, error) {
	recordedFields := map[string]string{
		"binding": "proofBindingDigest", "command": "commandDigest", "dependency": "dependencyDigest",
		"environment": "environmentDigest", "selectors": "witnessSelectorDigest",
	}
	checks := []any{}
	for _, class := range trajectoryCheckClasses() {
		recorded, ok := receipt[recordedFields[class]].(string)
		if !ok {
			return nil, fmt.Errorf("receipt lacks recorded %s subject", class)
		}
		checks = append(checks, map[string]any{
			"checkId": "greeter.check." + class, "checkClass": "greeter." + class + "-subject",
			"recordedDigest": recorded, "currentDigest": current.digest(class),
			"evidenceRefs": receipt["evidenceRefs"], "nonClaims": []any{"Consumer declarations require independent evidence."},
		})
	}
	scope, err := digest.StableJSONSHA256Ref([]any{current.Edge.RequirementID, current.Edge.ScenarioID})
	if err != nil {
		return nil, err
	}
	selectors, _ := receipt["witnessSelectors"].([]any)
	if len(selectors) != 1 {
		return nil, fmt.Errorf("receipt must name one logical selector")
	}
	recordedScope, err := digest.StableJSONSHA256Ref([]any{current.Edge.RequirementID, selectors[0]})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"obligationId": "greeter.obligation." + current.Edge.RequirementID, "requirementId": current.Edge.RequirementID,
		"proofRouteRef": current.Edge.ScenarioID, "receiptId": receipt["receiptId"], "owner": trajectoryOwner,
		"reason":            "Reuse the receipt only while every selected subject is unchanged.",
		"currentnessChecks": checks,
		"scopeChecks": []any{map[string]any{
			"checkId": "greeter.scope.edge", "scopeClass": "greeter.requirement-scenario", "admissionState": "admitted_current_scope",
			"recordedScopeDigest": recordedScope, "currentScopeDigest": scope,
			"reason":       "The receipt covers exactly this requirement and scenario.",
			"evidenceRefs": receipt["evidenceRefs"], "nonClaims": []any{"Consumer declarations require independent evidence."},
		}},
		"evidenceRefs": receipt["evidenceRefs"], "nonClaims": []any{"Current subjects and scope are supplied by the consumer."},
	}, nil
}

func trajectoryCurrentnessInput(obligations ...map[string]any) map[string]any {
	values := make([]any, len(obligations))
	for index, obligation := range obligations {
		values[index] = obligation
	}
	sortAnyMaps(values, "obligationId")
	return map[string]any{
		"schemaVersion": json.Number("1"), "admissionId": "greeter.currentness", "obligationReceipts": values,
		"nonClaims": []any{"Currentness is not producer authentication or merge approval."},
	}
}

func trajectoryBundle(binding, scheduler, receiptInput, report map[string]any, exitCode int, mergeRequired []any) map[string]any {
	failures := []any{}
	diagnostics, _ := report["diagnostics"].([]any)
	for _, item := range diagnostics {
		if record, ok := item.(map[string]any); ok && record["key"] == "failures" {
			failures, _ = record["value"].([]any)
		}
	}
	return map[string]any{
		"schemaVersion": json.Number("1"), "bundleId": "greeter.bundle",
		"requirementBindings": binding, "witnessPlan": scheduler,
		"receiptAdmission": map[string]any{
			"exitCode": json.Number(fmt.Sprint(exitCode)), "failures": failures, "nonClaims": receiptInput["nonClaims"],
			"producers": []any{}, "receipts": receiptInput["receipts"], "report": report,
		},
		"receiptProducerAdmission": nil, "mergeRequiredReceiptIds": mergeRequired,
		"nonClaims": []any{"Bundle linkage does not execute witnesses, authenticate producers or approve merge."},
	}
}

// failedRuleMessages returns the exact failed rule messages of one report.
func failedRuleMessages(report map[string]any) []any {
	messages := []any{}
	results, _ := report["ruleResults"].([]any)
	for _, item := range results {
		if record, ok := item.(map[string]any); ok && record["status"] == "failed" {
			messages = append(messages, record["message"])
		}
	}
	slices.SortFunc(messages, func(left, right any) int {
		leftText, _ := left.(string)
		rightText, _ := right.(string)
		if leftText < rightText {
			return -1
		}
		if leftText > rightText {
			return 1
		}
		return 0
	})
	return messages
}
