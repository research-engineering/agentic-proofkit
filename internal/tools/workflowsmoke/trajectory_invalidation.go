package workflowsmoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func trajectoryFinding(class string) string {
	return "currentness check greeter.check." + class + " recorded digest does not match current digest"
}

// rejectUnexecutedEvidence proves that declarations, not-run attempts,
// relabelled reports and forged subjects are never accepted as current proof.
func (t *trajectory) rejectUnexecutedEvidence(state *trajectoryState) error {
	executed, farewell := state.receipts[trajectoryEmptyNameID], state.receipts[trajectoryFarewellID]
	executedID := executed["receiptId"].(string)
	subjects, _, err := t.subjects(state.context, state.scheduler, trajectoryEmptyNameID)
	if err != nil {
		return err
	}
	// The binding exists but its edge has no receipt: the requirement is
	// declared, not executed.
	report, _, err := t.link(state, "binding without execution", []any{executedID}, 1, farewell)
	if err != nil {
		return err
	}
	if err := expect("binding without execution", failedRuleMessages(report), map[string]any{"": []any{
		"merge-required receipt is missing from receiptAdmission: " + executedID,
	}}); err != nil {
		return err
	}
	// Differential control: with the executed receipt present the absence
	// failure disappears; only the separate producer-trust predicate remains.
	report, _, err = t.link(state, "executed advisory evidence", []any{executedID}, 1, executed, farewell)
	if err != nil {
		return err
	}
	if err := expect("executed advisory evidence", failedRuleMessages(report), map[string]any{"": []any{
		"merge-required receipt must use merge_satisfying producer admission: " + executedID,
	}}); err != nil {
		return err
	}
	notRun, err := t.receipt("greeter.receipt.empty-name.not-run", "not_run", subjects)
	if err != nil {
		return err
	}
	report, _, err = t.link(state, "not-run attempt", []any{"greeter.receipt.empty-name.not-run"}, 1, notRun, farewell)
	if err != nil {
		return err
	}
	if err := expect("not-run attempt", failedRuleMessages(report), map[string]any{"": []any{
		"merge-required receipt must pass: greeter.receipt.empty-name.not-run",
		"merge-required receipt must use merge_satisfying producer admission: greeter.receipt.empty-name.not-run",
	}}); err != nil {
		return err
	}
	// A failed run relabelled as passed inside its admission report must not
	// survive the bundle's recomputation of the child report.
	failedRun, err := t.receipt("greeter.receipt.empty-name.failed", "failed", subjects)
	if err != nil {
		return err
	}
	input := trajectoryReceiptInput("greeter.receipts", failedRun, farewell)
	admitted, err := t.admitReceipts("failed run", input)
	if err != nil {
		return err
	}
	forged, err := relabelReceiptStatus(admitted, "greeter.receipt.empty-name.failed", "passed")
	if err != nil {
		return err
	}
	bundle, err := encodeInput(trajectoryBundle(trajectoryBinding(state.spec), state.scheduler, input, forged, 0, []any{}))
	if err != nil {
		return err
	}
	if err := t.refuse("relabelled failed run", bytesInvocation(bundle, "spec-proof-bundle-admission", "--input", "-"), "receipt admission report body does not match owner validator result"); err != nil {
		return err
	}
	// The positive acceptance predicate itself refuses the same not-run and
	// failed attempts: their subjects are current, so only the admitted
	// status conjunct can refuse them.
	for _, attempt := range []map[string]any{notRun, failedRun} {
		status := attempt["status"].(string)
		state.receipts[trajectoryEmptyNameID] = attempt
		err := t.requireCurrent(state, status+" attempt as current proof")
		state.receipts[trajectoryEmptyNameID] = executed
		want := "was admitted with status " + status + ", not passed"
		if err == nil || !strings.Contains(err.Error(), want) {
			return fmt.Errorf("%s attempt must be refused as current proof with %q: %v", status, want, err)
		}
	}
	// A forged recorded subject cannot equal the recomputed current subject.
	forgedReceipt := map[string]any{}
	for key, value := range executed {
		forgedReceipt[key] = value
	}
	forgedReceipt["proofBindingDigest"] = digest.SHA256TextRef("forged proof binding subject")
	state.receipts[trajectoryEmptyNameID] = forgedReceipt
	failed, err := t.currentness(state, "forged subject")
	state.receipts[trajectoryEmptyNameID] = executed
	if err != nil {
		return err
	}
	return requireStale("forged subject", failed, state.lastStale, trajectoryEmptyNameID, "binding")
}

// requireStale proves the exact failed obligation and failing check classes.
func requireStale(label string, failed, stale []any, requirementID string, classes ...string) error {
	findings := []any{}
	for _, class := range classes {
		findings = append(findings, trajectoryFinding(class))
	}
	if err := expect(label+" failed obligations", failed, map[string]any{"": []any{"greeter.obligation." + requirementID}}); err != nil {
		return err
	}
	return expect(label+" stale findings", stale, map[string]any{"": []any{[]any{requirementID, findings, []any{"stale_receipt"}}}})
}

func relabelReceiptStatus(report map[string]any, receiptID, status string) (map[string]any, error) {
	encoded, err := encodeInput(report)
	if err != nil {
		return nil, err
	}
	value, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		return nil, err
	}
	copy := value.(map[string]any)
	diagnostics, _ := copy["diagnostics"].([]any)
	for _, item := range diagnostics {
		record := item.(map[string]any)
		if record["key"] != "receipts" {
			continue
		}
		for _, receipt := range record["value"].([]any) {
			if row := receipt.(map[string]any); row["receiptId"] == receiptID {
				row["status"] = status
				return copy, nil
			}
		}
	}
	return nil, fmt.Errorf("report has no receipt %s", receiptID)
}

func (t *trajectory) cover(state *trajectoryState) error {
	help, err := t.help("requirement-coverage-input-compose")
	if err != nil {
		return err
	}
	if err := t.requireNames("coverage help", help, "requirement-coverage-input-compose", "requirement-coverage-view"); err != nil {
		return err
	}
	template, err := guideTemplate("coverage help", help)
	if err != nil {
		return err
	}
	input := trajectoryCoverageInput(state.spec)
	for _, pointer := range []string{"", "/coverageUniverse"} {
		left, _ := pointerValue(template, pointer)
		right, _ := pointerValue(input, pointer)
		if err := sameKeys("coverage input"+pointer, left, right); err != nil {
			return err
		}
	}
	return t.coverage(state, "initial coverage", []any{
		[]any{trajectoryEmptyNameID, "mapped_to_declared_semantic_falsifier_route", []any{"greeter.test.empty-name-python"}},
		[]any{trajectoryFarewellID, "mapped_to_declared_semantic_falsifier_route", []any{"greeter.test.farewell-go"}},
	})
}

func (t *trajectory) coverage(state *trajectoryState, label string, rows []any) error {
	input, err := encodeInput(trajectoryCoverageInput(state.spec))
	if err != nil {
		return err
	}
	composed, err := t.call(label+" compose", bytesInvocation(input, "requirement-coverage-input-compose", "--input", "-"))
	if err != nil {
		return err
	}
	if composed.ExitCode != 0 || len(composed.Stderr) != 0 {
		return fmt.Errorf("%s compose must exit 0", label)
	}
	view, _, err := t.object(label+" view", bytesInvocation(composed.Stdout, "requirement-coverage-view", "--input", "-", "--format", "json"), 0)
	if err != nil {
		return err
	}
	observed := []any{}
	coverage, _ := view["requirementCoverage"].([]any)
	for _, item := range coverage {
		record := item.(map[string]any)
		observed = append(observed, []any{record["requirementId"], record["coverageState"], record["testIds"]})
	}
	if !sameJSON(observed, rows) {
		return fmt.Errorf("%s rows = %s, want %s", label, canonicalText(observed), canonicalText(rows))
	}
	nonClaims, _ := view["nonClaims"].([]any)
	const declarationOnly = "Mapped declaration routes do not prove selector resolution, oracle quality, execution, freshness, trust, sensitivity, or assurance closure."
	if !containsAny(nonClaims, declarationOnly) {
		return fmt.Errorf("%s lost its declaration-only non-claim", label)
	}
	return expect(label+" view", view, map[string]any{"/state": "passed", "/failureCount": 0, "/unmappedTests": []any{}, "/deadZones": []any{}})
}

func containsAny(values []any, want any) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// rematerialize plans and applies one owner-approved packet with the exact
// reviewed operations, after proving the previous identities are stale.
func (t *trajectory) rematerialize(state *trajectoryState, label string, packet map[string]any, actions map[string]string) error {
	input, err := encodeInput(packet)
	if err != nil {
		return err
	}
	oldTransaction, oldDesired := trajectoryIdentities(state.plan)
	if err := t.unchanged(label+" stale identity", func() error {
		blocked, _, err := t.object(label+" stale identity apply", bytesInvocation(input, "adopt", "materialize", "apply", "--input", "-", "--repo-root", t.root, "--expect-transaction", oldTransaction, "--expect-desired-state", oldDesired), 1)
		if err != nil {
			return err
		}
		return expect(label+" stale identity apply", blocked, map[string]any{
			"/state": "blocked", "/failureClass": "desired_state_identity_mismatch", "/transactionResult": nil,
		})
	}); err != nil {
		return err
	}
	plan, err := t.reviewPlan(label+" plan", input, actions)
	if err != nil {
		return err
	}
	transactionID, desiredStateID := trajectoryIdentities(plan)
	if err := t.apply(label, input, transactionID, desiredStateID); err != nil {
		return err
	}
	state.plan, state.packet = plan, packet
	return t.requireVerificationRequired(state, label)
}

func (t *trajectory) invalidateRequirement(state *trajectoryState) error {
	base := state.context
	before := cloneFragments(state.fragments)
	changed := state.spec
	changed.EmptyNameStatement = "Empty or whitespace-only names are rejected with a stable error."
	authoring, err := encodeInput(trajectoryAuthoring(state.spec, changed))
	if err != nil {
		return err
	}
	var plan map[string]any
	if err := t.unchanged("candidate requirement change", func() error {
		plan, _, err = t.object("candidate requirement change", bytesInvocation(authoring, "requirement-authoring-plan", "--input", "-"), 0)
		if err != nil {
			return err
		}
		return expect("candidate requirement change", plan, map[string]any{
			"/state": "passed", "/mode": "pull_request_design",
			"/nonAuthoritativeAdmissionPreview/authority": "candidate_only", "/nonAuthoritativeAdmissionPreview/candidateOnly": true,
			"/nonAuthoritativeAdmissionPreview/ownerReviewRequired": true,
			"/candidateChangeSet/0/operation":                       "modify", "/candidateChangeSet/0/requirementId": trajectoryEmptyNameID,
			"/candidateChangeSet/0/sourceRefIds": []any{"greeter.ref.coverage", "greeter.ref.design", "greeter.ref.plan"},
		})
	}); err != nil {
		return err
	}
	preview, _ := pointerValue(plan, "/nonAuthoritativeAdmissionPreview/requirementSourcePreview")
	packet := trajectoryPacket(state.sourcePlan, changed)
	packet["requirementSources"] = []any{preview}
	if err := t.rematerialize(state, "owner-approved requirement change", packet, map[string]string{
		trajectorySourcePath: "replace", trajectoryManifestPath: "replace", trajectoryBindingPath: "unchanged", trajectoryInventoryPath: "unchanged",
	}); err != nil {
		return err
	}
	state.spec = changed
	if state.context, err = t.capture("requirement change context"); err != nil {
		return err
	}
	changes, err := t.diff("requirement change diff", base, state.context)
	if err != nil {
		return err
	}
	if err := expect("requirement change diff", changes, map[string]any{"": []any{
		[]any{trajectoryEmptyNameID, "scalar_changed", "/requirements/" + trajectoryEmptyNameID + "/invariant"},
	}}); err != nil {
		return err
	}
	failed, err := t.currentness(state, "requirement change")
	if err != nil {
		return err
	}
	if err := requireStale("requirement change", failed, state.lastStale, trajectoryEmptyNameID, "binding"); err != nil {
		return err
	}
	if err := requireFragments("requirement change", before, state.fragments, trajectoryEmptyNameID); err != nil {
		return err
	}
	if err := t.reviewChange(before[trajectoryEmptyNameID], state.fragments[trajectoryEmptyNameID]); err != nil {
		return err
	}
	// The unchanged witness cannot falsify the whitespace case, so the
	// blocking proof obligation is discharged before reaffirmation: the
	// witness gains that case and the implementation is repaired to pass it.
	reviewed := cloneFragments(state.fragments)
	if err := writeTrajectoryFiles(t.root, trajectoryWhitespaceFiles()); err != nil {
		return err
	}
	if failed, err = t.currentness(state, "whitespace witness extension"); err != nil {
		return err
	}
	if err := requireStale("whitespace witness extension", failed, state.lastStale, trajectoryEmptyNameID, "binding", "dependency"); err != nil {
		return err
	}
	if err := requireFragments("whitespace witness extension", reviewed, state.fragments); err != nil {
		return err
	}
	if err := t.reaffirm(state, "requirement change", trajectoryEmptyNameID, "greeter.receipt.empty-name.2"); err != nil {
		return err
	}
	// A scenario-body edit reaches its member requirement and nothing else.
	base, before = state.context, cloneFragments(state.fragments)
	scenario := state.spec
	scenario.EmptyNameAction = "Call greet with an empty or whitespace-only name."
	if err := t.rematerialize(state, "owner-approved scenario change", trajectoryPacket(state.sourcePlan, scenario), map[string]string{
		trajectorySourcePath: "replace", trajectoryManifestPath: "replace", trajectoryBindingPath: "unchanged", trajectoryInventoryPath: "unchanged",
	}); err != nil {
		return err
	}
	state.spec = scenario
	if state.context, err = t.capture("scenario change context"); err != nil {
		return err
	}
	if changes, err = t.diff("scenario change diff", base, state.context); err != nil {
		return err
	}
	if err := expect("scenario change diff", changes, map[string]any{"": []any{
		[]any{trajectoryEmptyNameID, "scalar_changed", "/requirements/" + trajectoryEmptyNameID + "/sourceReviewDigest"},
	}}); err != nil {
		return err
	}
	if failed, err = t.currentness(state, "scenario change"); err != nil {
		return err
	}
	if err := requireStale("scenario change", failed, state.lastStale, trajectoryEmptyNameID, "binding"); err != nil {
		return err
	}
	if err := requireFragments("scenario change", before, state.fragments, trajectoryEmptyNameID); err != nil {
		return err
	}
	return t.reaffirm(state, "scenario change", trajectoryEmptyNameID, "greeter.receipt.empty-name.3")
}

// requireFragments proves that exactly the changed requirements' proof
// fragments changed; every other fragment is byte-identical.
func requireFragments(label string, before, after map[string][]byte, changed ...string) error {
	for _, requirementID := range []string{trajectoryEmptyNameID, trajectoryFarewellID} {
		equal := bytes.Equal(before[requirementID], after[requirementID])
		if equal == containsText(changed, requirementID) {
			return fmt.Errorf("%s proof fragment of %s changed=%t, want %t", label, requirementID, !equal, containsText(changed, requirementID))
		}
	}
	return nil
}

func containsText(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func cloneFragments(fragments map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(fragments))
	for key, value := range fragments {
		result[key] = append([]byte(nil), value...)
	}
	return result
}

// reaffirm records fresh evidence for exactly one edge and proves that the
// other edge keeps its original receipt.
func (t *trajectory) reaffirm(state *trajectoryState, label, requirementID, receiptID string) error {
	untouched := map[string]any{}
	for key, receipt := range state.receipts {
		if key != requirementID {
			untouched[key] = receipt["receiptId"]
		}
	}
	subjects, _, err := t.subjects(state.context, state.scheduler, requirementID)
	if err != nil {
		return err
	}
	receipt, err := t.receipt(receiptID, "passed", subjects)
	if err != nil {
		return err
	}
	state.receipts[requirementID] = receipt
	if err := t.requireCurrent(state, label+" reaffirmed"); err != nil {
		return err
	}
	for key, id := range untouched {
		if state.receipts[key]["receiptId"] != id {
			return fmt.Errorf("%s replaced unrelated evidence for %s", label, key)
		}
	}
	return nil
}

// reviewChange proves that a review bound to the old subject cannot approve
// the changed subject, while the new subject is routed to review.
func (t *trajectory) reviewChange(before, after []byte) error {
	help, err := t.help("change", "plan")
	if err != nil {
		return err
	}
	template, err := guideTemplate("change plan help", help)
	if err != nil {
		return err
	}
	oldSubject, newSubject := digest.SHA256BytesRef(before), digest.SHA256BytesRef(after)
	authority := digest.SHA256TextRef("greeter.owner review authority")
	checkpoint := func(state string, assessment any) map[string]any {
		current := map[string]any{"state": state, "subjectRefId": "greeter.subject.empty-name", "subjectDigest": newSubject}
		if assessment != nil {
			current["assessmentSubjectDigest"] = assessment
		}
		return map[string]any{
			"schemaVersion": json.Number("1"), "completedStageIds": []any{}, "checkpoint": current,
			"contextRefs": []any{
				map[string]any{"refId": "greeter.authority", "refKind": "authority", "artifactPath": "review/authority.json", "subjectDigest": authority, "dependencyRefIds": []any{}},
				map[string]any{"refId": "greeter.subject.empty-name", "refKind": "artifact", "artifactPath": "review/empty-name-fragment.json", "subjectDigest": newSubject, "dependencyRefIds": []any{}},
			},
			"governingAuthorityRefId": "greeter.authority", "requiredContextRefIds": []any{},
		}
	}
	stale := checkpoint("review_passed", oldSubject)
	if err := sameKeys("change checkpoint", template, stale); err != nil {
		return err
	}
	input, err := encodeInput(stale)
	if err != nil {
		return err
	}
	if err := t.refuse("stale review assessment", bytesInvocation(input, "change", "plan", "--input", "-"), "proofkit.workflow.assessment_digest_mismatch"); err != nil {
		return err
	}
	if input, err = encodeInput(checkpoint("ready_for_review", nil)); err != nil {
		return err
	}
	envelope, _, err := t.object("changed subject review", bytesInvocation(input, "change", "plan", "--input", "-", "--agent-envelope"), 0)
	if err != nil {
		return err
	}
	return expect("changed subject review", envelope, map[string]any{
		"/actionPlan/0/outputKind": "next_action", "/actionPlan/0/subjectDigest": newSubject,
		"/actionPlan/0/subjectRefId": "greeter.subject.empty-name", "/actionPlan/0/phase": "architecture",
		"/actionPlan/0/instruction": "Independently attempt to falsify the active-stage artifact under its declared owner, bounds, non-claims, and exact subject digest.",
	})
}

func trajectoryAuthoring(current, candidate trajectorySpec) map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("2"), "authoringPlanId": "greeter.authoring.whitespace", "mode": "pull_request_design",
		"currentRequirementSource": trajectorySource(current), "candidateRequirementSource": trajectorySource(candidate),
		"authoringRefs": []any{
			map[string]any{"refId": "greeter.ref.coverage", "kind": "test_summary", "path": "artifacts/coverage.txt", "digest": nil, "summary": "Coverage observation: the whitespace branch of greet is uncovered.", "nonClaims": []any{"Coverage observation only; it does not establish desired behavior."}},
			map[string]any{"refId": "greeter.ref.design", "kind": "design_doc", "path": "docs/design/whitespace.md", "digest": nil, "summary": "The external design proposes rejecting whitespace-only names.", "nonClaims": []any{"Design input, not imported authority."}},
			map[string]any{"refId": "greeter.ref.plan", "kind": "implementation_plan", "path": "docs/plans/whitespace.md", "digest": nil, "summary": "The plan proposes trimming before the emptiness check.", "nonClaims": []any{"Plan proposal, not evidence that behavior exists."}},
		},
		"candidateUpdates": []any{map[string]any{
			"candidateId": "greeter.candidate.whitespace", "operation": "modify", "requirementId": trajectoryEmptyNameID,
			"sourceRefIds":   []any{"greeter.ref.coverage", "greeter.ref.design", "greeter.ref.plan"},
			"rationale":      "Extend the empty-name rule to whitespace-only names after owner review.",
			"ownerQuestions": []any{"Should whitespace-only names be rejected?"},
			"declaredProofObligations": []any{map[string]any{
				"obligationId": "greeter.obligation.whitespace", "kind": "native_witness", "ownerId": trajectoryOwner,
				"description": "Extend the native witness with a whitespace-only name case.", "blocking": true, "evidenceRefs": []any{},
			}},
		}},
		"nonClaims": []any{"Fixture authoring plan; owner approval and test execution are not proven."},
	}
}

func (t *trajectory) invalidateTest(state *trajectoryState) error {
	base, before := state.context, cloneFragments(state.fragments)
	status, _, err := t.object("status before native test change", unreadInvocation("status", "--repo-root", t.root), 0)
	if err != nil {
		return err
	}
	path := filepath.Join(t.root, filepath.FromSlash(trajectoryFarewellTest))
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	changed := bytes.Replace(content, []byte(`[]string{"Ada", "Grace"}`), []byte(`[]string{"Ada", "Grace", "Linus"}`), 1)
	if bytes.Equal(changed, content) {
		return fmt.Errorf("native test fixture did not change")
	}
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		return err
	}
	// Project status covers only admitted records, never native test bytes.
	after, _, err := t.object("status after native test change", unreadInvocation("status", "--repo-root", t.root), 0)
	if err != nil {
		return err
	}
	if !sameJSON(status["statusId"], after["statusId"]) || after["projectState"] != "verification_required" {
		return fmt.Errorf("native test change unexpectedly changed project status")
	}
	var current map[string]any
	if current, err = t.capture("native test change context"); err != nil {
		return err
	}
	changes, err := t.diff("native test change diff", base, current)
	if err != nil {
		return err
	}
	if len(changes) != 0 {
		return fmt.Errorf("a native test change must not rewrite specification meaning: %s", canonicalText(changes))
	}
	state.context = current
	failed, err := t.currentness(state, "native test change")
	if err != nil {
		return err
	}
	if err := requireStale("native test change", failed, state.lastStale, trajectoryFarewellID, "dependency"); err != nil {
		return err
	}
	if err := requireFragments("native test change", before, state.fragments); err != nil {
		return err
	}
	return t.reaffirm(state, "native test change", trajectoryFarewellID, "greeter.receipt.farewell.2")
}

func (t *trajectory) migrate(state *trajectoryState) error {
	base, before := state.context, cloneFragments(state.fragments)
	pythonReceipt := state.receipts[trajectoryEmptyNameID]
	files, removed := trajectoryMigratedFiles()
	if err := writeTrajectoryFiles(t.root, files); err != nil {
		return err
	}
	for _, path := range removed {
		if err := os.Remove(filepath.Join(t.root, filepath.FromSlash(path))); err != nil {
			return err
		}
	}
	migrated := state.spec
	migrated.Migrated = true
	if err := t.rematerialize(state, "witness migration", trajectoryPacket(state.sourcePlan, migrated), map[string]string{
		trajectorySourcePath: "unchanged", trajectoryManifestPath: "replace", trajectoryBindingPath: "replace", trajectoryInventoryPath: "replace",
	}); err != nil {
		return err
	}
	state.spec = migrated
	var err error
	if state.scheduler, err = t.plannedScheduler(migrated, "migrated", []any{
		[]any{trajectoryFarewellCommand, []any{"go", "test", "./greeter", "-run", "TestFarewellNamesOnce"}},
		[]any{trajectoryGoGreetCommand, []any{"go", "test", "./greeter", "-run", "TestGreetRejectsEmptyName"}},
	}); err != nil {
		return err
	}
	if state.context, err = t.capture("migration context"); err != nil {
		return err
	}
	changes, err := t.diff("migration diff", base, state.context)
	if err != nil {
		return err
	}
	if len(changes) != 0 {
		return fmt.Errorf("witness migration must keep requirement and scenario meaning: %s", canonicalText(changes))
	}
	for _, requirementID := range []string{trajectoryEmptyNameID, trajectoryFarewellID} {
		old, err := t.slice(base, requirementID)
		if err != nil {
			return err
		}
		current, err := t.slice(state.context, requirementID)
		if err != nil {
			return err
		}
		requirement, _ := pointerValue(old, "/projections/requirementSources/0/requirements/0")
		if err := expect("migrated requirement "+requirementID, current, map[string]any{
			"/projections/requirementSources/0/requirements/0": requirement,
			"/projections/proofBinding/bindings/0/scenarioId":  map[string]string{trajectoryEmptyNameID: trajectoryEmptyScenario, trajectoryFarewellID: trajectoryFarewellScenario}[requirementID],
		}); err != nil {
			return err
		}
	}
	// Old-language execution evidence is not linked to the migrated binding.
	report, _, err := t.link(state, "python evidence after migration", []any{}, 1, pythonReceipt, state.receipts[trajectoryFarewellID])
	if err != nil {
		return err
	}
	if err := expect("python evidence after migration", failedRuleMessages(report), map[string]any{"": trajectoryPythonLinkFailures(pythonReceipt["receiptId"].(string))}); err != nil {
		return err
	}
	failed, err := t.currentness(state, "python evidence after migration")
	if err != nil {
		return err
	}
	if err := requireStale("python evidence after migration", failed, state.lastStale, trajectoryEmptyNameID, "binding", "command", "dependency", "environment"); err != nil {
		return err
	}
	if err := requireFragments("witness migration", before, state.fragments, trajectoryEmptyNameID); err != nil {
		return err
	}
	if err := t.reaffirm(state, "witness migration", trajectoryEmptyNameID, "greeter.receipt.empty-name.go.1"); err != nil {
		return err
	}
	goReceipt := state.receipts[trajectoryEmptyNameID]
	if err := expect("go receipt", goReceipt, map[string]any{"/receiptKind": trajectoryGoGreetCommand, "/environmentClass": "local-go", "/witnessSelectors": []any{trajectoryEmptyScenario}}); err != nil {
		return err
	}
	// Replaying the Python receipt beside the Go receipt still fails linkage.
	report, _, err = t.link(state, "python evidence replay", []any{}, 1, pythonReceipt, goReceipt, state.receipts[trajectoryFarewellID])
	if err != nil {
		return err
	}
	if err := expect("python evidence replay", failedRuleMessages(report), map[string]any{"": trajectoryPythonLinkFailures(pythonReceipt["receiptId"].(string))}); err != nil {
		return err
	}
	return t.coverage(state, "migrated coverage", []any{
		[]any{trajectoryEmptyNameID, "mapped_to_declared_semantic_falsifier_route", []any{"greeter.test.empty-name-go"}},
		[]any{trajectoryFarewellID, "mapped_to_declared_semantic_falsifier_route", []any{"greeter.test.farewell-go"}},
	})
}

func trajectoryPythonLinkFailures(receiptID string) []any {
	return []any{
		"receipt " + receiptID + " receiptKind " + trajectoryPythonCommand + " does not cover witness selector " + trajectoryEmptyScenario,
		"receipt " + receiptID + " receiptKind must match a requirement binding command id",
	}
}

func (t *trajectory) repair(state *trajectoryState) error {
	path := filepath.Join(t.root, filepath.FromSlash(trajectoryBindingPath))
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte("\n")); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	manifestID, _ := pointerValue(state.plan, "/manifest/manifestId")
	next, _, err := t.object("drifted next", unreadInvocation("next", "--repo-root", t.root), 0)
	if err != nil {
		return err
	}
	if err := expect("drifted next", next, map[string]any{
		"/projectState": "stale", "/issueCodes": []any{"project_record_digest_mismatch"},
		"/action/actionClass": "rematerialize_project", "/action/commandRoute": []any{"adopt", "materialize", "plan"},
		"/action/contextRef": manifestID, "/action/executable": false,
	}); err != nil {
		return err
	}
	input, err := encodeInput(state.packet)
	if err != nil {
		return err
	}
	plan, err := t.reviewPlan("repair plan", input, map[string]string{
		trajectorySourcePath: "unchanged", trajectoryManifestPath: "unchanged", trajectoryBindingPath: "replace", trajectoryInventoryPath: "unchanged",
	})
	if err != nil {
		return err
	}
	transactionID, desiredStateID := trajectoryIdentities(plan)
	if err := t.apply("repair", input, transactionID, desiredStateID); err != nil {
		return err
	}
	state.plan = plan
	if err := t.requireVerificationRequired(state, "repaired project"); err != nil {
		return err
	}
	if state.context, err = t.capture("repaired context"); err != nil {
		return err
	}
	return t.requireCurrent(state, "repaired project")
}
