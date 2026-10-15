package workflowsmoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

// VerifyTrajectory drives one agent session through the whole truth chain of
// one temporary two-language repository: install bootstrap, intake, reviewed
// materialization, scenario storage, binding, scheduling, receipts, coverage,
// bidirectional invalidation, Python-to-Go witness migration and repair.
// Every step asserts exact machine facts; every negative control asserts the
// specific rejection that keeps it from being accepted as current proof.
func VerifyTrajectory(ctx context.Context, run Runner) (returnErr error) {
	if ctx == nil || run == nil {
		return fmt.Errorf("trajectory smoke requires a context and runner")
	}
	root, err := os.MkdirTemp("", "proofkit-trajectory-")
	if err != nil {
		return fmt.Errorf("create trajectory repository: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, os.RemoveAll(root)) }()
	if err := writeTrajectoryFiles(root, trajectoryNativeFiles()); err != nil {
		return fmt.Errorf("write trajectory repository: %w", err)
	}
	session := newTrajectory(ctx, run, root)
	state := &trajectoryState{}
	for _, phase := range []struct {
		name string
		run  func(*trajectoryState) error
	}{
		{"bootstrap and discovery", session.discover},
		{"candidate intake", session.intake},
		{"owner-admitted materialization", session.materialize},
		{"scenario storage", session.scenarioStorage},
		{"command and environment", session.schedule},
		{"execution evidence", session.execute},
		{"declaration coverage", session.cover},
		{"requirement-side invalidation", session.invalidateRequirement},
		{"test-side invalidation", session.invalidateTest},
		{"bilingual witness migration", session.migrate},
		{"repair", session.repair},
	} {
		if err := phase.run(state); err != nil {
			return fmt.Errorf("trajectory %s: %w", phase.name, err)
		}
	}
	return nil
}

// trajectoryState is the agent's retained memory: only CLI outputs and the
// caller-owned inputs it authored.
type trajectoryState struct {
	nextHelp   []byte
	sourcePlan any
	spec       trajectorySpec
	packet     map[string]any
	plan       map[string]any
	context    map[string]any
	scheduler  map[string]any
	receipts   map[string]map[string]any
	fragments  map[string][]byte
	lastStale  []any
}

func (t *trajectory) discover(state *trajectoryState) error {
	result, err := t.call("install bootstrap", unreadInvocation("integration", "source", "--tool", "codex", "--format", "text"))
	if err != nil {
		return err
	}
	if result.ExitCode != 0 || len(result.Stderr) != 0 {
		return fmt.Errorf("install bootstrap must succeed")
	}
	starts := trajectoryBootstrapRoute.FindAllSubmatch(result.Stdout, -1)
	if len(starts) != 2 || string(starts[0][1]) != "status" || string(starts[1][1]) != "next" {
		return fmt.Errorf("install bootstrap must start with status then next")
	}
	t.name("install bootstrap", []string{"status"})
	t.name("install bootstrap", []string{"next"})
	return t.unchanged("adoption planning", func() error { return t.discoverAdoption(state) })
}

func (t *trajectory) discoverAdoption(state *trajectoryState) error {
	next, _, err := t.object("uninitialized next", unreadInvocation("next", "--repo-root", t.root), 0)
	if err != nil {
		return err
	}
	if err := expect("uninitialized next", next, map[string]any{
		"/packetKind": "proofkit.project-next-action", "/projectState": "uninitialized", "/issueCodes": []any{"project_manifest_missing"},
		"/action/actionClass": "choose_adoption_mode", "/action/commandRoute": []any{"adopt", "plan"},
		"/action/executable": false, "/action/requiredDecision": "adoption_mode", "/action/contextRef": nil,
	}); err != nil {
		return err
	}
	t.name("uninitialized next", []string{"adopt", "plan"})
	if state.nextHelp, err = t.help("next"); err != nil {
		return err
	}
	for _, continuation := range []struct {
		class string
		route []string
	}{
		{"choose_adoption_mode", []string{"adopt", "plan"}},
		{"rematerialize_project", []string{"adopt", "materialize", "plan"}},
		{"choose_recovery", []string{"adopt", "materialize", "recover"}},
		{"run_repository_verification", []string{"native-evidence-guidance"}},
	} {
		if err := t.requireContinuation(state.nextHelp, continuation.class, continuation.route); err != nil {
			return err
		}
	}
	adoptHelp, err := t.help("adopt", "plan")
	if err != nil {
		return err
	}
	if err := t.requireNames("adopt plan help", adoptHelp, "adopt materialize plan"); err != nil {
		return err
	}
	for _, mode := range []struct {
		flag, declaration string
		trust             any
		tasks             []any
	}{
		{"audit-from-code", "untrusted_code_observation", "audit_from_code", []any{nil, "capability-map-admission", "requirement-authoring-plan", "native-evidence-guidance"}},
		{"code-baseline", "caller_declared_code_baseline", "code_baseline", []any{nil, "capability-map-admission", "requirement-authoring-plan", "native-evidence-guidance"}},
		{"fresh", "owner_intent_required", nil, []any{nil, "requirement-source-admission", "native-evidence-guidance"}},
	} {
		label := "adopt plan " + mode.flag
		plan, _, err := t.object(label, unreadInvocation("adopt", "plan", "--mode", mode.flag, "--repo-root", t.root, "--format", "json"), 0)
		if err != nil {
			return err
		}
		if err := expect(label, plan, map[string]any{
			"/planKind": "proofkit.adoption-plan", "/intent": mode.flag, "/state": "authoring_required",
			"/authority": "derived_non_authoritative_plan", "/sourceTrust/declarationClass": mode.declaration,
			"/sourceTrust/capabilityMapTrustMode": mode.trust, "/authoringPacket/authority": "candidate_only",
			"/authoringPacket/proposedRequirementCount": 0, "/authoringPacket/proposedBindingCount": 0,
			"/summary/generatedRequirementCount": 0, "/summary/generatedBindingCount": 0,
			"/summary/codeBaselineDeclared": mode.flag == "code-baseline",
		}); err != nil {
			return err
		}
		tasks, _ := pointerValue(plan, "/authoringPacket/tasks")
		commandIDs := []any{}
		for _, task := range tasks.([]any) {
			commandID := task.(map[string]any)["commandId"]
			commandIDs = append(commandIDs, commandID)
			if text, ok := commandID.(string); ok {
				t.name(label, []string{text})
			}
		}
		if !sameJSON(commandIDs, mode.tasks) {
			return fmt.Errorf("%s task routes = %s, want %s", label, canonicalText(commandIDs), canonicalText(mode.tasks))
		}
		if mode.flag == "fresh" {
			state.sourcePlan = plan
		}
	}
	return nil
}

// unchanged proves that a candidate-only or refused step wrote no repository
// byte and left the observed project status identity unchanged.
func (t *trajectory) unchanged(label string, action func() error) error {
	beforeStatus, _, err := t.object(label+" status before", unreadInvocation("status", "--repo-root", t.root), 0)
	if err != nil {
		return err
	}
	beforeTree, err := integrationTree(t.root)
	if err != nil {
		return err
	}
	if err := action(); err != nil {
		return err
	}
	afterTree, err := integrationTree(t.root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(beforeTree, afterTree) {
		return fmt.Errorf("%s changed repository bytes", label)
	}
	afterStatus, _, err := t.object(label+" status after", unreadInvocation("status", "--repo-root", t.root), 0)
	if err != nil {
		return err
	}
	if !sameJSON(beforeStatus["statusId"], afterStatus["statusId"]) {
		return fmt.Errorf("%s changed the project status identity", label)
	}
	return nil
}

// requireContinuation proves that next/status help maps one action class to
// exactly one named help route.
func (t *trajectory) requireContinuation(help []byte, class string, route []string) error {
	lines := strings.Split(string(help), "\n")
	for index, line := range lines {
		if !strings.HasPrefix(line, "  "+class+": ") {
			continue
		}
		want := "    " + t.prefix + " " + strings.Join(route, " ") + " --help"
		if index+1 >= len(lines) || lines[index+1] != want {
			return fmt.Errorf("next help does not continue %s with %q", class, want)
		}
		return nil
	}
	return fmt.Errorf("next help omits action class %s", class)
}

func (t *trajectory) intake(*trajectoryState) error {
	return t.unchanged("candidate intake", t.admitCandidates)
}

func (t *trajectory) admitCandidates() error {
	capabilityHelp, err := t.help("capability-map-admission")
	if err != nil {
		return err
	}
	sections := bytes.Split(capabilityHelp, []byte("```json\n"))
	if len(sections) != 3 {
		return fmt.Errorf("capability help must contain the audit and baseline examples")
	}
	for index, want := range []struct {
		mode  string
		seeds int
	}{{"audit_from_code", 0}, {"code_baseline", 1}} {
		input, _, _ := bytes.Cut(sections[index+1], []byte("\n```"))
		label := "capability map " + want.mode
		report, _, err := t.object(label, bytesInvocation(input, "capability-map-admission", "--input", "-"), 0)
		if err != nil {
			return err
		}
		if err := expect(label, report, map[string]any{
			"/state": "passed", "/summary/trustMode": want.mode,
			"/summary/candidateRequirementSeedCount": want.seeds, "/summary/candidateProofBindingSeedCount": want.seeds,
		}); err != nil {
			return err
		}
	}
	authoringHelp, err := t.help("requirement-authoring-plan")
	if err != nil {
		return err
	}
	for _, kind := range []string{"design_doc:", "implementation_plan:", "test_summary:", "code_summary:"} {
		if !bytes.Contains(authoringHelp, []byte("\n  "+kind+" ")) {
			return fmt.Errorf("authoring help lost the %s reference role", kind)
		}
	}
	return nil
}

func (t *trajectory) materialize(state *trajectoryState) error {
	help, err := t.help("adopt", "materialize", "plan")
	if err != nil {
		return err
	}
	if err := t.requireNames("materialization help", help, "requirement-source-admission", "requirement-bindings", "test-evidence-inventory", "adopt materialize plan", "adopt materialize apply"); err != nil {
		return err
	}
	template, err := guideTemplate("materialization help", help)
	if err != nil {
		return err
	}
	state.spec = trajectoryInitialSpec()
	state.packet = trajectoryPacket(state.sourcePlan, state.spec)
	if err := sameKeys("materialization packet", template, state.packet); err != nil {
		return err
	}
	sourceHelp, err := t.help("requirement-source-admission")
	if err != nil {
		return err
	}
	example, err := guideTemplate("scenario guide", sourceHelp)
	if err != nil {
		return err
	}
	examples, _ := example.([]any)
	if len(examples) != 1 {
		return fmt.Errorf("scenario guide must show one scenario body")
	}
	for _, scenario := range trajectoryScenarios(state.spec) {
		if err := sameKeys("scenario body", examples[0], scenario); err != nil {
			return err
		}
	}
	input, err := encodeInput(state.packet)
	if err != nil {
		return err
	}
	for _, child := range []struct{ route, pointer, kind string }{
		{"requirement-source-admission", "/requirementSources/0", "proofkit.requirement-source-admission"},
		{"requirement-bindings", "/requirementProofBinding/record", "proofkit.requirement-proof-bindings"},
		{"test-evidence-inventory", "/testEvidenceInventory/record", "proofkit.test-evidence-inventory"},
	} {
		report, _, err := t.object(child.route+" child", bytesInvocation(input, child.route, "--input", "-", "--input-pointer", child.pointer), 0)
		if err != nil {
			return err
		}
		if err := expect(child.route+" child", report, map[string]any{"/state": "passed", "/reportKind": child.kind}); err != nil {
			return err
		}
	}
	// Negative control: a binding row may use a scenario body only when the
	// body's membership names that requirement.
	crossed := trajectoryPacket(state.sourcePlan, state.spec)
	rows, _ := pointerValue(crossed, "/requirementProofBinding/record/bindings")
	rows.([]any)[1].(map[string]any)["scenarioId"] = trajectoryEmptyScenario
	crossedInput, err := encodeInput(crossed)
	if err != nil {
		return err
	}
	if err := t.unchanged("refused materialization", func() error {
		if err := t.refuse("scenario membership", bytesInvocation(crossedInput, "adopt", "materialize", "plan", "--input", "-", "--repo-root", t.root), "scenario link disagrees with its admitted source"); err != nil {
			return err
		}
		if state.plan, err = t.reviewPlan("initial materialization plan", input, map[string]string{
			trajectorySourcePath: "create", trajectoryManifestPath: "create", trajectoryBindingPath: "create", trajectoryInventoryPath: "create",
		}); err != nil {
			return err
		}
		// Negative control: skipping the reviewed identities is an invocation error.
		if err := t.refuse("apply without reviewed identities", bytesInvocation(input, "adopt", "materialize", "apply", "--input", "-", "--repo-root", t.root), "requires --expect-desired-state"); err != nil {
			return err
		}
		// Negative control: a forged transaction identity blocks before mutation.
		_, desiredStateID := trajectoryIdentities(state.plan)
		forged := digest.SHA256TextRef("forged transaction identity")
		blocked, _, err := t.object("forged identity apply", bytesInvocation(input, "adopt", "materialize", "apply", "--input", "-", "--repo-root", t.root, "--expect-transaction", forged, "--expect-desired-state", desiredStateID), 1)
		if err != nil {
			return err
		}
		return expect("forged identity apply", blocked, map[string]any{
			"/state": "blocked", "/failureClass": "transaction_identity_mismatch", "/transactionResult": nil, "/expectedTransactionId": forged,
		})
	}); err != nil {
		return err
	}
	transactionID, desiredStateID := trajectoryIdentities(state.plan)
	if err := t.apply("initial materialization", input, transactionID, desiredStateID); err != nil {
		return err
	}
	return t.requireVerificationRequired(state, "initial materialization")
}

func trajectoryIdentities(plan map[string]any) (string, string) {
	transactionID, _ := pointerValue(plan, "/transaction/transactionId")
	desiredStateID, _ := pointerValue(plan, "/transaction/desiredStateId")
	transaction, _ := transactionID.(string)
	desired, _ := desiredStateID.(string)
	return transaction, desired
}

// reviewPlan admits one materialization plan and proves its exact operations.
func (t *trajectory) reviewPlan(label string, input []byte, actions map[string]string) (map[string]any, error) {
	plan, _, err := t.object(label, bytesInvocation(input, "adopt", "materialize", "plan", "--input", "-", "--repo-root", t.root), 0)
	if err != nil {
		return nil, err
	}
	if err := expect(label, plan, map[string]any{"/state": "ready", "/projectId": "greeter.project", "/sourceIntent": "fresh"}); err != nil {
		return nil, err
	}
	operations, _ := pointerValue(plan, "/transaction/operations")
	observed := map[string]string{}
	for _, operation := range operations.([]any) {
		record := operation.(map[string]any)
		observed[record["path"].(string)], _ = record["action"].(string)
	}
	if !reflect.DeepEqual(observed, actions) {
		return nil, fmt.Errorf("%s operations = %v, want %v", label, observed, actions)
	}
	return plan, nil
}

func (t *trajectory) apply(label string, input []byte, transactionID, desiredStateID string) error {
	receipt, _, err := t.object(label+" apply", bytesInvocation(input, "adopt", "materialize", "apply", "--input", "-", "--repo-root", t.root, "--expect-transaction", transactionID, "--expect-desired-state", desiredStateID), 0)
	if err != nil {
		return err
	}
	return expect(label+" apply", receipt, map[string]any{
		"/state": "passed", "/operation": "apply", "/transactionResult/state": "applied",
		"/transactionResult/transactionId": transactionID, "/expectedDesiredStateId": desiredStateID,
	})
}

// requireVerificationRequired proves the only post-write state Proofkit can
// reach: never verified, only owner verification required.
func (t *trajectory) requireVerificationRequired(state *trajectoryState, label string) error {
	manifestID, _ := pointerValue(state.plan, "/manifest/manifestId")
	next, _, err := t.object(label+" next", unreadInvocation("next", "--repo-root", t.root), 0)
	if err != nil {
		return err
	}
	return expect(label+" next", next, map[string]any{
		"/projectState": "verification_required", "/issueCodes": []any{},
		"/action/actionClass": "run_repository_verification", "/action/commandRoute": []any{},
		"/action/executable": false, "/action/contextRef": manifestID,
	})
}

func (t *trajectory) scenarioStorage(state *trajectoryState) error {
	file, err := os.ReadFile(filepath.Join(t.root, filepath.FromSlash(trajectorySourcePath)))
	if err != nil {
		return err
	}
	if err := expect("materialized source operation", state.plan, map[string]any{
		"/transaction/operations/0/path": trajectorySourcePath, "/transaction/operations/0/after/sha256": digest.SHA256BytesRef(file),
	}); err != nil {
		return err
	}
	stored, err := admission.DecodeJSON(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		return err
	}
	if err := expect("materialized source", stored, map[string]any{"/scenarios": trajectoryScenarios(state.spec)}); err != nil {
		return err
	}
	report, _, err := t.object("materialized source admission", unreadInvocation("requirement-source-admission", "--input", filepath.Join(t.root, filepath.FromSlash(trajectorySourcePath))), 0)
	if err != nil {
		return err
	}
	if err := expect("materialized source admission", report, map[string]any{"/state": "passed"}); err != nil {
		return err
	}
	input, err := encodeInput(state.packet)
	if err != nil {
		return err
	}
	if _, err := t.reviewPlan("byte-stable replan", input, map[string]string{
		trajectorySourcePath: "unchanged", trajectoryManifestPath: "unchanged", trajectoryBindingPath: "unchanged", trajectoryInventoryPath: "unchanged",
	}); err != nil {
		return err
	}
	guidance, err := t.help("native-evidence-guidance")
	if err != nil {
		return err
	}
	if err := t.requireNames("native evidence cookbook", guidance, "requirement-semantic-diff", "proof-receipt-admission", "spec-proof-bundle-admission", "receipt-currentness-scope", "requirement-coverage-input-compose", "change plan"); err != nil {
		return err
	}
	diffHelp, err := t.help("requirement-semantic-diff")
	if err != nil {
		return err
	}
	if err := t.requireNames("semantic diff help", diffHelp, "requirement-context-compose", "requirement-semantic-diff"); err != nil {
		return err
	}
	contextHelp, err := t.help("requirement-context-compose")
	if err != nil {
		return err
	}
	if err := t.requireNames("context help", contextHelp, "requirement-spec-tree", "requirement-context-compose", "requirement-context-slice"); err != nil {
		return err
	}
	template, err := guideTemplate("context help", contextHelp)
	if err != nil {
		return err
	}
	packet := map[string]any{"catalog": trajectoryCatalog(), "tree": trajectorySpecTree()}
	for _, pointer := range []string{"", "/catalog", "/tree"} {
		left, _ := pointerValue(template, pointer)
		right, _ := pointerValue(packet, pointer)
		if err := sameKeys("context packet"+pointer, left, right); err != nil {
			return err
		}
	}
	tree, err := canonicalBytes(packet["tree"])
	if err != nil {
		return err
	}
	if err := writeTrajectoryFiles(t.root, map[string]string{trajectorySpecTreePath: string(tree)}); err != nil {
		return err
	}
	encodedPacket, err := encodeInput(packet)
	if err != nil {
		return err
	}
	treeReport, _, err := t.object("spec tree", bytesInvocation(encodedPacket, "requirement-spec-tree", "--input", "-", "--input-pointer", "/tree"), 0)
	if err != nil {
		return err
	}
	if err := expect("spec tree", treeReport, map[string]any{"/state": "passed"}); err != nil {
		return err
	}
	if _, err := t.help("requirement-context-slice"); err != nil {
		return err
	}
	if state.context, err = t.capture("initial context"); err != nil {
		return err
	}
	if err := expect("initial context", state.context, map[string]any{
		"/projections/requirementSources/0/scenarios": trajectoryScenarios(state.spec),
		"/sources/0/kind": "requirement_source", "/sources/0/currentDigest": digest.SHA256BytesRef(file),
	}); err != nil {
		return err
	}
	slice, err := t.slice(state.context, trajectoryFarewellID)
	if err != nil {
		return err
	}
	return expect("farewell proof slice", slice, map[string]any{
		"/state": "selected", "/omissions": []any{},
		"/projections/proofBinding/bindings/0/scenarioId":                             trajectoryFarewellScenario,
		"/projections/requirementSources/0/requirements/0/requirementId":              trajectoryFarewellID,
		"/projections/requirementSources/0/selectedRequirementCount":                  1,
		"/projections/proofBinding/witnessCommands/0/commandId":                       trajectoryFarewellCommand,
		"/projections/requirementSources/0/requirements/0/proofBindingRefs/0":         trajectoryBindingPath,
		"/projections/requirementSources/0/requirements/0/lifecycle/state":            "active",
		"/projections/requirementSources/0/requirements/0/updatePolicy/reviewOwnerId": trajectoryOwner,
	})
}

// capture composes a fresh context from the materialized files.
func (t *trajectory) capture(label string) (map[string]any, error) {
	input, err := encodeInput(map[string]any{"catalog": trajectoryCatalog()})
	if err != nil {
		return nil, err
	}
	context, _, err := t.object(label, bytesInvocation(input, "requirement-context-compose", "--input", "-", "--input-pointer", "/catalog", "--repo-root", t.root), 0)
	if err != nil {
		return nil, err
	}
	return context, expect(label, context, map[string]any{"/contextKind": "proofkit.requirement-context", "/expectedDigestCoverage": "none"})
}

func (t *trajectory) slice(context map[string]any, requirementID string) (map[string]any, error) {
	input, err := encodeInput(map[string]any{
		"schemaVersion": json.Number("2"), "sliceId": "greeter.slice." + requirementID, "context": context,
		"query": map[string]any{"profile": "proof", "requirementIds": []any{requirementID}},
	})
	if err != nil {
		return nil, err
	}
	slice, _, err := t.object("proof slice "+requirementID, bytesInvocation(input, "requirement-context-slice", "--input", "-"), 0)
	return slice, err
}

// diff compares two retained contexts and returns the exact change facts.
func (t *trajectory) diff(label string, base, current map[string]any) ([]any, error) {
	input, err := encodeInput(map[string]any{"schemaVersion": json.Number("3"), "diffId": "greeter.diff", "baseContext": base, "currentContext": current, "query": nil})
	if err != nil {
		return nil, err
	}
	report, _, err := t.object(label, bytesInvocation(input, "requirement-semantic-diff", "--input", "-"), 0)
	if err != nil {
		return nil, err
	}
	changes := []any{}
	values, _ := report["changes"].([]any)
	for _, value := range values {
		change := value.(map[string]any)
		changes = append(changes, []any{change["entityId"], change["changeClass"], change["jsonPointer"]})
	}
	return changes, expect(label, report, map[string]any{"/diffKind": "proofkit.requirement-semantic-diff", "/changeCount": len(changes)})
}

func (t *trajectory) schedule(state *trajectoryState) error {
	bundleHelp, err := t.help("spec-proof-bundle-admission")
	if err != nil {
		return err
	}
	if err := t.requireNames("bundle help", bundleHelp, "requirement-bindings", "witness-scheduler-plan", "proof-receipt-admission", "spec-proof-bundle-admission"); err != nil {
		return err
	}
	help, err := t.help("witness-scheduler-plan")
	if err != nil {
		return err
	}
	if err := t.requireNames("scheduler help", help, "witness-plan", "witness-scheduler-plan"); err != nil {
		return err
	}
	template, err := guideTemplate("scheduler help", help)
	if err != nil {
		return err
	}
	scheduler, err := t.plannedScheduler(state.spec, "initial", []any{
		[]any{trajectoryFarewellCommand, []any{"go", "test", "./greeter", "-run", "TestFarewellNamesOnce"}},
		[]any{trajectoryPythonCommand, []any{"python3", "-m", "unittest", "tests.test_greeter"}},
	})
	if err != nil {
		return err
	}
	for _, pointer := range []string{"", "/vocabulary", "/policies/0"} {
		left, _ := pointerValue(template, pointer)
		right, _ := pointerValue(scheduler, pointer)
		if err := sameKeys("scheduler input"+pointer, left, right); err != nil {
			return err
		}
	}
	state.scheduler = scheduler
	return nil
}

// plannedScheduler projects witness commands from the current binding and
// admits the scheduler policy over that exact projection.
func (t *trajectory) plannedScheduler(spec trajectorySpec, label string, wantCommands []any) (map[string]any, error) {
	projection, err := encodeInput(map[string]any{
		"schemaVersion": json.Number("1"), "projection": "requirement-bindings",
		"requirementProofBinding": trajectoryBinding(spec), "vocabulary": trajectoryVocabulary(),
	})
	if err != nil {
		return nil, err
	}
	planned, _, err := t.object(label+" witness projection", bytesInvocation(projection, "witness-plan", "--input", "-"), 0)
	if err != nil {
		return nil, err
	}
	commands, _ := planned["commands"].([]any)
	observed := []any{}
	for _, command := range commands {
		record := command.(map[string]any)
		observed = append(observed, []any{record["id"], record["argv"]})
	}
	if !sameJSON(observed, wantCommands) {
		return nil, fmt.Errorf("%s witness projection = %s, want %s", label, canonicalText(observed), canonicalText(wantCommands))
	}
	scheduler := map[string]any{
		"schemaVersion": json.Number("1"), "schedulerPlanId": trajectorySchedulerID, "vocabulary": trajectoryVocabulary(),
		"commands": commands, "policies": trajectoryPolicies(spec),
		"nonClaims": []any{"Trajectory scheduler declarations do not prove execution or approve merge."},
	}
	input, err := encodeInput(scheduler)
	if err != nil {
		return nil, err
	}
	report, _, err := t.object(label+" scheduler", bytesInvocation(input, "witness-scheduler-plan", "--input", "-"), 0)
	if err != nil {
		return nil, err
	}
	return scheduler, expect(label+" scheduler", report, map[string]any{"/state": "passed", "/reportId": trajectorySchedulerID})
}

func (t *trajectory) execute(state *trajectoryState) error {
	receiptHelp, err := t.help("proof-receipt-admission")
	if err != nil {
		return err
	}
	if _, err := t.help("receipt-currentness-scope"); err != nil {
		return err
	}
	template, err := guideTemplate("receipt help", receiptHelp)
	if err != nil {
		return err
	}
	state.receipts = map[string]map[string]any{}
	state.fragments = map[string][]byte{}
	for _, item := range []struct{ requirementID, receiptID string }{
		{trajectoryEmptyNameID, "greeter.receipt.empty-name.1"},
		{trajectoryFarewellID, "greeter.receipt.farewell.1"},
	} {
		subjects, fragment, err := t.subjects(state.context, state.scheduler, item.requirementID)
		if err != nil {
			return err
		}
		receipt, err := t.receipt(item.receiptID, "passed", subjects)
		if err != nil {
			return err
		}
		state.receipts[item.requirementID], state.fragments[item.requirementID] = receipt, fragment
	}
	receipts, _ := pointerValue(template, "/receipts/0")
	if err := sameKeys("receipt", receipts, state.receipts[trajectoryEmptyNameID]); err != nil {
		return err
	}
	if err := t.requireCurrent(state, "initial evidence"); err != nil {
		return err
	}
	return t.rejectUnexecutedEvidence(state)
}

// requireCurrent is the consumer acceptance predicate for every edge: each
// retained receipt passed admission and linkage, was admitted with status
// passed, and every recorded subject equals the freshly recomputed subject.
func (t *trajectory) requireCurrent(state *trajectoryState, label string) error {
	failed, err := t.currentness(state, label)
	if err != nil {
		return err
	}
	if len(failed) != 0 {
		return fmt.Errorf("%s left stale obligations %v", label, failed)
	}
	report, admitted, err := t.link(state, label, []any{}, 0, state.receipts[trajectoryEmptyNameID], state.receipts[trajectoryFarewellID])
	if err != nil {
		return err
	}
	if err := expect(label+" bundle", report, map[string]any{"/state": "passed"}); err != nil {
		return err
	}
	// Bundle linkage checks status only for merge-required receipts, so the
	// passed conjunct is checked here on the admitted report, not the input.
	for _, requirementID := range []string{trajectoryEmptyNameID, trajectoryFarewellID} {
		receiptID := state.receipts[requirementID]["receiptId"]
		if status := admittedReceiptStatus(admitted, receiptID); status != "passed" {
			return fmt.Errorf("%s receipt %v for %s was admitted with status %v, not passed", label, receiptID, requirementID, status)
		}
	}
	return nil
}

// admittedReceiptStatus returns the status that one receipt admission report
// recorded for receiptID, or nil when the report does not admit it.
func admittedReceiptStatus(report map[string]any, receiptID any) any {
	diagnostics, _ := report["diagnostics"].([]any)
	for _, item := range diagnostics {
		record, _ := item.(map[string]any)
		if record["key"] != "receipts" {
			continue
		}
		rows, _ := record["value"].([]any)
		for _, receipt := range rows {
			if row, _ := receipt.(map[string]any); row["receiptId"] == receiptID {
				return row["status"]
			}
		}
	}
	return nil
}

// admitReceipts admits one receipt set and proves every recorded status.
func (t *trajectory) admitReceipts(label string, input map[string]any) (map[string]any, error) {
	encoded, err := encodeInput(input)
	if err != nil {
		return nil, err
	}
	report, _, err := t.object(label+" receipt admission", bytesInvocation(encoded, "proof-receipt-admission", "--input", "-"), 0)
	if err != nil {
		return nil, err
	}
	statuses := []any{}
	for _, receipt := range input["receipts"].([]any) {
		record := receipt.(map[string]any)
		statuses = append(statuses, []any{record["receiptId"], record["status"]})
	}
	admitted := []any{}
	diagnostics, _ := report["diagnostics"].([]any)
	for _, item := range diagnostics {
		if record := item.(map[string]any); record["key"] == "receipts" {
			for _, receipt := range record["value"].([]any) {
				row := receipt.(map[string]any)
				admitted = append(admitted, []any{row["receiptId"], row["status"]})
			}
		}
	}
	if !sameJSON(admitted, statuses) {
		return nil, fmt.Errorf("%s receipt statuses %s differ from recorded %s", label, canonicalText(admitted), canonicalText(statuses))
	}
	return report, expect(label+" receipt admission", report, map[string]any{"/state": "passed", "/reportId": input["receiptSetId"]})
}

// link admits receipts and runs bundle linkage against current bindings.
func (t *trajectory) link(state *trajectoryState, label string, mergeRequired []any, wantExit int, receipts ...map[string]any) (map[string]any, map[string]any, error) {
	input := trajectoryReceiptInput("greeter.receipts", receipts...)
	report, err := t.admitReceipts(label, input)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := encodeInput(trajectoryBundle(trajectoryBinding(state.spec), state.scheduler, input, report, 0, mergeRequired))
	if err != nil {
		return nil, nil, err
	}
	result, _, err := t.object(label+" bundle", bytesInvocation(bundle, "spec-proof-bundle-admission", "--input", "-"), wantExit)
	return result, report, err
}

// currentness recomputes every edge subject and returns failed obligations.
func (t *trajectory) currentness(state *trajectoryState, label string) ([]any, error) {
	obligations := []map[string]any{}
	for _, requirementID := range []string{trajectoryEmptyNameID, trajectoryFarewellID} {
		current, fragment, err := t.subjects(state.context, state.scheduler, requirementID)
		if err != nil {
			return nil, err
		}
		state.fragments[requirementID] = fragment
		obligation, err := trajectoryObligation(state.receipts[requirementID], current)
		if err != nil {
			return nil, err
		}
		obligations = append(obligations, obligation)
	}
	input, err := encodeInput(trajectoryCurrentnessInput(obligations...))
	if err != nil {
		return nil, err
	}
	result, err := t.call(label+" currentness", bytesInvocation(input, "receipt-currentness-scope", "--input", "-"))
	if err != nil {
		return nil, err
	}
	if len(result.Stderr) != 0 || (result.ExitCode != 0 && result.ExitCode != 1) {
		return nil, fmt.Errorf("%s currentness must emit a report", label)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(result.Stdout), maximumProcessOutputBytes)
	if err != nil {
		return nil, err
	}
	report, _ := value.(map[string]any)
	failed, _ := pointerValue(report, "/diagnostics/0/value")
	failedIDs, _ := failed.([]any)
	wantState, wantExit := "passed", 0
	if len(failedIDs) != 0 {
		wantState, wantExit = "failed", 1
	}
	if result.ExitCode != wantExit {
		return nil, fmt.Errorf("%s currentness exit %d disagrees with its failed obligations", label, result.ExitCode)
	}
	stale := []any{}
	findings, _ := pointerValue(report, "/diagnostics/1/value")
	for _, item := range findings.([]any) {
		record := item.(map[string]any)
		if messages, _ := record["currentnessFindings"].([]any); len(messages) != 0 {
			stale = append(stale, []any{record["requirementId"], messages, record["decisionCandidateStates"]})
		}
	}
	state.lastStale = stale
	return failedIDs, expect(label+" currentness", report, map[string]any{
		"/state": wantState, "/diagnostics/0/key": "failedObligationIds", "/diagnostics/1/key": "receiptCurrentnessScope",
		"/summary/obligationReceiptCount": 2, "/summary/staleReceiptCount": len(failedIDs), "/summary/unknownScopeCount": 0,
	})
}
