package adoptionworkflow

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/contractenv"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var scenarios = map[string]struct{}{
	"existing_gradual_adoption": {},
	"legacy_proof_migration":    {},
	"new_repository":            {},
	"release_channel":           {},
}

var inputKinds = map[string]struct{}{
	"adoption_checklist":         {},
	"branch_authority":           {},
	"external_consumer":          {},
	"gradual_adoption_bootstrap": {},
	"gradual_adoption_guidance":  {},
	"migration_plan":             {},
	"receipt_producer_admission": {},
	"registry_consumer":          {},
	"release_authority":          {},
	"repo_profile_scaffold":      {},
	"requirement_bindings":       {},
	"selective_gate_evidence":    {},
	"selective_gate_plan":        {},
	"witness_plan":               {},
}

var phaseOrder = []string{"profile", "bootstrap", "bind", "migrate", "plan-gates", "collect-evidence", "release"}

var workflowNonClaims = []string{
	"Adoption workflow plans do not authenticate receipts or decide proof freshness.",
	"Adoption workflow plans do not approve merge, enforcement, release, or rollout.",
	"Adoption workflow plans do not execute native witnesses or planned commands.",
	"Adoption workflow plans do not scan repository state.",
	"Adoption workflow plans do not write files or materialize payloads.",
}

type inputRef struct {
	InputKind string
	Path      string
	RefID     string
}

type blocker struct {
	BlockerID          string
	NonClaim           string
	Reason             string
	RequiredInputKinds []string
	Scenario           string
}

type result struct {
	ExitCode int
	Plan     map[string]any
	Record   report.Record
}

type Result struct {
	ExitCode int
	Plan     map[string]any
	Record   report.Record
}

func Build(raw any) (map[string]any, int, error) {
	result, err := BuildResult(raw)
	if err != nil {
		return nil, 1, err
	}
	return result.Plan, result.ExitCode, nil
}

func BuildResult(raw any) (Result, error) {
	result, err := build(raw)
	if err != nil {
		return Result{}, err
	}
	return Result(result), nil
}

func BuildEnvelope(raw any) (map[string]any, int, error) {
	result, err := build(raw)
	if err != nil {
		return agentenvelope.InvalidInput(err.Error()), 1, nil
	}
	return envelope(result), result.ExitCode, nil
}

func BuildFromContractEnvelope(raw any) (map[string]any, int, error) {
	workflowInput, err := inputFromContractEnvelope(raw)
	if err != nil {
		return nil, 1, err
	}
	return Build(workflowInput)
}

func BuildEnvelopeFromContractEnvelope(raw any) (map[string]any, int, error) {
	workflowInput, err := inputFromContractEnvelope(raw)
	if err != nil {
		return agentenvelope.InvalidInput(err.Error()), 1, nil
	}
	return BuildEnvelope(workflowInput)
}

func inputFromContractEnvelope(raw any) (map[string]any, error) {
	envelope, err := contractenv.Object(raw, "proofkit.adoption-workflow.v1", "adoption workflow", "workflow")
	if err != nil {
		return nil, err
	}
	return contractenv.ObjectField(envelope, "workflow", "adoption workflow contract envelope")
}

func build(raw any) (result, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return result{}, fmt.Errorf("adoption workflow plan input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"inputRefs", "nonClaims", "presetId", "scenario", "schemaVersion", "workflowId"}, "adoption workflow plan input"); err != nil {
		return result{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return result{}, fmt.Errorf("adoption workflow plan schemaVersion must be 1")
	}
	workflowID, err := admit.RuleID(record["workflowId"], "adoption workflow workflowId")
	if err != nil {
		return result{}, err
	}
	scenario, err := enum(record["scenario"], scenarios, "adoption workflow scenario")
	if err != nil {
		return result{}, err
	}
	presetID, err := presetID(record["presetId"])
	if err != nil {
		return result{}, err
	}
	inputRefs, err := sortedInputRefs(record["inputRefs"])
	if err != nil {
		return result{}, err
	}
	callerNonClaims, err := admit.SortedTextArray(record["nonClaims"], "adoption workflow nonClaims", false)
	if err != nil {
		return result{}, err
	}
	allNonClaims, err := admit.SortedText(append(append([]string{}, workflowNonClaims...), callerNonClaims...), "adoption workflow merged nonClaims", false)
	if err != nil {
		return result{}, err
	}
	blockers := workflowBlockers(scenario, presetID, inputRefs)
	phases := workflowPhases(scenario, presetID, inputRefs)
	planState := "blocked"
	exitCode := 1
	if len(blockers) == 0 {
		planState = "ready_for_caller_review"
		exitCode = 0
	}
	plan := map[string]any{
		"blockers":      blockersJSON(blockers),
		"inputRefs":     inputRefsJSON(inputRefs),
		"nonClaims":     admit.StringSliceToAny(allNonClaims),
		"phases":        phases,
		"planKind":      "proofkit.adoption-workflow-plan",
		"planState":     planState,
		"scenario":      scenario,
		"schemaVersion": 1,
		"workflowId":    workflowID,
	}
	rec := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.adoption-workflow-plan",
		ReportID:      workflowID,
		State:         map[bool]string{true: "passed", false: "failed"}[planState == "ready_for_caller_review"],
		Summary: map[string]any{
			"blockerCount":  len(blockers),
			"commandCount":  commandCount(phases),
			"inputRefCount": len(inputRefs),
			"scenario":      scenario,
		},
		Diagnostics: []report.Diagnostic{{Key: "plan", Value: plan}},
		RuleResults: workflowRuleResults(blockers),
		NonClaims:   admit.StringSliceToAny(allNonClaims),
	}
	return result{ExitCode: exitCode, Plan: plan, Record: rec}, nil
}

func sortedInputRefs(raw any) ([]inputRef, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("adoption workflow inputRefs must be an array")
	}
	refs := make([]inputRef, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("adoption workflow input ref must be an object")
		}
		if err := admit.KnownKeys(record, []string{"inputKind", "path", "refId"}, "adoption workflow input ref"); err != nil {
			return nil, err
		}
		refID, err := admit.RuleID(record["refId"], "adoption workflow input refId")
		if err != nil {
			return nil, err
		}
		inputKind, err := enum(record["inputKind"], inputKinds, "adoption workflow inputKind")
		if err != nil {
			return nil, err
		}
		pathValueRaw, ok := record["path"].(string)
		if !ok {
			return nil, fmt.Errorf("adoption workflow input path must be a repository-relative POSIX path")
		}
		pathValue, err := admit.SafeRepoRelativePath(pathValueRaw, "adoption workflow input path")
		if err != nil {
			return nil, err
		}
		refs = append(refs, inputRef{InputKind: inputKind, Path: pathValue, RefID: refID})
	}
	sort.Slice(refs, func(left int, right int) bool {
		return refs[left].RefID < refs[right].RefID
	})
	refIDs := make([]string, 0, len(refs))
	kinds := make([]string, 0, len(refs))
	for _, ref := range refs {
		refIDs = append(refIDs, ref.RefID)
		kinds = append(kinds, ref.InputKind)
	}
	if _, err := admit.PreserveSortedText(refIDs, "adoption workflow input ref ids", true); err != nil {
		return nil, err
	}
	sort.Strings(kinds)
	if _, err := admit.PreserveSortedText(kinds, "adoption workflow input kinds", true); err != nil {
		return nil, err
	}
	return refs, nil
}

func presetID(raw any) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, ok := raw.(string)
	if !ok || !stackpreset.IsPresetID(value) {
		return nil, fmt.Errorf("adoption workflow presetId must be a known stack preset id")
	}
	return &value, nil
}

func workflowPhases(scenario string, presetID *string, refs []inputRef) []any {
	byKind := refsByKind(refs)
	phases := make([]any, 0, len(phaseOrder))
	for _, phase := range phaseOrder {
		phases = append(phases, map[string]any{
			"commands": workflowCommandsForPhase(scenario, presetID, byKind, phase),
			"phase":    phase,
		})
	}
	return phases
}

func workflowCommandsForPhase(scenario string, presetID *string, refs map[string]inputRef, phase string) []any {
	if phase == "profile" {
		commands := []map[string]any{}
		if presetID != nil {
			commands = append(commands, command("stack-preset", []string{"stack-preset", "--preset", *presetID}, []string{}))
		}
		if scenario == "new_repository" || scenario == "existing_gradual_adoption" {
			commands = appendInputCommand(commands, refs, "repo_profile_scaffold", "scaffold-profile-plan")
		}
		commands = appendInputCommand(commands, refs, "branch_authority", "branch-authority")
		return mapsToAny(commands)
	}
	if phase == "bootstrap" {
		if scenario != "new_repository" && scenario != "existing_gradual_adoption" {
			return []any{}
		}
		commands := []map[string]any{}
		commands = appendInputCommand(commands, refs, "gradual_adoption_bootstrap", "gradual-adoption-bootstrap")
		commands = appendInputCommand(commands, refs, "gradual_adoption_guidance", "gradual-adoption-guidance")
		return mapsToAny(commands)
	}
	if phase == "bind" {
		if scenario == "release_channel" {
			return []any{}
		}
		commands := []map[string]any{}
		commands = appendInputCommand(commands, refs, "requirement_bindings", "requirement-bindings")
		commands = appendInputCommand(commands, refs, "requirement_bindings", "proof-slice")
		commands = appendInputCommand(commands, refs, "witness_plan", "witness-scheduler-plan")
		return mapsToAny(commands)
	}
	if phase == "migrate" {
		if scenario != "legacy_proof_migration" {
			return []any{}
		}
		return mapsToAny(appendInputCommand([]map[string]any{}, refs, "migration_plan", "migration-plan"))
	}
	if phase == "plan-gates" {
		if scenario == "new_repository" {
			return []any{}
		}
		return mapsToAny(appendInputCommand([]map[string]any{}, refs, "selective_gate_plan", "selective-gate-plan"))
	}
	if phase == "collect-evidence" {
		commands := []map[string]any{}
		if scenario != "new_repository" {
			commands = appendInputCommand(commands, refs, "receipt_producer_admission", "receipt-producer-admission")
			commands = appendInputCommand(commands, refs, "selective_gate_evidence", "selective-gate-evidence")
		}
		commands = appendInputCommand(commands, refs, "adoption_checklist", "adoption-checklist")
		return mapsToAny(commands)
	}
	if scenario != "release_channel" {
		return []any{}
	}
	commands := []map[string]any{}
	commands = appendInputCommand(commands, refs, "release_authority", "release-authority")
	commands = appendInputCommand(commands, refs, "external_consumer", "external-consumer")
	commands = appendInputCommand(commands, refs, "registry_consumer", "registry-consumer")
	return mapsToAny(commands)
}

func workflowBlockers(scenario string, presetID *string, refs []inputRef) []blocker {
	byKind := refsByKind(refs)
	blockers := []blocker{}
	if (scenario == "new_repository" || scenario == "existing_gradual_adoption") && presetID == nil {
		blockers = append(blockers, newBlocker(scenario, "scenario requires caller-selected stack preset", []string{}))
	}
	for _, kind := range requiredKinds(scenario) {
		if _, ok := byKind[kind]; !ok {
			blockers = append(blockers, newBlocker(scenario, fmt.Sprintf("scenario requires %s input ref", kind), []string{kind}))
		}
	}
	if scenario == "release_channel" {
		_, hasExternal := byKind["external_consumer"]
		_, hasRegistry := byKind["registry_consumer"]
		if !hasExternal && !hasRegistry {
			blockers = append(blockers, newBlocker(scenario, "release channel requires external or registry consumer evidence input ref", []string{"external_consumer", "registry_consumer"}))
		}
	}
	sort.Slice(blockers, func(left int, right int) bool {
		return blockers[left].BlockerID < blockers[right].BlockerID
	})
	return blockers
}

func requiredKinds(scenario string) []string {
	switch scenario {
	case "new_repository":
		return []string{"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold", "requirement_bindings", "witness_plan"}
	case "existing_gradual_adoption":
		return []string{"gradual_adoption_bootstrap", "gradual_adoption_guidance", "repo_profile_scaffold", "requirement_bindings", "selective_gate_evidence", "selective_gate_plan", "witness_plan"}
	case "legacy_proof_migration":
		return []string{"migration_plan", "requirement_bindings", "selective_gate_evidence", "selective_gate_plan"}
	default:
		return []string{"release_authority"}
	}
}

func command(commandID string, argv []string, inputRefIDs []string) map[string]any {
	return map[string]any{
		"argv":        admit.StringSliceToAny(append([]string{"agentic-proofkit"}, argv...)),
		"commandId":   "proofkit.adoption-workflow.command." + commandID,
		"inputRefIds": admit.StringSliceToAny(inputRefIDs),
		"nonClaim":    "Workflow command refs are caller-owned routes only and do not execute commands or prove pass evidence.",
		"owner":       "consumer_repository",
	}
}

func appendInputCommand(commands []map[string]any, refs map[string]inputRef, inputKind string, cliCommand string) []map[string]any {
	ref, ok := refs[inputKind]
	if !ok {
		return commands
	}
	return append(commands, command(cliCommand, []string{cliCommand, "--input", ref.Path}, []string{ref.RefID}))
}

func newBlocker(scenario string, reason string, requiredKinds []string) blocker {
	sort.Strings(requiredKinds)
	return blocker{
		BlockerID:          "proofkit.adoption-workflow.blocker." + scenario + "." + blockerSlug(reason),
		NonClaim:           "Workflow blockers are caller-review prompts and do not prove repository readiness.",
		Reason:             reason,
		RequiredInputKinds: requiredKinds,
		Scenario:           scenario,
	}
}

var slugPattern = regexp.MustCompile(`[^a-z0-9]+`)

func blockerSlug(reason string) string {
	return strings.Trim(slugPattern.ReplaceAllString(reason, "-"), "-")
}

func workflowRuleResults(blockers []blocker) []report.RuleResult {
	if len(blockers) == 0 {
		return []report.RuleResult{{
			RuleID:      "proofkit.adoption-workflow.accepted",
			Status:      "passed",
			Message:     "adoption workflow plan is ready for caller review",
			Diagnostics: []report.Diagnostic{},
		}}
	}
	results := make([]report.RuleResult, 0, len(blockers))
	for _, item := range blockers {
		results = append(results, report.RuleResult{
			RuleID:  item.BlockerID,
			Status:  "failed",
			Message: item.Reason,
			Diagnostics: []report.Diagnostic{
				{Key: "scenario", Value: item.Scenario},
				{Key: "requiredInputKinds", Value: admit.StringSliceToAny(item.RequiredInputKinds)},
			},
		})
	}
	return results
}

func envelope(result result) map[string]any {
	plan := result.Plan
	phases := plan["phases"].([]any)
	commands := []map[string]any{}
	actionPlan := []map[string]any{}
	for _, rawPhase := range phases {
		phase := rawPhase.(map[string]any)
		phaseName := phase["phase"].(string)
		phaseCommands := phase["commands"].([]any)
		if len(phaseCommands) == 0 {
			continue
		}
		commandIDs := []string{}
		evidenceRefs := []string{}
		for _, rawCommand := range phaseCommands {
			commandRef := rawCommand.(map[string]any)
			commandID := commandRef["commandId"].(string)
			commandIDs = append(commandIDs, commandID)
			argv := anyToStrings(commandRef["argv"].([]any))
			commands = append(commands, map[string]any{
				"argv":      admit.StringSliceToAny(argv),
				"command":   strings.Join(argv, " "),
				"commandId": commandID,
				"nonClaim":  "Agent command refs preserve argv boundaries but do not execute commands or prove pass evidence.",
				"owner":     "consumer_repository",
				"purpose":   fmt.Sprintf("Run the %s workflow route only after caller review.", phaseName),
			})
			evidenceRefs = append(evidenceRefs, anyToStrings(commandRef["inputRefIds"].([]any))...)
		}
		sort.Strings(commandIDs)
		evidenceRefs = uniqueSorted(evidenceRefs)
		actionPlan = append(actionPlan, map[string]any{
			"commandIds":   admit.StringSliceToAny(commandIDs),
			"evidenceRefs": admit.StringSliceToAny(evidenceRefs),
			"instruction":  fmt.Sprintf("Review and run the %s workflow command refs when caller-owned preconditions are satisfied.", phaseName),
			"nonClaims": []any{
				"Workflow action items do not approve edits, merge, enforcement, release, or rollout.",
				"Workflow action items do not execute commands.",
			},
			"owner":     "consumer_repository",
			"phase":     actionPhase(phaseName),
			"rationale": "The workflow plan routes to existing Proofkit primitives without executing them.",
			"stepId":    "proofkit.adoption-workflow.action." + phaseName,
		})
	}
	inputRefs := plan["inputRefs"].([]any)
	contextRefs := make([]map[string]any, 0, len(inputRefs))
	for _, rawRef := range inputRefs {
		ref := rawRef.(map[string]any)
		inputKind := ref["inputKind"].(string)
		refID := ref["refId"].(string)
		contextRefs = append(contextRefs, map[string]any{
			"kind":     "path",
			"nonClaim": "Workflow context refs identify caller-owned inputs and do not prove file existence or freshness.",
			"owner":    "consumer_repository",
			"purpose":  fmt.Sprintf("Caller-provided %s input for the selected adoption workflow scenario.", inputKind),
			"ref":      ref["path"].(string),
			"refId":    "proofkit.adoption-workflow.context." + refID,
			"role":     contextRole(inputKind),
		})
	}
	blockers := blockersFromPlan(plan["blockers"].([]any))
	blockedPreconditions := make([]map[string]any, 0, len(blockers))
	for _, item := range blockers {
		blockedPreconditions = append(blockedPreconditions, map[string]any{
			"description":    item.Reason,
			"evidenceRefs":   admit.StringSliceToAny(item.RequiredInputKinds),
			"nonClaim":       item.NonClaim,
			"owner":          "consumer_repository",
			"preconditionId": item.BlockerID,
		})
	}
	if len(actionPlan) == 0 && len(blockedPreconditions) > 0 {
		actionPlan = blockedWorkflowActions(blockedPreconditions)
	}
	commandIDs := make([]string, 0, len(commands))
	for _, command := range commands {
		commandIDs = append(commandIDs, command["commandId"].(string))
	}
	sort.Strings(commandIDs)
	refIDs := make([]string, 0, len(inputRefs))
	for _, rawRef := range inputRefs {
		refIDs = append(refIDs, rawRef.(map[string]any)["refId"].(string))
	}
	sort.Strings(refIDs)
	bounds := map[string]any{
		"escalation":      "If the workflow is blocked or incomplete, ask the consumer to provide the missing caller-owned input refs.",
		"fanout":          map[bool]string{true: "wide", false: "bounded"}[plan["scenario"] == "existing_gradual_adoption"],
		"maxActionItems":  len(actionPlan),
		"maxCommandRefs":  len(commands),
		"maxContextRefs":  len(contextRefs),
		"maxOmittedItems": 0,
		"maxReceiptRefs":  0,
		"maxTokenBudget":  nil,
		"nonClaim":        "Workflow envelopes are bounded routing packets and do not replace caller-owned review.",
		"omittedCount":    0,
	}
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID:   "proofkit-adoption-workflow.agent-envelope",
		SourceReport: sourceReportIdentity(result.Record),
		Bounds:       bounds,
		ContextRefs:  contextRefs,
		RouteQuestions: []map[string]any{
			{
				"evidenceRefs": admit.StringSliceToAny(refIDs),
				"nonClaim":     "Route questions do not prove repository facts.",
				"question":     "what changed",
				"questionId":   "proofkit.adoption-workflow.question.what-changed",
			},
			{
				"evidenceRefs": admit.StringSliceToAny(commandIDs),
				"nonClaim":     "Planned command refs are not command pass evidence.",
				"question":     "what proves it",
				"questionId":   "proofkit.adoption-workflow.question.what-proves-it",
			},
			{
				"evidenceRefs": []any{"consumer_repository"},
				"nonClaim":     "The consuming repository owns scenario choice, input content, execution, receipts, and rollout.",
				"question":     "who owns it",
				"questionId":   "proofkit.adoption-workflow.question.who-owns-it",
			},
		},
		ClarificationQuestion: clarificationQuestions(blockers),
		ActionPlan:            actionPlan,
		Commands:              commands,
		BlockedPreconditions:  blockedPreconditions,
		Omitted:               []map[string]any{},
		ReceiptRefs:           []map[string]any{},
		NonClaims: append(anyToStrings(plan["nonClaims"].([]any)),
			"Adoption workflow agent envelopes do not approve scenario choice, merge, enforcement, release, or rollout.",
			"Adoption workflow agent envelopes do not execute planned commands.",
			"Adoption workflow agent envelopes do not include primitive input payload bodies.",
		),
	})
}

func sourceReportIdentity(record report.Record) map[string]any {
	return map[string]any{
		"artifactRef": nil,
		"nonClaim":    "Embedded source report identity does not prove source report freshness.",
		"reportId":    record.ReportID,
		"reportKind":  record.ReportKind,
		"stableHash":  nil,
		"state":       record.State,
	}
}

func actionPhase(phase string) string {
	if phase == "bind" {
		return "bind"
	}
	if phase == "plan-gates" || phase == "collect-evidence" {
		return "verify"
	}
	return "route"
}

func contextRole(inputKind string) string {
	switch inputKind {
	case "requirement_bindings":
		return "proof_binding"
	case "gradual_adoption_bootstrap":
		return "bootstrap_entrypoint"
	case "gradual_adoption_guidance", "repo_profile_scaffold":
		return "router"
	case "adoption_checklist":
		return "evidence"
	case "receipt_producer_admission":
		return "receipt_source"
	case "selective_gate_plan", "witness_plan":
		return "command_registry"
	case "branch_authority", "migration_plan", "release_authority":
		return "owner_surface"
	default:
		return "evidence"
	}
}

func blockedWorkflowActions(blocked []map[string]any) []map[string]any {
	evidence := []string{}
	for _, item := range blocked {
		evidence = append(evidence, anyToStrings(item["evidenceRefs"].([]any))...)
	}
	return []map[string]any{{
		"commandIds":   []any{},
		"evidenceRefs": admit.StringSliceToAny(uniqueSorted(evidence)),
		"instruction":  "Resolve the blocked caller-owned workflow preconditions before running any Proofkit command route.",
		"nonClaims": []any{
			"Blocked workflow action items do not execute commands.",
			"Blocked workflow action items do not infer or repair missing caller-owned inputs.",
		},
		"owner":     "consumer_repository",
		"phase":     "route",
		"rationale": "The workflow plan has no executable command refs until the caller supplies the missing input refs.",
		"stepId":    "proofkit.adoption-workflow.action.resolve-preconditions",
	}}
}

func clarificationQuestions(blockers []blocker) []map[string]any {
	questions := make([]map[string]any, 0, len(blockers))
	for _, item := range blockers {
		questions = append(questions, map[string]any{
			"askWhen":            item.Reason,
			"blocking":           true,
			"evidenceRefs":       admit.StringSliceToAny(item.RequiredInputKinds),
			"expectedAnswerKind": "missing_context_ref",
			"nonClaim":           "Clarification questions do not infer repository state.",
			"owner":              "consumer_repository",
			"question":           fmt.Sprintf("Provide caller-owned input refs for: %s.", missingInputText(item)),
			"questionId":         "proofkit.adoption-workflow.clarification." + item.BlockerID,
		})
	}
	return questions
}

func missingInputText(item blocker) string {
	if len(item.RequiredInputKinds) == 0 {
		return item.Reason
	}
	return strings.Join(item.RequiredInputKinds, ", ")
}

func commandCount(phases []any) int {
	count := 0
	for _, rawPhase := range phases {
		count += len(rawPhase.(map[string]any)["commands"].([]any))
	}
	return count
}

func inputRefsJSON(refs []inputRef) []any {
	result := make([]any, 0, len(refs))
	for _, ref := range refs {
		result = append(result, map[string]any{
			"inputKind": ref.InputKind,
			"path":      ref.Path,
			"refId":     ref.RefID,
		})
	}
	return result
}

func blockersJSON(blockers []blocker) []any {
	result := make([]any, 0, len(blockers))
	for _, item := range blockers {
		result = append(result, map[string]any{
			"blockerId":          item.BlockerID,
			"nonClaim":           item.NonClaim,
			"reason":             item.Reason,
			"requiredInputKinds": admit.StringSliceToAny(item.RequiredInputKinds),
			"scenario":           item.Scenario,
		})
	}
	return result
}

func blockersFromPlan(values []any) []blocker {
	result := make([]blocker, 0, len(values))
	for _, value := range values {
		record := value.(map[string]any)
		result = append(result, blocker{
			BlockerID:          record["blockerId"].(string),
			NonClaim:           record["nonClaim"].(string),
			Reason:             record["reason"].(string),
			RequiredInputKinds: anyToStrings(record["requiredInputKinds"].([]any)),
			Scenario:           record["scenario"].(string),
		})
	}
	return result
}

func refsByKind(refs []inputRef) map[string]inputRef {
	result := map[string]inputRef{}
	for _, ref := range refs {
		result[ref.InputKind] = ref
	}
	return result
}

func enum(raw any, admitted map[string]struct{}, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, sortedKeys(admitted))
	}
	if _, ok := admitted[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, sortedKeys(admitted))
	}
	return value, nil
}

func sortedKeys(values map[string]struct{}) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func anyToStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.(string))
	}
	return result
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
