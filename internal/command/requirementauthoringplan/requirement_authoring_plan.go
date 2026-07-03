package requirementauthoringplan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourcetransition"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const planKind = "proofkit.requirement-authoring-plan"

var (
	modeSet            = map[string]struct{}{"pull_request_design": {}, "retrospective_baseline": {}}
	refKindSet         = map[string]struct{}{"clarification_answer": {}, "code_summary": {}, "design_doc": {}, "implementation_plan": {}, "pr_facts": {}, "test_summary": {}}
	operationSet       = map[string]struct{}{"add": {}, "deprecate": {}, "modify": {}, "supersede": {}}
	obligationKindSet  = map[string]struct{}{"native_witness": {}, "overview_claim": {}, "proof_binding": {}, "receipt": {}, "test_inventory": {}}
	sha256DigestRegexp = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

var standardNonClaims = []string{
	"Requirement authoring plans do not read design documents, implementation plans, pull requests, code, tests, or repositories.",
	"Requirement authoring plans do not infer requirement meaning or extraction completeness.",
	"Requirement authoring plans do not approve requirement promotion, proof adequacy, witness execution, proof freshness, merge, release, rollout, or production readiness.",
	"Candidate requirement previews remain advisory until the consuming repository owner materializes and admits them.",
}

type input struct {
	AuthoringPlanID         string
	AuthoringRefs           []authoringRef
	CandidateUpdates        []candidateUpdate
	CurrentRequirementRaw   map[string]any
	CurrentRequirementState requirementsourceadmission.Source
	Mode                    string
	NonClaims               []string
}

type authoringRef struct {
	Digest    *string
	Kind      string
	NonClaims []string
	Path      string
	RefID     string
	Summary   string
}

type candidateUpdate struct {
	CandidateID          string
	CandidateRequirement map[string]any
	Operation            string
	OwnerQuestions       []string
	ProofObligations     []proofObligation
	Rationale            string
	RequirementID        string
	SourceRefIDs         []string
}

type proofObligation struct {
	Blocking     bool
	Description  string
	EvidenceRefs []string
	Kind         string
	ObligationID string
	OwnerID      string
}

func Build(raw any) (map[string]any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, 1, err
	}
	output, exitCode := buildOutput(input)
	return output, exitCode, nil
}

func buildOutput(input input) (map[string]any, int) {
	nextSource, compositionFailures := composeNextRequirementSource(input)
	sourceResult, sourceErr := requirementsourceadmission.Evaluate(nextSource)
	transitionInput := map[string]any{
		"schemaVersion": json.Number("1"),
		"transitionId":  input.AuthoringPlanID + ".transition",
		"nonClaims": []any{
			"Requirement authoring plan transition proof does not promote candidates to stable repository truth.",
		},
		"previous": input.CurrentRequirementRaw,
		"next":     nextSource,
	}
	transitionRecord, transitionExitCode, transitionErr := requirementsourcetransition.Build(transitionInput)

	failures := append([]string{}, compositionFailures...)
	if sourceErr != nil {
		failures = append(failures, "candidate next source admission error: "+sourceErr.Error())
	} else if sourceResult.ExitCode != 0 {
		failures = append(failures, "candidate next source must pass requirement-source-admission")
	}
	if transitionErr != nil {
		failures = append(failures, "candidate transition admission error: "+transitionErr.Error())
	} else if transitionExitCode != 0 {
		failures = append(failures, "candidate transition must pass requirement-source-transition")
	}
	sort.Strings(failures)

	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	var nextCandidate any
	if state == "passed" {
		nextCandidate = map[string]any{
			"authority":                "candidate_only",
			"candidateOnly":            true,
			"nonClaims":                []any{"This preview is not stable requirement source authority until the consuming repository owner materializes and admits it."},
			"ownerReviewRequired":      true,
			"requirementSourcePreview": nextSource,
			"sourceAdmissionState":     "passed",
			"transitionAdmissionState": "passed",
		}
	}
	output := map[string]any{
		"authoringPlanId":                  input.AuthoringPlanID,
		"candidateChangeSet":               candidateUpdateValues(input.CandidateUpdates, state == "passed"),
		"mode":                             input.Mode,
		"nonAuthoritativeAdmissionPreview": nextCandidate,
		"nonClaims":                        admit.StringSliceToAny(nonClaims(input.NonClaims)),
		"ownerReviewPlan":                  ownerReviewPlan(input),
		"planKind":                         planKind,
		"promotionPreconditions":           promotionPreconditions(input),
		"ruleResults":                      ruleResults(failures, sourceResult, sourceErr, transitionRecord.State, transitionErr),
		"schemaVersion":                    1,
		"state":                            state,
		"summary": map[string]any{
			"authoringRefCount":            len(input.AuthoringRefs),
			"candidateUpdateCount":         len(input.CandidateUpdates),
			"executedWitnessCountNonClaim": 0,
			"failureCount":                 len(failures),
			"mode":                         input.Mode,
			"sourceAdmissionState":         stateFromSourceResult(sourceResult, sourceErr),
			"targetRequirementSourceId":    input.CurrentRequirementState.SourceID,
			"targetRequirementsPath":       input.CurrentRequirementState.RequirementsPath,
			"targetSpecPackagePath":        input.CurrentRequirementState.SpecPackagePath,
			"transitionAdmissionState":     stateFromTransition(transitionRecord.State, transitionErr),
			"writtenFileCountNonClaim":     0,
		},
	}
	if state == "passed" {
		return output, 0
	}
	return output, 1
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("requirement authoring plan input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authoringPlanId", "authoringRefs", "candidateUpdates", "currentRequirementSource", "mode", "nonClaims", "schemaVersion"}, "requirement authoring plan input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("requirement authoring plan schemaVersion must be 1")
	}
	authoringPlanID, err := admit.RuleID(record["authoringPlanId"], "requirement authoring plan authoringPlanId")
	if err != nil {
		return input{}, err
	}
	mode, err := admit.Enum(record["mode"], modeSet, "requirement authoring plan mode")
	if err != nil {
		return input{}, err
	}
	current, ok := record["currentRequirementSource"].(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("requirement authoring plan currentRequirementSource must be an object")
	}
	currentResult, err := requirementsourceadmission.Evaluate(current)
	if err != nil {
		return input{}, err
	}
	if currentResult.ExitCode != 0 {
		return input{}, fmt.Errorf("requirement authoring plan currentRequirementSource must pass requirement-source-admission")
	}
	refs, err := admitAuthoringRefs(record["authoringRefs"])
	if err != nil {
		return input{}, err
	}
	updates, err := admitCandidateUpdates(record["candidateUpdates"], refs)
	if err != nil {
		return input{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "requirement authoring plan nonClaims", true)
	if err != nil {
		return input{}, err
	}
	return input{
		AuthoringPlanID:         authoringPlanID,
		AuthoringRefs:           refs,
		CandidateUpdates:        updates,
		CurrentRequirementRaw:   cloneObject(current),
		CurrentRequirementState: currentResult.Source,
		Mode:                    mode,
		NonClaims:               nonClaims,
	}, nil
}

func admitAuthoringRefs(raw any) ([]authoringRef, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement authoring plan authoringRefs must be a non-empty array")
	}
	result := make([]authoringRef, 0, len(values))
	ids := []string{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement authoring plan authoringRef must be an object")
		}
		if err := admit.KnownKeys(record, []string{"digest", "kind", "nonClaims", "path", "refId", "summary"}, "requirement authoring plan authoringRef"); err != nil {
			return nil, err
		}
		refID, err := admit.RuleID(record["refId"], "requirement authoring plan authoringRef.refId")
		if err != nil {
			return nil, err
		}
		kind, err := admit.Enum(record["kind"], refKindSet, "requirement authoring plan authoringRef.kind")
		if err != nil {
			return nil, err
		}
		path, err := repoPath(record["path"], "requirement authoring plan authoringRef.path")
		if err != nil {
			return nil, err
		}
		summary, err := admit.NonEmptyText(record["summary"], "requirement authoring plan authoringRef.summary")
		if err != nil {
			return nil, err
		}
		digest, err := optionalDigest(record["digest"], "requirement authoring plan authoringRef.digest")
		if err != nil {
			return nil, err
		}
		nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "requirement authoring plan authoringRef.nonClaims", false)
		if err != nil {
			return nil, err
		}
		result = append(result, authoringRef{Digest: digest, Kind: kind, NonClaims: nonClaims, Path: path, RefID: refID, Summary: summary})
		ids = append(ids, refID)
	}
	if _, err := admit.PreserveSortedText(ids, "requirement authoring plan authoringRef ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitCandidateUpdates(raw any, refs []authoringRef) ([]candidateUpdate, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement authoring plan candidateUpdates must be a non-empty array")
	}
	refIDs := map[string]struct{}{}
	for _, ref := range refs {
		refIDs[ref.RefID] = struct{}{}
	}
	result := make([]candidateUpdate, 0, len(values))
	candidateIDs := []string{}
	requirementIDs := []string{}
	for _, value := range values {
		update, err := admitCandidateUpdate(value, refIDs)
		if err != nil {
			return nil, err
		}
		result = append(result, update)
		candidateIDs = append(candidateIDs, update.CandidateID)
		requirementIDs = append(requirementIDs, update.RequirementID)
	}
	if _, err := admit.PreserveSortedText(candidateIDs, "requirement authoring plan candidate ids", false); err != nil {
		return nil, err
	}
	if _, err := admit.PreserveSortedText(requirementIDs, "requirement authoring plan candidate requirement ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitCandidateUpdate(raw any, admittedRefIDs map[string]struct{}) (candidateUpdate, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return candidateUpdate{}, fmt.Errorf("requirement authoring plan candidateUpdate must be an object")
	}
	if err := admit.KnownKeys(record, []string{"candidateId", "candidateRequirement", "declaredProofObligations", "operation", "ownerQuestions", "rationale", "requirementId", "sourceRefIds"}, "requirement authoring plan candidateUpdate"); err != nil {
		return candidateUpdate{}, err
	}
	candidateID, err := admit.RuleID(record["candidateId"], "requirement authoring plan candidateId")
	if err != nil {
		return candidateUpdate{}, err
	}
	targetRequirementID, err := requirementID(record["requirementId"], "requirement authoring plan requirementId")
	if err != nil {
		return candidateUpdate{}, err
	}
	operation, err := admit.Enum(record["operation"], operationSet, "requirement authoring plan operation")
	if err != nil {
		return candidateUpdate{}, err
	}
	sourceRefIDs, err := admit.PreserveSortedTextArray(record["sourceRefIds"], "requirement authoring plan sourceRefIds", false)
	if err != nil {
		return candidateUpdate{}, err
	}
	for _, refID := range sourceRefIDs {
		if _, ok := admittedRefIDs[refID]; !ok {
			return candidateUpdate{}, fmt.Errorf("requirement authoring plan sourceRefIds references unknown authoring ref %s", refID)
		}
	}
	rationale, err := admit.NonEmptyText(record["rationale"], "requirement authoring plan rationale")
	if err != nil {
		return candidateUpdate{}, err
	}
	ownerQuestions, err := admit.PreserveSortedTextArray(record["ownerQuestions"], "requirement authoring plan ownerQuestions", false)
	if err != nil {
		return candidateUpdate{}, err
	}
	proofObligations, err := admitProofObligations(record["declaredProofObligations"])
	if err != nil {
		return candidateUpdate{}, err
	}
	candidateRequirement, ok := record["candidateRequirement"].(map[string]any)
	if !ok {
		return candidateUpdate{}, fmt.Errorf("requirement authoring plan candidateRequirement must be an object")
	}
	candidateRequirement = cloneObject(candidateRequirement)
	candidateRequirementID, err := requirementID(candidateRequirement["requirementId"], "requirement authoring plan candidateRequirement.requirementId")
	if err != nil {
		return candidateUpdate{}, err
	}
	if candidateRequirementID != targetRequirementID {
		return candidateUpdate{}, fmt.Errorf("requirement authoring plan candidateRequirement.requirementId must equal candidateUpdate.requirementId")
	}
	return candidateUpdate{
		CandidateID:          candidateID,
		CandidateRequirement: candidateRequirement,
		Operation:            operation,
		OwnerQuestions:       ownerQuestions,
		ProofObligations:     proofObligations,
		Rationale:            rationale,
		RequirementID:        targetRequirementID,
		SourceRefIDs:         sourceRefIDs,
	}, nil
}

func admitProofObligations(raw any) ([]proofObligation, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement authoring plan proofObligations must be a non-empty array")
	}
	result := make([]proofObligation, 0, len(values))
	ids := []string{}
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement authoring plan proofObligation must be an object")
		}
		if err := admit.KnownKeys(record, []string{"blocking", "description", "evidenceRefs", "kind", "obligationId", "ownerId"}, "requirement authoring plan proofObligation"); err != nil {
			return nil, err
		}
		obligationID, err := admit.RuleID(record["obligationId"], "requirement authoring plan proofObligation.obligationId")
		if err != nil {
			return nil, err
		}
		kind, err := admit.Enum(record["kind"], obligationKindSet, "requirement authoring plan proofObligation.kind")
		if err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(record["ownerId"], "requirement authoring plan proofObligation.ownerId")
		if err != nil {
			return nil, err
		}
		description, err := admit.NonEmptyText(record["description"], "requirement authoring plan proofObligation.description")
		if err != nil {
			return nil, err
		}
		blocking, err := admit.Bool(record["blocking"], "requirement authoring plan proofObligation.blocking")
		if err != nil {
			return nil, err
		}
		evidenceRefs, err := preserveSortedPaths(record["evidenceRefs"], "requirement authoring plan proofObligation.evidenceRefs", true)
		if err != nil {
			return nil, err
		}
		result = append(result, proofObligation{Blocking: blocking, Description: description, EvidenceRefs: evidenceRefs, Kind: kind, ObligationID: obligationID, OwnerID: ownerID})
		ids = append(ids, obligationID)
	}
	if _, err := admit.PreserveSortedText(ids, "requirement authoring plan proof obligation ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func composeNextRequirementSource(input input) (map[string]any, []string) {
	current := cloneObject(input.CurrentRequirementRaw)
	requirements := cloneArray(current["requirements"].([]any))
	indexByRequirementID := map[string]int{}
	for index, raw := range requirements {
		record := raw.(map[string]any)
		id, _ := record["requirementId"].(string)
		indexByRequirementID[id] = index
	}
	failures := []string{}
	for _, update := range input.CandidateUpdates {
		index, exists := indexByRequirementID[update.RequirementID]
		state := lifecycleState(update.CandidateRequirement)
		switch update.Operation {
		case "add":
			if exists {
				failures = append(failures, fmt.Sprintf("add candidate must target a new requirement id: %s", update.RequirementID))
			}
			if state != "active" {
				failures = append(failures, fmt.Sprintf("add candidate must start active: %s", update.RequirementID))
			}
			requirements = append(requirements, update.CandidateRequirement)
		case "modify":
			if !exists {
				failures = append(failures, fmt.Sprintf("modify candidate must target an existing requirement id: %s", update.RequirementID))
			} else if state != "active" {
				failures = append(failures, fmt.Sprintf("modify candidate must keep active lifecycle: %s", update.RequirementID))
			} else {
				requirements[index] = update.CandidateRequirement
			}
		case "deprecate":
			if !exists {
				failures = append(failures, fmt.Sprintf("deprecate candidate must target an existing requirement id: %s", update.RequirementID))
			} else if state != "deprecated" {
				failures = append(failures, fmt.Sprintf("deprecate candidate must set deprecated lifecycle: %s", update.RequirementID))
			} else {
				requirements[index] = update.CandidateRequirement
			}
		case "supersede":
			if !exists {
				failures = append(failures, fmt.Sprintf("supersede candidate must target an existing requirement id: %s", update.RequirementID))
			} else if state != "superseded" {
				failures = append(failures, fmt.Sprintf("supersede candidate must set superseded lifecycle: %s", update.RequirementID))
			} else {
				requirements[index] = update.CandidateRequirement
			}
		}
	}
	sort.Slice(requirements, func(left, right int) bool {
		leftID, _ := requirements[left].(map[string]any)["requirementId"].(string)
		rightID, _ := requirements[right].(map[string]any)["requirementId"].(string)
		return leftID < rightID
	})
	current["requirements"] = requirements
	return current, failures
}

func lifecycleState(requirement map[string]any) string {
	lifecycle, ok := requirement["lifecycle"].(map[string]any)
	if !ok {
		return ""
	}
	state, _ := lifecycle["state"].(string)
	return state
}

func candidateUpdateValues(updates []candidateUpdate, includeRequirement bool) []any {
	values := make([]any, 0, len(updates))
	for _, update := range updates {
		record := map[string]any{
			"candidateId":              update.CandidateID,
			"declaredProofObligations": proofObligationValues(update.ProofObligations),
			"operation":                update.Operation,
			"ownerQuestions":           admit.StringSliceToAny(update.OwnerQuestions),
			"rationale":                update.Rationale,
			"requirementId":            update.RequirementID,
			"sourceRefIds":             admit.StringSliceToAny(update.SourceRefIDs),
		}
		if includeRequirement {
			record["candidateRequirement"] = cloneObject(update.CandidateRequirement)
		} else {
			record["candidateRequirementOmitted"] = "candidate requirement payload is omitted until candidate source and transition admission pass"
		}
		values = append(values, record)
	}
	return values
}

func proofObligationValues(obligations []proofObligation) []any {
	values := make([]any, 0, len(obligations))
	for _, obligation := range obligations {
		values = append(values, map[string]any{
			"blocking":     obligation.Blocking,
			"description":  obligation.Description,
			"evidenceRefs": admit.StringSliceToAny(obligation.EvidenceRefs),
			"kind":         obligation.Kind,
			"obligationId": obligation.ObligationID,
			"ownerId":      obligation.OwnerID,
		})
	}
	return values
}

func promotionPreconditions(input input) []any {
	return []any{
		precondition("owner.review", "owner_review", "A consuming repository owner must approve candidate requirement meaning before materialization.", input.AuthoringPlanID),
		precondition("source.materialization", "materialization", "The consuming repository must write requirements.v1.json and overview changes itself.", input.CurrentRequirementState.RequirementsPath),
		precondition("proof.binding", "proof_binding", "The consuming repository must run proof-binding coverage after materialization.", "proofkit/requirement-bindings.json"),
		precondition("native.witness", "native_witness", "The consuming repository must execute native witnesses and admit receipts through its producer policy.", input.CurrentRequirementState.SourceID),
	}
}

func precondition(id string, kind string, description string, ref string) map[string]any {
	return map[string]any{
		"description":    description,
		"kind":           kind,
		"preconditionId": "proofkit.requirement-authoring-plan." + id,
		"ref":            ref,
	}
}

func ownerReviewPlan(input input) []any {
	actions := []any{
		map[string]any{
			"actionId":    "proofkit.requirement-authoring-plan.review-candidates",
			"actionKind":  "review_candidate",
			"owner":       "consuming_repository_owner",
			"phase":       "owner-review",
			"instruction": "Review each candidate requirement for durable product meaning before writing stable source files.",
			"nonClaims":   []any{"This action does not approve requirement promotion or file materialization."},
		},
		map[string]any{
			"actionId":    "proofkit.requirement-authoring-plan.run-admitted-validation",
			"actionKind":  "run_admitted_validation",
			"owner":       "consuming_repository_owner",
			"phase":       "post-materialization-validation",
			"instruction": "After owner approval and materialization, run the consuming repository's requirement-source, proof-binding, and native witness gates.",
			"nonClaims":   []any{"This action does not execute witnesses or prove proof freshness."},
		},
	}
	for _, update := range input.CandidateUpdates {
		actions = append(actions, map[string]any{
			"actionId":                 "proofkit.requirement-authoring-plan.candidate." + update.CandidateID,
			"actionKind":               "ask_owner",
			"candidateId":              update.CandidateID,
			"declaredProofObligations": proofObligationValues(update.ProofObligations),
			"evidenceRefs":             admit.StringSliceToAny(update.SourceRefIDs),
			"nonClaims":                []any{"Candidate actions are advisory and do not create stable requirement truth."},
			"owner":                    "consuming_repository_owner",
			"ownerQuestions":           admit.StringSliceToAny(update.OwnerQuestions),
			"phase":                    "candidate-review",
			"requirementId":            update.RequirementID,
		})
	}
	return actions
}

func ruleResults(failures []string, sourceResult requirementsourceadmission.Result, sourceErr error, transitionState string, transitionErr error) []any {
	return []any{
		ruleResult("proofkit.requirement-authoring-plan.candidate-source-admission", sourceRuleStatus(sourceResult, sourceErr), "composed candidate source must pass requirement-source-admission", failuresForPrefix(failures, "candidate next source")),
		ruleResult("proofkit.requirement-authoring-plan.transition-admission", transitionRuleStatus(transitionState, transitionErr), "current to candidate next source must pass requirement-source-transition", failuresForPrefix(failures, "candidate transition")),
		ruleResult("proofkit.requirement-authoring-plan.non-authority", "passed", "authoring output remains candidate data until owner materialization", []string{}),
		ruleResult("proofkit.requirement-authoring-plan.composition", statusFailedIf(len(failuresForComposition(failures)) > 0), "candidate operations must match current requirement ids and lifecycle targets", failuresForComposition(failures)),
	}
}

func ruleResult(ruleID string, status string, message string, failures []string) map[string]any {
	diagnostics := []any{}
	for index, failure := range failures {
		diagnostics = append(diagnostics, map[string]any{
			"key":   fmt.Sprintf("failure.%03d", index+1),
			"value": failure,
		})
	}
	return map[string]any{
		"diagnostics": diagnostics,
		"message":     message,
		"ruleId":      ruleID,
		"status":      status,
	}
}

func sourceRuleStatus(sourceResult requirementsourceadmission.Result, sourceErr error) string {
	if sourceErr != nil || sourceResult.ExitCode != 0 {
		return "failed"
	}
	return "passed"
}

func transitionRuleStatus(state string, err error) string {
	if err != nil || state != "passed" {
		return "failed"
	}
	return "passed"
}

func stateFromSourceResult(result requirementsourceadmission.Result, err error) string {
	if err != nil {
		return "failed"
	}
	return result.Report.State
}

func stateFromTransition(state string, err error) string {
	if err != nil {
		return "failed"
	}
	return state
}

func failuresForPrefix(failures []string, prefix string) []string {
	selected := []string{}
	for _, failure := range failures {
		if len(failure) >= len(prefix) && failure[:len(prefix)] == prefix {
			selected = append(selected, failure)
		}
	}
	return selected
}

func failuresForComposition(failures []string) []string {
	selected := []string{}
	for _, failure := range failures {
		if len(failure) >= len("add ") && failure[:len("add ")] == "add " ||
			len(failure) >= len("modify ") && failure[:len("modify ")] == "modify " ||
			len(failure) >= len("deprecate ") && failure[:len("deprecate ")] == "deprecate " ||
			len(failure) >= len("supersede ") && failure[:len("supersede ")] == "supersede " {
			selected = append(selected, failure)
		}
	}
	return selected
}

func statusFailedIf(value bool) string {
	if value {
		return "failed"
	}
	return "passed"
}

func nonClaims(caller []string) []string {
	values := append([]string{}, standardNonClaims...)
	values = append(values, caller...)
	sort.Strings(values)
	return values
}

func repoPath(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	pathValue, err := admit.SafeRepoRelativePath(value, context)
	if err != nil {
		return "", err
	}
	if pathValue == ".git" || len(pathValue) > len(".git/") && pathValue[:len(".git/")] == ".git/" {
		return "", fmt.Errorf("%s must not target repository metadata", context)
	}
	return pathValue, nil
}

func preserveSortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		pathValue, err := admit.SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		out = append(out, pathValue)
	}
	return admit.PreserveSortedText(out, context, allowEmpty)
}

func optionalDigest(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return nil, err
	}
	if !sha256DigestRegexp.MatchString(value) {
		return nil, fmt.Errorf("%s must be sha256:<64 lowercase hex>", context)
	}
	return &value, nil
}

func requirementID(raw any, context string) (string, error) {
	value, err := admit.RuleID(raw, context)
	if err != nil {
		return "", err
	}
	if len(value) < 4 || value[:4] != "REQ-" {
		return "", fmt.Errorf("%s must start with REQ-", context)
	}
	return value, nil
}

func cloneObject(value map[string]any) map[string]any {
	out := map[string]any{}
	for key, item := range value {
		out[key] = cloneValue(item)
	}
	return out
}

func cloneArray(values []any) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, cloneValue(value))
	}
	return out
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneObject(typed)
	case []any:
		return cloneArray(typed)
	case json.Number:
		return json.Number(typed.String())
	default:
		return typed
	}
}
