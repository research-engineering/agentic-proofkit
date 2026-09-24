package requirementauthoringplan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourcetransition"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const planKind = "proofkit.requirement-authoring-plan"

var (
	modeSet            = map[string]struct{}{"pull_request_design": {}, "retrospective_baseline": {}}
	refKindSet         = referenceKindSet()
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
	AuthoringPlanID            string
	AuthoringRefs              []authoringRef
	CandidateUpdates           []candidateUpdate
	CurrentRequirementValue    map[string]any
	CurrentRequirementState    requirementsourceadmission.Source
	CandidateRequirementResult requirementsourceadmission.Result
	CandidateRequirementValue  map[string]any
	Mode                       string
	NonClaims                  []string
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
	if err := authoringOutputShape.CheckGenerated(output, "requirement authoring plan output"); err != nil {
		return nil, 1, err
	}
	return output, exitCode, nil
}

func buildOutput(input input) (map[string]any, int) {
	nextSource := input.CandidateRequirementValue
	sourceResult := input.CandidateRequirementResult
	var sourceErr error
	updates, changedPlanes, compositionFailures := compareCandidateSource(input)
	transitionInput := map[string]any{
		"schemaVersion": json.Number("2"),
		"transitionId":  input.AuthoringPlanID + ".transition",
		"nonClaims": []any{
			"Requirement authoring plan transition proof does not promote candidates to stable repository truth.",
		},
		"previous": input.CurrentRequirementValue,
		"next":     nextSource,
	}
	transitionRecord := report.Record{State: "skipped"}
	transitionExitCode := 1
	var transitionErr error
	if sourceResult.ExitCode == 0 {
		transitionRecord, transitionExitCode, transitionErr = requirementsourcetransition.Build(transitionInput)
	}

	sourceFailures := []string{}
	transitionFailures := []string{}
	if sourceErr != nil {
		sourceFailures = append(sourceFailures, "candidate next source admission error: "+sourceErr.Error())
	} else if sourceResult.ExitCode != 0 {
		sourceFailures = append(sourceFailures, "candidate next source must pass requirement-source-admission")
	}
	if transitionErr != nil {
		transitionFailures = append(transitionFailures, "candidate transition admission error: "+transitionErr.Error())
	} else if transitionRecord.State == "skipped" {
		transitionFailures = append(transitionFailures, "candidate transition requires an admitted candidate source")
	} else if transitionExitCode != 0 {
		transitionFailures = append(transitionFailures, "candidate transition must pass requirement-source-transition")
	}
	failures := append(append(append([]string{}, compositionFailures...), sourceFailures...), transitionFailures...)
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
	var sourcePlanes any = admit.StringSliceToAny(changedPlanes)
	comparisonState := "compared"
	if sourceResult.ExitCode != 0 {
		sourcePlanes = nil
		comparisonState = "skipped_source_admission"
	}
	output := map[string]any{
		"authoringRefs":                     authoringRefValues(input.AuthoringRefs),
		"authoringPlanId":                   input.AuthoringPlanID,
		"candidateChangeSet":                candidateUpdateValues(updates, state == "passed"),
		"changedSourcePlanes":               sourcePlanes,
		"sourceComparisonState":             comparisonState,
		"wholeCandidateOwnerReviewRequired": true,
		"mode":                              input.Mode,
		"nonAuthoritativeAdmissionPreview":  nextCandidate,
		"nonClaims":                         admit.StringSliceToAny(nonClaims(input.NonClaims)),
		"ownerReviewPlan":                   ownerReviewPlan(input),
		"planKind":                          planKind,
		"promotionPreconditions":            promotionPreconditions(input),
		"ruleResults":                       ruleResults(compositionFailures, sourceFailures, transitionFailures, sourceResult, sourceErr, transitionRecord.State, transitionErr),
		"schemaVersion":                     outputSchemaVersion,
		"state":                             state,
		"summary": map[string]any{
			"authoringRefCount":            len(input.AuthoringRefs),
			"candidateUpdateCount":         len(input.CandidateUpdates),
			"executedWitnessCountNonClaim": 0,
			"failureCount":                 len(failures),
			"mode":                         input.Mode,
			"sourceAdmissionState":         stateFromSourceResult(sourceResult, sourceErr),
			"targetRequirementSourceId":    input.CurrentRequirementState.SourceID(),
			"targetRequirementsPath":       input.CurrentRequirementState.RequirementsPath(),
			"targetSpecPackagePath":        input.CurrentRequirementState.SpecPackagePath(),
			"transitionAdmissionState":     stateFromTransition(transitionRecord.State, transitionErr),
			"writtenFileCountNonClaim":     0,
		},
	}
	if state == "passed" {
		return output, 0
	}
	return output, 1
}

func authoringRefValues(refs []authoringRef) []any {
	values := make([]any, 0, len(refs))
	for _, ref := range refs {
		var digest any
		if ref.Digest != nil {
			digest = *ref.Digest
		}
		values = append(values, map[string]any{
			"digest":    digest,
			"kind":      ref.Kind,
			"nonClaims": admit.StringSliceToAny(ref.NonClaims),
			"path":      ref.Path,
			"refId":     ref.RefID,
			"summary":   ref.Summary,
		})
	}
	return values
}

func admitInput(raw any) (input, error) {
	value, err := authoringInputShape.Admit(raw, "requirement authoring plan input")
	if err != nil {
		return input{}, err
	}
	record := value.(map[string]any)
	authoringPlanID, err := admit.RuleID(record["authoringPlanId"], "requirement authoring plan authoringPlanId")
	if err != nil {
		return input{}, err
	}
	mode, err := admit.Enum(record["mode"], modeSet, "requirement authoring plan mode")
	if err != nil {
		return input{}, err
	}
	current := record["currentRequirementSource"].(map[string]any)
	currentResult, err := requirementsourceadmission.Evaluate(current)
	if err != nil {
		return input{}, err
	}
	if currentResult.ExitCode != 0 {
		return input{}, fmt.Errorf("requirement authoring plan currentRequirementSource must pass requirement-source-admission")
	}
	candidateResult, err := requirementsourceadmission.Evaluate(record["candidateRequirementSource"])
	if err != nil {
		return input{}, err
	}
	var candidateValue map[string]any
	if candidateResult.ExitCode == 0 {
		candidateValue, err = requirementsourceadmission.SourceValue(candidateResult.Source)
		if err != nil {
			return input{}, err
		}
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
	currentValue, err := requirementsourceadmission.SourceValue(currentResult.Source)
	if err != nil {
		return input{}, err
	}
	return input{
		AuthoringPlanID:            authoringPlanID,
		AuthoringRefs:              refs,
		CandidateUpdates:           updates,
		CurrentRequirementValue:    currentValue,
		CurrentRequirementState:    currentResult.Source,
		CandidateRequirementResult: candidateResult,
		CandidateRequirementValue:  candidateValue,
		Mode:                       mode,
		NonClaims:                  nonClaims,
	}, nil
}

func admitAuthoringRefs(raw any) ([]authoringRef, error) {
	values := raw.([]any)
	result := make([]authoringRef, 0, len(values))
	ids := []string{}
	for _, value := range values {
		record := value.(map[string]any)
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
		nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "requirement authoring plan authoringRef.nonClaims", true)
		if err != nil {
			return nil, err
		}
		result = append(result, authoringRef{Digest: digest, Kind: kind, NonClaims: nonClaims, Path: path, RefID: refID, Summary: summary})
		ids = append(ids, refID)
	}
	if _, err := admit.PreserveSortedText(ids, "requirement authoring plan authoringRef ids", true); err != nil {
		return nil, err
	}
	return result, nil
}

func admitCandidateUpdates(raw any, refs []authoringRef) ([]candidateUpdate, error) {
	values := raw.([]any)
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
	if _, err := admit.PreserveSortedText(candidateIDs, "requirement authoring plan candidate ids", true); err != nil {
		return nil, err
	}
	if _, err := admit.PreserveSortedText(requirementIDs, "requirement authoring plan candidate requirement ids", true); err != nil {
		return nil, err
	}
	return result, nil
}

func admitCandidateUpdate(raw any, admittedRefIDs map[string]struct{}) (candidateUpdate, error) {
	record := raw.(map[string]any)
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
	sourceRefIDs, err := admit.PreserveSortedTextArray(record["sourceRefIds"], "requirement authoring plan sourceRefIds", true)
	if err != nil {
		return candidateUpdate{}, err
	}
	for index, refID := range sourceRefIDs {
		if _, ok := admittedRefIDs[refID]; !ok {
			return candidateUpdate{}, fmt.Errorf("requirement authoring plan sourceRefIds[%d] references unknown authoring ref", index)
		}
	}
	rationale, err := admit.NonEmptyText(record["rationale"], "requirement authoring plan rationale")
	if err != nil {
		return candidateUpdate{}, err
	}
	ownerQuestions, err := admit.PreserveSortedTextArray(record["ownerQuestions"], "requirement authoring plan ownerQuestions", true)
	if err != nil {
		return candidateUpdate{}, err
	}
	proofObligations, err := admitProofObligations(record["declaredProofObligations"])
	if err != nil {
		return candidateUpdate{}, err
	}
	return candidateUpdate{
		CandidateID:      candidateID,
		Operation:        operation,
		OwnerQuestions:   ownerQuestions,
		ProofObligations: proofObligations,
		Rationale:        rationale,
		RequirementID:    targetRequirementID,
		SourceRefIDs:     sourceRefIDs,
	}, nil
}

func admitProofObligations(raw any) ([]proofObligation, error) {
	values := raw.([]any)
	result := make([]proofObligation, 0, len(values))
	ids := []string{}
	for _, value := range values {
		record := value.(map[string]any)
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
	if _, err := admit.PreserveSortedText(ids, "requirement authoring plan proof obligation ids", true); err != nil {
		return nil, err
	}
	return result, nil
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
			record["candidateRequirementOmitted"] = omittedCandidateMessage
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
		precondition("source.materialization", "materialization", "The consuming repository must write requirements.v2.json and overview changes itself.", input.CurrentRequirementState.RequirementsPath()),
		precondition("proof.binding", "proof_binding", "The consuming repository must run proof-binding coverage after materialization.", "proofkit/requirement-bindings.json"),
		precondition("native.witness", "native_witness", "The consuming repository must execute native witnesses and admit receipts through its producer policy.", input.CurrentRequirementState.SourceID()),
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
			"instruction": "Review the whole candidate source, including grouped ownership, scenario bodies, vocabulary, derivations and nonclaims, and each declared requirement change before writing stable source files.",
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

func ruleResults(compositionFailures, sourceFailures, transitionFailures []string, sourceResult requirementsourceadmission.Result, sourceErr error, transitionState string, transitionErr error) []any {
	compositionState := statusFailedIf(len(compositionFailures) > 0)
	if sourceErr != nil || sourceResult.ExitCode != 0 {
		compositionState = "skipped"
	}
	return []any{
		ruleResult("proofkit.requirement-authoring-plan.candidate-source-admission", sourceRuleStatus(sourceResult, sourceErr), "candidate source must pass requirement-source-admission", sourceFailures),
		ruleResult("proofkit.requirement-authoring-plan.transition-admission", transitionRuleStatus(transitionState, transitionErr), "current to candidate next source must pass requirement-source-transition", transitionFailures),
		ruleResult("proofkit.requirement-authoring-plan.non-authority", "passed", "authoring output remains candidate data until owner materialization", []string{}),
		ruleResult("proofkit.requirement-authoring-plan.composition", compositionState, "candidate operations must cover exact changed requirement ids and lifecycle targets", compositionFailures),
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
	if state == "skipped" && err == nil {
		return "skipped"
	}
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
	_, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	pathValue, err := admit.SafeRepoRelativePath(raw.(string), context)
	if err != nil {
		return "", err
	}
	if pathValue == ".git" || len(pathValue) > len(".git/") && pathValue[:len(".git/")] == ".git/" {
		return "", fmt.Errorf("%s must not target repository metadata", context)
	}
	return pathValue, nil
}

func preserveSortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	return admit.PreserveSortedPathArray(raw, context, allowEmpty)
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
