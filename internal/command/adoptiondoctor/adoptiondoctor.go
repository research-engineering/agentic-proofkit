package adoptiondoctor

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.adoption-doctor"

var (
	admissionStates = map[string]struct{}{
		"advisory":       {},
		"owner_admitted": {},
	}
	childReportStates = map[string]struct{}{
		"blocked": {},
		"failed":  {},
		"passed":  {},
		"skipped": {},
		"warning": {},
	}
	baseNonClaims = []string{
		"Adoption doctor reports do not approve enforcement, merge, release, rollout, or old proof-owner retirement.",
		"Adoption doctor reports do not authenticate receipts, compute proof freshness, execute native witnesses, or scan repositories.",
		"Adoption doctor reports classify caller-provided facts only; consuming repositories own semantic boundaries and product truth.",
	}
)

type Input struct {
	BlockedPreconditions []precondition
	CandidateBoundaries  []candidateBoundary
	CheckedScope         string
	ChildReports         []childReport
	DoctorID             string
	Mode                 string
	NonClaims            []string
	OwnerRoutes          []ownerRoute
	StaleAuthority       staleAuthority
	TouchedRuleIDs       []string
}

type ownerRoute struct {
	Commands          []string
	NativeWitnessRefs []string
	NonClaims         []string
	Owner             string
	ProofBindingPaths []string
	RouteID           string
	SpecPaths         []string
	TouchedRuleIDs    []string
}

type candidateBoundary struct {
	AdmissionState       string
	AffectedPaths        []string
	BlockedPreconditions []string
	BoundaryID           string
	CandidateOwner       string
	ContractWitnessRefs  []string
	NativeWitnessRefs    []string
	NonClaims            []string
	ObservedFacts        []string
	OwnerQuestions       []string
	ProofBindingRefs     []string
	RequirementRefs      []string
	Uncertainties        []string
}

type childReport struct {
	EvidenceRefs   []string
	NonClaim       string
	ReportID       string
	ReportKind     string
	State          string
	Summary        string
	TouchedRuleIDs []string
}

type precondition struct {
	EvidenceRefs   []string
	NonClaim       string
	Owner          string
	PreconditionID string
	Reason         string
	TouchedRuleIDs []string
}

type gap struct {
	EvidenceRefs []string
	GapID        string
	Kind         string
	Message      string
	Owner        string
	Phase        string
	RuleRefs     []string
	Touched      bool
}

type Result struct {
	ExitCode int
	Gaps     []gap
	Input    Input
	Record   report.Record
}

func Build(raw any) (map[string]any, int, error) {
	result, err := BuildResult(raw)
	if err != nil {
		return nil, 1, err
	}
	return result.Record.JSONValue(), result.ExitCode, nil
}

func BuildResult(raw any) (Result, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Result{}, err
	}
	return build(input), nil
}

func BuildEnvelope(raw any) (map[string]any, int, error) {
	result, err := BuildResult(raw)
	if err != nil {
		return agentenvelope.InvalidInput(err.Error()), 1, nil
	}
	return AgentEnvelope(result), result.ExitCode, nil
}

func admitInput(raw any) (Input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Input{}, fmt.Errorf("adoption doctor input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"blockedPreconditions", "checkedScope", "childReports", "doctorId", "mode", "modernization", "nonClaims", "ownerRoutes", "schemaVersion", "staleAuthority", "touchedRuleIds"}, "adoption doctor input"); err != nil {
		return Input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Input{}, fmt.Errorf("adoption doctor schemaVersion must be 1")
	}
	doctorID, err := admit.RuleID(record["doctorId"], "adoption doctor doctorId")
	if err != nil {
		return Input{}, err
	}
	mode, err := adoptionmode.Admit(record["mode"], "adoption doctor mode")
	if err != nil {
		return Input{}, err
	}
	checkedScope, err := adoptionmode.AdmitScope(record["checkedScope"], "adoption doctor checkedScope")
	if err != nil {
		return Input{}, err
	}
	if err := adoptionmode.ValidateScope(mode, checkedScope, "adoption doctor"); err != nil {
		return Input{}, err
	}
	touchedRuleIDs, err := sortedRuleIDs(optional(record, "touchedRuleIds", []any{}), "adoption doctor touchedRuleIds")
	if err != nil {
		return Input{}, err
	}
	ownerRoutes, err := ownerRoutes(record["ownerRoutes"])
	if err != nil {
		return Input{}, err
	}
	candidates, err := modernizationCandidates(record["modernization"])
	if err != nil {
		return Input{}, err
	}
	childReports, err := childReports(record["childReports"])
	if err != nil {
		return Input{}, err
	}
	blocked, err := blockedPreconditions(record["blockedPreconditions"])
	if err != nil {
		return Input{}, err
	}
	staleAuthority, err := staleAuthorityFromAny(record["staleAuthority"])
	if err != nil {
		return Input{}, err
	}
	nonClaims, err := admit.SortedTextArray(record["nonClaims"], "adoption doctor nonClaims", false)
	if err != nil {
		return Input{}, err
	}
	return Input{
		BlockedPreconditions: blocked,
		CandidateBoundaries:  candidates,
		CheckedScope:         checkedScope,
		ChildReports:         childReports,
		DoctorID:             doctorID,
		Mode:                 mode,
		NonClaims:            nonClaims,
		OwnerRoutes:          ownerRoutes,
		StaleAuthority:       staleAuthority,
		TouchedRuleIDs:       touchedRuleIDs,
	}, nil
}

func build(input Input) Result {
	gaps := adoptionGaps(input)
	enforced := enforcedGaps(input, gaps)
	state := "passed"
	exitCode := 0
	if hasBlockedGap(enforced) {
		state = "blocked"
		exitCode = 1
	} else if len(enforced) > 0 {
		state = "failed"
		exitCode = 1
	}
	rec := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.DoctorID,
		State:         state,
		Summary: map[string]any{
			"blockedPreconditionCount":   len(input.BlockedPreconditions),
			"candidateBoundaryCount":     len(input.CandidateBoundaries),
			"checkedScope":               input.CheckedScope,
			"childReportCount":           len(input.ChildReports),
			"enforcedGapCount":           len(enforced),
			"forbiddenVocabularyCount":   len(input.StaleAuthority.ForbiddenVocabulary),
			"gapCount":                   len(gaps),
			"mode":                       input.Mode,
			"ownerRouteCount":            len(input.OwnerRoutes),
			"staleAuthoritySurfaceCount": len(input.StaleAuthority.AuthoritySurfaces),
			"touchedRuleCount":           len(input.TouchedRuleIDs),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "doctor", Value: doctorDiagnostic(input, state)},
			{Key: "gaps", Value: gapsJSON(gaps)},
			{Key: "routeCommands", Value: routeCommandDiagnostics(input.OwnerRoutes)},
			{Key: "candidateBoundaries", Value: candidatesJSON(input.CandidateBoundaries)},
			{Key: "staleAuthority", Value: staleAuthorityJSON(input.StaleAuthority)},
			{Key: "promotionReadiness", Value: promotionReadiness(input, enforced)},
		},
		RuleResults: ruleResults(input, gaps, enforced),
		NonClaims:   admit.StringSliceToAny(mergedNonClaims(input.NonClaims)),
	}
	return Result{ExitCode: exitCode, Gaps: gaps, Input: input, Record: rec}
}

func adoptionGaps(input Input) []gap {
	touched := stringSet(input.TouchedRuleIDs)
	gaps := []gap{}
	gaps = append(gaps, missingOwnerRouteGaps(input, touched)...)
	for _, route := range input.OwnerRoutes {
		routeTouched := hasTouched(route.TouchedRuleIDs, touched) || input.CheckedScope == adoptionmode.ScopeAll
		if len(route.ProofBindingPaths) == 0 {
			gaps = append(gaps, gapForRoute(route, "missing_proof_binding", "bind", "Owner route has no proof binding path.", routeTouched))
		}
		if len(route.NativeWitnessRefs) == 0 {
			gaps = append(gaps, gapForRoute(route, "missing_native_witness", "verify", "Owner route has no native witness reference.", routeTouched))
		}
		if len(route.Commands) == 0 {
			gaps = append(gaps, gapForRoute(route, "missing_command_route", "verify", "Owner route has no command route.", routeTouched))
		}
	}
	for _, candidate := range input.CandidateBoundaries {
		candidateTouched := hasTouched(candidate.RequirementRefs, touched) || input.CheckedScope == adoptionmode.ScopeAll
		if candidate.AdmissionState != "owner_admitted" {
			gaps = append(gaps, gap{
				EvidenceRefs: sortedUnique(append(append([]string{}, candidate.AffectedPaths...), candidate.ProofBindingRefs...)),
				GapID:        candidate.BoundaryID + ".candidate-boundary-not-admitted",
				Kind:         "candidate_boundary_not_admitted",
				Message:      "Candidate boundary is advisory until the consuming repository owner admits stable requirements and proof bindings.",
				Owner:        candidate.CandidateOwner,
				Phase:        "modernize-boundary",
				RuleRefs:     candidate.RequirementRefs,
				Touched:      candidateTouched,
			})
		}
		for _, precondition := range candidate.BlockedPreconditions {
			gaps = append(gaps, gap{
				EvidenceRefs: candidate.AffectedPaths,
				GapID:        candidate.BoundaryID + ".blocked-precondition",
				Kind:         "blocked_precondition",
				Message:      precondition,
				Owner:        candidate.CandidateOwner,
				Phase:        "verify",
				RuleRefs:     candidate.RequirementRefs,
				Touched:      candidateTouched,
			})
		}
	}
	for _, child := range input.ChildReports {
		childTouched := hasTouched(child.TouchedRuleIDs, touched) || input.CheckedScope == adoptionmode.ScopeAll
		if child.State != "passed" {
			gaps = append(gaps, gap{
				EvidenceRefs: child.EvidenceRefs,
				GapID:        child.ReportID + "." + child.State,
				Kind:         "child_report_" + child.State,
				Message:      child.Summary,
				Owner:        "consumer_repository",
				Phase:        "verify",
				RuleRefs:     child.TouchedRuleIDs,
				Touched:      childTouched,
			})
		}
	}
	gaps = append(gaps, staleAuthorityGaps(input.StaleAuthority, touched, input.CheckedScope)...)
	for _, blocked := range input.BlockedPreconditions {
		gaps = append(gaps, gap{
			EvidenceRefs: blocked.EvidenceRefs,
			GapID:        blocked.PreconditionID,
			Kind:         "blocked_precondition",
			Message:      blocked.Reason,
			Owner:        blocked.Owner,
			Phase:        "verify",
			RuleRefs:     blocked.TouchedRuleIDs,
			Touched:      hasTouched(blocked.TouchedRuleIDs, touched) || input.CheckedScope == adoptionmode.ScopeAll,
		})
	}
	sort.Slice(gaps, func(left int, right int) bool {
		return gaps[left].GapID < gaps[right].GapID
	})
	return gaps
}

func missingOwnerRouteGaps(input Input, touched map[string]struct{}) []gap {
	if len(input.OwnerRoutes) == 0 {
		return []gap{{
			EvidenceRefs: []string{input.DoctorID},
			GapID:        input.DoctorID + ".missing-owner-route",
			Kind:         "missing_owner_route",
			Message:      "Checked adoption scope has no caller-owned owner route.",
			Owner:        "consumer_repository",
			Phase:        "route",
			RuleRefs:     append([]string{}, input.TouchedRuleIDs...),
			Touched:      input.CheckedScope != adoptionmode.ScopeNone,
		}}
	}
	if len(touched) == 0 {
		return []gap{}
	}

	covered := map[string]struct{}{}
	for _, route := range input.OwnerRoutes {
		for _, ruleID := range route.TouchedRuleIDs {
			if _, ok := touched[ruleID]; ok {
				covered[ruleID] = struct{}{}
			}
		}
	}
	missing := []string{}
	for _, ruleID := range input.TouchedRuleIDs {
		if _, ok := covered[ruleID]; !ok {
			missing = append(missing, ruleID)
		}
	}
	if len(missing) == 0 {
		return []gap{}
	}
	return []gap{{
		EvidenceRefs: []string{input.DoctorID},
		GapID:        input.DoctorID + ".missing-touched-owner-route",
		Kind:         "missing_owner_route",
		Message:      "Touched adoption requirements have no covering caller-owned owner route.",
		Owner:        "consumer_repository",
		Phase:        "route",
		RuleRefs:     missing,
		Touched:      input.CheckedScope != adoptionmode.ScopeNone,
	}}
}

func enforcedGaps(input Input, gaps []gap) []gap {
	if !adoptionmode.IsEnforcing(input.Mode) {
		return []gap{}
	}
	enforced := []gap{}
	for _, item := range gaps {
		if input.Mode == adoptionmode.EnforceAll || item.Touched {
			enforced = append(enforced, item)
		}
	}
	return enforced
}

func hasBlockedGap(gaps []gap) bool {
	for _, item := range gaps {
		if item.Kind == "blocked_precondition" || item.Kind == "child_report_blocked" {
			return true
		}
	}
	return false
}

func ruleResults(input Input, gaps []gap, enforced []gap) []report.RuleResult {
	if len(gaps) == 0 {
		return []report.RuleResult{{
			RuleID:  "proofkit.adoption-doctor.no-gaps",
			Status:  "passed",
			Message: "Caller-provided adoption facts contain no missing owner routes, advisory candidate boundaries, non-passing child reports, or blocked preconditions.",
		}}
	}
	enforcedSet := map[string]struct{}{}
	for _, item := range enforced {
		enforcedSet[item.GapID] = struct{}{}
	}
	results := make([]report.RuleResult, 0, len(gaps))
	for _, item := range gaps {
		status := "passed"
		if input.Mode == adoptionmode.Warn {
			status = "warning"
		}
		if _, ok := enforcedSet[item.GapID]; ok {
			status = "failed"
			if item.Kind == "blocked_precondition" || item.Kind == "child_report_blocked" {
				status = "blocked"
			}
		}
		results = append(results, report.RuleResult{
			RuleID:  "proofkit.adoption-doctor." + item.Kind,
			Status:  status,
			Message: item.Message,
			Diagnostics: []report.Diagnostic{
				{Key: "gapId", Value: item.GapID},
				{Key: "phase", Value: item.Phase},
				{Key: "touched", Value: item.Touched},
			},
		})
	}
	return results
}

func doctorDiagnostic(input Input, state string) map[string]any {
	return map[string]any{
		"checkedScope":   input.CheckedScope,
		"doctorId":       input.DoctorID,
		"mode":           input.Mode,
		"state":          state,
		"touchedRuleIds": admit.StringSliceToAny(input.TouchedRuleIDs),
	}
}

func promotionReadiness(input Input, enforced []gap) map[string]any {
	status := map[string]any{}
	for _, phase := range []string{"route", "modernize-boundary", "bind", "verify", "parity", "retirement-review", "promote"} {
		status[phase] = "caller_review_required"
	}
	if len(input.OwnerRoutes) == 0 {
		status["route"] = "blocked_missing_owner_route"
	} else {
		status["route"] = "ready_for_owner_review"
	}
	if len(input.CandidateBoundaries) == 0 {
		status["modernize-boundary"] = "ready_for_owner_review"
	}
	if len(enforced) == 0 && input.Mode == adoptionmode.EnforceAll {
		status["promote"] = "ready_for_owner_review"
	} else {
		status["promote"] = "not_ready"
	}
	for _, item := range enforced {
		if item.Kind == "missing_owner_route" && item.Phase == "route" {
			status[item.Phase] = "blocked_missing_owner_route"
			continue
		}
		status[item.Phase] = "blocked"
	}
	return status
}

func ownerRoutes(raw any) ([]ownerRoute, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("adoption doctor ownerRoutes must be an array")
	}
	routes := make([]ownerRoute, 0, len(values))
	ids := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("adoption doctor ownerRoutes[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"commands", "nativeWitnessRefs", "nonClaims", "owner", "proofBindingPaths", "routeId", "specPaths", "touchedRuleIds"}, fmt.Sprintf("adoption doctor ownerRoutes[%d]", index)); err != nil {
			return nil, err
		}
		routeID, err := admit.RuleID(record["routeId"], fmt.Sprintf("adoption doctor ownerRoutes[%d] routeId", index))
		if err != nil {
			return nil, err
		}
		ids = append(ids, routeID)
		owner, err := admit.NonEmptyText(record["owner"], fmt.Sprintf("adoption doctor ownerRoutes[%d] owner", index))
		if err != nil {
			return nil, err
		}
		route := ownerRoute{Owner: owner, RouteID: routeID}
		if route.SpecPaths, err = sortedPaths(optional(record, "specPaths", []any{}), fmt.Sprintf("adoption doctor ownerRoutes[%d] specPaths", index)); err != nil {
			return nil, err
		}
		if route.ProofBindingPaths, err = sortedPaths(optional(record, "proofBindingPaths", []any{}), fmt.Sprintf("adoption doctor ownerRoutes[%d] proofBindingPaths", index)); err != nil {
			return nil, err
		}
		if route.NativeWitnessRefs, err = sortedPaths(optional(record, "nativeWitnessRefs", []any{}), fmt.Sprintf("adoption doctor ownerRoutes[%d] nativeWitnessRefs", index)); err != nil {
			return nil, err
		}
		if route.Commands, err = displayCommands(optional(record, "commands", []any{}), fmt.Sprintf("adoption doctor ownerRoutes[%d] commands", index)); err != nil {
			return nil, err
		}
		if route.TouchedRuleIDs, err = sortedRuleIDs(optional(record, "touchedRuleIds", []any{}), fmt.Sprintf("adoption doctor ownerRoutes[%d] touchedRuleIds", index)); err != nil {
			return nil, err
		}
		if route.NonClaims, err = admit.SortedTextArray(optional(record, "nonClaims", []any{}), fmt.Sprintf("adoption doctor ownerRoutes[%d] nonClaims", index), true); err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	if _, err := admit.PreserveSortedText(ids, "adoption doctor owner route ids", true); err != nil {
		return nil, err
	}
	return routes, nil
}

func modernizationCandidates(raw any) ([]candidateBoundary, error) {
	if raw == nil {
		return []candidateBoundary{}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("adoption doctor modernization must be an object")
	}
	if err := admit.KnownKeys(record, []string{"candidateBoundaries"}, "adoption doctor modernization"); err != nil {
		return nil, err
	}
	values, ok := record["candidateBoundaries"].([]any)
	if !ok {
		return nil, fmt.Errorf("adoption doctor modernization candidateBoundaries must be an array")
	}
	candidates := make([]candidateBoundary, 0, len(values))
	ids := []string{}
	for index, value := range values {
		candidate, err := candidateFromAny(value, index)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
		ids = append(ids, candidate.BoundaryID)
	}
	if _, err := admit.PreserveSortedText(ids, "adoption doctor candidate boundary ids", true); err != nil {
		return nil, err
	}
	return candidates, nil
}

func candidateFromAny(raw any, index int) (candidateBoundary, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return candidateBoundary{}, fmt.Errorf("adoption doctor candidateBoundaries[%d] must be an object", index)
	}
	context := fmt.Sprintf("adoption doctor candidateBoundaries[%d]", index)
	if err := admit.KnownKeys(record, []string{"admissionState", "affectedPaths", "blockedPreconditions", "boundaryId", "candidateOwner", "contractWitnessRefs", "nativeWitnessRefs", "nonClaims", "observedFacts", "ownerQuestions", "proofBindingRefs", "requirementRefs", "uncertainties"}, context); err != nil {
		return candidateBoundary{}, err
	}
	boundaryID, err := admit.RuleID(record["boundaryId"], context+" boundaryId")
	if err != nil {
		return candidateBoundary{}, err
	}
	candidateOwner, err := admit.NonEmptyText(record["candidateOwner"], context+" candidateOwner")
	if err != nil {
		return candidateBoundary{}, err
	}
	admissionState, err := admit.Enum(record["admissionState"], admissionStates, context+" admissionState")
	if err != nil {
		return candidateBoundary{}, err
	}
	candidate := candidateBoundary{AdmissionState: admissionState, BoundaryID: boundaryID, CandidateOwner: candidateOwner}
	if candidate.AffectedPaths, err = sortedPaths(optional(record, "affectedPaths", []any{}), context+" affectedPaths"); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.RequirementRefs, err = sortedRuleIDs(optional(record, "requirementRefs", []any{}), context+" requirementRefs"); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.ProofBindingRefs, err = sortedPaths(optional(record, "proofBindingRefs", []any{}), context+" proofBindingRefs"); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.NativeWitnessRefs, err = sortedPaths(optional(record, "nativeWitnessRefs", []any{}), context+" nativeWitnessRefs"); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.ContractWitnessRefs, err = sortedPaths(optional(record, "contractWitnessRefs", []any{}), context+" contractWitnessRefs"); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.BlockedPreconditions, err = admit.SortedTextArray(optional(record, "blockedPreconditions", []any{}), context+" blockedPreconditions", true); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.OwnerQuestions, err = admit.TextArray(optional(record, "ownerQuestions", []any{}), context+" ownerQuestions", true); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.ObservedFacts, err = admit.TextArray(optional(record, "observedFacts", []any{}), context+" observedFacts", true); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.Uncertainties, err = admit.TextArray(optional(record, "uncertainties", []any{}), context+" uncertainties", true); err != nil {
		return candidateBoundary{}, err
	}
	if candidate.NonClaims, err = admit.SortedTextArray(optional(record, "nonClaims", []any{}), context+" nonClaims", true); err != nil {
		return candidateBoundary{}, err
	}
	return candidate, nil
}

func childReports(raw any) ([]childReport, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("adoption doctor childReports must be an array")
	}
	reports := make([]childReport, 0, len(values))
	ids := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("adoption doctor childReports[%d] must be an object", index)
		}
		context := fmt.Sprintf("adoption doctor childReports[%d]", index)
		if err := admit.KnownKeys(record, []string{"evidenceRefs", "nonClaim", "reportId", "reportKind", "state", "summary", "touchedRuleIds"}, context); err != nil {
			return nil, err
		}
		reportID, err := admit.RuleID(record["reportId"], context+" reportId")
		if err != nil {
			return nil, err
		}
		ids = append(ids, reportID)
		reportKind, err := admit.RuleID(record["reportKind"], context+" reportKind")
		if err != nil {
			return nil, err
		}
		state, err := admit.Enum(record["state"], childReportStates, context+" state")
		if err != nil {
			return nil, err
		}
		summary, err := admit.NonEmptyText(record["summary"], context+" summary")
		if err != nil {
			return nil, err
		}
		nonClaim, err := admit.NonEmptyText(record["nonClaim"], context+" nonClaim")
		if err != nil {
			return nil, err
		}
		evidenceRefs, err := sortedPaths(optional(record, "evidenceRefs", []any{}), context+" evidenceRefs")
		if err != nil {
			return nil, err
		}
		touchedRuleIDs, err := sortedRuleIDs(optional(record, "touchedRuleIds", []any{}), context+" touchedRuleIds")
		if err != nil {
			return nil, err
		}
		reports = append(reports, childReport{EvidenceRefs: evidenceRefs, NonClaim: nonClaim, ReportID: reportID, ReportKind: reportKind, State: state, Summary: summary, TouchedRuleIDs: touchedRuleIDs})
	}
	if _, err := admit.PreserveSortedText(ids, "adoption doctor child report ids", true); err != nil {
		return nil, err
	}
	return reports, nil
}

func blockedPreconditions(raw any) ([]precondition, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("adoption doctor blockedPreconditions must be an array")
	}
	preconditions := make([]precondition, 0, len(values))
	ids := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("adoption doctor blockedPreconditions[%d] must be an object", index)
		}
		context := fmt.Sprintf("adoption doctor blockedPreconditions[%d]", index)
		if err := admit.KnownKeys(record, []string{"evidenceRefs", "nonClaim", "owner", "preconditionId", "reason", "touchedRuleIds"}, context); err != nil {
			return nil, err
		}
		preconditionID, err := admit.RuleID(record["preconditionId"], context+" preconditionId")
		if err != nil {
			return nil, err
		}
		ids = append(ids, preconditionID)
		owner, err := admit.NonEmptyText(record["owner"], context+" owner")
		if err != nil {
			return nil, err
		}
		reason, err := admit.NonEmptyText(record["reason"], context+" reason")
		if err != nil {
			return nil, err
		}
		nonClaim, err := admit.NonEmptyText(record["nonClaim"], context+" nonClaim")
		if err != nil {
			return nil, err
		}
		evidenceRefs, err := sortedPaths(optional(record, "evidenceRefs", []any{}), context+" evidenceRefs")
		if err != nil {
			return nil, err
		}
		touchedRuleIDs, err := sortedRuleIDs(optional(record, "touchedRuleIds", []any{}), context+" touchedRuleIds")
		if err != nil {
			return nil, err
		}
		preconditions = append(preconditions, precondition{EvidenceRefs: evidenceRefs, NonClaim: nonClaim, Owner: owner, PreconditionID: preconditionID, Reason: reason, TouchedRuleIDs: touchedRuleIDs})
	}
	if _, err := admit.PreserveSortedText(ids, "adoption doctor blocked precondition ids", true); err != nil {
		return nil, err
	}
	return preconditions, nil
}

func sortedPaths(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	paths := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain repository-relative POSIX paths", context)
		}
		path, err := admit.SafeRepoRelativePath(text, context)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return admit.PreserveSortedText(paths, context, true)
}

func sortedRuleIDs(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	ids := make([]string, 0, len(values))
	for _, value := range values {
		id, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return admit.PreserveSortedText(ids, context, true)
}

func displayCommands(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	commands := make([]string, 0, len(values))
	for _, value := range values {
		command, err := admit.DisplayOnlyCommandText(value, context)
		if err != nil {
			return nil, err
		}
		commands = append(commands, command)
	}
	return admit.PreserveSortedText(commands, context, true)
}

func optional(record map[string]any, key string, defaultValue any) any {
	value, ok := record[key]
	if !ok || value == nil {
		return defaultValue
	}
	return value
}

func gapForRoute(route ownerRoute, kind string, phase string, message string, touched bool) gap {
	return gap{
		EvidenceRefs: route.SpecPaths,
		GapID:        route.RouteID + "." + kind,
		Kind:         kind,
		Message:      message,
		Owner:        route.Owner,
		Phase:        phase,
		RuleRefs:     route.TouchedRuleIDs,
		Touched:      touched,
	}
}

func gapsJSON(gaps []gap) []any {
	out := make([]any, 0, len(gaps))
	for _, item := range gaps {
		out = append(out, gapJSON(item))
	}
	return out
}

func gapJSON(item gap) map[string]any {
	return map[string]any{
		"evidenceRefs": admit.StringSliceToAny(item.EvidenceRefs),
		"gapId":        item.GapID,
		"kind":         item.Kind,
		"message":      item.Message,
		"owner":        item.Owner,
		"phase":        item.Phase,
		"ruleRefs":     admit.StringSliceToAny(item.RuleRefs),
		"touched":      item.Touched,
	}
}

func candidatesJSON(candidates []candidateBoundary) []any {
	out := make([]any, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, map[string]any{
			"admissionState":       candidate.AdmissionState,
			"affectedPaths":        admit.StringSliceToAny(candidate.AffectedPaths),
			"blockedPreconditions": admit.StringSliceToAny(candidate.BlockedPreconditions),
			"boundaryId":           candidate.BoundaryID,
			"candidateOwner":       candidate.CandidateOwner,
			"requirementRefs":      admit.StringSliceToAny(candidate.RequirementRefs),
		})
	}
	return out
}

func routeCommandDiagnostics(routes []ownerRoute) []any {
	out := []any{}
	for _, route := range routes {
		for index, command := range route.Commands {
			out = append(out, map[string]any{
				"command":   command,
				"commandId": fmt.Sprintf("%s.command.%03d", route.RouteID, index+1),
				"nonClaim":  "Command refs are display-only; the consuming repository owns execution and receipt admission.",
				"owner":     route.Owner,
			})
		}
	}
	sort.Slice(out, func(left int, right int) bool {
		return out[left].(map[string]any)["commandId"].(string) < out[right].(map[string]any)["commandId"].(string)
	})
	return out
}

func mergedNonClaims(caller []string) []string {
	return sortedUnique(append(append([]string{}, baseNonClaims...), caller...))
}

func hasTouched(values []string, touched map[string]struct{}) bool {
	if len(touched) == 0 {
		return false
	}
	for _, value := range values {
		if _, ok := touched[value]; ok {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := append([]string{}, values...)
	sort.Strings(out)
	write := 0
	for _, value := range out {
		if write == 0 || out[write-1] != value {
			out[write] = value
			write++
		}
	}
	return out[:write]
}
