package gradualadoption

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/contractenv"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var sourceReportStates = map[string]struct{}{
	"blocked": {},
	"failed":  {},
	"passed":  {},
	"skipped": {},
	"warning": {},
}

const candidateBoundaryNonClaim = "Candidate boundary guidance is advisory until the consuming repository owner admits it in stable requirements and proof bindings."

type GuidanceOptions struct {
	CheckedScope   string
	GuidanceMode   string
	TouchedRuleIDs []string
}

type guidanceResult struct {
	ExitCode int
	Guidance map[string]any
	Record   report.Record
}

func BuildGuidance(raw any, options GuidanceOptions) (map[string]any, int, error) {
	result, err := buildGuidance(raw, options)
	if err != nil {
		return nil, 1, err
	}
	return result.Record.JSONValue(), result.ExitCode, nil
}

func BuildGuidanceEnvelope(raw any, options GuidanceOptions) (map[string]any, int, error) {
	result, err := buildGuidance(raw, options)
	if err != nil {
		return agentenvelope.InvalidInput(err.Error()), 1, nil
	}
	return guidanceEnvelope(result), result.ExitCode, nil
}

func BuildGuidanceFromContractEnvelope(raw any, options GuidanceOptions) (map[string]any, int, error) {
	input, err := GuidanceInputFromContractEnvelope(raw, options)
	if err != nil {
		return nil, 1, err
	}
	return BuildGuidance(input, GuidanceOptions{})
}

func BuildGuidanceEnvelopeFromContractEnvelope(raw any, options GuidanceOptions) (map[string]any, int, error) {
	input, err := GuidanceInputFromContractEnvelope(raw, options)
	if err != nil {
		return agentenvelope.InvalidInput(err.Error()), 1, nil
	}
	return BuildGuidanceEnvelope(input, GuidanceOptions{})
}

func GuidanceInputFromContractEnvelope(raw any, options GuidanceOptions) (map[string]any, error) {
	envelope, err := contractenv.Object(raw, "proofkit.gradual-adoption-profile.v1", "gradual adoption", "guidance", "input")
	if err != nil {
		return nil, err
	}
	adoptionInput, err := contractenv.ObjectField(envelope, "input", "gradual adoption contract envelope")
	if err != nil {
		return nil, err
	}
	adoptionReport, err := BuildReport(adoptionInput)
	if err != nil {
		return nil, err
	}
	guidance, err := contractenv.ObjectField(envelope, "guidance", "gradual adoption contract envelope")
	if err != nil {
		return nil, err
	}
	scopeEvidence, err := contractenv.ObjectField(guidance, "scopeEvidence", "gradual adoption guidance contract")
	if err != nil {
		return nil, err
	}
	mode := options.GuidanceMode
	if mode == "" {
		mode, err = contractenv.StringField(guidance, "defaultMode", "gradual adoption guidance contract")
		if err != nil {
			return nil, err
		}
	}
	checkedScope := options.CheckedScope
	if checkedScope == "" {
		checkedScope, err = contractenv.StringField(scopeEvidence, "checkedScope", "gradual adoption guidance contract")
		if err != nil {
			return nil, err
		}
	}
	touchedRuleIDs := options.TouchedRuleIDs
	if len(touchedRuleIDs) == 0 {
		touchedRuleIDs, err = contractenv.StringArrayField(scopeEvidence, "touchedRuleIds", "gradual adoption guidance contract")
		if err != nil {
			return nil, err
		}
	}
	ownerRoute, err := contractenv.ObjectField(guidance, "ownerRoute", "gradual adoption guidance contract")
	if err != nil {
		return nil, err
	}
	agentGuidance, err := contractenv.ObjectField(guidance, "agentGuidance", "gradual adoption guidance contract")
	if err != nil {
		return nil, err
	}
	guidanceID, err := contractenv.StringField(guidance, "guidanceId", "gradual adoption guidance contract")
	if err != nil {
		return nil, err
	}
	nonClaims, err := contractenv.StringArrayField(guidance, "nonClaims", "gradual adoption guidance contract")
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"agentGuidance": agentGuidance,
		"guidanceId":    guidanceID,
		"guidanceMode":  mode,
		"nonClaims":     admit.StringSliceToAny(nonClaims),
		"ownerRoute":    ownerRoute,
		"schemaVersion": jsonNumberOne(),
		"scopeEvidence": map[string]any{
			"basis":          "caller_provided_touched_rule_ids",
			"checkedScope":   checkedScope,
			"touchedRuleIds": admit.StringSliceToAny(touchedRuleIDs),
		},
		"sourceReport": adoptionReport.Record.JSONValue(),
	}
	if modernization, ok := guidance["modernization"]; ok {
		result["modernization"] = modernization
	}
	return result, nil
}

func buildGuidance(raw any, options GuidanceOptions) (guidanceResult, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return guidanceResult{}, fmt.Errorf("proofkit gradual adoption guidance input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"agentGuidance", "guidanceId", "guidanceMode", "modernization", "nonClaims", "ownerRoute", "schemaVersion", "scopeEvidence", "sourceReport"}, "proofkit gradual adoption guidance input"); err != nil {
		return guidanceResult{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return guidanceResult{}, fmt.Errorf("proofkit gradual adoption guidance schemaVersion must be 1")
	}
	failures := []string{}
	guidanceID, err := admit.RuleID(record["guidanceId"], "gradual adoption guidanceId")
	if err != nil {
		return guidanceResult{}, err
	}
	guidanceMode := options.GuidanceMode
	if guidanceMode == "" {
		guidanceMode, err = adoptionmode.Admit(record["guidanceMode"], "guidanceMode")
	} else {
		guidanceMode, err = adoptionmode.Validate(guidanceMode, "guidanceMode")
	}
	if err != nil {
		return guidanceResult{}, err
	}
	sourceReport, err := admitSourceReport(record["sourceReport"])
	if err != nil {
		return guidanceResult{}, err
	}
	scopeEvidence := admitScopeEvidence(object(record["scopeEvidence"]), options, &failures)
	ownerRoute := admitOwnerRoute(object(record["ownerRoute"]), &failures, "ownerRoute")
	agentGuidance := admitAgentGuidance(object(record["agentGuidance"]), &failures)
	modernization := admitModernization(record["modernization"], &failures)
	nonClaims, err := admit.SortedTextArray(record["nonClaims"], "gradual adoption guidance nonClaims", false)
	if err != nil {
		return guidanceResult{}, err
	}
	sourceFailedRuleIDs := sourceRuleIDs(sourceReport, "failed")
	sourceWarningRuleIDs := sourceRuleIDs(sourceReport, "warning")
	enforcementFailedRuleIDs := sourceFailedRuleIDs
	if scopeEvidence["checkedScope"] != adoptionmode.ScopeAll {
		touched := stringSet(stringArrayFromMap(scopeEvidence, "touchedRuleIds"))
		enforcementFailedRuleIDs = []string{}
		for _, ruleID := range sourceFailedRuleIDs {
			if _, ok := touched[ruleID]; ok {
				enforcementFailedRuleIDs = append(enforcementFailedRuleIDs, ruleID)
			}
		}
	}
	failures = append(failures, guidanceModeFailures(guidanceMode, scopeEvidence["checkedScope"].(string), sourceReport, agentGuidance, modernization, enforcementFailedRuleIDs)...)
	if scopeEvidence["checkedScope"] == adoptionmode.ScopeNone && len(stringArrayFromMap(scopeEvidence, "touchedRuleIds")) > 0 {
		failures = append(failures, "checkedScope none must not declare touchedRuleIds")
	}
	if hasActionableGap(sourceReport, agentGuidance, enforcementFailedRuleIDs) && len(stringArrayFromMap(agentGuidance, "requiredNextActions")) == 0 {
		failures = append(failures, "requiredNextActions must be non-empty when guidance has actionable gaps")
	}
	state := guidanceState(guidanceMode, sourceReport, agentGuidance, failures)
	guidance := map[string]any{
		"agentActionPlan":                  guidanceActionPlan(guidanceMode, ownerRoute, agentGuidance, modernization, sourceFailedRuleIDs, sourceWarningRuleIDs),
		"blockedPreconditions":             anyStringArrayFromMap(agentGuidance, "blockedPreconditions"),
		"callerSuggestedAutofixCandidates": anyStringArrayFromMap(agentGuidance, "callerSuggestedAutofixCandidates"),
		"candidateBoundaries":              modernization["candidateBoundaries"],
		"checkedScope":                     scopeEvidence["checkedScope"],
		"commands":                         anyStringArrayFromMap(agentGuidance, "commands"),
		"guidanceMode":                     guidanceMode,
		"minimalAdoptionPath":              anyStringArrayFromMap(agentGuidance, "minimalAdoptionPath"),
		"nonClaims":                        admit.StringSliceToAny(nonClaims),
		"ownerRoute":                       ownerRoute,
		"proofBindingsMissing":             anyStringArrayFromMap(agentGuidance, "proofBindingsMissing"),
		"requiredNextActions":              anyStringArrayFromMap(agentGuidance, "requiredNextActions"),
		"sourceFailedRuleIds":              admit.StringSliceToAny(sourceFailedRuleIDs),
		"sourceWarningRuleIds":             admit.StringSliceToAny(sourceWarningRuleIDs),
		"touchedRuleIds":                   anyStringArrayFromMap(scopeEvidence, "touchedRuleIds"),
	}
	rec := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.gradual-adoption-guidance",
		ReportID:      guidanceID,
		State:         state,
		Summary: map[string]any{
			"blockedPreconditionCount":             len(stringArrayFromMap(agentGuidance, "blockedPreconditions")),
			"callerSuggestedAutofixCandidateCount": len(stringArrayFromMap(agentGuidance, "callerSuggestedAutofixCandidates")),
			"candidateBoundaryCount":               len(anyArrayFromMap(modernization, "candidateBoundaries")),
			"checkedScope":                         scopeEvidence["checkedScope"],
			"commandCount":                         len(stringArrayFromMap(agentGuidance, "commands")),
			"guidanceMode":                         guidanceMode,
			"proofBindingMissingCount":             len(stringArrayFromMap(agentGuidance, "proofBindingsMissing")),
			"requiredNextActionCount":              len(stringArrayFromMap(agentGuidance, "requiredNextActions")),
			"sourceFailedRuleCount":                len(sourceFailedRuleIDs),
			"sourceReportState":                    sourceReport["state"],
			"sourceWarningRuleCount":               len(sourceWarningRuleIDs),
			"touchedRuleCount":                     len(stringArrayFromMap(scopeEvidence, "touchedRuleIds")),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "guidance", Value: guidance},
			{Key: "sourceReport", Value: map[string]any{
				"reportId":   sourceReport["reportId"],
				"reportKind": sourceReport["reportKind"],
				"state":      sourceReport["state"],
			}},
		},
		RuleResults: guidanceRuleResults(guidanceMode, sourceReport["state"].(string), agentGuidance, modernization, failures, sourceFailedRuleIDs, sourceWarningRuleIDs, enforcementFailedRuleIDs),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	return guidanceResult{ExitCode: exitCode(rec), Guidance: guidance, Record: rec}, nil
}

func admitSourceReport(raw any) (map[string]any, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("sourceReport must be an object")
	}
	if err := admit.KnownKeys(record, []string{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}, "sourceReport"); err != nil {
		return nil, err
	}
	if !schemaVersionIsOne(record["schemaVersion"]) {
		return nil, fmt.Errorf("sourceReport schemaVersion must be 1")
	}
	reportID, err := admit.RuleID(record["reportId"], "sourceReport reportId")
	if err != nil {
		return nil, err
	}
	reportKind, err := admit.NonEmptyText(record["reportKind"], "sourceReport reportKind")
	if err != nil {
		return nil, err
	}
	state, err := admit.Enum(record["state"], sourceReportStates, "sourceReport state")
	if err != nil {
		return nil, err
	}
	ruleResults, err := admitSourceReportRuleResults(record["ruleResults"])
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"reportId":    reportID,
		"reportKind":  reportKind,
		"ruleResults": ruleResults,
		"state":       state,
	}, nil
}

func schemaVersionIsOne(raw any) bool {
	if admit.JSONNumberEquals(raw, 1) {
		return true
	}
	value, ok := raw.(int)
	return ok && value == 1
}

func admitSourceReportRuleResults(raw any) ([]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("sourceReport ruleResults must be an array")
	}
	results := make([]any, 0, len(values))
	for index, rawRule := range values {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("sourceReport ruleResults[%d] must be an object", index)
		}
		if err := admit.KnownKeys(rule, []string{"diagnostics", "message", "ruleId", "status"}, fmt.Sprintf("sourceReport ruleResults[%d]", index)); err != nil {
			return nil, err
		}
		ruleID, err := admit.RuleID(rule["ruleId"], fmt.Sprintf("sourceReport ruleResults[%d] ruleId", index))
		if err != nil {
			return nil, err
		}
		status, err := admit.Enum(rule["status"], sourceReportStates, fmt.Sprintf("sourceReport ruleResults[%d] status", index))
		if err != nil {
			return nil, err
		}
		results = append(results, map[string]any{
			"ruleId": ruleID,
			"status": status,
		})
	}
	return results, nil
}

func admitScopeEvidence(raw map[string]any, options GuidanceOptions, failures *[]string) map[string]any {
	if err := admit.KnownKeys(raw, []string{"basis", "checkedScope", "touchedRuleIds"}, "scopeEvidence"); err != nil {
		addErr(failures, err)
	}
	if raw["basis"] != "caller_provided_touched_rule_ids" {
		*failures = append(*failures, "scopeEvidence basis must be caller_provided_touched_rule_ids")
	}
	checkedScope := options.CheckedScope
	var err error
	if checkedScope == "" {
		checkedScope, err = adoptionmode.AdmitScope(raw["checkedScope"], "checkedScope")
	} else {
		checkedScope, err = adoptionmode.ValidateScopeValue(checkedScope, "checkedScope")
	}
	addErr(failures, err)
	touchedRuleIDs := options.TouchedRuleIDs
	if len(touchedRuleIDs) == 0 {
		touchedRuleIDs, err = sortedRuleIDArray(raw["touchedRuleIds"], "scopeEvidence touchedRuleIds")
		addErr(failures, err)
	} else {
		touchedRuleIDs, err = admit.SortedText(touchedRuleIDs, "scopeEvidence touchedRuleIds", true)
		addErr(failures, err)
	}
	return map[string]any{
		"basis":          "caller_provided_touched_rule_ids",
		"checkedScope":   checkedScope,
		"touchedRuleIds": admit.StringSliceToAny(touchedRuleIDs),
	}
}

func admitOwnerRoute(raw map[string]any, failures *[]string, context string) map[string]any {
	if err := admit.KnownKeys(raw, []string{"evidencePaths", "primaryOwner", "proofBindingPaths", "specPaths"}, context); err != nil {
		addErr(failures, err)
	}
	specPaths, err := sortedPaths(raw["specPaths"], context+" specPaths")
	addErr(failures, err)
	proofBindingPaths, err := sortedPaths(raw["proofBindingPaths"], context+" proofBindingPaths")
	addErr(failures, err)
	if len(specPaths) == 0 {
		*failures = append(*failures, context+" must declare at least one spec path")
	}
	if len(proofBindingPaths) == 0 {
		*failures = append(*failures, context+" must declare at least one proof binding path")
	}
	evidencePaths, err := sortedPaths(raw["evidencePaths"], context+" evidencePaths")
	addErr(failures, err)
	primaryOwner, err := text(raw["primaryOwner"], context+" primaryOwner")
	addErr(failures, err)
	return map[string]any{
		"evidencePaths":     admit.StringSliceToAny(evidencePaths),
		"primaryOwner":      primaryOwner,
		"proofBindingPaths": admit.StringSliceToAny(proofBindingPaths),
		"specPaths":         admit.StringSliceToAny(specPaths),
	}
}

func admitAgentGuidance(raw map[string]any, failures *[]string) map[string]any {
	if err := admit.KnownKeys(raw, []string{"artifactPath", "blockedPreconditions", "callerSuggestedAutofixCandidates", "commands", "minimalAdoptionPath", "proofBindingsMissing", "reportKind", "requiredNextActions", "routeQuestions", "schemaId"}, "agentGuidance"); err != nil {
		addErr(failures, err)
	}
	if raw["reportKind"] != "proofkit.gradual-adoption-guidance" {
		*failures = append(*failures, "agentGuidance reportKind must be proofkit.gradual-adoption-guidance")
	}
	questions, err := admit.SortedTextArray(raw["routeQuestions"], "agentGuidance routeQuestions", false)
	addErr(failures, err)
	for _, question := range standardQuestions {
		if !contains(questions, question) {
			*failures = append(*failures, fmt.Sprintf("agentGuidance routeQuestions must include %s", question))
		}
	}
	artifactPath, err := safePath(raw["artifactPath"], "agentGuidance artifactPath")
	addErr(failures, err)
	schemaID, err := admit.RuleID(raw["schemaId"], "agentGuidance schemaId")
	addErr(failures, err)
	requiredNextActions, err := preserveText(raw["requiredNextActions"], "agentGuidance requiredNextActions", true)
	addErr(failures, err)
	minimalAdoptionPath, err := preserveText(raw["minimalAdoptionPath"], "agentGuidance minimalAdoptionPath", false)
	addErr(failures, err)
	autofix, err := admit.SortedTextArray(raw["callerSuggestedAutofixCandidates"], "agentGuidance callerSuggestedAutofixCandidates", true)
	addErr(failures, err)
	commands, err := preserveDisplayCommands(raw["commands"], "agentGuidance commands", true)
	addErr(failures, err)
	missing, err := sortedRuleIDArray(raw["proofBindingsMissing"], "agentGuidance proofBindingsMissing")
	addErr(failures, err)
	blocked, err := admit.SortedTextArray(raw["blockedPreconditions"], "agentGuidance blockedPreconditions", true)
	addErr(failures, err)
	return map[string]any{
		"artifactPath":                     artifactPath,
		"blockedPreconditions":             admit.StringSliceToAny(blocked),
		"callerSuggestedAutofixCandidates": admit.StringSliceToAny(autofix),
		"commands":                         admit.StringSliceToAny(commands),
		"minimalAdoptionPath":              admit.StringSliceToAny(minimalAdoptionPath),
		"proofBindingsMissing":             admit.StringSliceToAny(missing),
		"reportKind":                       "proofkit.gradual-adoption-guidance",
		"requiredNextActions":              admit.StringSliceToAny(requiredNextActions),
		"routeQuestions":                   admit.StringSliceToAny(questions),
		"schemaId":                         schemaID,
	}
}

func admitModernization(raw any, failures *[]string) map[string]any {
	if raw == nil {
		return map[string]any{
			"candidateBoundaries":         []any{},
			"promoteOnlyAfterOwnerReview": true,
		}
	}
	record, ok := raw.(map[string]any)
	if !ok {
		*failures = append(*failures, "gradual adoption modernization must be an object")
		return map[string]any{
			"candidateBoundaries":         []any{},
			"promoteOnlyAfterOwnerReview": true,
		}
	}
	if err := admit.KnownKeys(record, []string{"candidateBoundaries", "promoteOnlyAfterOwnerReview"}, "gradual adoption modernization"); err != nil {
		addErr(failures, err)
	}
	if record["promoteOnlyAfterOwnerReview"] != true {
		*failures = append(*failures, "modernization promoteOnlyAfterOwnerReview must be true")
	}
	candidates := admitCandidateBoundaries(record["candidateBoundaries"], failures)
	return map[string]any{
		"candidateBoundaries":         candidates,
		"promoteOnlyAfterOwnerReview": true,
	}
}

func admitCandidateBoundaries(raw any, failures *[]string) []any {
	if raw == nil {
		return []any{}
	}
	values, ok := raw.([]any)
	if !ok {
		*failures = append(*failures, "modernization candidateBoundaries must be an array")
		return []any{}
	}
	candidates := make([]map[string]any, 0, len(values))
	ids := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			*failures = append(*failures, fmt.Sprintf("modernization candidateBoundaries[%d] must be an object", index))
			continue
		}
		candidate := admitCandidateBoundary(record, index, failures)
		candidates = append(candidates, candidate)
		ids = append(ids, candidate["boundaryId"].(string))
	}
	if _, err := admit.SortedText(ids, "modernization candidate boundary ids", true); err != nil {
		addErr(failures, err)
	}
	out := make([]any, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate)
	}
	return out
}

func admitCandidateBoundary(raw map[string]any, index int, failures *[]string) map[string]any {
	context := fmt.Sprintf("modernization candidateBoundaries[%d]", index)
	if err := admit.KnownKeys(raw, []string{"admissionState", "affectedPaths", "blockedPreconditions", "boundaryId", "candidateOwner", "contractWitnessRefs", "migrationRefs", "nativeWitnessRefs", "nonClaims", "observedFacts", "ownerQuestions", "proofBindingRefs", "requirementRefs", "uncertainties"}, context); err != nil {
		addErr(failures, err)
	}
	boundaryID, err := admit.RuleID(raw["boundaryId"], context+" boundaryId")
	addErr(failures, err)
	if raw["admissionState"] != "advisory" {
		*failures = append(*failures, context+" admissionState must be advisory")
	}
	candidateOwner, err := text(raw["candidateOwner"], context+" candidateOwner")
	addErr(failures, err)
	affectedPaths, err := sortedPaths(raw["affectedPaths"], context+" affectedPaths")
	addErr(failures, err)
	if len(affectedPaths) == 0 {
		*failures = append(*failures, context+" affectedPaths must be non-empty")
	}
	observedFacts, err := preserveText(raw["observedFacts"], context+" observedFacts", false)
	addErr(failures, err)
	uncertainties, err := preserveText(raw["uncertainties"], context+" uncertainties", false)
	addErr(failures, err)
	ownerQuestions, err := preserveText(raw["ownerQuestions"], context+" ownerQuestions", false)
	addErr(failures, err)
	requirementRefs, err := sortedRuleIDArray(raw["requirementRefs"], context+" requirementRefs")
	addErr(failures, err)
	proofBindingRefs, err := sortedPaths(raw["proofBindingRefs"], context+" proofBindingRefs")
	addErr(failures, err)
	nativeWitnessRefs, err := sortedPaths(raw["nativeWitnessRefs"], context+" nativeWitnessRefs")
	addErr(failures, err)
	contractWitnessRefs, err := sortedPaths(raw["contractWitnessRefs"], context+" contractWitnessRefs")
	addErr(failures, err)
	migrationRefs, err := sortedPaths(raw["migrationRefs"], context+" migrationRefs")
	addErr(failures, err)
	blockedPreconditions, err := admit.SortedTextArray(raw["blockedPreconditions"], context+" blockedPreconditions", true)
	addErr(failures, err)
	nonClaims, err := admit.SortedTextArray(raw["nonClaims"], context+" nonClaims", false)
	addErr(failures, err)
	if !contains(nonClaims, candidateBoundaryNonClaim) {
		*failures = append(*failures, context+" nonClaims must include candidate boundary advisory non-claim")
	}
	return map[string]any{
		"admissionState":       "advisory",
		"affectedPaths":        admit.StringSliceToAny(affectedPaths),
		"blockedPreconditions": admit.StringSliceToAny(blockedPreconditions),
		"boundaryId":           boundaryID,
		"candidateOwner":       candidateOwner,
		"contractWitnessRefs":  admit.StringSliceToAny(contractWitnessRefs),
		"migrationRefs":        admit.StringSliceToAny(migrationRefs),
		"nativeWitnessRefs":    admit.StringSliceToAny(nativeWitnessRefs),
		"nonClaims":            admit.StringSliceToAny(nonClaims),
		"observedFacts":        admit.StringSliceToAny(observedFacts),
		"ownerQuestions":       admit.StringSliceToAny(ownerQuestions),
		"proofBindingRefs":     admit.StringSliceToAny(proofBindingRefs),
		"requirementRefs":      admit.StringSliceToAny(requirementRefs),
		"uncertainties":        admit.StringSliceToAny(uncertainties),
	}
}

func sourceRuleIDs(sourceReport map[string]any, status string) []string {
	rules, _ := sourceReport["ruleResults"].([]any)
	ids := []string{}
	for _, rawRule := range rules {
		rule := rawRule.(map[string]any)
		if rule["status"] == status {
			ids = append(ids, rule["ruleId"].(string))
		}
	}
	sort.Strings(ids)
	if status == "failed" && sourceReport["state"] == "failed" && len(ids) == 0 {
		return []string{sourceReport["reportId"].(string)}
	}
	return ids
}

func guidanceModeFailures(mode string, checkedScope string, sourceReport map[string]any, agentGuidance map[string]any, modernization map[string]any, enforcementFailedRuleIDs []string) []string {
	failures := []string{}
	failures = append(failures, adoptionmode.ScopeFailures(mode, checkedScope)...)
	if mode == adoptionmode.EnforceAll && sourceReport["state"] == "failed" {
		failures = append(failures, "enforce-all fails closed when sourceReport is failed")
	}
	if mode == adoptionmode.EnforceTouched && len(enforcementFailedRuleIDs) > 0 {
		failures = append(failures, "enforce-touched fails closed for failed source rules inside checked scope")
	}
	if adoptionmode.IsEnforcing(mode) && len(stringArrayFromMap(agentGuidance, "proofBindingsMissing")) > 0 {
		failures = append(failures, "enforcement modes fail closed for missing proof bindings")
	}
	if adoptionmode.IsEnforcing(mode) && len(anyArrayFromMap(modernization, "candidateBoundaries")) > 0 {
		failures = append(failures, "enforcement modes require candidate boundaries to be owner-admitted before enforcement")
	}
	return failures
}

func hasActionableGap(sourceReport map[string]any, agentGuidance map[string]any, enforcementFailedRuleIDs []string) bool {
	return sourceReport["state"] != "passed" ||
		len(stringArrayFromMap(agentGuidance, "proofBindingsMissing")) > 0 ||
		len(stringArrayFromMap(agentGuidance, "blockedPreconditions")) > 0 ||
		len(enforcementFailedRuleIDs) > 0
}

func guidanceState(mode string, sourceReport map[string]any, agentGuidance map[string]any, failures []string) string {
	if len(failures) > 0 {
		return "failed"
	}
	if adoptionmode.IsEnforcing(mode) &&
		(sourceReport["state"] == "blocked" || len(stringArrayFromMap(agentGuidance, "blockedPreconditions")) > 0) {
		return "blocked"
	}
	return "passed"
}

func guidanceActionPlan(mode string, ownerRoute map[string]any, agentGuidance map[string]any, modernization map[string]any, sourceFailedRuleIDs []string, sourceWarningRuleIDs []string) []any {
	routeRefs := append(append(stringArrayFromMap(ownerRoute, "specPaths"), stringArrayFromMap(ownerRoute, "proofBindingPaths")...), stringArrayFromMap(ownerRoute, "evidencePaths")...)
	routeRefs = uniqueStrings(routeRefs)
	witnessRefs := append(append(sourceFailedRuleIDs, sourceWarningRuleIDs...), stringArrayFromMap(agentGuidance, "blockedPreconditions")...)
	witnessRefs = uniqueStrings(witnessRefs)
	actions := []any{
		map[string]any{
			"commands":     []any{},
			"evidenceRefs": admit.StringSliceToAny(routeRefs),
			"instruction":  "Load only the caller-owned spec, proof binding, and evidence routes needed for this module before editing.",
			"nonClaims":    []any{"This step does not make proofkit the owner of caller repository specifications."},
			"owner":        "consumer_repository",
			"phase":        "route",
			"stepId":       "proofkit.agent.route-owner",
		},
	}
	candidateRefs := candidateBoundaryRefs(anyArrayFromMap(modernization, "candidateBoundaries"))
	if len(candidateRefs) > 0 {
		actions = append(actions, map[string]any{
			"commands":     []any{},
			"evidenceRefs": admit.StringSliceToAny(candidateRefs),
			"instruction":  "Resolve advisory candidate boundaries by owner decision before creating stable requirements, proof bindings, or enforcement policy.",
			"nonClaims":    []any{"This step does not admit candidate boundaries as repository semantics."},
			"owner":        "consumer_repository",
			"phase":        "modernize-boundary",
			"stepId":       "proofkit.agent.resolve-candidate-boundaries",
		})
	}
	actions = append(actions,
		map[string]any{
			"commands":     []any{},
			"evidenceRefs": anyStringArrayFromMap(agentGuidance, "proofBindingsMissing"),
			"instruction":  "Keep human requirements, requirement-to-witness bindings, and native witness commands synchronized in the caller repository.",
			"nonClaims":    []any{"This step reports missing bindings but does not create or approve repository proof truth."},
			"owner":        "consumer_repository",
			"phase":        "bind",
			"stepId":       "proofkit.agent.bind-requirements",
		},
		map[string]any{
			"commands":     anyStringArrayFromMap(agentGuidance, "commands"),
			"evidenceRefs": admit.StringSliceToAny(witnessRefs),
			"instruction":  "Run the caller-owned native witness commands outside proofkit and feed their source report back into guidance.",
			"nonClaims":    []any{"Proofkit guidance does not execute native witnesses or turn skipped commands into passing proof."},
			"owner":        "consumer_repository",
			"phase":        "verify",
			"stepId":       "proofkit.agent.run-native-witnesses",
		},
		map[string]any{
			"commands":     []any{},
			"evidenceRefs": []any{},
			"instruction":  fmt.Sprintf("Promote beyond %s only after owner routes, bindings, native witnesses, and blocked preconditions are resolved by caller-owned evidence.", mode),
			"nonClaims":    []any{"This step does not approve rollout or organization-wide enforcement."},
			"owner":        "consumer_repository",
			"phase":        "promote",
			"stepId":       "proofkit.agent.promote-enforcement",
		},
	)
	return actions
}

func candidateBoundaryRefs(candidates []any) []string {
	refs := []string{}
	for _, raw := range candidates {
		candidate := raw.(map[string]any)
		refs = append(refs, candidate["boundaryId"].(string))
		refs = append(refs, stringArrayFromMap(candidate, "affectedPaths")...)
		refs = append(refs, stringArrayFromMap(candidate, "requirementRefs")...)
		refs = append(refs, stringArrayFromMap(candidate, "proofBindingRefs")...)
		refs = append(refs, stringArrayFromMap(candidate, "nativeWitnessRefs")...)
		refs = append(refs, stringArrayFromMap(candidate, "contractWitnessRefs")...)
		refs = append(refs, stringArrayFromMap(candidate, "migrationRefs")...)
		refs = append(refs, stringArrayFromMap(candidate, "blockedPreconditions")...)
	}
	return uniqueStrings(refs)
}

func guidanceRuleResults(mode string, sourceState string, agentGuidance map[string]any, modernization map[string]any, failures []string, sourceFailedRuleIDs []string, sourceWarningRuleIDs []string, enforcementFailedRuleIDs []string) []report.RuleResult {
	if len(failures) > 0 {
		results := make([]report.RuleResult, 0, len(failures))
		for index, failure := range failures {
			results = append(results, report.RuleResult{
				RuleID:      fmt.Sprintf("proofkit.gradual-adoption-guidance.failure.%03d", index+1),
				Status:      "failed",
				Message:     failure,
				Diagnostics: []report.Diagnostic{},
			})
		}
		return results
	}
	results := []report.RuleResult{{
		RuleID:      "proofkit.gradual-adoption-guidance.structure",
		Status:      "passed",
		Message:     "gradual adoption guidance is structurally admitted",
		Diagnostics: []report.Diagnostic{},
	}}
	if sourceState != "passed" {
		results = append(results, report.RuleResult{
			RuleID:  "proofkit.gradual-adoption-guidance.source-report",
			Status:  adoptionmode.NonEnforcingStatus(mode),
			Message: "source report is not passed",
			Diagnostics: []report.Diagnostic{
				{Key: "enforcementFailedRuleIds", Value: admit.StringSliceToAny(enforcementFailedRuleIDs)},
				{Key: "sourceFailedRuleIds", Value: admit.StringSliceToAny(sourceFailedRuleIDs)},
				{Key: "sourceReportState", Value: sourceState},
			},
		})
	}
	if len(stringArrayFromMap(agentGuidance, "proofBindingsMissing")) > 0 {
		results = append(results, report.RuleResult{
			RuleID:      "proofkit.gradual-adoption-guidance.missing-proof-bindings",
			Status:      adoptionmode.NonEnforcingStatus(mode),
			Message:     "caller reported missing proof bindings",
			Diagnostics: []report.Diagnostic{{Key: "proofBindingsMissing", Value: agentGuidance["proofBindingsMissing"]}},
		})
	}
	if len(stringArrayFromMap(agentGuidance, "blockedPreconditions")) > 0 {
		results = append(results, report.RuleResult{
			RuleID:      "proofkit.gradual-adoption-guidance.blocked-preconditions",
			Status:      adoptionmode.NonEnforcingStatus(mode),
			Message:     "caller reported blocked proof preconditions",
			Diagnostics: []report.Diagnostic{{Key: "blockedPreconditions", Value: agentGuidance["blockedPreconditions"]}},
		})
	}
	if len(sourceWarningRuleIDs) > 0 {
		status := "warning"
		if mode == adoptionmode.Observe {
			status = "skipped"
		}
		results = append(results, report.RuleResult{
			RuleID:      "proofkit.gradual-adoption-guidance.source-warnings",
			Status:      status,
			Message:     "source report emitted warnings",
			Diagnostics: []report.Diagnostic{{Key: "sourceWarningRuleIds", Value: admit.StringSliceToAny(sourceWarningRuleIDs)}},
		})
	}
	if candidates := anyArrayFromMap(modernization, "candidateBoundaries"); len(candidates) > 0 {
		status := "warning"
		if mode == adoptionmode.Observe {
			status = "skipped"
		}
		results = append(results, report.RuleResult{
			RuleID:      "proofkit.gradual-adoption-guidance.candidate-boundaries",
			Status:      status,
			Message:     "caller reported advisory candidate boundaries that require owner admission before enforcement",
			Diagnostics: []report.Diagnostic{{Key: "candidateBoundaryIds", Value: candidateBoundaryIDs(candidates)}},
		})
	}
	return results
}

func candidateBoundaryIDs(candidates []any) []any {
	ids := make([]string, 0, len(candidates))
	for _, raw := range candidates {
		ids = append(ids, raw.(map[string]any)["boundaryId"].(string))
	}
	sort.Strings(ids)
	return admit.StringSliceToAny(ids)
}

func sortedPaths(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	paths := make([]string, 0, len(values))
	for _, value := range values {
		path, err := safePath(value, context)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return admit.SortedText(paths, context, true)
}

func preserveText(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return nil, fmt.Errorf("%s must be unique", context)
		}
		seen[value] = struct{}{}
	}
	return values, nil
}

func preserveDisplayCommands(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for index, value := range values {
		command, err := admit.DisplayOnlyCommandText(value, context)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[command]; ok {
			return nil, fmt.Errorf("%s must be unique", context)
		}
		seen[command] = struct{}{}
		values[index] = command
	}
	return values, nil
}

func stringSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func jsonNumberOne() any {
	return json.Number("1")
}
