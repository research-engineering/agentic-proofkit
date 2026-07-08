package capabilitymapadmission

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.capability-map-admission"

var (
	authorityValues = map[string]struct{}{
		"caller_owned_observation": {},
	}
	modeValues = map[string]struct{}{
		"audit_from_code": {},
		"code_baseline":   {},
	}
	requiredEvidenceWitnessKind = map[string]string{
		"negative_test": "falsification",
		"positive_test": "positive",
	}
	anchorStatusValues = map[string]struct{}{
		"admitted":  {},
		"candidate": {},
		"missing":   {},
		"retired":   {},
	}
	dirtyStateValues = map[string]struct{}{
		"clean":          {},
		"dirty_excluded": {},
		"dirty_included": {},
		"unknown":        {},
	}
)

const (
	maxCapabilities                 = 32
	maxScenarioShapesPerCapability  = 16
	maxScenarioAnchors              = 256
	maxRequiredVerificationCommands = 128
	maxSummaryRunes                 = 280
	maxQuestionRunes                = 240
	maxQuestionsPerScenario         = 8
	maxTextItems                    = 16
	maxCommandRunes                 = 240
)

var commandNonClaims = []string{
	"Capability map admission does not scan repositories, read code, write files, execute witnesses, or approve merge.",
	"Capability map admission does not decide product truth, stable module boundaries, proof adequacy, receipt freshness, rollout, or production readiness.",
	"Capability map outputs are candidate-only until the consuming repository materializes and admits requirement sources, proof bindings, and test inventories.",
	"In code_baseline mode, Proofkit admits the caller's baseline declaration; it does not independently prove the code is correct.",
	"In audit_from_code mode, code observations remain untrusted and must be resolved by the consuming repository owner before stable requirement promotion.",
}

type input struct {
	Authority            string
	Capabilities         []capability
	MapID                string
	NonClaims            []string
	ProofScope           proofScope
	Repository           repository
	RequiredVerification []verificationCommand
	ScenarioAnchors      []scenarioAnchor
	TrustMode            string
}

type repository struct {
	NonClaims        []string
	PrimaryLanguages []string
	RepositoryID     string
}

type proofScope struct {
	BaseRef    *string
	DirtyState string
	HeadRef    *string
	NonClaims  []string
	ScopeID    string
}

type capability struct {
	CapabilityID   string
	NonClaims      []string
	OwnerID        string
	RiskClasses    []string
	ScenarioShapes []scenarioShape
	SourcePaths    []string
	Summary        string
}

type scenarioShape struct {
	CandidateRequirementID *string
	NonClaims              []string
	OwnerQuestions         []string
	RequiredEvidence       []string
	ScenarioID             string
	Summary                string
}

type scenarioAnchor struct {
	CommandRefs          []string
	FalsificationWitness bool
	NonClaims            []string
	PositiveWitness      bool
	ScenarioID           string
	Selector             string
	SourcePath           string
	Status               string
}

type verificationCommand struct {
	Command          string
	CommandID        string
	EnvironmentClass string
	NonClaims        []string
	Reason           string
}

type action struct {
	ActionID     string
	CapabilityID string
	CommandRefs  []string
	Message      string
	OwnerID      string
	ScenarioID   string
	Severity     string
	Type         string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	record, exitCode := buildReport(input)
	return record, exitCode, nil
}

func buildReport(input input) (report.Record, int) {
	anchorsByScenario := map[string][]scenarioAnchor{}
	for _, anchor := range input.ScenarioAnchors {
		anchorsByScenario[anchor.ScenarioID] = append(anchorsByScenario[anchor.ScenarioID], anchor)
	}
	commandsByID := map[string]verificationCommand{}
	for _, command := range input.RequiredVerification {
		commandsByID[command.CommandID] = command
	}

	failures := []string{}
	actions := []action{}
	candidateRequirements := []any{}
	candidateBindings := []any{}

	for _, capability := range input.Capabilities {
		for _, shape := range capability.ScenarioShapes {
			anchors := activeAnchors(anchorsByScenario[shape.ScenarioID])
			missingAnchor := len(anchors) == 0
			missingExecutableAnchor := !hasRequiredExecutableAnchor(anchors, shape.RequiredEvidence)
			missingCandidateRequirement := shape.CandidateRequirementID == nil

			if shape.CandidateRequirementID != nil {
				candidateRequirements = append(candidateRequirements, candidateRequirement(input, capability, shape))
				for _, anchor := range anchors {
					if isExecutableAnchor(anchor) && anchorSatisfiesRequiredEvidence(anchor, shape.RequiredEvidence) {
						candidateBindings = append(candidateBindings, candidateBinding(input, *shape.CandidateRequirementID, shape.RequiredEvidence, anchor))
					}
				}
			}

			if input.TrustMode == "code_baseline" {
				if missingCandidateRequirement {
					failures = append(failures, fmt.Sprintf("scenario %s must declare candidateRequirementId in code_baseline mode", shape.ScenarioID))
				}
				if missingAnchor {
					failures = append(failures, fmt.Sprintf("scenario %s must declare an active scenario anchor in code_baseline mode", shape.ScenarioID))
				} else if missingExecutableAnchor {
					failures = append(failures, fmt.Sprintf("scenario %s must declare an executable anchor satisfying requiredEvidence in code_baseline mode", shape.ScenarioID))
				}
				failures = append(failures, requiredEvidenceFailures(shape, anchors)...)
			}

			if missingAnchor {
				actions = append(actions, action{
					ActionID:     "proofkit.capability-map." + shape.ScenarioID + ".add-anchor",
					CapabilityID: capability.CapabilityID,
					Message:      "Add a scenario anchor with sourcePath, selector, and commandRefs before treating this scenario as covered.",
					OwnerID:      capability.OwnerID,
					ScenarioID:   shape.ScenarioID,
					Severity:     severityForMode(input.TrustMode, "missing_anchor"),
					Type:         "add_scenario_anchor",
				})
			}
			if len(shape.OwnerQuestions) > 0 {
				actions = append(actions, action{
					ActionID:     "proofkit.capability-map." + shape.ScenarioID + ".resolve-owner-questions",
					CapabilityID: capability.CapabilityID,
					CommandRefs:  commandRefsForAnchors(anchors),
					Message:      "Resolve owner questions before promoting candidate requirements to stable source records.",
					OwnerID:      capability.OwnerID,
					ScenarioID:   shape.ScenarioID,
					Severity:     "review",
					Type:         "resolve_owner_questions",
				})
			}
		}
	}

	failures = append(failures, crossReferenceFailures(input, commandsByID)...)
	sort.Strings(failures)
	sort.Slice(actions, func(left int, right int) bool {
		return actions[left].ActionID < actions[right].ActionID
	})

	state := "passed"
	exitCode := 0
	if len(failures) > 0 {
		state = "failed"
		exitCode = 1
	}

	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.MapID,
		State:         state,
		Summary: map[string]any{
			"agentActionCount":               len(actions),
			"candidateProofBindingSeedCount": len(candidateBindings),
			"candidateRequirementSeedCount":  len(candidateRequirements),
			"capabilityCount":                len(input.Capabilities),
			"failureCount":                   len(failures),
			"mapId":                          input.MapID,
			"repositoryId":                   input.Repository.RepositoryID,
			"scenarioAnchorCount":            len(input.ScenarioAnchors),
			"scenarioShapeCount":             scenarioShapeCount(input.Capabilities),
			"scopeId":                        input.ProofScope.ScopeID,
			"trustMode":                      input.TrustMode,
			"verificationCommandCount":       len(input.RequiredVerification),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "trustMode", Value: input.TrustMode},
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "instructions", Value: instructions(input.TrustMode)},
			{Key: "candidateRequirementSeeds", Value: candidateRequirements},
			{Key: "candidateProofBindingSeeds", Value: candidateBindings},
			{Key: "agentActionPlan", Value: actionsJSON(actions)},
		},
		RuleResults: []report.RuleResult{
			{
				RuleID:  "proofkit.capability-map-admission.shape",
				Status:  statusForFailures(failures),
				Message: shapeRuleMessage(failures),
			},
			{
				RuleID:  "proofkit.capability-map-admission.trust-mode." + strings.ReplaceAll(input.TrustMode, "_", "-"),
				Status:  statusForFailures(failures),
				Message: modeRuleMessage(input.TrustMode, failures),
			},
		},
		NonClaims: nonClaims(input),
	}, exitCode
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("capability map input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authority", "capabilities", "mapId", "nonClaims", "proofScope", "repository", "requiredVerification", "scenarioAnchors", "schemaVersion", "trustMode"}, "capability map input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("capability map schemaVersion must be 1")
	}
	mapID, err := admit.RuleID(record["mapId"], "capability map mapId")
	if err != nil {
		return input{}, err
	}
	authority, err := admit.Enum(record["authority"], authorityValues, "capability map authority")
	if err != nil {
		return input{}, err
	}
	trustMode, err := admit.Enum(record["trustMode"], modeValues, "capability map trustMode")
	if err != nil {
		return input{}, err
	}
	repository, err := admitRepository(record["repository"])
	if err != nil {
		return input{}, err
	}
	proofScope, err := admitProofScope(record["proofScope"])
	if err != nil {
		return input{}, err
	}
	capabilities, err := admitCapabilities(record["capabilities"])
	if err != nil {
		return input{}, err
	}
	anchors, err := admitScenarioAnchors(record["scenarioAnchors"])
	if err != nil {
		return input{}, err
	}
	verification, err := admitRequiredVerification(record["requiredVerification"])
	if err != nil {
		return input{}, err
	}
	nonClaims, err := admitOptionalNonClaims(record["nonClaims"], "capability map nonClaims")
	if err != nil {
		return input{}, err
	}
	return input{
		Authority:            authority,
		Capabilities:         capabilities,
		MapID:                mapID,
		NonClaims:            nonClaims,
		ProofScope:           proofScope,
		Repository:           repository,
		RequiredVerification: verification,
		ScenarioAnchors:      anchors,
		TrustMode:            trustMode,
	}, nil
}

func admitRepository(raw any) (repository, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return repository{}, fmt.Errorf("capability map repository must be an object")
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "primaryLanguages", "repositoryId"}, "capability map repository"); err != nil {
		return repository{}, err
	}
	repositoryID, err := admit.RuleID(record["repositoryId"], "capability map repositoryId")
	if err != nil {
		return repository{}, err
	}
	languages, err := admitOptionalSortedRuleIDs(record["primaryLanguages"], "capability map primaryLanguages", true)
	if err != nil {
		return repository{}, err
	}
	nonClaims, err := admitOptionalNonClaims(record["nonClaims"], "capability map repository nonClaims")
	if err != nil {
		return repository{}, err
	}
	return repository{NonClaims: nonClaims, PrimaryLanguages: languages, RepositoryID: repositoryID}, nil
}

func admitProofScope(raw any) (proofScope, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return proofScope{}, fmt.Errorf("capability map proofScope must be an object")
	}
	if err := admit.KnownKeys(record, []string{"baseRef", "dirtyState", "headRef", "nonClaims", "scopeId"}, "capability map proofScope"); err != nil {
		return proofScope{}, err
	}
	scopeID, err := admit.RuleID(record["scopeId"], "capability map proofScope.scopeId")
	if err != nil {
		return proofScope{}, err
	}
	dirtyState, err := admit.Enum(record["dirtyState"], dirtyStateValues, "capability map proofScope.dirtyState")
	if err != nil {
		return proofScope{}, err
	}
	baseRef, err := admit.NullableText(record["baseRef"], "capability map proofScope.baseRef")
	if err != nil {
		return proofScope{}, err
	}
	headRef, err := admit.NullableText(record["headRef"], "capability map proofScope.headRef")
	if err != nil {
		return proofScope{}, err
	}
	nonClaims, err := admitOptionalNonClaims(record["nonClaims"], "capability map proofScope nonClaims")
	if err != nil {
		return proofScope{}, err
	}
	return proofScope{BaseRef: baseRef, DirtyState: dirtyState, HeadRef: headRef, NonClaims: nonClaims, ScopeID: scopeID}, nil
}

func admitCapabilities(raw any) ([]capability, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("capability map capabilities must be a non-empty array")
	}
	if len(values) > maxCapabilities {
		return nil, fmt.Errorf("capability map capabilities must contain at most %d entries", maxCapabilities)
	}
	result := make([]capability, 0, len(values))
	ids := map[string]struct{}{}
	for index, value := range values {
		item, err := admitCapability(value, index)
		if err != nil {
			return nil, err
		}
		if _, exists := ids[item.CapabilityID]; exists {
			return nil, fmt.Errorf("capability map capabilityId values must be unique")
		}
		ids[item.CapabilityID] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].CapabilityID < result[right].CapabilityID
	})
	return result, nil
}

func admitCapability(raw any, index int) (capability, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return capability{}, fmt.Errorf("capability map capabilities[%d] must be an object", index)
	}
	context := fmt.Sprintf("capability map capabilities[%d]", index)
	if err := admit.KnownKeys(record, []string{"capabilityId", "nonClaims", "ownerId", "riskClasses", "scenarioShapes", "sourcePaths", "summary"}, context); err != nil {
		return capability{}, err
	}
	capabilityID, err := admit.RuleID(record["capabilityId"], context+".capabilityId")
	if err != nil {
		return capability{}, err
	}
	ownerID, err := admit.RuleID(record["ownerId"], context+".ownerId")
	if err != nil {
		return capability{}, err
	}
	summary, err := boundedText(record["summary"], context+".summary", maxSummaryRunes)
	if err != nil {
		return capability{}, err
	}
	sourcePaths, err := admit.PreserveSortedPathArray(record["sourcePaths"], context+".sourcePaths", false)
	if err != nil {
		return capability{}, err
	}
	riskClasses, err := admitOptionalSortedRuleIDs(record["riskClasses"], context+".riskClasses", true)
	if err != nil {
		return capability{}, err
	}
	shapes, err := admitScenarioShapes(record["scenarioShapes"], context)
	if err != nil {
		return capability{}, err
	}
	nonClaims, err := admitOptionalNonClaims(record["nonClaims"], context+".nonClaims")
	if err != nil {
		return capability{}, err
	}
	return capability{CapabilityID: capabilityID, NonClaims: nonClaims, OwnerID: ownerID, RiskClasses: riskClasses, ScenarioShapes: shapes, SourcePaths: sourcePaths, Summary: summary}, nil
}

func admitScenarioShapes(raw any, context string) ([]scenarioShape, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s.scenarioShapes must be a non-empty array", context)
	}
	if len(values) > maxScenarioShapesPerCapability {
		return nil, fmt.Errorf("%s.scenarioShapes must contain at most %d entries", context, maxScenarioShapesPerCapability)
	}
	result := make([]scenarioShape, 0, len(values))
	ids := map[string]struct{}{}
	for index, value := range values {
		item, err := admitScenarioShape(value, fmt.Sprintf("%s.scenarioShapes[%d]", context, index))
		if err != nil {
			return nil, err
		}
		if _, exists := ids[item.ScenarioID]; exists {
			return nil, fmt.Errorf("%s.scenarioShapes scenarioId values must be unique", context)
		}
		ids[item.ScenarioID] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ScenarioID < result[right].ScenarioID
	})
	return result, nil
}

func admitScenarioShape(raw any, context string) (scenarioShape, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return scenarioShape{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"candidateRequirementId", "nonClaims", "ownerQuestions", "requiredEvidence", "scenarioId", "summary"}, context); err != nil {
		return scenarioShape{}, err
	}
	scenarioID, err := admit.RuleID(record["scenarioId"], context+".scenarioId")
	if err != nil {
		return scenarioShape{}, err
	}
	summary, err := boundedText(record["summary"], context+".summary", maxSummaryRunes)
	if err != nil {
		return scenarioShape{}, err
	}
	candidateRequirementID, err := admitOptionalRuleID(record["candidateRequirementId"], context+".candidateRequirementId")
	if err != nil {
		return scenarioShape{}, err
	}
	requiredEvidence, err := admitOptionalSortedRuleIDs(record["requiredEvidence"], context+".requiredEvidence", true)
	if err != nil {
		return scenarioShape{}, err
	}
	ownerQuestions, err := admitOptionalSortedText(record["ownerQuestions"], context+".ownerQuestions", true)
	if err != nil {
		return scenarioShape{}, err
	}
	if len(ownerQuestions) > maxQuestionsPerScenario {
		return scenarioShape{}, fmt.Errorf("%s.ownerQuestions must contain at most %d entries", context, maxQuestionsPerScenario)
	}
	for index, question := range ownerQuestions {
		if len([]rune(question)) > maxQuestionRunes {
			return scenarioShape{}, fmt.Errorf("%s.ownerQuestions[%d] must contain at most %d runes", context, index, maxQuestionRunes)
		}
	}
	nonClaims, err := admitOptionalNonClaims(record["nonClaims"], context+".nonClaims")
	if err != nil {
		return scenarioShape{}, err
	}
	return scenarioShape{CandidateRequirementID: candidateRequirementID, NonClaims: nonClaims, OwnerQuestions: ownerQuestions, RequiredEvidence: requiredEvidence, ScenarioID: scenarioID, Summary: summary}, nil
}

func admitScenarioAnchors(raw any) ([]scenarioAnchor, error) {
	if raw == nil {
		return []scenarioAnchor{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("capability map scenarioAnchors must be an array")
	}
	if len(values) > maxScenarioAnchors {
		return nil, fmt.Errorf("capability map scenarioAnchors must contain at most %d entries", maxScenarioAnchors)
	}
	result := make([]scenarioAnchor, 0, len(values))
	ids := map[string]struct{}{}
	for index, value := range values {
		item, err := admitScenarioAnchor(value, index)
		if err != nil {
			return nil, err
		}
		key := item.ScenarioID + "\x00" + item.SourcePath + "\x00" + item.Selector
		if _, exists := ids[key]; exists {
			return nil, fmt.Errorf("capability map scenarioAnchors must be unique by scenarioId, sourcePath, and selector")
		}
		ids[key] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return scenarioAnchorSortKey(result[left]) < scenarioAnchorSortKey(result[right])
	})
	return result, nil
}

func admitScenarioAnchor(raw any, index int) (scenarioAnchor, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return scenarioAnchor{}, fmt.Errorf("capability map scenarioAnchors[%d] must be an object", index)
	}
	context := fmt.Sprintf("capability map scenarioAnchors[%d]", index)
	if err := admit.KnownKeys(record, []string{"commandRefs", "falsificationWitness", "nonClaims", "positiveWitness", "scenarioId", "selector", "sourcePath", "status"}, context); err != nil {
		return scenarioAnchor{}, err
	}
	scenarioID, err := admit.RuleID(record["scenarioId"], context+".scenarioId")
	if err != nil {
		return scenarioAnchor{}, err
	}
	selector, err := admit.NonEmptyText(record["selector"], context+".selector")
	if err != nil {
		return scenarioAnchor{}, err
	}
	if !strings.Contains(selector, "::") {
		return scenarioAnchor{}, fmt.Errorf("%s.selector must use source::selector form", context)
	}
	sourcePathRaw, err := admit.NonEmptyText(record["sourcePath"], context+".sourcePath")
	if err != nil {
		return scenarioAnchor{}, err
	}
	sourcePath, err := admit.SafeRepoRelativePath(sourcePathRaw, context+".sourcePath")
	if err != nil {
		return scenarioAnchor{}, err
	}
	if err := admit.StructuredSelectorSourcePath(selector, sourcePath, context+".selector"); err != nil {
		return scenarioAnchor{}, err
	}
	status, err := admit.Enum(record["status"], anchorStatusValues, context+".status")
	if err != nil {
		return scenarioAnchor{}, err
	}
	commandRefs, err := admitOptionalSortedRuleIDs(record["commandRefs"], context+".commandRefs", true)
	if err != nil {
		return scenarioAnchor{}, err
	}
	positiveWitness, err := admitOptionalBool(record["positiveWitness"], context+".positiveWitness")
	if err != nil {
		return scenarioAnchor{}, err
	}
	falsificationWitness, err := admitOptionalBool(record["falsificationWitness"], context+".falsificationWitness")
	if err != nil {
		return scenarioAnchor{}, err
	}
	nonClaims, err := admitOptionalNonClaims(record["nonClaims"], context+".nonClaims")
	if err != nil {
		return scenarioAnchor{}, err
	}
	return scenarioAnchor{CommandRefs: commandRefs, FalsificationWitness: falsificationWitness, NonClaims: nonClaims, PositiveWitness: positiveWitness, ScenarioID: scenarioID, Selector: selector, SourcePath: sourcePath, Status: status}, nil
}

func admitRequiredVerification(raw any) ([]verificationCommand, error) {
	if raw == nil {
		return []verificationCommand{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("capability map requiredVerification must be an array")
	}
	if len(values) > maxRequiredVerificationCommands {
		return nil, fmt.Errorf("capability map requiredVerification must contain at most %d entries", maxRequiredVerificationCommands)
	}
	result := make([]verificationCommand, 0, len(values))
	ids := map[string]struct{}{}
	for index, value := range values {
		item, err := admitVerificationCommand(value, index)
		if err != nil {
			return nil, err
		}
		if _, exists := ids[item.CommandID]; exists {
			return nil, fmt.Errorf("capability map requiredVerification commandId values must be unique")
		}
		ids[item.CommandID] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].CommandID < result[right].CommandID
	})
	return result, nil
}

func admitVerificationCommand(raw any, index int) (verificationCommand, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return verificationCommand{}, fmt.Errorf("capability map requiredVerification[%d] must be an object", index)
	}
	context := fmt.Sprintf("capability map requiredVerification[%d]", index)
	if err := admit.KnownKeys(record, []string{"command", "commandId", "environmentClass", "nonClaims", "reason"}, context); err != nil {
		return verificationCommand{}, err
	}
	commandID, err := admit.RuleID(record["commandId"], context+".commandId")
	if err != nil {
		return verificationCommand{}, err
	}
	command, err := admit.DisplayOnlyCommandText(record["command"], context+".command")
	if err != nil {
		return verificationCommand{}, err
	}
	if len([]rune(command)) > maxCommandRunes {
		return verificationCommand{}, fmt.Errorf("%s.command must contain at most %d runes", context, maxCommandRunes)
	}
	environmentClass, err := admit.RuleID(record["environmentClass"], context+".environmentClass")
	if err != nil {
		return verificationCommand{}, err
	}
	reason, err := boundedText(record["reason"], context+".reason", maxSummaryRunes)
	if err != nil {
		return verificationCommand{}, err
	}
	nonClaims, err := admitOptionalNonClaims(record["nonClaims"], context+".nonClaims")
	if err != nil {
		return verificationCommand{}, err
	}
	return verificationCommand{Command: command, CommandID: commandID, EnvironmentClass: environmentClass, NonClaims: nonClaims, Reason: reason}, nil
}

func crossReferenceFailures(input input, commandsByID map[string]verificationCommand) []string {
	failures := []string{}
	scenarioIDs := map[string]struct{}{}
	for _, capability := range input.Capabilities {
		for _, shape := range capability.ScenarioShapes {
			scenarioIDs[shape.ScenarioID] = struct{}{}
		}
	}
	for _, anchor := range input.ScenarioAnchors {
		if _, ok := scenarioIDs[anchor.ScenarioID]; !ok {
			failures = append(failures, fmt.Sprintf("scenario anchor %s must reference a declared scenario shape", anchor.ScenarioID))
		}
		if anchor.Status == "candidate" || anchor.Status == "admitted" {
			for _, commandRef := range anchor.CommandRefs {
				if _, ok := commandsByID[commandRef]; !ok {
					failures = append(failures, fmt.Sprintf("scenario anchor %s commandRef %s must reference requiredVerification", anchor.ScenarioID, commandRef))
				}
			}
		}
	}
	return failures
}

func activeAnchors(anchors []scenarioAnchor) []scenarioAnchor {
	result := []scenarioAnchor{}
	for _, anchor := range anchors {
		if anchor.Status == "candidate" || anchor.Status == "admitted" {
			result = append(result, anchor)
		}
	}
	return result
}

func hasRequiredExecutableAnchor(anchors []scenarioAnchor, requiredEvidence []string) bool {
	for _, anchor := range anchors {
		if isExecutableAnchor(anchor) && anchorSatisfiesRequiredEvidence(anchor, requiredEvidence) {
			return true
		}
	}
	return false
}

func isExecutableAnchor(anchor scenarioAnchor) bool {
	return len(anchor.CommandRefs) > 0 && (anchor.PositiveWitness || anchor.FalsificationWitness)
}

func anchorSatisfiesRequiredEvidence(anchor scenarioAnchor, requiredEvidence []string) bool {
	for _, required := range requiredEvidence {
		switch requiredEvidenceWitnessKind[required] {
		case "positive":
			if !anchor.PositiveWitness {
				return false
			}
		case "falsification":
			if !anchor.FalsificationWitness {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func requiredEvidenceFailures(shape scenarioShape, anchors []scenarioAnchor) []string {
	failures := []string{}
	for _, required := range shape.RequiredEvidence {
		requiredKind, ok := requiredEvidenceWitnessKind[required]
		if !ok {
			failures = append(failures, fmt.Sprintf("scenario %s requiredEvidence %s is unsupported", shape.ScenarioID, required))
			continue
		}
		satisfied := false
		for _, anchor := range anchors {
			if !isExecutableAnchor(anchor) {
				continue
			}
			if requiredKind == "positive" && anchor.PositiveWitness {
				satisfied = true
			}
			if requiredKind == "falsification" && anchor.FalsificationWitness {
				satisfied = true
			}
		}
		if !satisfied {
			failures = append(failures, fmt.Sprintf("scenario %s requiredEvidence %s requires an executable %s witness anchor", shape.ScenarioID, required, requiredKind))
		}
	}
	return failures
}

func candidateRequirement(input input, capability capability, shape scenarioShape) map[string]any {
	return map[string]any{
		"claimLevel":         "candidate",
		"sourceTrustMode":    input.TrustMode,
		"promotionState":     promotionState(input.TrustMode),
		"nonClaims":          admit.StringSliceToAny(sortedUnique(append(append([]string{}, capability.NonClaims...), shape.NonClaims...))),
		"ownerId":            capability.OwnerID,
		"requirementId":      *shape.CandidateRequirementID,
		"requiredEvidence":   admit.StringSliceToAny(shape.RequiredEvidence),
		"sourceCapabilityId": capability.CapabilityID,
		"sourceScenarioId":   shape.ScenarioID,
		"statementSeed":      shape.Summary,
	}
}

func candidateBinding(input input, requirementID string, requiredEvidence []string, anchor scenarioAnchor) map[string]any {
	witnessKinds := []string{}
	if anchor.PositiveWitness {
		witnessKinds = append(witnessKinds, "positive")
	}
	if anchor.FalsificationWitness {
		witnessKinds = append(witnessKinds, "falsification")
	}
	return map[string]any{
		"commandRefs":             admit.StringSliceToAny(anchor.CommandRefs),
		"evidenceAuthority":       evidenceAuthority(input.TrustMode),
		"executableEvidenceState": executableEvidenceState(input.TrustMode),
		"nonClaims":               admit.StringSliceToAny(anchor.NonClaims),
		"promotionState":          promotionState(input.TrustMode),
		"requiredEvidence":        admit.StringSliceToAny(requiredEvidence),
		"requirementId":           requirementID,
		"scenarioId":              anchor.ScenarioID,
		"selector":                anchor.Selector,
		"sourcePath":              anchor.SourcePath,
		"state":                   "candidate",
		"witnessKinds":            admit.StringSliceToAny(witnessKinds),
	}
}

func evidenceAuthority(mode string) string {
	if mode == "code_baseline" {
		return "caller_owned_executable_anchor"
	}
	return "untrusted_code_observation"
}

func executableEvidenceState(mode string) string {
	if mode == "code_baseline" {
		return "candidate_executable_anchor"
	}
	return "not_executable_until_owner_materialized"
}

func promotionState(mode string) string {
	if mode == "code_baseline" {
		return "candidate_requires_admission"
	}
	return "owner_review_required"
}

func instructions(mode string) []any {
	if mode == "code_baseline" {
		return []any{
			"Review candidateRequirementSeeds and materialize accepted records into requirements.v1.json.",
			"Run requirement-source-admission after materialization.",
			"Materialize candidateProofBindingSeeds for accepted scenarios and run requirement-bindings.",
			"Create or update test-evidence-inventory records from native tests before claiming coverage.",
		}
	}
	return []any{
		"Treat code observations as untrusted hypotheses.",
		"Resolve ownerQuestions before materializing any stable requirement.",
		"Add falsification witnesses and command refs for each accepted scenario.",
		"Run requirement-source-admission, requirement-bindings, test-evidence-inventory, and requirement-coverage-view only after owner materialization.",
	}
}

func actionsJSON(actions []action) []any {
	result := make([]any, 0, len(actions))
	for _, action := range actions {
		result = append(result, map[string]any{
			"actionId":     action.ActionID,
			"capabilityId": action.CapabilityID,
			"commandRefs":  admit.StringSliceToAny(action.CommandRefs),
			"message":      action.Message,
			"ownerId":      action.OwnerID,
			"scenarioId":   action.ScenarioID,
			"severity":     action.Severity,
			"type":         action.Type,
		})
	}
	return result
}

func commandRefsForAnchors(anchors []scenarioAnchor) []string {
	values := []string{}
	for _, anchor := range anchors {
		values = append(values, anchor.CommandRefs...)
	}
	return sortedUnique(values)
}

func scenarioShapeCount(capabilities []capability) int {
	count := 0
	for _, capability := range capabilities {
		count += len(capability.ScenarioShapes)
	}
	return count
}

func nonClaims(input input) []any {
	values := append([]string{}, commandNonClaims...)
	values = append(values, input.NonClaims...)
	values = append(values, input.Repository.NonClaims...)
	values = append(values, input.ProofScope.NonClaims...)
	for _, capability := range input.Capabilities {
		values = append(values, capability.NonClaims...)
		for _, shape := range capability.ScenarioShapes {
			values = append(values, shape.NonClaims...)
		}
	}
	for _, anchor := range input.ScenarioAnchors {
		values = append(values, anchor.NonClaims...)
	}
	for _, command := range input.RequiredVerification {
		values = append(values, command.NonClaims...)
	}
	return admit.StringSliceToAny(sortedUnique(values))
}

func shapeRuleMessage(failures []string) string {
	if len(failures) == 0 {
		return "Capability map structural references are admitted."
	}
	return strings.Join(failures, "; ")
}

func modeRuleMessage(mode string, failures []string) string {
	if len(failures) > 0 {
		return "Capability map mode preconditions are not satisfied."
	}
	if mode == "code_baseline" {
		return "Code baseline mode has candidate requirement ids and executable anchors for admitted scenarios."
	}
	return "Audit-from-code mode emitted candidate-only guidance without trusting code as stable requirement truth."
}

func statusForFailures(failures []string) string {
	if len(failures) > 0 {
		return "failed"
	}
	return "passed"
}

func severityForMode(mode string, condition string) string {
	if mode == "code_baseline" && condition == "missing_anchor" {
		return "blocking"
	}
	return "review"
}

func scenarioAnchorSortKey(anchor scenarioAnchor) string {
	return anchor.ScenarioID + "\x00" + anchor.SourcePath + "\x00" + anchor.Selector
}

func admitOptionalRuleID(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := admit.RuleID(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func admitOptionalSortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	values, err := admit.PreserveSortedTextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	if len(values) > maxTextItems {
		return nil, fmt.Errorf("%s must contain at most %d entries", context, maxTextItems)
	}
	return values, nil
}

func admitOptionalSortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := admitOptionalSortedText(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if _, err := admit.RuleID(value, context); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func admitOptionalNonClaims(raw any, context string) ([]string, error) {
	values, err := admitOptionalSortedText(raw, context, true)
	if err != nil {
		return nil, err
	}
	if len(values) > 12 {
		return nil, fmt.Errorf("%s must contain at most 12 entries", context)
	}
	for index, value := range values {
		if len([]rune(value)) > 240 {
			return nil, fmt.Errorf("%s[%d] must contain at most 240 runes", context, index)
		}
	}
	return values, nil
}

func admitOptionalBool(raw any, context string) (bool, error) {
	if raw == nil {
		return false, nil
	}
	value, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be boolean", context)
	}
	return value, nil
}

func boundedText(raw any, context string, maxRunes int) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if len([]rune(value)) > maxRunes {
		return "", fmt.Errorf("%s must contain at most %d runes", context, maxRunes)
	}
	return value, nil
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value == "" {
			continue
		}
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
