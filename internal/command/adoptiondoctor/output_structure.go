package adoptiondoctor

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

// Report text is native-normalized; nonempty text is its structural claim.
func ReportShape() jsonshape.Shape {
	id, text, path, count := identifierShape(), nonemptyText(), pathShape(), jsonshape.IntegerMinimum(0)
	mode, scope := jsonshape.Enum(adoptionmode.ValuesMap()), jsonshape.Enum(scopeValues())
	summary := []jsonshape.Property{jsonshape.Required("checkedScope", scope), jsonshape.Required("mode", mode)}
	for _, key := range []string{"blockedGapCount", "blockedPreconditionCount", "candidateBoundaryCount", "childReportCount", "enforcedGapCount",
		"forbiddenVocabularyCount", "gapCount", "ownerRouteCount", "staleAuthoritySurfaceCount", "touchedRuleCount"} {
		summary = append(summary, jsonshape.Required(key, count))
	}
	gap := jsonshape.Object(
		jsonshape.Required("evidenceRefs", jsonshape.Array(path, 0)), jsonshape.Required("gapId", text),
		jsonshape.Required("kind", jsonshape.Enum(gapKinds())), jsonshape.Required("message", text), jsonshape.Required("owner", text),
		jsonshape.Required("phase", jsonshape.Enum(gapPhases())), jsonshape.Required("ruleRefs", jsonshape.Array(id, 0)),
		jsonshape.Required("touched", jsonshape.Boolean()),
	)
	command := jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("commandId", text),
		jsonshape.Required("nonClaim", text), jsonshape.Required("owner", text))
	candidate := jsonshape.Object(
		jsonshape.Required("admissionState", jsonshape.Enum(admissionStates)), jsonshape.Required("affectedPaths", jsonshape.Array(path, 0)),
		jsonshape.Required("blockedPreconditions", jsonshape.Array(text, 0)), jsonshape.Required("boundaryId", id),
		jsonshape.Required("candidateOwner", text), jsonshape.Required("requirementRefs", jsonshape.Array(id, 0)),
	)
	// Absent optional caller records normalize to empty strings, never to null.
	optionalID := jsonshape.BoundedStringGrammar(`(?:`+admit.RuleIDPatternBody+`)?`, admit.MaxRuleIDBytes)
	// Absent caller values are empty strings; present values are admitted
	// non-blank text, so whitespace-only values are not emitted.
	empty, nonblank := jsonshape.StringLiteral(""), jsonshape.NonBlankString()
	stale := jsonshape.Object(
		jsonshape.Required("authoritySurfaces", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("authorityState", jsonshape.Enum(authorityStates)), jsonshape.Required("evidenceRefs", jsonshape.Array(path, 0)),
			jsonshape.Required("matchedVocabularyIds", jsonshape.Array(id, 0)), jsonshape.Required("nonClaims", jsonshape.Array(text, 0)),
			jsonshape.Required("owner", text), jsonshape.Required("path", path), jsonshape.Required("retiredScopeId", optionalID),
			jsonshape.Required("surfaceId", id), jsonshape.Required("touchedRuleIds", jsonshape.Array(id, 0)),
		), 0)),
		jsonshape.Required("currentPackage", jsonshape.OneOf(
			jsonshape.Object(jsonshape.Required("name", empty), jsonshape.Required("version", empty)),
			jsonshape.Object(jsonshape.Required("name", nonblank), jsonshape.Required("version", nonblank)),
		)),
		jsonshape.Required("forbiddenVocabulary", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("replacementText", jsonshape.OneOf(empty, nonblank)), jsonshape.Required("text", text),
			jsonshape.Required("vocabularyId", id),
		), 0)),
		jsonshape.Required("retiredScopes", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("allowedVocabularyIds", jsonshape.Array(id, 0)), jsonshape.Required("nonClaim", text),
			jsonshape.Required("pathPrefixes", jsonshape.Array(path, 1)), jsonshape.Required("scopeId", id),
		), 0)),
	)
	diagnostics := jsonshape.Tuple(
		report.DiagnosticStructure("doctor", jsonshape.Object(
			jsonshape.Required("checkedScope", scope), jsonshape.Required("doctorId", id), jsonshape.Required("mode", mode),
			jsonshape.Required("state", jsonshape.Enum(reportStates())), jsonshape.Required("touchedRuleIds", jsonshape.Array(id, 0)),
		)),
		report.DiagnosticStructure("gaps", jsonshape.Array(gap, 0)),
		report.DiagnosticStructure("routeCommands", jsonshape.Array(command, 0)),
		report.DiagnosticStructure("candidateBoundaries", jsonshape.Array(candidate, 0)),
		report.DiagnosticStructure("staleAuthority", stale),
		report.DiagnosticStructure("promotionReadiness", promotionReadinessShape()),
	)
	gapRuleIDs := map[string]struct{}{}
	for kind := range gapKinds() {
		gapRuleIDs[reportKind+"."+kind] = struct{}{}
	}
	rules := jsonshape.OneOf(
		report.RuleStructure(jsonshape.StringLiteral(noGapsRuleID), jsonshape.StringLiteral(statePassed), text, jsonshape.Tuple()),
		report.RuleStructure(jsonshape.Enum(gapRuleIDs), valuesShape(stateBlocked, stateFailed, stateSkipped, stateWarning), text, jsonshape.Tuple(
			report.DiagnosticStructure("gapId", text), report.DiagnosticStructure("phase", jsonshape.Enum(gapPhases())),
			report.DiagnosticStructure("touched", jsonshape.Boolean()),
		)),
	)
	return report.Structure(1, reportKind, jsonshape.Enum(reportStates()), jsonshape.Object(summary...), diagnostics, jsonshape.Array(rules, 1))
}

func OutputStructure() map[string]any {
	schema := ReportShape().JSONSchema()
	schema["description"] = "Complete report for admitted input, including advisory, failed and blocked states. Gap and rule order follows the native gap IDs; a gap-free report has exactly one passed no-gaps rule. Gap rules are blocked for unconditional preconditions and blocked child reports; other gaps are failed when enforced, warning in warn mode and otherwise skipped. Promotion readiness carries the seven fixed phases plus retire-stale-authority only when an enforced stale-authority gap blocks it. Absent stale-authority package, replacement text and retired-scope references normalize to empty strings. Native owners determine gap derivation, touched selection, enforcement, ordering and state/exit consistency; structural validity does not authenticate receipts, execute witnesses or approve promotion."
	return schema
}

// EnvelopeShape describes Build's sanitized carrier for one admitted doctor.
func EnvelopeShape(envelopeID string) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	evidence := jsonshape.BoundedArray(text, 0, agentenvelope.MaxActionEvidenceRefs)
	noGaps := jsonshape.Object(
		jsonshape.Required("candidateAction", text), jsonshape.Required("commandIds", jsonshape.Tuple()),
		jsonshape.Required("evidenceRefs", jsonshape.BoundedArray(text, 0, 1)), jsonshape.Required("instruction", text),
		jsonshape.Required("missingWitness", jsonshape.StringLiteral("")), jsonshape.Required("nonClaims", jsonshape.Tuple(text)),
		jsonshape.Required("observedFact", text), jsonshape.Required("owner", jsonshape.StringLiteral(consumerRepositoryOwner)),
		jsonshape.Required("phase", jsonshape.StringLiteral(phasePromote)), jsonshape.Required("proofCommand", jsonshape.StringLiteral(consumerRepositoryFullGate)),
		jsonshape.Required("rationale", text), jsonshape.Required("selectors", jsonshape.Object(
			jsonshape.Required("evidenceRefs", jsonshape.Tuple(text)), jsonshape.Required("ruleRefs", jsonshape.Tuple()),
		)),
		jsonshape.Required("stepId", jsonshape.StringLiteral(noGapsRuleID)), jsonshape.Required("uncertainty", text),
	)
	// Route and candidate selectors are independently present when the gap ID
	// has the corresponding owner prefix; both can apply to one gap.
	gapAction := jsonshape.Object(
		jsonshape.Required("candidateAction", text), jsonshape.Required("commandIds", texts), jsonshape.Required("evidenceRefs", evidence),
		jsonshape.Required("instruction", text),
		jsonshape.Required("missingWitness", valuesShape("", missingWitnessCandidateNotAdmitted, gapKindMissingNativeWitness, gapKindMissingOwnerRoute, gapKindMissingProofBinding)),
		jsonshape.Required("nonClaims", jsonshape.Tuple(text, text)), jsonshape.Required("observedFact", text),
		jsonshape.Required("observedFacts", jsonshape.Array(text, 1)), jsonshape.Required("owner", text),
		jsonshape.Required("ownerQuestions", texts), jsonshape.Required("phase", jsonshape.Enum(gapPhases())),
		jsonshape.Required("proofCommand", text), jsonshape.Required("rationale", text),
		jsonshape.Required("selectors", jsonshape.Object(
			jsonshape.Required("evidenceRefs", texts), jsonshape.Required("ruleRefs", texts),
			jsonshape.Optional("affectedPaths", texts), jsonshape.Optional("candidateBoundaryId", text),
			jsonshape.Optional("contractWitnessRefs", texts), jsonshape.Optional("nativeWitnessRefs", texts),
			jsonshape.Optional("ownerRouteId", text), jsonshape.Optional("proofBindingPaths", texts),
			jsonshape.Optional("proofBindingRefs", texts), jsonshape.Optional("specPaths", texts),
		)),
		jsonshape.Required("stepId", text), jsonshape.Required("uncertainties", jsonshape.Array(text, 1)), jsonshape.Required("uncertainty", text),
	)
	return agentenvelope.Structure(envelopeID, agentenvelope.StructureParts{
		ActionPlan:             jsonshape.BoundedArray(jsonshape.OneOf(noGaps, gapAction), 1, agentenvelope.MaxActionItems),
		BlockedPreconditions:   jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, agentenvelope.MaxBlockedPreconditions),
		Bounds:                 agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.StringLiteral(ownerDecisionAnswerKind)), 0, 1),
		Commands: jsonshape.BoundedArray(jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("commandId", text),
			jsonshape.Required("nonClaim", text), jsonshape.Required("owner", text)), 0, agentenvelope.MaxCommandRefs),
		ContextRefs: jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("kind", valuesShape(contextKindCandidateBoundary, contextKindOwnerRoute, contextKindStaleAuthoritySurface)),
			jsonshape.Required("nonClaim", text), jsonshape.Required("owner", text), jsonshape.Required("path", text), jsonshape.Required("refId", text),
		), 0, agentenvelope.MaxContextRefs),
		// The producer declares zero omitted items, so Build caps any
		// identity/reference/bound degradation at one summarized record.
		Omitted: jsonshape.BoundedArray(agentenvelope.OmissionStructure(), 0, 1), ReceiptRefs: jsonshape.Tuple(),
		RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport:   agentenvelope.SourceReportStructure(reportKind, identifierShape(), jsonshape.Null(), jsonshape.Enum(reportStates())),
	})
}

func EnvelopeStructure() map[string]any {
	schema := EnvelopeShape("placeholder").JSONSchema()
	// A suffixed admitted ID can become secret-shaped and is then redacted.
	schema["properties"].(map[string]any)["envelopeId"] = map[string]any{"anyOf": []any{
		fragment(jsonshape.StringSuffix(".agent-envelope")), fragment(jsonshape.StringLiteral(admit.DiagnosticRedactionMarker)),
	}}
	schema["description"] = "Agent envelope for admitted doctor input. A gap-free report yields one promote action; otherwise each gap yields one owner-specific action with observed facts, uncertainties and route/candidate selectors. Commands and context refs project owner routes, candidate affected paths and stale-authority surfaces; at most one owner clarification question appears. The source report is projected without stableHash. Strings are sanitized by the envelope owner and may be redacted; unsafe or ambiguous local identities, references and bounds violations are summarized by at most one omission record and degradation bounds. Native Build owns ordering, limits, reference pruning, redaction and stop reasons. Refused input uses the separately declared invalid-input envelope."
	return schema
}

// Every fixed promotion phase is required; retire-stale-authority appears only
// when an enforced stale-authority gap blocks it.
func promotionReadinessShape() jsonshape.Shape {
	return jsonshape.ObjectFromKeys(append(slices.Clone(promotionPhases), phaseRetireStaleAuthority), map[string]jsonshape.Shape{
		phaseBind:                 valuesShape(readinessCallerReview, readinessBlocked),
		phaseModernizeBoundary:    valuesShape(readinessCallerReview, readinessReady, readinessBlocked),
		phaseParity:               jsonshape.StringLiteral(readinessCallerReview),
		phasePromote:              valuesShape(readinessNotReady, readinessReady),
		phaseRetireStaleAuthority: jsonshape.StringLiteral(readinessBlocked),
		phaseRetirementReview:     jsonshape.StringLiteral(readinessCallerReview),
		phaseRoute:                valuesShape(readinessBlockedOwnerRoute, readinessReady),
		phaseVerify:               valuesShape(readinessCallerReview, readinessBlocked),
	}, phaseRetireStaleAuthority)
}

// Child report gap kinds are derived from the admitted non-passing states.
func gapKinds() map[string]struct{} {
	kinds := map[string]struct{}{}
	for _, kind := range []string{gapKindBlockedPrecondition, gapKindCandidateBoundaryNotAdmitted, gapKindMissingCommandRoute, gapKindMissingNativeWitness,
		gapKindMissingOwnerRoute, gapKindMissingProofBinding, gapKindStaleCurrentVocabulary, gapKindStaleRetiredScope} {
		kinds[kind] = struct{}{}
	}
	for state := range childReportStates {
		if state != statePassed {
			kinds[childReportGapKindPrefix+state] = struct{}{}
		}
	}
	return kinds
}

func gapPhases() map[string]struct{} {
	return map[string]struct{}{phaseBind: {}, phaseModernizeBoundary: {}, phaseRetireStaleAuthority: {}, phaseRoute: {}, phaseVerify: {}}
}

func reportStates() map[string]struct{} {
	return map[string]struct{}{stateBlocked: {}, stateFailed: {}, statePassed: {}}
}
