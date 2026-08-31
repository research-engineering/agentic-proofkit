package changeworkflowplan

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func agentEnvelope(value projection) (map[string]any, error) {
	contextRefs := make([]map[string]any, 0, len(value.Closure.Retained))
	for _, ref := range value.Closure.Retained {
		contextRefs = append(contextRefs, map[string]any{
			"kind":          ref.RefKind,
			"nonClaim":      "Caller-declared context does not prove source truth, freshness, completeness, or authority.",
			"owner":         "consumer_repository",
			"purpose":       "Admitted change-workflow context selected by least dependency closure.",
			"ref":           ref.ArtifactPath,
			"refId":         ref.RefID,
			"role":          contextRole(ref, value.Input.GoverningAuthorityRefID),
			"subjectDigest": ref.SubjectDigest,
		})
	}
	omitted := []map[string]any{}
	if len(value.Closure.Omitted) > 0 {
		omitted = append(omitted, map[string]any{
			"kind":         "context_ref",
			"nonClaim":     "Omitted context remains caller-owned and may require a wider or full gate.",
			"omissionId":   "proofkit.change-workflow-plan.omitted-context",
			"omittedCount": len(value.Closure.Omitted),
			"reason":       "candidate_not_required_by_least_dependency_closure",
		})
	}
	actionPlan := []map[string]any{}
	blocked, clarifications := envelopeBlockers(value, workflowCatalog)
	if value.Decision.OutputKind == "next_action" {
		if len(blocked) == 0 {
			prompt := value.Prompt
			action := map[string]any{
				"commandIds":   []any{},
				"evidenceRefs": stringsValue(contextRefIDs(value.Closure.Retained)),
				"instruction":  prompt["candidateAction"],
				"nonClaims":    []any{promptNonClaim},
				"owner":        prompt["ownerOrEscalationTarget"],
				"outputKind":   value.Decision.OutputKind,
				"phase":        value.Decision.ActiveStageID,
				"rationale":    "The admitted checkpoint relation selects exactly one next action for the active stage.",
				"stepId":       "proofkit.change-workflow-plan.next-action",
			}
			if value.Decision.SuccessorStateDelta != nil {
				action["successorStateDelta"] = successorValue(*value.Decision.SuccessorStateDelta)
			}
			if value.Input.Checkpoint != nil && value.Input.Checkpoint.SubjectRefID != "" {
				action["subjectDigest"] = value.Input.Checkpoint.SubjectDigest
				action["subjectRefId"] = value.Input.Checkpoint.SubjectRefID
			}
			actionPlan = append(actionPlan, action)
		}
	} else {
		actionPlan = append(actionPlan, map[string]any{
			"commandIds":   []any{},
			"evidenceRefs": stringsValue(contextRefIDs(value.Closure.Retained)),
			"instruction":  terminalStop,
			"nonClaims":    []any{promptNonClaim},
			"outputKind":   value.Decision.OutputKind,
			"owner":        "consumer_repository",
			"phase":        "terminal",
			"rationale":    "The complete stage prefix and null checkpoint select the disjoint terminal workflow variant.",
			"stepId":       "proofkit.change-workflow-plan.workflow-complete",
		})
	}
	sourceHash, err := stableHash(value.Plan)
	if err != nil {
		return nil, err
	}
	envelope := agentenvelope.Build(agentenvelope.Input{
		ActionPlan:           actionPlan,
		BlockedPreconditions: blocked,
		Bounds: map[string]any{
			"escalation":                "Caller must inspect omitted context or resolve blocked authority and witness preconditions before mutation or verification.",
			"fanout":                    envelopeFanout(len(omitted), len(blocked)),
			"maxActionEvidenceRefs":     len(value.Closure.Retained),
			"maxActionItems":            len(actionPlan),
			"maxBlockedPreconditions":   len(blocked),
			"maxClarificationQuestions": len(clarifications),
			"maxCommandRefs":            0,
			"maxContextRefs":            len(contextRefs),
			"maxOmittedItems":           len(omitted),
			"maxReceiptRefs":            0,
			"maxRouteQuestions":         3,
			"maxTokenBudget":            nil,
			"nonClaim":                  "Bounds count emitted records only and do not prove tokenizer-specific cost or semantic sufficiency.",
			"omittedCount":              len(value.Closure.Omitted),
		},
		ClarificationQuestion: clarifications,
		Commands:              []map[string]any{},
		ContextRefs:           contextRefs,
		EnvelopeID:            "proofkit.change-workflow-plan.agent-envelope",
		NonClaims:             boundaryNonClaims,
		Omitted:               omitted,
		ReceiptRefs:           []map[string]any{},
		RouteQuestions: []map[string]any{
			workflowQuestion("proofkit.agent.question.what-changed", "what changed", contextRefIDs(value.Closure.Retained)),
			workflowQuestion("proofkit.agent.question.what-proves-it", "what proves it", contextRefIDs(value.Closure.Retained)),
			workflowQuestion("proofkit.agent.question.who-owns-it", "who owns it", governingEvidence(value.Input.GoverningAuthorityRefID)),
		},
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Plan identity does not authenticate caller context or prove action execution.",
			"reportId":    reportKind,
			"reportKind":  reportKind,
			"stableHash":  sourceHash,
			"state":       "passed",
		},
	})
	if err := enforceJSONCap(envelope); err != nil {
		return nil, err
	}
	return envelope, nil
}

func envelopeBlockers(value projection, catalog workflowCatalogDefinition) ([]map[string]any, []map[string]any) {
	if value.Decision.OutputKind != "next_action" {
		return []map[string]any{}, []map[string]any{}
	}
	blocked := []map[string]any{}
	clarifications := []map[string]any{}
	if catalog.ActiveActionsRequireGoverningAuthority && value.Input.GoverningAuthorityRefID == nil {
		blocked = append(blocked, map[string]any{
			"description":    missingOwnerStop,
			"evidenceRefs":   []any{},
			"nonClaim":       "This blocker does not identify or authorize a consuming-repository owner.",
			"owner":          "consumer_repository",
			"preconditionId": "proofkit.change-workflow-plan.missing-governing-authority",
		})
		clarifications = append(clarifications, map[string]any{
			"askWhen":            "No governing authority ref is admitted for the active workflow stage.",
			"blocking":           true,
			"evidenceRefs":       []any{},
			"expectedAnswerKind": "governing_authority_ref",
			"nonClaim":           "Naming an authority ref does not prove its content, scope, or authority.",
			"owner":              "consumer_repository",
			"question":           "Which admitted caller-owned context ref is the governing semantic authority for this stage?",
			"questionId":         "proofkit.change-workflow-plan.clarify-governing-authority",
		})
	}
	if value.Decision.RequiresSubject && (value.Input.Checkpoint == nil || value.Input.Checkpoint.SubjectRefID == "") {
		retainedRefIDs := contextRefIDs(value.Closure.Retained)
		blocked = append(blocked, map[string]any{
			"description":    "The active workflow action requires one admitted artifact subject and equal digest.",
			"evidenceRefs":   stringsValue(retainedRefIDs),
			"nonClaim":       "A declared artifact subject does not prove its content, freshness, review state, or suitability.",
			"owner":          "consumer_repository",
			"preconditionId": "proofkit.change-workflow-plan.missing-action-subject",
		})
		clarifications = append(clarifications, map[string]any{
			"askWhen":            "The selected action requires a subject but the admitted checkpoint has no artifact identity.",
			"blocking":           true,
			"evidenceRefs":       stringsValue(retainedRefIDs),
			"expectedAnswerKind": "artifact_subject_ref",
			"nonClaim":           "Supplying an artifact ref does not authenticate or approve the referenced subject.",
			"owner":              "consumer_repository",
			"question":           "Which admitted artifact ref and digest identify the exact subject for this action?",
			"questionId":         "proofkit.change-workflow-plan.clarify-action-subject",
		})
	}
	witnessRefIDs := contextRefIDsOfKind(value.Closure.Retained, "witness")
	if value.Decision.RequiresWitness && len(witnessRefIDs) == 0 {
		retainedRefIDs := contextRefIDs(value.Closure.Retained)
		blocked = append(blocked, map[string]any{
			"description":    "Verification requires a retained caller-owned witness ref; use native-evidence-guidance to define repository-specific positive controls and near-miss falsifiers.",
			"evidenceRefs":   stringsValue(retainedRefIDs),
			"nonClaim":       "A declared witness ref does not prove execution, correctness, freshness, or command success.",
			"owner":          "consumer_repository",
			"preconditionId": "proofkit.change-workflow-plan.missing-consumer-witness",
		})
		clarifications = append(clarifications, map[string]any{
			"askWhen":            "The active verification stage has no retained caller-owned witness ref.",
			"blocking":           true,
			"evidenceRefs":       stringsValue(retainedRefIDs),
			"expectedAnswerKind": "consumer_witness_ref",
			"nonClaim":           "Supplying a witness ref does not execute or validate the referenced native evidence.",
			"owner":              "consumer_repository",
			"question":           "Which admitted witness ref binds the consuming repository's positive controls and independent near-miss falsifiers?",
			"questionId":         "proofkit.change-workflow-plan.clarify-consumer-witness",
		})
	}
	return blocked, clarifications
}

func stableHash(value map[string]any) (string, error) {
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func contextRole(ref contextRef, governingAuthorityRefID *string) string {
	if governingAuthorityRefID != nil && ref.RefID == *governingAuthorityRefID {
		return "semantic_owner"
	}
	if ref.RefKind == "finding" {
		return "review_finding"
	}
	if ref.RefKind == "witness" {
		return "proof_binding"
	}
	if ref.RefKind == "artifact" {
		return "evidence"
	}
	return "owner_surface"
}

func envelopeFanout(omitted int, blocked int) string {
	if omitted > 0 || blocked > 0 {
		return "wide_or_full_gate_required"
	}
	return "bounded"
}

func workflowQuestion(id string, question string, refs []string) map[string]any {
	return map[string]any{
		"evidenceRefs": stringsValue(refs),
		"nonClaim":     "Routing questions do not prove caller context completeness or answer truth.",
		"question":     question,
		"questionId":   id,
	}
}

func governingEvidence(value *string) []string {
	if value == nil {
		return []string{}
	}
	return []string{*value}
}
