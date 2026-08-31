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
			"role":          contextRole(ref.RefKind),
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
	blocked := []map[string]any{}
	if value.Decision.OutputKind == "next_action" {
		prompt := value.Prompt
		actionPlan = append(actionPlan, map[string]any{
			"commandIds":   []any{},
			"evidenceRefs": stringsValue(contextRefIDs(value.Closure.Retained)),
			"instruction":  prompt["candidateAction"],
			"nonClaims":    []any{promptNonClaim},
			"owner":        prompt["ownerOrEscalationTarget"],
			"phase":        value.Decision.ActiveStageID,
			"rationale":    "The admitted checkpoint relation selects exactly one next action for the active stage.",
			"stepId":       "proofkit.change-workflow-plan.next-action",
		})
		if value.Input.GoverningAuthorityRefID == nil {
			blocked = append(blocked, map[string]any{
				"description":    missingOwnerStop,
				"evidenceRefs":   []any{},
				"nonClaim":       "This blocker does not identify or authorize a consuming-repository owner.",
				"owner":          "consumer_repository",
				"preconditionId": "proofkit.change-workflow-plan.missing-governing-authority",
			})
		}
	}
	sourceHash, err := stableHash(value.Plan)
	if err != nil {
		return nil, err
	}
	envelope := agentenvelope.Build(agentenvelope.Input{
		ActionPlan:           actionPlan,
		BlockedPreconditions: blocked,
		Bounds: map[string]any{
			"escalation":      "Caller must inspect omitted context or unresolved governing authority before mutation.",
			"fanout":          envelopeFanout(len(omitted), len(blocked)),
			"maxActionItems":  len(actionPlan),
			"maxCommandRefs":  0,
			"maxContextRefs":  len(contextRefs),
			"maxOmittedItems": len(omitted),
			"maxReceiptRefs":  0,
			"maxTokenBudget":  nil,
			"nonClaim":        "Bounds count emitted records only and do not prove tokenizer-specific cost or semantic sufficiency.",
			"omittedCount":    len(value.Closure.Omitted),
		},
		ClarificationQuestion: []map[string]any{},
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

func stableHash(value map[string]any) (string, error) {
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func contextRole(kind string) string {
	if kind == "authority" {
		return "semantic_owner"
	}
	if kind == "finding" {
		return "review_finding"
	}
	if kind == "witness" {
		return "proof_binding"
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
