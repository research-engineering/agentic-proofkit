package requirementsourceadmission

import (
	"fmt"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

// The model owns evaluation and occurrence identity. These strings only render
// admitted violations; they do not independently decide any policy predicate.
func policyFailure(violation requirementsourcemodel.PolicyViolation) string {
	messages := map[string]string{
		"missing_proof_binding":          "active blocking requirement must route to proof bindings",
		"impact_review_required":         "active blocking requirement must require impact declaration on change",
		"proof_binding_review_required":  "active blocking requirement must require proof-binding review on change",
		"missing_deferral":               "deferred requirement must declare deferral policy",
		"unexpected_deferral":            "non-deferred requirement must not declare deferral policy",
		"missing_lifecycle_evidence":     "non-active requirement must declare lifecycle evidenceRefs",
		"unexpected_replacement":         "only superseded requirements may declare replacementRequirementIds",
		"missing_replacement":            "superseded requirement must declare replacementRequirementIds",
		"self_replacement":               "requirement must not replace itself",
		"dangling_replacement":           "replacement requirement must be present in the same source",
		"inactive_replacement":           "replacement requirement must be active in the same source",
		"nonactive_blocking_requirement": "non-active requirement must not remain blocking",
	}
	message, ok := messages[violation.Code]
	if !ok {
		message = "requirement source policy failed: " + violation.Code
	}
	if violation.RelatedRequirementID != "" && violation.Code != "self_replacement" {
		return fmt.Sprintf("%s: %s -> %s", message, violation.RequirementID, violation.RelatedRequirementID)
	}
	return fmt.Sprintf("%s: %s", message, violation.RequirementID)
}
