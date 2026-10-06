package producerpolicyselfproof

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	id, text := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString()
	digest := jsonshape.StringGrammar(`sha256:[a-f0-9]{64}`)
	change := jsonshape.Object(
		jsonshape.Required("artifactRetentionRuleRef", text), jsonshape.Required("changeId", id), jsonshape.Required("changeKind", jsonshape.Enum(changeKindSet)),
		jsonshape.Required("environmentClass", id), jsonshape.Required("evidenceRefs", jsonshape.Array(text, 1)),
		jsonshape.Required("fromAdmissionLevel", jsonshape.Nullable(jsonshape.Enum(admissionLevelSet))),
		jsonshape.Required("nonClaim", text), jsonshape.Required("nonClaimRefs", jsonshape.Array(id, 0)),
		jsonshape.Required("producerClass", id), jsonshape.Required("producerId", id), jsonshape.Required("proofClass", id),
		jsonshape.Required("provenanceRuleRef", text), jsonshape.Required("receiptKind", id), jsonshape.Required("toAdmissionLevel", jsonshape.Enum(admissionLevelSet)),
	)
	receipt := jsonshape.Object(
		jsonshape.Required("artifactRetentionRuleRef", text), jsonshape.Required("environmentClass", id), jsonshape.Required("evidenceRef", text),
		jsonshape.Required("nonClaim", text), jsonshape.Required("nonClaimRefs", jsonshape.Array(id, 0)),
		jsonshape.Required("producerAdmissionClass", jsonshape.Enum(admissionLevelSet)), jsonshape.Required("producerClass", id),
		jsonshape.Required("producerId", id), jsonshape.Required("proofClass", id), jsonshape.Required("proofReceiptDigest", digest),
		jsonshape.Required("proofReceiptRef", text), jsonshape.Required("provenanceRuleRef", text), jsonshape.Required("receiptId", id),
		jsonshape.Required("receiptKind", id), jsonshape.Required("receiptStatus", jsonshape.Enum(receiptStatusSet)),
		jsonshape.Required("satisfiesMergeObligation", jsonshape.Boolean()), jsonshape.Required("usedForPolicyChangeId", id),
	)
	schema := jsonshape.Object(
		jsonshape.Required("admissionChanges", jsonshape.Array(change, 0)), jsonshape.Required("baselinePolicyDigest", digest),
		jsonshape.Required("guardId", id), jsonshape.Required("mergeObligationReceiptRefs", jsonshape.Array(receipt, 0)),
		jsonshape.Required("nonClaimRefs", jsonshape.Array(id, 0)), jsonshape.Required("nonClaims", jsonshape.Array(text, 0)),
		jsonshape.Required("policyChangeDigest", digest), jsonshape.Required("policyChangeId", id), jsonshape.Required("policyId", id),
		jsonshape.Required("policyOwner", text), jsonshape.Required("policySurfaceRefs", jsonshape.Array(text, 1)),
		jsonshape.Required("proposedPolicyDigest", digest), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
	).JSONSchema()
	schema["description"] = "All thirteen root, fourteen change and seventeen receipt fields are required. Only fromAdmissionLevel is nullable. Records may be empty and normalize by unique ID; text/path/ID arrays must already be sorted and unique after normalization. policySurfaceRefs and change evidenceRefs are nonempty. IDs, kinds and digests do not trim; other text trims and paths must be safe repository-relative values. Canonical numeric tokens, privacy, normalized uniqueness and usedForPolicyChangeId equality are native admission predicates. Policy change, receipt status/class and exact eight-coordinate tuple relations may produce a failed report. These caller facts do not authenticate producers, prove provenance/freshness or approve merge."
	return schema
}

func OutputStructure() map[string]any {
	id, text, count := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString(), jsonshape.IntegerMinimum(0)
	digest, status := jsonshape.StringGrammar(`sha256:[a-f0-9]{64}`), jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	summary := jsonshape.Object(jsonshape.Required("admissionChangeCount", count), jsonshape.Required("declaredMergeObligationReceiptCount", count),
		jsonshape.Required("failureCount", count), jsonshape.Required("newlyMergeSatisfyingTupleCount", count),
		jsonshape.Required("policyChanged", jsonshape.Boolean()), jsonshape.Required("selfProofReceiptCount", count))
	policy := jsonshape.Object(jsonshape.Required("baselinePolicyDigest", digest), jsonshape.Required("nonClaimRefs", jsonshape.Array(id, 0)),
		jsonshape.Required("policyChangeDigest", digest), jsonshape.Required("policyChangeId", id), jsonshape.Required("policyId", id),
		jsonshape.Required("policyOwner", text), jsonshape.Required("policySurfaceRefs", jsonshape.Array(text, 1)), jsonshape.Required("proposedPolicyDigest", digest))
	receipt := jsonshape.Object(jsonshape.Required("artifactRetentionRuleRef", text), jsonshape.Required("environmentClass", id),
		jsonshape.Required("nonClaimRefs", jsonshape.Array(id, 0)), jsonshape.Required("producerClass", id), jsonshape.Required("producerId", id),
		jsonshape.Required("proofClass", id), jsonshape.Required("proofReceiptDigest", digest), jsonshape.Required("proofReceiptRef", text),
		jsonshape.Required("provenanceRuleRef", text), jsonshape.Required("receiptId", id), jsonshape.Required("receiptKind", id))
	failures := jsonshape.Array(jsonshape.Object(jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)), jsonshape.Required("value", text)), 0)
	schema := report.Structure(1, reportKind, status, summary, jsonshape.Tuple(
		report.DiagnosticStructure("failures", jsonshape.Array(text, 0)), report.DiagnosticStructure("policy", policy), report.DiagnosticStructure("selfProofReceipts", jsonshape.Array(receipt, 0))),
		jsonshape.Tuple(
			report.RuleStructure(jsonshape.StringLiteral(boundaryRuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(boundaryRuleMessage), jsonshape.Tuple()),
			report.RuleStructure(jsonshape.StringLiteral(receiptRuleID), status, jsonshape.StringLiteral(receiptRuleMessage), failures)),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	nonClaims := jsonshape.Array(text, len(boundaryNonClaims)).JSONSchema()
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	nonClaims["allOf"], properties["nonClaims"] = contains, nonClaims
	schema["description"] = "All output fields are required and nonnull; diagnostics and ruleResults are fixed ordered tuples. Variable receipt/failure arrays may be empty. Six summary fields, state, sequential failure keys and repeated diagnostics are native dependent facts. NonClaims retains sorted builtin/caller overlap multiplicity. Exact producer tuple identity is the eight-coordinate relation, not delimiter-joined text. The report grants no producer authentication, freshness, merge, release, rollout or migration authority."
	return schema
}
