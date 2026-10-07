package migrationparityadmission

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func parityFields() []jsonshape.Property {
	id, text := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString()
	digest := jsonshape.StringGrammar(`sha256:[a-f0-9]{64}`)
	return []jsonshape.Property{
		jsonshape.Required("equivalenceKind", jsonshape.Enum(equivalenceKindSet)), jsonshape.Required("evidenceId", id),
		jsonshape.Required("evidenceRefs", jsonshape.Array(text, 1)), jsonshape.Required("legacyDigest", digest), jsonshape.Required("legacySubjectRef", text),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)), jsonshape.Required("proofkitDigest", digest), jsonshape.Required("proofkitSubjectRef", text),
		jsonshape.Required("reason", text), jsonshape.Required("receiptRefs", jsonshape.Array(id, 0)), jsonshape.Required("sourceOwnerId", id),
		jsonshape.Required("status", jsonshape.Enum(parityStatusSet)), jsonshape.Required("targetId", id),
	}
}

func InputStructure() map[string]any {
	id, text := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString()
	owner := jsonshape.Object(jsonshape.Required("ownerId", id), jsonshape.Required("ownerKind", jsonshape.Enum(sourceOwnerKindSet)), jsonshape.Required("path", text))
	target := jsonshape.Object(jsonshape.Required("path", text), jsonshape.Required("targetId", id), jsonshape.Required("targetKind", jsonshape.Enum(targetKindSet)))
	schema := jsonshape.Object(jsonshape.Required("nonClaims", jsonshape.Array(text, 0)), jsonshape.Required("parityRecords", jsonshape.Array(jsonshape.Object(parityFields()...), 1)),
		jsonshape.Required("paritySetId", id), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("sourceProofOwners", jsonshape.Array(owner, 1)), jsonshape.Required("targetProofkitRefs", jsonshape.Array(target, 1)),
	).JSONSchema()
	schema["description"] = "All six root, three source-owner/target and thirteen parity fields are required and nonnull. Record arrays and record evidenceRefs/nonClaims are nonempty; root nonClaims and receiptRefs may be empty. Record order normalizes by unique ID. Simple text/path/ID arrays trim where allowed, sort and reject normalized duplicates. IDs, kinds and digests do not trim. Text rejects blank/sensitive values; paths must be safe repository-relative values. Canonical numeric tokens, privacy, safe paths and normalized uniqueness remain native admission predicates. Owner/target membership and digest/status coherence may emit failed reports. These are caller-declared parity facts, not authenticated evidence, execution results or migration approval."
	return schema
}

func OutputStructure() map[string]any {
	id, text, count := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString(), jsonshape.IntegerMinimum(0)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	summary := jsonshape.Object(jsonshape.Required("admittedParityClaimCount", count), jsonshape.Required("callerDeclaredMatchCount", count),
		jsonshape.Required("callerDeclaredMismatchCount", count), jsonshape.Required("callerDeclaredNotComparableCount", count),
		jsonshape.Required("callerDeclaredNotRunCount", count), jsonshape.Required("failureCount", count),
		jsonshape.Required("parityRecordCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("sourceProofOwnerCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("targetProofkitRefCount", jsonshape.IntegerMinimum(1)))
	claim := jsonshape.Object(jsonshape.Required("equivalenceKind", jsonshape.Enum(equivalenceKindSet)), jsonshape.Required("evidenceId", id),
		jsonshape.Required("evidenceRefs", jsonshape.Array(text, 1)), jsonshape.Required("receiptRefs", jsonshape.Array(id, 0)),
		jsonshape.Required("sourceOwnerId", id), jsonshape.Required("targetId", id))
	parity := jsonshape.Object(append(parityFields(), jsonshape.Required("findings", jsonshape.Array(text, 0)))...)
	ruleID := jsonshape.BoundedStringGrammar(regexp.QuoteMeta(recordRulePrefix)+admit.RuleIDPatternBody, len(recordRulePrefix)+admit.MaxRuleIDBytes)
	rules := jsonshape.Array(jsonshape.OneOf(
		report.RuleStructure(ruleID, jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(admittedMessage), jsonshape.Tuple()),
		report.RuleStructure(ruleID, jsonshape.StringLiteral("failed"), jsonshape.StringLiteral(rejectedMessage), jsonshape.Tuple(report.DiagnosticStructure("findings", jsonshape.Array(text, 1)))),
	), 1)
	schema := report.Structure(1, reportKind, status, summary, jsonshape.Tuple(
		report.DiagnosticStructure("admittedParityClaimRefs", jsonshape.Array(claim, 0)), report.DiagnosticStructure("failures", jsonshape.Array(text, 0)),
		report.DiagnosticStructure("migrationParity", jsonshape.Array(parity, 1))), rules,
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	nonClaims := jsonshape.Array(text, len(boundaryNonClaims)).JSONSchema()
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	nonClaims["allOf"], properties["nonClaims"] = contains, nonClaims
	schema["description"] = "All output fields are required and nonnull. Three diagnostic entries form an ordered tuple. Parity/rule arrays are nonempty; admitted refs and failures may be empty. Passed rules have no diagnostics; failed rules have one nonempty findings diagnostic. Generated rule IDs contain the fixed prefix plus an admitted256-byte ID. Native Build owns sorted IDs, nine dependent counters, membership, digest/status coherence, admitted-ref selection and report state. Builtin/caller nonClaims overlap multiplicity is retained. No parity declaration authenticates evidence, proves semantic equivalence or approves deletion, migration, merge or release."
	return schema
}
