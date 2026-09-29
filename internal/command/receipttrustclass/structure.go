package receipttrustclass

import (
	"regexp"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.String()
	texts := jsonshape.Array(text, 1)
	// These two native lists trim text before admitting identifiers; scalar IDs do not.
	trimmedID := jsonshape.String()
	trust := jsonshape.RequiredObject(trustClassKeys, map[string]jsonshape.Shape{
		"allowedProducerAdmissionLevels": jsonshape.Array(jsonshape.Enum(producerAdmissionLevelSet), 1),
		"allowedReceiptStatuses":         jsonshape.Array(jsonshape.Enum(receiptStatusSet), 1),
		"nonClaims":                      texts, "rank": jsonshape.IntegerMinimum(1),
		"requiresArtifactRefs": jsonshape.Boolean(), "requiresProvenanceRef": jsonshape.Boolean(), "trustClassId": id,
	})
	proof := jsonshape.RequiredObject(proofClassKeys, map[string]jsonshape.Shape{
		"allowedEnvironmentClasses": jsonshape.Array(trimmedID, 1), "allowedReceiptKinds": jsonshape.Array(trimmedID, 1),
		"minimumTrustClassId": id, "nonClaims": texts, "owner": text, "proofClassId": id, "rationale": text, "riskClass": id,
	})
	receipt := jsonshape.RequiredObject(obligationKeys, map[string]jsonshape.Shape{
		"artifactRefs": jsonshape.Array(text, 0), "environmentClass": id, "evidenceRefs": texts, "nonClaims": texts,
		"obligationId": id, "producerAdmissionClass": jsonshape.Enum(producerAdmissionLevelSet), "proofClassId": id,
		"proofRouteRef": id, "provenanceRef": jsonshape.Nullable(text), "receiptId": id, "receiptKind": id,
		"receiptStatus": jsonshape.Enum(receiptStatusSet), "requirementId": id, "trustClassId": id,
	})
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"nonClaims": texts, "obligationReceipts": jsonshape.Array(receipt, 1), "policyId": id,
		"proofClasses": jsonshape.Array(proof, 1), "schemaVersion": jsonshape.IntegerLiteral(1),
		"trustClasses": jsonshape.BoundedArray(trust, 1, maxTrustClasses),
	}).JSONSchema()
	space := jsonshape.TrimSpacePatternClass()
	proofProperties := schema["properties"].(map[string]any)["proofClasses"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	for _, key := range []string{"allowedEnvironmentClasses", "allowedReceiptKinds"} {
		item := proofProperties[key].(map[string]any)["items"].(map[string]any)
		item["allOf"] = []any{
			map[string]any{"pattern": "^[" + space + "]*(?:" + admit.RuleIDPatternBody + ")[" + space + "]*(?![\\s\\S])"},
			map[string]any{"pattern": "^[" + space + "]*[^" + space + "]{1," + strconv.Itoa(admit.MaxRuleIDBytes) + "}[" + space + "]*(?![\\s\\S])"},
		}
	}
	annotateUniqueCarrier(schema)
	schema["description"] = "Every member is required; provenanceRef admits explicit null but not absence. No defaults are inserted. Scalar IDs and enums, including enum-array items, are exact and untrimmed. allowedEnvironmentClasses and allowedReceiptKinds instead trim each string before RuleID admission; the normalized identifier must fit the native 256-byte bound. Prose and nonClaims trim to nonempty text and normalized duplicates reject. Path refs use canonical repository-relative POSIX path admission without prose trimming or existence checks. Native privacy and timestamp-like identifier admission still apply. Trust/proof/obligation IDs and trust ranks are unique. Higher ranks preserve lower-rank artifact/provenance requirements and refine allowed producer/status sets; proof-class minimumTrustClassId must resolve. Unknown proof/trust IDs in obligations are admitted for failed-report evaluation. Root nonClaims cannot collide with builtin nonClaims after normalization. Native JSON framing rejects duplicate members and requires literal schemaVersion 1 and positive canonical int ranks within the platform native-int range (signed 64-bit on shipped platforms), not a JavaScript safe-integer limit. JSON Schema integer semantics do not prove lexical spelling or dynamic policy."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	states := jsonshape.OneOf(jsonshape.Tuple(),
		jsonshape.Tuple(jsonshape.StringLiteral("invalid_producer")),
		jsonshape.Tuple(jsonshape.StringLiteral("invalid_receipt")),
		jsonshape.Tuple(jsonshape.StringLiteral("invalid_producer"), jsonshape.StringLiteral("invalid_receipt")))
	diagnostic := jsonshape.Object(
		jsonshape.Required("actualTrustRank", jsonshape.Nullable(jsonshape.IntegerMinimum(1))),
		jsonshape.Required("decisionCandidateStates", states), jsonshape.Required("environmentClass", id),
		jsonshape.Required("minimumTrustClassId", jsonshape.Nullable(id)),
		jsonshape.Required("minimumTrustRank", jsonshape.Nullable(jsonshape.IntegerMinimum(1))),
		jsonshape.Required("obligationId", id), jsonshape.Required("producerAdmissionClass", jsonshape.Enum(producerAdmissionLevelSet)),
		jsonshape.Required("proofClassId", id), jsonshape.Required("proofRouteRef", id),
		jsonshape.Required("receiptId", id), jsonshape.Required("receiptKind", id),
		jsonshape.Required("receiptStatus", jsonshape.Enum(receiptStatusSet)), jsonshape.Required("requirementId", id),
		jsonshape.Required("riskClass", jsonshape.Nullable(id)),
		jsonshape.Required("structuralFindings", jsonshape.Array(jsonshape.String(), 0)), jsonshape.Required("trustClassId", id),
	)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	rule := report.RuleStructure(
		jsonshape.BoundedStringGrammar(regexp.QuoteMeta(ruleIDPrefix)+"(?:"+admit.RuleIDPatternBody+")", len(ruleIDPrefix)+admit.MaxRuleIDBytes),
		status, jsonshape.String(), jsonshape.Tuple(report.DiagnosticStructure("receiptTrustClass", diagnostic)),
	)
	schema := report.Structure(1, reportKind, status,
		jsonshape.Object(
			jsonshape.Required("failedObligationCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("obligationReceiptCount", jsonshape.IntegerMinimum(1)),
			jsonshape.Required("proofClassCount", jsonshape.IntegerMinimum(1)),
			jsonshape.Required("trustClassCount", jsonshape.IntegerRange(1, maxTrustClasses)),
		),
		jsonshape.Tuple(report.DiagnosticStructure("failedObligationIds", jsonshape.Array(id, 0)),
			report.DiagnosticStructure("obligationReceiptTrust", jsonshape.Array(diagnostic, 1))),
		jsonshape.Array(rule, 1),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	nonClaims := properties["nonClaims"].(map[string]any)
	nonClaims["minItems"] = len(boundaryNonClaims) + 1
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, value := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": value}})
	}
	nonClaims["allOf"] = contains
	annotateUniqueCarrier(schema)
	schema["description"] = "Reports preserve policyId as reportId. Obligation diagnostics, failed IDs and rules follow sorted obligation IDs; findings and merged nonClaims are sorted. Each rule prefixes its obligation ID and repeats the corresponding diagnostic under receiptTrustClass. Actual rank is null for unknown trust class; minimum class/rank and risk are null for unknown proof class. The evaluator derives invalid_producer and invalid_receipt from unresolved classes, minimum-rank and declared producer/receipt restrictions, with states ordered by the proof vocabulary. A rule fails iff it has findings; the report fails iff any rule fails. Summary counts derive from admitted inputs/diagnostics. Passed reports exit 0; admitted failed reports exit 1 with JSON. Admission errors exit 1 on stderr without a report. Structural validity does not authenticate producers, execute witnesses, compute freshness or approve merge."
	return schema
}

// All arrays in this carrier are sets, keyed inventories or distinct fixed
// tuples. Equality after normalization and keyed uniqueness remain native.
func annotateUniqueCarrier(value any) {
	switch value := value.(type) {
	case map[string]any:
		if value["type"] == "array" {
			value["uniqueItems"] = true
		}
		if value["type"] == "string" {
			value["minLength"] = 1
		}
		for _, child := range value {
			annotateUniqueCarrier(child)
		}
	case []any:
		for _, child := range value {
			annotateUniqueCarrier(child)
		}
	}
}
