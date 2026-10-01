package proofreceiptadmission

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"nonClaims", "receiptSetId", "receipts", "schemaVersion"}
var receiptKeys = []string{"artifactRefs", "commandDigest", "dependencyDigest", "environmentClass", "environmentDigest", "evidenceRefs", "exitCode", "finishedAt", "lockfileDigest", "nonClaims", "preconditionDigest", "producerAdmissionClass", "producerId", "proofBindingDigest", "proofPlanId", "provenanceRef", "receiptId", "receiptKind", "runnerClass", "runnerIdentity", "sourceRevision", "startedAt", "status", "toolchainDigest", "witnessSelectorDigest", "witnessSelectors"}
var artifactKeys = []string{"kind", "path", "sha256"}

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.String()
	digest := jsonshape.StringGrammar(strings.TrimSuffix(strings.TrimPrefix(digestPattern.String(), "^"), "$"))
	timestamp := jsonshape.StringGrammar(strings.TrimSuffix(strings.TrimPrefix(utcTimestampPattern.String(), "^"), "$"))
	artifact := jsonshape.RequiredObject(artifactKeys, map[string]jsonshape.Shape{
		"kind": jsonshape.Enum(artifactKindSet), "path": text, "sha256": digest,
	})
	receipt := jsonshape.RequiredObject(receiptKeys, map[string]jsonshape.Shape{
		"artifactRefs": jsonshape.Array(artifact, 0), "commandDigest": digest,
		"dependencyDigest": jsonshape.Nullable(digest), "environmentClass": id, "environmentDigest": digest,
		"evidenceRefs": jsonshape.Array(text, 1), "exitCode": jsonshape.Nullable(jsonshape.IntegerRange(0, 255)),
		"finishedAt": timestamp, "lockfileDigest": jsonshape.Nullable(digest), "nonClaims": jsonshape.Array(text, 0),
		"preconditionDigest": digest, "producerAdmissionClass": jsonshape.Enum(producerAdmissionClassSet),
		"producerId": id, "proofBindingDigest": digest, "proofPlanId": id, "provenanceRef": jsonshape.Nullable(text),
		"receiptId": id, "receiptKind": id, "runnerClass": id, "runnerIdentity": id, "sourceRevision": text,
		"startedAt": timestamp, "status": jsonshape.Enum(proofReceiptStatusSet), "toolchainDigest": digest,
		"witnessSelectorDigest": digest, "witnessSelectors": jsonshape.Array(id, 1),
	})
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"nonClaims": jsonshape.Array(text, 0), "receiptSetId": id, "receipts": jsonshape.Array(receipt, 1),
		"schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	annotateInput(schema)
	receiptSchema := schema["properties"].(map[string]any)["receipts"].(map[string]any)["items"].(map[string]any)
	required := []any{}
	for _, key := range receiptKeys {
		switch key {
		case "dependencyDigest", "exitCode", "lockfileDigest", "provenanceRef":
			continue
		}
		required = append(required, key)
	}
	receiptSchema["required"] = required
	schema["description"] = "All root fields and receipt/artifact fields are required except dependencyDigest, lockfileDigest, provenanceRef and exitCode, which admit absence or explicit null. No defaults are inserted. IDs and enums are untrimmed; text trims to nonempty and paths are canonical repository-relative POSIX refs without existence checks. Native admission rejects duplicate keys, sensitive text, unsorted/duplicate text and ID lists, duplicate receipt IDs and duplicate artifact kind/path pairs. Receipts/artifacts are sorted by native admission. Timestamp grammar and calendar validity are both required; schema grammar alone is not calendar proof. schemaVersion requires literal 1; exitCode requires an Int64-decoding JSON number between 0 and 255 (including -0, excluding 1.0/1e0). JSON Schema numeric semantics do not enforce lexical spelling. Finish-before-start, status/exit/artifact/non-claim inconsistencies and merge_satisfying without provenance produce admitted failed reports, not structural input errors."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	receipt := jsonshape.Object(
		jsonshape.Required("environmentClass", id), jsonshape.Required("producerAdmissionClass", jsonshape.Enum(producerAdmissionClassSet)),
		jsonshape.Required("producerId", id), jsonshape.Required("proofPlanId", id), jsonshape.Required("receiptId", id),
		jsonshape.Required("receiptKind", id), jsonshape.Required("runnerClass", id), jsonshape.Required("status", jsonshape.Enum(proofReceiptStatusSet)),
	)
	summary := jsonshape.Object(
		jsonshape.Required("artifactRefCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("blockedReceiptCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("declaredAdvisoryProducerClassReceiptCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("declaredMergeSatisfyingProducerClassReceiptCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("evidenceRefCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("failedReceiptCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("failureCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("notRunReceiptCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("passedReceiptCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("receiptCount", jsonshape.IntegerMinimum(1)),
	)
	nativeRules := ruleResults(nil)
	rules := jsonshape.Tuple(
		report.RuleStructure(jsonshape.StringLiteral(nativeRules[0].RuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(nativeRules[0].Message), jsonshape.Tuple()),
		report.RuleStructure(jsonshape.StringLiteral(nativeRules[1].RuleID), status, jsonshape.StringLiteral(nativeRules[1].Message), failureStructure()),
	)
	schema := report.Structure(1, reportKind, status, summary,
		jsonshape.Tuple(report.DiagnosticStructure("failures", jsonshape.Array(jsonshape.String(), 0)), report.DiagnosticStructure("receipts", jsonshape.Array(receipt, 1))), rules,
	).JSONSchema()
	annotateNonemptyStrings(schema)
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	nonClaims := properties["nonClaims"].(map[string]any)
	nonClaims["minItems"] = len(boundaryNonClaims)
	contains := []any{}
	for _, value := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": value}})
	}
	nonClaims["allOf"] = contains
	schema["description"] = "reportId preserves receiptSetId. Receipt diagnostics follow sorted receipt IDs; failures and merged builtin/caller nonClaims are sorted. Builtin/caller nonClaims collisions remain valid duplicates. The boundary rule always passes; the receipts rule and report fail iff receiptFailures is nonempty. Summary counts derive from admitted receipts. Failed receipt status is distinct from failed report state: a consistent failed receipt may produce a passed report. Passed reports exit 0, admitted failed reports exit 1 with JSON, and admission errors exit 1 on stderr without a report. Structural validity does not authenticate producers, execute commands, prove currentness or approve merge."
	return schema
}

func failureStructure() jsonshape.Shape {
	return jsonshape.Array(jsonshape.Object(jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)), jsonshape.Required("value", jsonshape.String())), 0)
}

func annotateInput(value any) {
	switch value := value.(type) {
	case map[string]any:
		if value["type"] == "array" {
			value["uniqueItems"] = true
		}
		if value["type"] == "string" {
			value["minLength"] = 1
		}
		for _, child := range value {
			annotateInput(child)
		}
	case []any:
		for _, child := range value {
			annotateInput(child)
		}
	}
}

func annotateNonemptyStrings(value any) {
	switch value := value.(type) {
	case map[string]any:
		if value["type"] == "string" {
			value["minLength"] = 1
		}
		for _, child := range value {
			annotateNonemptyStrings(child)
		}
	case []any:
		for _, child := range value {
			annotateNonemptyStrings(child)
		}
	}
}
