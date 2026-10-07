package receiptproduceradmission

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"environmentClasses", "nonClaims", "policyId", "producers", "receiptKinds", "receipts", "schemaVersion"}
var producerKeys = []string{"admissionLevel", "environmentClasses", "evidenceRefs", "nonClaim", "owner", "producerId", "receiptKinds"}
var receiptKeys = []string{"artifactRefs", "environmentClass", "evidenceRef", "nonClaim", "producerId", "provenanceRef", "receiptId", "receiptKind", "satisfiesMergeObligation", "status", "subjectRef"}

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.String()
	ids := jsonshape.Array(id, 0)
	paths := jsonshape.Array(text, 0)
	producer := jsonshape.RequiredObject(producerKeys, map[string]jsonshape.Shape{
		"admissionLevel": jsonshape.Enum(admissionLevelSet), "environmentClasses": ids, "evidenceRefs": paths,
		"nonClaim": text, "owner": text, "producerId": id, "receiptKinds": ids,
	})
	receipt := jsonshape.RequiredObject(receiptKeys, map[string]jsonshape.Shape{
		"artifactRefs": paths, "environmentClass": id, "evidenceRef": text, "nonClaim": text, "producerId": id,
		"provenanceRef": jsonshape.Nullable(text), "receiptId": id, "receiptKind": id,
		"satisfiesMergeObligation": jsonshape.Boolean(), "status": jsonshape.Enum(receiptStatusSet), "subjectRef": id,
	})
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"environmentClasses": ids, "nonClaims": jsonshape.Array(text, 1), "policyId": id,
		"producers": jsonshape.Array(producer, 0), "receiptKinds": ids, "receipts": jsonshape.Array(receipt, 0),
		"schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	annotateInput(schema)
	receiptSchema := schema["properties"].(map[string]any)["receipts"].(map[string]any)["items"].(map[string]any)
	required := []any{}
	for _, key := range receiptKeys {
		if key != "provenanceRef" {
			required = append(required, key)
		}
	}
	receiptSchema["required"] = required
	schema["description"] = "All root/producer/receipt fields are required except receipt provenanceRef, which admits absence or explicit null. No defaults are inserted. Root nonClaims is nonempty; vocabularies, producers, receipts and producer/receipt ref arrays may be empty. IDs/enums are untrimmed; prose trims to nonempty and paths are canonical repository-relative POSIX refs without existence checks. Native admission rejects duplicate JSON keys, sensitive text, unsorted/duplicate lists and producer/receipt IDs; producer kind/environment subsets and receipt kind/environment membership must fit root vocabularies. schemaVersion requires literal 1, not decimal/exponent spelling. JSON Schema does not prove lexical framing, path/privacy, normalized uniqueness or dynamic relations. Unknown producers, uncovered vocabulary, incompatible producer/receipt relations and merge-obligation status/provenance conflicts yield admitted failed reports."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	receipt := jsonshape.Object(
		jsonshape.Required("environmentClass", id), jsonshape.Required("producerId", id), jsonshape.Required("provenanceRef", jsonshape.Nullable(jsonshape.String())),
		jsonshape.Required("receiptId", id), jsonshape.Required("receiptKind", id), jsonshape.Required("status", jsonshape.Enum(receiptStatusSet)), jsonshape.Required("subjectRef", id),
	)
	summary := jsonshape.Object(
		jsonshape.Required("advisoryProducerCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("environmentClassCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("failureCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("mergeSatisfyingProducerCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("mergeSatisfyingReceiptCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("producerCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("receiptCount", jsonshape.IntegerMinimum(0)), jsonshape.Required("receiptKindCount", jsonshape.IntegerMinimum(0)),
	)
	nativeRules := ruleResults(nil)
	rules := make([]jsonshape.Shape, 0, len(nativeRules))
	for index, rule := range nativeRules {
		ruleStatus, diagnostics := status, jsonshape.Tuple()
		if index == 0 {
			ruleStatus = jsonshape.StringLiteral("passed")
		}
		if index == 2 {
			diagnostics = jsonshape.Array(jsonshape.Object(jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)), jsonshape.Required("value", jsonshape.String())), 0)
		}
		rules = append(rules, report.RuleStructure(jsonshape.StringLiteral(rule.RuleID), ruleStatus, jsonshape.StringLiteral(rule.Message), diagnostics))
	}
	schema := report.Structure(1, reportKind, status, summary,
		jsonshape.Tuple(
			report.DiagnosticStructure("coverage", jsonshape.Object(jsonshape.Required("environmentClasses", jsonshape.Array(id, 0)), jsonshape.Required("receiptKinds", jsonshape.Array(id, 0)))),
			report.DiagnosticStructure("failures", jsonshape.Array(jsonshape.String(), 0)), report.DiagnosticStructure("mergeSatisfyingReceipts", jsonshape.Array(receipt, 0)),
		), jsonshape.Tuple(rules...),
	).JSONSchema()
	annotateNonemptyStrings(schema)
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	nonClaims := properties["nonClaims"].(map[string]any)
	nonClaims["minItems"] = len(boundaryNonClaims) + 1
	contains := []any{}
	for _, value := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": value}})
	}
	nonClaims["allOf"] = contains
	schema["description"] = "reportId preserves policyId. Coverage arrays, failures, merge-obligation receipt diagnostics and merged builtin/caller nonClaims are sorted; builtin/caller collisions remain valid duplicates. mergeSatisfyingReceipts includes every declared merge-obligation receipt, even when its provenance is null or its status/producer is invalid. The boundary rule always passes; coverage and receipts rules classify their native failure sets, while report state fails iff any failure exists. Summary counters derive from admitted inventories. Passed reports exit 0, admitted failed reports exit 1 with JSON, and admission errors exit 1 on stderr without a report. Structural validity does not authenticate producers, prove execution/currentness or approve merge."
	return schema
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
