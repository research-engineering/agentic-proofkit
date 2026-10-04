package selectivegateevidence

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/selectivegateplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func InputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("evidenceId", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
		jsonshape.Required("evidenceClass", jsonshape.Enum(evidenceClassSet)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("plan", selectivegateplan.EvidencePlanStructure()),
		jsonshape.Required("preexistingFailures", jsonshape.Array(text, 0)),
		jsonshape.Required("receipts", jsonshape.Array(receiptStructure(false), 0)),
	).JSONSchema()
	schema["properties"].(map[string]any)["producerAdmission"] = map[string]any{"oneOf": []any{map[string]any{"type": "null"}, receiptproduceradmission.InputStructure()}}
	schema["description"] = "Missing or null producerAdmission means not provided; other values pass the producer owner. Merge-satisfying evidence without producer admission yields an admitted failed report, not an input error. Input receipt sourcePath and producerReceiptId are optional but nonnull. Passed receipts require zero exitCode, failed receipts require a positive int64, and blocked/not_run admit absent or null exitCode. Native admission owns canonical integer spelling/range, paths, display-only command text, privacy and normalized uniqueness; plan relations and producer receipt linkage remain native."
	return schema
}

func receiptStructure(output bool) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	variants := make([]jsonshape.Shape, 0, 4)
	for _, status := range []string{"passed", "failed", "blocked", "not_run"} {
		fields := []jsonshape.Property{
			jsonshape.Required("artifactRefs", jsonshape.Array(text, 0)), jsonshape.Required("command", text),
			jsonshape.Required("evidenceRef", text), jsonshape.Required("id", id), jsonshape.Required("status", jsonshape.StringLiteral(status)),
		}
		if output {
			fields = append(fields, jsonshape.Required("producerReceiptId", jsonshape.Nullable(id)), jsonshape.Required("sourcePath", jsonshape.Nullable(text)))
		} else {
			fields = append(fields, jsonshape.Optional("producerReceiptId", id), jsonshape.Optional("sourcePath", text))
		}
		switch status {
		case "passed":
			fields = append(fields, jsonshape.Required("exitCode", jsonshape.IntegerRange(0, 0)))
		case "failed":
			fields = append(fields, jsonshape.Required("exitCode", jsonshape.IntegerMinimum(1)))
		default:
			if output {
				fields = append(fields, jsonshape.Required("exitCode", jsonshape.Null()))
			} else {
				fields = append(fields, jsonshape.Optional("exitCode", jsonshape.Null()))
			}
		}
		variants = append(variants, jsonshape.Object(fields...))
	}
	return jsonshape.DiscriminatedUnion("status", variants...)
}

func OutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	count := jsonshape.IntegerMinimum(0)
	hash := jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
	planState := jsonshape.Enum(map[string]struct{}{"ok": {}, "fail_closed": {}})
	producerState := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "not_provided": {}})
	class := jsonshape.Enum(evidenceClassSet)
	merge := jsonshape.Object(
		jsonshape.Required("consumerObligationDecisionRequired", jsonshape.BooleanLiteral(true)),
		jsonshape.Required("evidenceClass", class), jsonshape.Required("mergeAdmissionOwner", jsonshape.StringLiteral("consumer_repository")),
		jsonshape.Required("nonClaim", text), jsonshape.Required("producerAdmissionPassed", jsonshape.Boolean()),
		jsonshape.Required("producerAdmissionProvided", jsonshape.Boolean()), jsonshape.Required("producerAdmissionRequired", jsonshape.Boolean()),
	)
	fields := []jsonshape.Property{
		jsonshape.Required("evidenceClass", class), jsonshape.Required("mergeEvidence", merge), jsonshape.Required("planHash", hash),
		jsonshape.Required("planState", planState), jsonshape.Required("producerAdmissionState", producerState),
	}
	for _, name := range []string{"blockedReceiptCount", "duplicateReceiptCount", "failedReceiptCount", "missingReceiptCount", "notRunReceiptCount", "plannedCommandCount", "producerAdmissionFailureCount", "producerAdmittedReceiptCount", "receiptCount", "unexpectedReceiptCount"} {
		fields = append(fields, jsonshape.Required(name, count))
	}
	keys := jsonshape.Array(jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("id", id), jsonshape.Required("sourcePath", jsonshape.Nullable(text))), 0)
	receipts := jsonshape.Array(receiptStructure(true), 0)
	coverage := jsonshape.Object(
		jsonshape.Required("blockedReceipts", receipts), jsonshape.Required("duplicateReceipts", keys), jsonshape.Required("failedReceipts", receipts),
		jsonshape.Required("missingReceipts", keys), jsonshape.Required("notRunReceipts", receipts), jsonshape.Required("unexpectedReceipts", receipts),
	)
	plan := jsonshape.Object(jsonshape.Required("changedPathCount", count), jsonshape.Required("generatedArtifactCount", count),
		jsonshape.Required("planHash", hash), jsonshape.Required("planState", planState), jsonshape.Required("requiredCommandCount", count))
	passFail := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	withSkip := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "skipped": {}})
	rules := []jsonshape.Shape{}
	for _, name := range []string{"plan", "coverage", "duplicates", "unexpected", "status", "producer-admission"} {
		status, diagnostics := passFail, jsonshape.Tuple()
		if name == "status" || name == "producer-admission" {
			status = withSkip
		}
		if name == "producer-admission" {
			diagnostics = jsonshape.Array(jsonshape.Object(jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)), jsonshape.Required("value", text)), 0)
		}
		rules = append(rules, report.RuleStructure(jsonshape.StringLiteral("proofkit.selective-gate-evidence."+name), status, text, diagnostics))
	}
	rules = append(rules, report.RuleStructure(jsonshape.StringGrammar(`proofkit\.selective-gate-evidence\.failure\.[0-9]{3,}`), jsonshape.StringLiteral("failed"), text, jsonshape.Tuple()))
	schema := report.Structure(1, "proofkit.selective-gate-evidence", jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "blocked": {}}), jsonshape.Object(fields...),
		jsonshape.Tuple(report.DiagnosticStructure("coverage", coverage), report.DiagnosticStructure("plan", plan), report.DiagnosticStructure("producerAdmission", jsonshape.Object(jsonshape.Required("state", producerState)))),
		jsonshape.Array(jsonshape.OneOf(rules...), 6),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	properties["nonClaims"] = jsonshape.Array(text, len(boundaryNonClaims)).JSONSchema()
	schema["description"] = "reportId preserves evidenceId. Counts and diagnostic partitions are native projections; duplicate/unexpected receipts remain reportable. Each of the six fixed rules occurs once; fixed and additional failure rules are sorted together by ruleId. Any failure yields failed, otherwise blocked receipts or a fail-closed plan yield blocked, otherwise passed. Only passed exits 0. The plan hash binds the normalized plan, not execution or freshness. Producer admission booleans classify the supplied producer evidence; the consumer still owns obligation and merge decisions."
	return schema
}
