package witnessschedulerplan

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

func InputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	retry := jsonshape.DiscriminatedUnion("kind",
		jsonshape.Object(jsonshape.Required("kind", jsonshape.StringLiteral("none")), jsonshape.Required("maxAttempts", jsonshape.IntegerLiteral(1))),
		jsonshape.Object(jsonshape.Required("kind", jsonshape.StringLiteral("bounded")), jsonshape.Required("maxAttempts", jsonshape.IntegerRange(2, 10))),
	)
	cancellation := jsonshape.DiscriminatedUnion("kind",
		jsonshape.Object(jsonshape.Required("kind", jsonshape.StringLiteral("cooperative")), jsonshape.Required("graceMs", jsonshape.IntegerMinimum(1))),
		jsonshape.Object(jsonshape.Required("kind", jsonshape.StringLiteral("not_supported")), jsonshape.Optional("graceMs", jsonshape.Null())),
	)
	policy := jsonshape.Object(
		jsonshape.Required("cacheAdmissionRefs", texts), jsonshape.Required("cancellationPolicy", cancellation),
		jsonshape.Required("commandId", text), jsonshape.Required("deterministicOutput", jsonshape.Boolean()),
		jsonshape.Required("exclusiveLocks", texts), jsonshape.Required("inputSelectors", texts),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)), jsonshape.Required("outputSelectors", texts),
		jsonshape.Required("resourceReads", texts), jsonshape.Required("resourceWrites", texts),
		jsonshape.Required("retryPolicy", retry), jsonshape.Required("sideEffectClass", jsonshape.Enum(sideEffectClassSet)),
		jsonshape.Required("timeoutPolicy", jsonshape.Object(jsonshape.Required("kind", jsonshape.Enum(timeoutKindSet)), jsonshape.Required("timeoutMs", jsonshape.IntegerMinimum(1)))),
	)
	schema := jsonshape.Object(
		jsonshape.Required("commands", jsonshape.Array(witnesscommand.CommandStructure(), 1)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)), jsonshape.Required("policies", jsonshape.Array(policy, 1)),
		jsonshape.Required("schedulerPlanId", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
	).JSONSchema()
	schema["properties"].(map[string]any)["vocabulary"] = witnesscommand.VocabularyStructure()
	schema["required"] = append(schema["required"].([]any), "vocabulary")
	schema["description"] = "Commands and policies are nonempty. Native admission owns canonical integer spelling and host range, text trimming, path/selector safety, RuleID privacy, sorted uniqueness, command/policy identity uniqueness and witness vocabulary constraints. Cache/retry/side-effect compatibility, command-policy bijection, timeout equality and parallel resource/lock collisions are evaluated after admission. Those failures still emit structurally valid reports. Unsupported cancellation admits omitted or null graceMs; cooperative cancellation requires a positive graceMs."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	states := jsonshape.Enum(map[string]struct{}{"failed": {}, "passed": {}})
	count := jsonshape.IntegerMinimum(0)
	summary := jsonshape.Object(
		jsonshape.Required("cacheableCommandCount", count), jsonshape.Required("commandCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("destructiveCommandCount", count), jsonshape.Required("executionGroupCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("exclusiveLockCount", count), jsonshape.Required("failureCount", count), jsonshape.Required("policyCount", jsonshape.IntegerMinimum(1)),
	)
	groups := jsonshape.Array(jsonshape.Object(
		jsonshape.Required("commandIds", jsonshape.Array(text, 1)), jsonshape.Required("exclusiveLocks", texts),
		jsonshape.Required("parallelGroup", text), jsonshape.Required("sideEffectClasses", jsonshape.Array(jsonshape.Enum(sideEffectClassSet), 0))), 1)
	failures := jsonshape.Array(jsonshape.Object(
		jsonshape.Required("key", jsonshape.StringGrammar(`failure\.[0-9]{3,}`)), jsonshape.Required("value", text)), 0)
	rules := jsonshape.Tuple(
		report.RuleStructure(jsonshape.StringLiteral("proofkit.witness-scheduler-plan.boundary"), jsonshape.StringLiteral("passed"),
			jsonshape.StringLiteral("proofkit validates caller-provided scheduler metadata without executing commands"), jsonshape.BoundedArray(text, 0, 0)),
		report.RuleStructure(jsonshape.StringLiteral("proofkit.witness-scheduler-plan.safety"), states,
			jsonshape.StringLiteral("witness scheduler metadata must declare safe cache, retry, cancellation, lock, resource, and timeout policy"), failures),
	)
	schema := report.Structure(1, reportKind, states, summary, jsonshape.Tuple(
		report.DiagnosticStructure("executionGroups", groups), report.DiagnosticStructure("failures", texts)), rules).JSONSchema()
	schema["description"] = "Both passed and failed evaluations have this carrier. Native derivation owns count equality, group membership, sorted strings, sequential failure diagnostic keys, correspondence of failures to safety rule and exit status, and caller plus boundary nonClaims (duplicates are retained). Missing policies can leave a group's sideEffectClasses empty. Report identity is fixed; reportId is the admitted schedulerPlanId. This derived report does not execute or approve witnesses."
	return schema
}
