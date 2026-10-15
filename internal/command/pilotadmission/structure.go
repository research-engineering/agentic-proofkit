package pilotadmission

import (
	"encoding/json"
	"regexp"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const (
	draft = "https://json-schema.org/draft/2020-12/schema"
	// Shared definitions are local to each published variant root.
	impactDemoDefinition = "pilotImpactDemo"
	inputDefinition      = "pilotInput"
	textDefinition       = "pilotText"
	reportDefinition     = "pilotReport"
)

// InputStructure describes direct admission for both pilot selections: the
// stack-diverse option adds only failure-collecting checks, never refusals.
func InputStructure() map[string]any {
	schema := inputMember()
	defs := Definitions()
	delete(defs, inputDefinition)
	schema["$schema"], schema["$defs"] = draft, defs
	return schema
}

// ContractInputStructure admits exactly the schema header and the named
// pilot input members, as contractenv extraction does.
func ContractInputStructure(fields ...string) map[string]any {
	properties := map[string]any{"schema": leaf(jsonshape.StringLiteral(contractEnvelopeSchema))}
	for _, field := range fields {
		properties[field] = InputReference()
	}
	schema := objectSchema(properties, false)
	schema["$schema"], schema["$defs"] = draft, Definitions()
	schema["description"] = "Exactly schema and the selected pilot input members are admitted; each member is a direct pilot input."
	return schema
}

// InputReference resolves only against a variant root carrying Definitions.
func InputReference() map[string]any { return ref(inputDefinition) }

// Definitions are described once per published variant root.
func Definitions() map[string]any {
	demo := objectSchema(map[string]any{
		"demoId": leaf(jsonshape.Nullable(ruleID())), "impactInput": member(impact.InputStructure()),
	}, true, "demoId")
	demo["description"] = "Absent or null demoId uses a positional fallback. Other demo members (sourceOwnedChangedPaths, generatedMirrorPaths, unknown keys) only collect failures. impactInput is admitted by the impact input owner; its refusal refuses the pilot."
	return map[string]any{impactDemoDefinition: demo, inputDefinition: inputMember(), textDefinition: leaf(jsonshape.NonBlankString())}
}

func inputMember() map[string]any {
	id := func() map[string]any { return leaf(ruleID()) }
	text := func() map[string]any { return ref(textDefinition) }
	route := objectSchema(map[string]any{
		"artifactPath": text(), "command": text(), "expectedUpdatePath": text(), "reportKind": id(), "schemaId": id(), "taskType": id(),
	}, true)
	check := objectSchema(map[string]any{"checkId": id(), "evidence": text()}, true)
	dimension := objectSchema(map[string]any{"baseline": text(), "candidate": text(), "evidence": text()}, true)
	diversity := objectSchema(map[string]any{"baselinePilotId": id(), "dimensions": map[string]any{"type": "array", "items": dimension}}, true)
	customRule := objectSchema(map[string]any{"owner": text(), "purpose": text(), "ruleId": id()}, true)
	fields := map[string]any{
		"agentReportRoutes":    map[string]any{"type": "array", "items": route},
		"blockingRequirements": openObject("Disposition policy, counts, requirement records and unknown members only collect failures."),
		"cacheNegativeChecks":  map[string]any{"anyOf": []any{map[string]any{"type": "null"}, map[string]any{"type": "array", "items": check}}},
		"cacheScheduler":       objectSchema(map[string]any{"parallelGroups": texts(1)}, true),
		"falsePositiveBudget":  objectSchema(map[string]any{"dispositionOwner": text()}, true),
		"impactDemo":           evaluated("Ignored when impactDemos is an array; otherwise its presence makes it the single admitted impact demo (see the root anyOf)."),
		"impactDemos":          map[string]any{"items": ref(impactDemoDefinition), "description": "An array selects these demos; any other value is ignored in favour of impactDemo, and no demo is a failure."},
		"infrastructureBudget": objectSchema(map[string]any{"customRules": map[string]any{"items": customRule, "description": "Only an array is admitted item by item; another value is a failure."}}, true, "customRules"),
		"metrics":              evaluated("Ignored caller JSON."),
		"nonClaims":            texts(1),
		"packageVersionRef":    evaluated("Non-text or blank values are failures, not refusals."),
		"pilotId":              id(),
		"pilotMode":            evaluated("Values other than non_blocking are failures; the raw value is echoed in the report summary, so the input is refused when its compact JSON serialization matches the shared secret-like predicate, including a credential key with its value."),
		"profile": closedRecord(profileKeys, map[string]any{
			"commandMatcherBridge": evaluated("Failure-collecting policy member."), "customRuleBoundary": evaluated("Failure-collecting policy member."),
			"primaryLanguages": texts(1), "repositoryClass": text(), "repositoryId": id(),
			"structuredWitnessCommands": evaluated("Failure-collecting policy member."), "verifierCodeCopied": evaluated("Failure-collecting policy member."),
		}, "commandMatcherBridge", "customRuleBoundary", "structuredWitnessCommands", "verifierCodeCopied"),
		"rollback":       closedRecord(rollbackKeys, map[string]any{"owner": text(), "rollbackCommand": text(), "versionPin": text()}),
		"rolloutClaim":   evaluated("Values other than false are failures."),
		"schemaVersion":  leaf(jsonshape.IntegerLiteral(inputSchemaVersion)),
		"stackDiversity": map[string]any{"anyOf": []any{map[string]any{"type": "null"}, diversity}},
		"timingBudget":   objectSchema(map[string]any{"reportArtifactPath": text()}, true),
	}
	schema := closedRecord(inputKeys, fields, "cacheNegativeChecks", "impactDemo", "impactDemos", "metrics", "packageVersionRef", "pilotMode", "rolloutClaim", "stackDiversity")
	schema["anyOf"] = []any{
		map[string]any{"required": []any{"impactDemos"}, "properties": map[string]any{"impactDemos": map[string]any{"type": "array"}}},
		map[string]any{"properties": map[string]any{"impactDemo": ref(impactDemoDefinition)}},
	}
	schema["description"] = "Root, profile and rollback are closed. Open nested records collect failures for unknown members, policy literals, counts, path lists and sort/uniqueness violations; listed members refuse when malformed. Native admission also owns trimming, secret and timestamp policy (report-echoed blocking status, stack dimension and cache outcome or input class text refuses when secret-shaped, while other unknown words are collected failures), repository-relative paths, display-only commands without shell control tokens and canonical integer spelling. Stack-diverse release requirements only add failures. No witness executes."
	return schema
}

// ReportStructure describes passed and failed reports; failed rules are the
// numbered collected failures and a passed report has the single accepted rule.
func ReportStructure() map[string]any {
	t, s, n := jsonshape.StringGrammar(`[\s\S]+`), jsonshape.String(), jsonshape.IntegerMinimum(0)
	summary := map[string]jsonshape.Shape{"repositoryClass": t, "maxAddedSeconds": jsonshape.Number(), "pilotMode": s}
	for _, key := range []string{"agentReportRouteCount", "cacheNegativeCheckCount", "changedRequirementCount", "copiedVerifierFileCount", "customRuleCount",
		"explicitlyDeferredRequirementCount", "falsePositiveSampleWindowRuns", "generatedMirrorImpactPathCount", "impactDemoCount", "impactObligationCount",
		"profileLineCount", "sourceOwnedImpactPathCount", "stackDiversityDimensionCount", "totalBlockingRequirementCount", "witnessBackedRequirementCount"} {
		summary[key] = n
	}
	fields := func(values map[string]jsonshape.Shape) jsonshape.Shape {
		properties := make([]jsonshape.Property, 0, len(values))
		for key, value := range values {
			properties = append(properties, jsonshape.Required(key, value))
		}
		return jsonshape.Object(properties...)
	}
	diagnostics := jsonshape.Tuple(
		report.DiagnosticStructure("blockingRequirements", jsonshape.Array(fields(map[string]jsonshape.Shape{"evidence": s, "owner": s, "requirementId": s, "status": s}), 0)),
		report.DiagnosticStructure("cacheNegativeChecks", jsonshape.Array(fields(map[string]jsonshape.Shape{
			"checkId": ruleID(), "evidence": t, "expectedOutcome": s, "invalidatedInputClass": s, "liveOrCredentialedCacheable": jsonshape.BooleanLiteral(false),
		}), 0)),
		report.DiagnosticStructure("customRules", jsonshape.Array(fields(map[string]jsonshape.Shape{
			"downgradeGenericFailures": jsonshape.BooleanLiteral(false), "owner": t, "purpose": t, "ruleId": ruleID(),
		}), 0)),
		report.DiagnosticStructure("impactDemos", jsonshape.Array(fields(map[string]jsonshape.Shape{"demoId": ruleID(), "obligationCount": n, "state": s}), 0)),
		report.DiagnosticStructure("packageVersionRef", s),
		report.DiagnosticStructure("rollbackVersionPin", t),
		report.DiagnosticStructure("stackDiversity", jsonshape.Array(fields(map[string]jsonshape.Shape{"baseline": t, "candidate": t, "dimension": s, "evidence": t}), 0)),
		report.DiagnosticStructure("timingReportArtifactPath", t),
	)
	rule := fields(map[string]jsonshape.Shape{
		"diagnostics": jsonshape.Tuple(), "message": t, "status": jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}),
		"ruleId": jsonshape.StringGrammar(regexp.QuoteMeta(acceptedRuleID) + `|` + failureRuleIDPattern()),
	})
	schema := report.Structure(1, reportKind, jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}), fields(summary), diagnostics, jsonshape.Array(rule, 1)).JSONSchema()
	properties := schema["properties"].(map[string]any)
	reportID := leaf(ruleID())
	properties["reportId"] = reportID
	properties["nonClaims"] = texts(1)
	properties["nonClaims"].(map[string]any)["items"] = leaf(t)
	values := properties["summary"].(map[string]any)["properties"].(map[string]any)
	values["maxAddedSeconds"] = map[string]any{"type": "number", "minimum": json.Number("0")}
	values["pilotMode"] = evaluated("Raw caller pilotMode JSON value, or null when absent; native admission refuses the input before echo when the compact JSON serialization of the value matches the shared secret-like predicate.")
	demo := properties["diagnostics"].(map[string]any)["prefixItems"].([]any)[3].(map[string]any)["properties"].(map[string]any)["value"].(map[string]any)
	demo["items"].(map[string]any)["properties"].(map[string]any)["state"] = impact.OutputStructure()["properties"].(map[string]any)["impactState"]
	schema["oneOf"] = []any{
		map[string]any{"properties": map[string]any{
			"state": map[string]any{"const": "passed"},
			"ruleResults": map[string]any{"maxItems": json.Number("1"), "items": map[string]any{"properties": map[string]any{
				"message": map[string]any{"const": acceptedRuleMessage}, "ruleId": map[string]any{"const": acceptedRuleID}, "status": map[string]any{"const": "passed"},
			}}},
			"summary": map[string]any{"properties": map[string]any{
				"copiedVerifierFileCount": map[string]any{"const": json.Number("0")}, "pilotMode": map[string]any{"const": nonBlockingPilotMode},
			}},
		}},
		map[string]any{"properties": map[string]any{
			"state": map[string]any{"const": "failed"},
			"ruleResults": map[string]any{"items": map[string]any{"properties": map[string]any{
				"ruleId": map[string]any{"pattern": "^(?:" + failureRuleIDPattern() + `)(?![\s\S])`}, "status": map[string]any{"const": "failed"},
			}}},
		}},
	}
	schema["description"] = "A passed report (exit 0) has only the accepted rule; a failed report (exit 1) lists every collected failure as a numbered failed rule. Counts, diagnostics and summary values are native projections of the admitted input and nested impact reports; failed reports may carry empty strings or zero counts for failure-collected members. Refused inputs emit no report."
	return schema
}

// AllOutputStructure is the --pilot all pair: first then stack-diverse report.
func AllOutputStructure() map[string]any {
	ref := map[string]any{"$ref": "#/$defs/" + reportDefinition}
	return map[string]any{
		"$schema": draft, "type": "array", "prefixItems": []any{ref, ref}, "items": false,
		"minItems": json.Number("2"), "maxItems": json.Number("2"),
		"$defs":       map[string]any{reportDefinition: member(ReportStructure())},
		"description": "Ordered pair: the first-pilot report, then the stack-diverse report. The process exits 1 when either report failed.",
	}
}

func failureRuleIDPattern() string { return regexp.QuoteMeta(failureRuleIDPrefix) + `[0-9]{3,}` }

func ruleID() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func texts(minimum int) map[string]any {
	return map[string]any{"type": "array", "items": ref(textDefinition), "minItems": minimum, "uniqueItems": true}
}

func ref(definition string) map[string]any { return map[string]any{"$ref": "#/$defs/" + definition} }

func leaf(shape jsonshape.Shape) map[string]any { return member(shape.JSONSchema()) }

func member(schema map[string]any) map[string]any {
	delete(schema, "$schema")
	return schema
}

func evaluated(description string) map[string]any { return map[string]any{"description": description} }

func openObject(description string) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": true, "description": description}
}

// Closed records are bound to the native KnownKeys inventory they mirror.
func closedRecord(keys []string, properties map[string]any, optional ...string) map[string]any {
	if len(keys) != len(properties) {
		panic("pilot structure differs from its native member inventory")
	}
	for _, key := range keys {
		if _, ok := properties[key]; !ok {
			panic("pilot structure omits a native member")
		}
	}
	return objectSchema(properties, false, optional...)
}

// objectSchema lists required members in sorted order; open records accept unknown
// members because native admission collects them as failures.
func objectSchema(properties map[string]any, open bool, optional ...string) map[string]any {
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	required := []any{}
	for _, key := range keys {
		if !slices.Contains(optional, key) {
			required = append(required, key)
		}
	}
	for _, key := range optional {
		if _, ok := properties[key]; !ok {
			panic("pilot structure optional member is undeclared")
		}
	}
	return map[string]any{"type": "object", "additionalProperties": open, "properties": properties, "required": required}
}
