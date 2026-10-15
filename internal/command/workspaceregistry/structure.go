package workspaceregistry

import (
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

// failureOrdinalPattern is the %03d spelling of a positive one-based index.
const failureOrdinalPattern = `(?:00[1-9]|0[1-9][0-9]|[1-9][0-9]{2,})`

// InputShape describes admitted registry facts, including facts whose
// policy evaluation later produces a failed report.
func InputShape() jsonshape.Shape {
	text := jsonshape.NonBlankString()
	texts := func(minimum int) jsonshape.Shape { return jsonshape.Array(text, minimum) }
	optionalTexts := jsonshape.Nullable(texts(0))
	refs := jsonshape.Nullable(jsonshape.Array(jsonshape.RequiredObject(dependencyRefKeys, map[string]jsonshape.Shape{
		"field": text, "name": text, "version": text,
	}), 0))
	scripts := jsonshape.Array(jsonshape.RequiredObject(scriptKeys, map[string]jsonshape.Shape{"command": scriptCommandShape(), "name": text}), 0)
	exact := jsonshape.ObjectFromKeys(scriptKeys, map[string]jsonshape.Shape{"command": scriptCommandShape(), "name": text}, "command")
	snippet := jsonshape.RequiredObject(expectedSnippetKeys, map[string]jsonshape.Shape{"failureMessage": text, "snippet": text})
	return jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		"schemaVersion": jsonshape.IntegerLiteral(1), "knownPackageNames": texts(1), "nonClaims": texts(0),
		"root": jsonshape.ObjectFromKeys(rootKeys, map[string]jsonshape.Shape{"dependencyRefs": refs, "name": text, "scripts": scripts}, "dependencyRefs", "name"),
		"packages": jsonshape.Array(jsonshape.ObjectFromKeys(packageKeys, map[string]jsonshape.Shape{
			"dependencyRefs": refs, "dirName": dirNameShape(), "name": text, "scripts": scripts,
		}, "dependencyRefs"), 0),
		"scriptPolicy": jsonshape.ObjectFromKeys(scriptPolicyKeys, map[string]jsonshape.Shape{
			"admittedRootScriptNames": optionalTexts, "exactRootScripts": jsonshape.Nullable(jsonshape.Array(exact, 0)),
			"requiredPackageScriptNames": optionalTexts, "requiredRootScriptNames": optionalTexts,
			"selfTargetOptionNames": texts(1), "targetNamePrefixes": texts(1), "targetOptionNames": texts(1),
		}, "admittedRootScriptNames", "exactRootScripts", "requiredPackageScriptNames", "requiredRootScriptNames"),
		"dependencyPolicy": jsonshape.Nullable(jsonshape.ObjectFromKeys(dependencyPolicyKeys, map[string]jsonshape.Shape{
			"internalDependencyLabel": text, "internalNamePrefixes": texts(1), "workspaceVersion": text,
		}, "internalDependencyLabel")),
		"lockfilePolicy": jsonshape.Nullable(jsonshape.ObjectFromKeys(lockfilePolicyKeys, map[string]jsonshape.Shape{
			"expectedSnippets": jsonshape.Nullable(jsonshape.Array(snippet, 0)), "lockfileText": text,
		}, "expectedSnippets")),
	}, "dependencyPolicy", "lockfilePolicy", "nonClaims")
}

func InputStructure() map[string]any {
	schema := InputShape().JSONSchema()
	schema["description"] = "schemaVersion, knownPackageNames, root, packages and scriptPolicy are required. dependencyPolicy and lockfilePolicy may be absent or null, which disables that policy; root nonClaims may be absent but not null. All nested records are closed. root.name, internalDependencyLabel and exact-script command may be absent but not null; dependencyRefs, expectedSnippets and the four optional script-name lists may be absent or null; except for admittedRootScriptNames they then mean empty. knownPackageNames and the target option and prefix lists are nonempty. Text trims Unicode whitespace and must be nonblank; script commands are single-line after trimming and dirName is one trimmed path segment other than . or .. without slash, backslash or NUL. Native admission owns secret-like text rejection and normalized uniqueness of known names, package names, script names and policy lists. An absent or null admittedRootScriptNames leaves root scripts unrestricted, while an explicit [] admits no root script. Known-package, script, target, dependency and lockfile policy failures are report data, not input refusals. No script is executed and no lockfile is read from disk."
	return schema
}

// Script commands are single-line after Go strings.TrimSpace normalization.
func scriptCommandShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		edge := `[^` + space + `\x00]`
		return `[` + space + `]*` + edge + `(?:[^\r\n\x00]*` + edge + `)?[` + space + `]*`
	})
}

// A trimmed dirName is one segment and neither "." nor "..".
func dirNameShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		separators := `/\\\x00`
		anyRune, edge, plain := `[^`+separators+`]`, `[^`+space+separators+`]`, `[^`+space+separators+`.]`
		return `[` + space + `]*(?:` + plain + edge + `?|\.` + plain + `|` + edge + anyRune + `+` + edge + `)[` + space + `]*`
	})
}

// OutputShape is the exclusive passed/failed report sum emitted by Build.
func OutputShape() jsonshape.Shape {
	return jsonshape.DiscriminatedUnion("state", reportShape(false), reportShape(true))
}

func OutputStructure() map[string]any {
	schema := OutputShape().JSONSchema()
	prefix := make([]any, 0, len(registryNonClaims))
	for _, claim := range registryNonClaims {
		prefix = append(prefix, map[string]any{"const": claim})
	}
	text := jsonshape.NonBlankString().JSONSchema()
	delete(text, "$schema")
	for _, raw := range schema["oneOf"].([]any) {
		branch := raw.(map[string]any)
		properties := branch["properties"].(map[string]any)
		properties["reportId"] = map[string]any{"type": "string", "const": reportKind}
		properties["nonClaims"] = map[string]any{"type": "array", "minItems": len(registryNonClaims), "prefixItems": prefix, "items": text}
		branch["description"] = "Passed reports (exit 0) have zero failures, no failure diagnostics and no failed rule; failed reports (exit 1) list failure.NNN diagnostics in rule failure order. ruleResults is the fixed six-rule tuple in native locale order. Passed rules carry their exact counter tuple; dependency and lockfile rules are skipped with zero checks exactly when their policy is absent or null; failed rules carry their counters and one or more failure.NNN diagnostics in native locale key order. nonClaims start with the four builtin claims followed by trimmed caller claims in caller order. Native Build owns counter arithmetic, failure text, aggregation and numbering, the presence of a failed rule in failed reports, summary/rule policy-flag agreement and state/exit-code consistency. Reports do not execute scripts, refresh lockfiles or prove repository freshness."
	}
	return schema
}

func reportShape(failed bool) jsonshape.Shape {
	count, positive := jsonshape.IntegerMinimum(0), jsonshape.IntegerMinimum(1)
	state, failures, diagnostics := "passed", jsonshape.IntegerLiteral(0), jsonshape.Tuple()
	if failed {
		state, failures, diagnostics = "failed", positive, jsonshape.Array(failureDiagnosticShape(), 1)
	}
	summary := jsonshape.Object(
		jsonshape.Required("checkedItemCount", positive), jsonshape.Required("dependencyPolicyEnabled", jsonshape.Boolean()),
		jsonshape.Required("failureCount", failures), jsonshape.Required("lockfilePolicyEnabled", jsonshape.Boolean()),
		jsonshape.Required("packageCount", count), jsonshape.Required("packageScriptCount", count), jsonshape.Required("rootScriptCount", count),
	)
	inventory := ruleInventory()
	sort.Slice(inventory, func(left, right int) bool { return jsLocaleLess(inventory[left].id, inventory[right].id) })
	rules := make([]jsonshape.Shape, 0, len(inventory))
	for _, rule := range inventory {
		rules = append(rules, rule.shape(failed))
	}
	return report.Structure(1, reportKind, jsonshape.StringLiteral(state), summary, diagnostics, jsonshape.Tuple(rules...))
}

type ruleCounters struct {
	id       string
	counters map[string]jsonshape.Shape
	enabled  string // Nonempty only for rules skipped when their policy is absent.
}

func ruleInventory() []ruleCounters {
	count, positive := jsonshape.IntegerMinimum(0), jsonshape.IntegerMinimum(1)
	return []ruleCounters{
		{id: knownPackageFactsRuleID, counters: map[string]jsonshape.Shape{"checkedItemCount": positive, "knownPackageCount": positive, "packageFactCount": count}},
		{id: rootScriptsRuleID, counters: map[string]jsonshape.Shape{"checkedItemCount": count, "rootScriptCount": count}},
		{id: packageScriptsRuleID, counters: map[string]jsonshape.Shape{"checkedItemCount": count, "packageCount": count, "requiredPackageScriptCount": count}},
		{id: scriptTargetsRuleID, counters: map[string]jsonshape.Shape{"checkedItemCount": count, "scopeCount": positive}},
		{id: dependenciesRuleID, counters: map[string]jsonshape.Shape{"checkedItemCount": count}, enabled: "dependencyPolicyEnabled"},
		{id: bunLockfileRuleID, counters: map[string]jsonshape.Shape{"checkedItemCount": count}, enabled: "lockfilePolicyEnabled"},
	}
}

func (rule ruleCounters) shape(allowFailed bool) jsonshape.Shape {
	id := jsonshape.StringLiteral(rule.id)
	active := rule.counters
	if rule.enabled != "" {
		active = map[string]jsonshape.Shape{rule.enabled: jsonshape.BooleanLiteral(true)}
		for key, value := range rule.counters {
			active[key] = value
		}
	}
	alternatives := []jsonshape.Shape{report.RuleStructure(id, jsonshape.StringLiteral("passed"), jsonshape.StringLiteral("passed"), diagnosticTuple(active))}
	if allowFailed {
		items := []jsonshape.Shape{failureDiagnosticShape()}
		for _, key := range localeKeys(active) {
			items = append(items, report.DiagnosticStructure(key, active[key]))
		}
		message := jsonshape.StringGrammar(`[1-9][0-9]*` + regexp.QuoteMeta(issueMessageSuffix))
		alternatives = append(alternatives, report.RuleStructure(id, jsonshape.StringLiteral("failed"), message,
			jsonshape.Array(jsonshape.OneOf(items...), len(active)+1)))
	}
	if rule.enabled != "" {
		skipped := map[string]jsonshape.Shape{"checkedItemCount": jsonshape.IntegerLiteral(0), rule.enabled: jsonshape.BooleanLiteral(false)}
		alternatives = append(alternatives, report.RuleStructure(id, jsonshape.StringLiteral("skipped"), jsonshape.StringLiteral("skipped"), diagnosticTuple(skipped)))
	}
	if len(alternatives) == 1 {
		return alternatives[0]
	}
	return jsonshape.DiscriminatedUnion("status", alternatives...)
}

func diagnosticTuple(values map[string]jsonshape.Shape) jsonshape.Shape {
	items := make([]jsonshape.Shape, 0, len(values))
	for _, key := range localeKeys(values) {
		items = append(items, report.DiagnosticStructure(key, values[key]))
	}
	return jsonshape.Tuple(items...)
}

func failureDiagnosticShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("key", jsonshape.StringGrammar(regexp.QuoteMeta(failureDiagnosticPrefix)+failureOrdinalPattern)),
		jsonshape.Required("value", jsonshape.NonBlankString()),
	)
}

// localeKeys reuses the native rule diagnostic ordering.
func localeKeys(values map[string]jsonshape.Shape) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool { return jsLocaleLess(keys[left], keys[right]) })
	return keys
}
