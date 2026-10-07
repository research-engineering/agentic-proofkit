package requirementproofview

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func StructuredInputStructure() map[string]any {
	schema := requirementbinding.InputStructure()
	schema["description"] = "Structured binding-owned input. Native admission and evaluation must succeed; failed binding reports become view input errors. Scope defaults to slice and accepts graph or slice. The CLI rejects local-environment policy flags for structured input. Structural validity neither evaluates binding semantics nor proves witness execution."
	return schema
}

func CompactInputStructure() map[string]any {
	return compactproofcontract.InputStructure()
}

func requiredNames(properties map[string]any) []any {
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]any, len(keys))
	for i, key := range keys {
		result[i] = key
	}
	return result
}

func StructuredOutputStructure() map[string]any {
	schema := requirementbinding.EvidenceGraphOutputStructure()
	properties := schema["properties"].(map[string]any)
	delete(properties, "bindingCount")
	delete(properties, "graphKind")
	properties["authority"] = jsonshape.StringLiteral("lookup_only").JSONSchema()
	properties["viewKind"] = jsonshape.StringLiteral("proofkit.requirement-proof-view").JSONSchema()
	properties["scope"] = jsonshape.Enum(map[string]struct{}{"graph": {}, "slice": {}}).JSONSchema()
	properties["omittedRequirementCount"] = jsonshape.IntegerMinimum(0).JSONSchema()
	properties["nonClaims"].(map[string]any)["minItems"] = len(defaultNonClaims)
	requirement := properties["requirements"].(map[string]any)["items"].(map[string]any)
	fields := requirement["properties"].(map[string]any)
	fields["scenarioCount"] = jsonshape.IntegerMinimum(0).JSONSchema()
	for _, name := range []string{"commandIds", "environmentClasses", "witnessPaths"} {
		fields[name] = jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 0).JSONSchema()
	}
	scenario := fields["scenarios"].(map[string]any)["items"].(map[string]any)
	delete(scenario["properties"].(map[string]any), "witnessSelectors")
	scenario["required"] = requiredNames(scenario["properties"].(map[string]any))
	requirement["required"] = requiredNames(fields)
	schema["required"] = requiredNames(properties)
	schema["description"] = "JSON lookup-only structured view, wire schemaVersion 1. Native binding admission owns identifiers, privacy, paths, references and passing proof-state relations; scope selects graph or slice. Native derivation owns count equality, omissions, normalized ordering and unique aggregated command/environment/path lists. All fields are present and non-null. JSON/Markdown/HTML are derived renderings, not witness execution, coverage, freshness or merge authority. Input errors emit no view."
	return schema
}

func CompactOutputStructure() map[string]any {
	schema := compactproofcontract.ResolverOutputStructure()
	properties := schema["properties"].(map[string]any)
	for key := range properties {
		if !slices.Contains([]string{"schemaVersion", "contractId", "localEnvironmentPolicy", "nonClaims", "bindings"}, key) {
			delete(properties, key)
		}
	}
	properties["authority"] = jsonshape.StringLiteral("lookup_only").JSONSchema()
	properties["viewKind"] = jsonshape.StringLiteral("proofkit.compact-requirement-proof-view").JSONSchema()
	for _, name := range []string{"bindingCount", "commandCount", "preconditionedBindingCount", "requirementCount"} {
		properties[name] = jsonshape.IntegerMinimum(0).JSONSchema()
	}
	properties["nonClaims"].(map[string]any)["minItems"] = len(defaultNonClaims) + 2
	binding := properties["bindings"].(map[string]any)["items"].(map[string]any)
	fields := binding["properties"].(map[string]any)
	witnesses := fields["testWitnesses"].(map[string]any)["properties"].(map[string]any)
	routes := make([]any, 0, 2)
	for _, role := range []string{"falsification", "positive"} {
		route := witnesses[role].(map[string]any)
		members := route["properties"].(map[string]any)
		members["verifyCommands"] = members["verifyCommandRefs"]
		delete(members, "verifyCommandRefs")
		members["bindingRecordId"] = fields["bindingRecordId"]
		route["required"] = requiredNames(members)
		routes = append(routes, route)
	}
	delete(fields, "testWitnesses")
	fields["declaredWitnessRoutes"] = map[string]any{"type": "array", "minItems": 2, "maxItems": 2, "items": false, "prefixItems": routes}
	binding["required"] = requiredNames(fields)
	schema["required"] = requiredNames(properties)
	schema["description"] = "JSON lookup-only compact view, wire schemaVersion 2. All fields are present and non-null. Binding and route IDs are sha256 references; native admission owns canonical integer tokens, identifiers, privacy, scoped scenario grammar, repo-relative selectors and display-only commands. Exactly two declaredWitnessRoutes are ordered falsification then positive, independent of resolutionOrderIndex; verifyCommands is projected from the resolver's verifyCommandRefs. Native derivation owns joins, ordering, unique lists, count equality and preconditioned classification under caller-provided localEnvironmentClasses. Empty contracts and lists are admitted. nonClaims includes the six built-in lookup limitations. JSON/Markdown/HTML neither execute witnesses nor prove coverage, freshness, authenticity or merge authority. Admission errors emit no view."
	return schema
}
