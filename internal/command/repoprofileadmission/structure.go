package repoprofileadmission

import (
	"regexp"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

// Member inventories are shared by native admission and the structural projection.
var (
	inputKeys                  = []string{"facts", "policy", "profile", "schemaVersion"}
	profileKeys                = []string{"commandMatchers", "documents", "nonClaims", "proofs", "repository", "requirements", "schema"}
	repositoryKeys             = []string{"name", "primaryLanguages", "rootPackageName"}
	documentsKeys              = []string{"generatedArtifacts", "policyPath", "routerPath"}
	requirementsKeys           = []string{"idPattern", "specGlobs"}
	proofsKeys                 = []string{"bindingPath", "environmentClasses", "proofLikePaths", "retiredProofLikePaths"}
	commandMatcherKeys         = []string{"allowedArgv", "allowedScripts", "allowedTestPathGlobs", "credentialClass", "id", "kind", "networkPolicy", "parallelGroup"}
	factsKeys                  = []string{"commandEnvironmentPairs", "docsPolicyGeneratedArtifacts", "packageScripts", "rootPackageName", "rootScripts", "trackedFiles"}
	policyKeys                 = []string{"environmentPolicy", "packageNamePattern"}
	environmentPolicyKeys      = []string{"environmentClassPolicies", "liveGithubRequiredClasses", "localSecretRequiredClasses"}
	environmentClassPolicyKeys = []string{"credentialClass", "environmentClass", "networkPolicy"}
	generatedArtifactKeys      = []string{"generator", "path", "sourceOfTruth"}
	commandEnvironmentPairKeys = []string{"command", "environmentClasses"}
	packageScriptsKeys         = []string{"packageName", "scripts"}
)

// Lists whose trimmed items native admission requires to be unique.
var uniqueInputLists = [][]string{
	{"profile", "nonClaims"}, {"profile", "repository", "primaryLanguages"}, {"profile", "requirements", "specGlobs"},
	{"profile", "proofs", "environmentClasses"}, {"profile", "proofs", "proofLikePaths"}, {"profile", "proofs", "retiredProofLikePaths"},
	{"profile", "documents", "generatedArtifacts", "*", "sourceOfTruth"}, {"profile", "commandMatchers", "*", "allowedScripts"},
	{"profile", "commandMatchers", "*", "allowedTestPathGlobs"}, {"facts", "docsPolicyGeneratedArtifacts", "*", "sourceOfTruth"},
	{"facts", "rootScripts"}, {"facts", "trackedFiles"},
}

func InputShape() jsonshape.Shape {
	text := jsonshape.NonBlankString()
	texts := func(minimum int) jsonshape.Shape { return jsonshape.Array(text, minimum) }
	artifact := jsonshape.RequiredObject(generatedArtifactKeys, map[string]jsonshape.Shape{"generator": text, "path": text, "sourceOfTruth": texts(1)})
	matcher := jsonshape.ObjectFromKeys(commandMatcherKeys, map[string]jsonshape.Shape{
		"allowedArgv": jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 1), "allowedScripts": texts(1), "allowedTestPathGlobs": texts(1),
		"credentialClass": trimmedEnumShape(credentialClasses), "id": text, "kind": trimmedEnumShape(commandMatcherKinds),
		"networkPolicy": trimmedEnumShape(networkPolicies), "parallelGroup": text,
	}, "allowedArgv", "allowedScripts", "allowedTestPathGlobs")
	profile := jsonshape.RequiredObject(profileKeys, map[string]jsonshape.Shape{
		"commandMatchers": jsonshape.Array(matcher, 0),
		"documents": jsonshape.RequiredObject(documentsKeys, map[string]jsonshape.Shape{
			"generatedArtifacts": jsonshape.Array(artifact, 0), "policyPath": text, "routerPath": text,
		}),
		"nonClaims": texts(1),
		"proofs": jsonshape.RequiredObject(proofsKeys, map[string]jsonshape.Shape{
			"bindingPath": text, "environmentClasses": texts(1), "proofLikePaths": texts(1), "retiredProofLikePaths": texts(0),
		}),
		"repository":   jsonshape.RequiredObject(repositoryKeys, map[string]jsonshape.Shape{"name": text, "primaryLanguages": texts(1), "rootPackageName": text}),
		"requirements": jsonshape.RequiredObject(requirementsKeys, map[string]jsonshape.Shape{"idPattern": text, "specGlobs": texts(1)}),
		"schema":       jsonshape.StringLiteral(profileSchema),
	})
	facts := jsonshape.RequiredObject(factsKeys, map[string]jsonshape.Shape{
		"commandEnvironmentPairs":      jsonshape.Array(jsonshape.RequiredObject(commandEnvironmentPairKeys, map[string]jsonshape.Shape{"command": text, "environmentClasses": texts(0)}), 0),
		"docsPolicyGeneratedArtifacts": jsonshape.Array(artifact, 0),
		"packageScripts":               jsonshape.Array(jsonshape.RequiredObject(packageScriptsKeys, map[string]jsonshape.Shape{"packageName": text, "scripts": texts(0)}), 0),
		"rootPackageName":              text, "rootScripts": texts(0), "trackedFiles": texts(0),
	})
	classPolicy := jsonshape.RequiredObject(environmentClassPolicyKeys, map[string]jsonshape.Shape{
		"credentialClass": trimmedEnumShape(credentialClasses), "environmentClass": text, "networkPolicy": trimmedEnumShape(networkPolicies),
	})
	policy := jsonshape.ObjectFromKeys(policyKeys, map[string]jsonshape.Shape{
		"environmentPolicy": jsonshape.ObjectFromKeys(environmentPolicyKeys, map[string]jsonshape.Shape{
			"environmentClassPolicies":  jsonshape.Nullable(jsonshape.Array(classPolicy, 0)),
			"liveGithubRequiredClasses": texts(0), "localSecretRequiredClasses": texts(0),
		}, "environmentClassPolicies"),
		"packageNamePattern": jsonshape.Nullable(text),
	}, "packageNamePattern")
	return jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		"facts": facts, "policy": policy, "profile": profile, "schemaVersion": jsonshape.IntegerLiteral(1),
	}, "schemaVersion")
}

func InputStructure() map[string]any {
	schema := InputShape().JSONSchema()
	for _, path := range uniqueInputLists {
		structureNode(schema, path...)["uniqueItems"] = true
	}
	schema["description"] = "profile, facts and policy are required; transitional schemaVersion is optional but, when present, must be literal 1. Every nested member is required except optional nonnull matcher allowedArgv, allowedScripts and allowedTestPathGlobs, optional nullable environmentClassPolicies and optional nullable packageNamePattern. Text trims by native Unicode whitespace to nonempty; kind, networkPolicy and credentialClass are trimmed finite vocabularies; allowedArgv tokens are untrimmed nonempty strings. Sorted lists, rootScripts and trackedFiles are unique after trimming. Native admission owns text privacy, sorted order, display-only command tokens, canonical repository-relative trackedFiles, sorted unique matcher IDs and environment classes, and a compilable packageNamePattern. Other paths, globs, the requirement ID regex, matcher/argv policy, tracked-file existence and command matching are evaluated into failed reports. No repository state is read and no command executes."
	return schema
}

func OutputShape() jsonshape.Shape {
	return jsonshape.DiscriminatedUnion("state", reportShape(true), reportShape(false))
}

func OutputStructure() map[string]any {
	schema := OutputShape().JSONSchema()
	for _, raw := range schema["oneOf"].([]any) {
		branch := raw.(map[string]any)
		properties := branch["properties"].(map[string]any)
		properties["reportId"] = nestedSchema(jsonshape.StringLiteral(reportKind))
		properties["nonClaims"] = reportNonClaimsStructure()
		branch["description"] = "reportId repeats the fixed structural report kind. Passed reports carry the single accepted rule and exit 0. Failed reports carry one numbered failed rule per sorted unique failure in order and exit 1 with JSON; input refusals exit 1 on stderr without a report. Root and rule diagnostics are empty. Summary counts derive from admitted profile and facts. nonClaims merge builtin and caller claims, sorted and deduplicated. Structural validity does not read repository state or prove command execution."
	}
	return schema
}

func reportShape(passed bool) jsonshape.Shape {
	count := jsonshape.IntegerMinimum(0)
	summary := jsonshape.Object(
		jsonshape.Required("commandMatcherCount", count), jsonshape.Required("distinctWitnessCommandCount", count),
		jsonshape.Required("environmentClassCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("generatedArtifactCount", count),
	)
	if passed {
		rule := report.RuleStructure(jsonshape.StringLiteral(acceptedRuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(acceptedRuleMessage), jsonshape.Tuple())
		return report.Structure(1, reportKind, jsonshape.StringLiteral("passed"), summary, jsonshape.Tuple(), jsonshape.Tuple(rule))
	}
	rule := report.RuleStructure(jsonshape.StringGrammar(regexp.QuoteMeta(failureRuleIDPrefix)+`[0-9]{3,}`), jsonshape.StringLiteral("failed"),
		jsonshape.StringGrammar(`[\s\S]+`), jsonshape.Tuple())
	return report.Structure(1, reportKind, jsonshape.StringLiteral("failed"), summary, jsonshape.Tuple(), jsonshape.Array(rule, 1))
}

func reportNonClaimsStructure() map[string]any {
	claims := nestedSchema(jsonshape.Array(canonicalTextShape(), len(boundaryNonClaims)))
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], claims["uniqueItems"] = contains, true
	return claims
}

// trimmedEnumShape admits a native vocabulary member after Unicode trimming.
func trimmedEnumShape(values []string) jsonshape.Shape {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = regexp.QuoteMeta(value)
	}
	slices.Sort(quoted)
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[" + space + "]*(?:" + strings.Join(quoted, "|") + ")[" + space + "]*"
	})
}

func canonicalTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[^" + space + "](?:[\\s\\S]*[^" + space + "])?"
	})
}

func nestedSchema(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}

// structureNode follows properties, array items and nullable wrappers only.
func structureNode(schema map[string]any, path ...string) map[string]any {
	node := schema
	for _, segment := range path {
		if segment == "*" {
			node = node["items"].(map[string]any)
		} else {
			node = node["properties"].(map[string]any)[segment].(map[string]any)
		}
		if alternatives, nullable := node["anyOf"].([]any); nullable {
			for _, raw := range alternatives {
				if branch := raw.(map[string]any); branch["type"] != "null" {
					node = branch
				}
			}
		}
	}
	return node
}
