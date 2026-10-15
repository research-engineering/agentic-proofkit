package scaffoldprofileplan

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

const PlanKind = "proofkit.repo-profile-scaffold-plan"

var inputKeys = []string{"commandMatcherHints", "environmentClasses", "nonClaims", "paths", "planId", "presetId", "repository", "requirements", "schemaVersion"}
var repositoryKeys = []string{"name", "primaryLanguages", "profilePath", "rootPackageName"}
var pathsKeys = []string{"bindingPath", "generatedArtifacts", "policyPath", "proofLikePaths", "retiredProofLikePaths", "routerPath", "specGlobs"}
var requirementsKeys = []string{"idPattern"}
var generatedArtifactKeys = []string{"generator", "path", "sourceOfTruth"}
var commandMatcherKeys = []string{"allowedArgv", "allowedScripts", "allowedTestPathGlobs", "credentialClass", "id", "kind", "networkPolicy", "parallelGroup"}

// InputShape describes the decoded JSON that native admission accepts,
// including present-but-null optional members that native code defaults.
func InputShape() jsonshape.Shape {
	id, text, path := identifierShape(), jsonshape.NonBlankString(), pathShape()
	repository := jsonshape.ObjectFromKeys(repositoryKeys, map[string]jsonshape.Shape{
		"name": text, "primaryLanguages": jsonshape.Array(text, 1), "profilePath": path, "rootPackageName": text,
	})
	paths := jsonshape.ObjectFromKeys(pathsKeys, map[string]jsonshape.Shape{
		"bindingPath": path, "generatedArtifacts": jsonshape.Nullable(jsonshape.Array(generatedArtifactShape(), 0)),
		"policyPath": path, "proofLikePaths": jsonshape.Nullable(jsonshape.Array(path, 1)),
		"retiredProofLikePaths": jsonshape.Nullable(jsonshape.Array(path, 0)), "routerPath": path,
		"specGlobs": jsonshape.Nullable(jsonshape.Array(path, 1)),
	}, "generatedArtifacts", "proofLikePaths", "retiredProofLikePaths", "specGlobs")
	return jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		"commandMatcherHints": jsonshape.Nullable(jsonshape.Array(commandMatcherShape(text), 0)),
		"environmentClasses":  jsonshape.Nullable(jsonshape.Array(text, 1)),
		"nonClaims":           jsonshape.Array(text, 1), "paths": paths, "planId": id,
		"presetId": jsonshape.Nullable(PresetShape()), "repository": repository,
		"requirements":  jsonshape.ObjectFromKeys(requirementsKeys, map[string]jsonshape.Shape{"idPattern": text}),
		"schemaVersion": jsonshape.IntegerLiteral(1),
	}, "commandMatcherHints", "environmentClasses", "presetId")
}

func InputStructure() map[string]any {
	schema := InputShape().JSONSchema()
	// presetId in callerSpecGlobPresets() requires present, non-null
	// paths.specGlobs: "not" refuses exactly such a preset whose paths lack them.
	if presets := callerSpecGlobPresets(); len(presets) != 0 {
		schema["not"] = map[string]any{
			"required": []any{"presetId"},
			"properties": map[string]any{
				"presetId": map[string]any{"enum": admit.StringSliceToAny(presets)},
				"paths": map[string]any{"not": map[string]any{
					"required": []any{"specGlobs"}, "properties": map[string]any{"specGlobs": map[string]any{"type": "array"}},
				}},
			},
		}
	}
	schema["description"] = "All root members are required except presetId, environmentClasses and commandMatcherHints; those and the optional paths lists admit absence or null, which native admission replaces with preset-derived or empty defaults. A preset supplies specGlobs only from its docs/specs/ starter paths; with a preset that has none (the root not clause), specGlobs must be present and non-null. Explicit specGlobs, proofLikePaths, environmentClasses, sourceOfTruth and matcher lists must be nonempty; native admission or draft construction refuses empty lists. Each command matcher kind owns exactly one list member: exact_argv uses allowedArgv, python_pytest_contract uses allowedTestPathGlobs and the bun kinds use allowedScripts. Text trims to nonempty secret-safe text; paths are untrimmed nonempty strings whose safe repository-relative POSIX grammar and privacy remain native. Native admission also owns IDs without secret/timestamp components, sorted unique normalized lists, unique artifact paths and matcher IDs, literal argv tokens, preset-derived lists that must be nonempty when caller lists are absent, and caller nonClaims that must not repeat builtin nonClaims. schemaVersion requires the literal integer token 1. The plan neither reads repository state nor writes files."
	return schema
}

// Output text is native-normalized; nonempty text is its structural claim.
func OutputShape() jsonshape.Shape {
	id, text, path := identifierShape(), nonemptyText(), pathShape()
	gaps := []jsonshape.Shape{
		gapShape(text, "command-matchers", "commandMatchers"),
		gapShape(text, "generated-artifacts", "documents.generatedArtifacts"),
		gapShape(text, "tracked-facts", "facts"),
	}
	provenance := jsonshape.Object(
		jsonshape.Required("evidenceRef", text),
		jsonshape.Required("fieldPath", valuesShape("commandMatchers", "documents.generatedArtifacts", "documents.policyPath", "documents.routerPath",
			"proofs.bindingPath", "proofs.environmentClasses", "proofs.proofLikePaths", "repository.name", "repository.primaryLanguages",
			"repository.rootPackageName", "requirements.idPattern", "requirements.specGlobs")),
		jsonshape.Required("nonClaim", text),
		jsonshape.Required("source", valuesShape("caller_input", "stack_preset")),
	)
	draft := jsonshape.Object(
		jsonshape.Required("commandMatchers", jsonshape.Array(commandMatcherShape(text), 0)),
		jsonshape.Required("documents", jsonshape.Object(
			jsonshape.Required("generatedArtifacts", jsonshape.Array(generatedArtifactShape(), 0)),
			jsonshape.Required("policyPath", path), jsonshape.Required("routerPath", path),
		)),
		jsonshape.Required("nonClaims", jsonshape.Tuple(text, text)),
		jsonshape.Required("proofs", jsonshape.Object(
			jsonshape.Required("bindingPath", path), jsonshape.Required("environmentClasses", jsonshape.Array(text, 1)),
			jsonshape.Required("proofLikePaths", jsonshape.Array(path, 1)), jsonshape.Required("retiredProofLikePaths", jsonshape.Array(path, 0)),
		)),
		jsonshape.Required("repository", jsonshape.Object(
			jsonshape.Required("name", text), jsonshape.Required("primaryLanguages", jsonshape.Array(text, 1)),
			jsonshape.Required("rootPackageName", text),
		)),
		jsonshape.Required("requirements", jsonshape.Object(
			jsonshape.Required("idPattern", text), jsonshape.Required("specGlobs", jsonshape.Array(path, 1)),
		)),
		jsonshape.Required("schema", jsonshape.StringLiteral("proofkit.repo-profile.v1")),
	)
	return jsonshape.Object(
		jsonshape.Required("callerRequiredGaps", jsonshape.BoundedArray(jsonshape.DiscriminatedUnion("gapId", gaps...), 1, len(gaps))),
		jsonshape.Required("nextCommands", jsonshape.Tuple(text, text, text)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, len(scaffoldNonClaims)+1)),
		jsonshape.Required("planId", id), jsonshape.Required("planKind", jsonshape.StringLiteral(PlanKind)),
		jsonshape.Required("presetId", jsonshape.Nullable(PresetShape())), jsonshape.Required("profilePath", path),
		jsonshape.Required("provenance", jsonshape.BoundedArray(provenance, 10, 12)),
		jsonshape.Required("repoProfileDraft", draft), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
	)
}

func OutputStructure() map[string]any {
	schema := OutputShape().JSONSchema()
	schema["description"] = "Complete emitted plan; native refusals emit no JSON. Gaps are sorted by gapId and always include tracked facts; matcher and generated-artifact gaps appear only for empty caller lists. Provenance has ten fixed rows plus optional generated-artifact and command-matcher rows, sorted by fieldPath; preset-derived rows name the preset in evidenceRef. Plan nonClaims merge builtin and caller claims without duplicates. The draft retains normalized sorted caller values, preset-derived starter lists and one list member per matcher kind. Structural validity does not prove repository facts, profile correctness, proof freshness or rollout readiness."
	return schema
}

// Native admission requires exactly the list member selected by the native
// matcher kind rules; the other list members are refused, not ignored.
func commandMatcherShape(text jsonshape.Shape) jsonshape.Shape {
	kinds := sortedValues(supportedMatcherKinds)
	branches := make([]jsonshape.Shape, 0, len(kinds))
	for _, kind := range kinds {
		list := jsonshape.Required("allowedScripts", jsonshape.Array(text, 1))
		switch kind {
		case "exact_argv":
			list = jsonshape.Required("allowedArgv", jsonshape.Array(text, 1))
		case "python_pytest_contract":
			list = jsonshape.Required("allowedTestPathGlobs", jsonshape.Array(pathShape(), 1))
		}
		branches = append(branches, jsonshape.Object(list,
			jsonshape.Required("credentialClass", jsonshape.Enum(supportedCredentialClasses)), jsonshape.Required("id", text),
			jsonshape.Required("kind", jsonshape.StringLiteral(kind)), jsonshape.Required("networkPolicy", jsonshape.Enum(supportedNetworkPolicies)),
			jsonshape.Required("parallelGroup", text),
		))
	}
	return jsonshape.DiscriminatedUnion("kind", branches...)
}

func generatedArtifactShape() jsonshape.Shape {
	path := pathShape()
	return jsonshape.ObjectFromKeys(generatedArtifactKeys, map[string]jsonshape.Shape{
		"generator": path, "path": path, "sourceOfTruth": jsonshape.Array(path, 1),
	})
}

func gapShape(text jsonshape.Shape, suffix string, fieldPath string) jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("fieldPath", jsonshape.StringLiteral(fieldPath)),
		jsonshape.Required("gapId", jsonshape.StringLiteral("proofkit.repo-profile-scaffold.gap."+suffix)),
		jsonshape.Required("nonClaim", text), jsonshape.Required("owner", jsonshape.StringLiteral("consumer_repository")),
		jsonshape.Required("reason", text), jsonshape.Required("suggestedAction", text),
	)
}

// PresetShape is the admitted stack preset vocabulary carried by plans and the
// workflow inputs composed from them.
// callerSpecGlobPresets lists the presets for which native admission requires
// caller-provided specGlobs, by the same rule that derives preset defaults.
func callerSpecGlobPresets() []string {
	presets := []string{}
	for _, id := range stackpreset.IDs() {
		if preset, ok := stackpreset.ProfileFor(id); ok && len(presetSpecGlobs(preset)) == 0 {
			presets = append(presets, id)
		}
	}
	return presets
}

func PresetShape() jsonshape.Shape {
	values := map[string]struct{}{}
	for _, id := range stackpreset.IDs() {
		values[id] = struct{}{}
	}
	return jsonshape.Enum(values)
}

func identifierShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

// Paths are not trimmed by this command. Their safe repository-relative POSIX
// grammar and path privacy remain native admission obligations.
func pathShape() jsonshape.Shape { return nonemptyText() }

func nonemptyText() jsonshape.Shape { return jsonshape.StringGrammar(`[\s\S]+`) }

func valuesShape(values ...string) jsonshape.Shape {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return jsonshape.Enum(set)
}

func sortedValues(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}
