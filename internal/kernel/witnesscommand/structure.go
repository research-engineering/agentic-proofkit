package witnesscommand

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

// CommandStructure describes admitted wire records. Vocabulary membership,
// privacy, canonical tokens, path safety and ordering remain native checks.
func CommandStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	classes := jsonshape.Array(text, 1)
	environment := jsonshape.DiscriminatedUnion("inherit",
		jsonshape.Object(
			jsonshape.Required("inherit", jsonshape.StringLiteral("none")),
			jsonshape.Required("allowlist", jsonshape.BoundedArray(text, 0, 0)),
			jsonshape.Required("classes", classes)),
		jsonshape.Object(
			jsonshape.Required("inherit", jsonshape.StringLiteral("allowlist")),
			jsonshape.Required("allowlist", jsonshape.Array(jsonshape.StringGrammar(`[_A-Z][_A-Z0-9]*`), 1)),
			jsonshape.Required("classes", classes)),
	)
	exit := jsonshape.DiscriminatedUnion("kind",
		jsonshape.Object(
			jsonshape.Required("kind", jsonshape.StringLiteral("zero")),
			jsonshape.Required("successCodes", jsonshape.Tuple(jsonshape.IntegerRange(0, 0)))),
		jsonshape.Object(
			jsonshape.Required("kind", jsonshape.StringLiteral("listed")),
			jsonshape.Required("successCodes", jsonshape.Array(jsonshape.IntegerRange(0, 255), 1))),
	)
	return jsonshape.Object(
		jsonshape.Required("argv", jsonshape.Array(text, 1)),
		jsonshape.Required("cachePolicy", jsonshape.Enum(cachePolicySet)),
		jsonshape.Required("credentialClass", text),
		jsonshape.Required("cwd", text),
		jsonshape.Required("environment", environment),
		jsonshape.Required("exitCodePolicy", exit),
		jsonshape.Required("expectedArtifacts", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("kind", text), jsonshape.Required("path", text),
			jsonshape.Required("required", jsonshape.Boolean())), 0)),
		jsonshape.Required("id", jsonshape.StringGrammar(`[a-z0-9][a-z0-9._:\-]*`)),
		jsonshape.Required("networkPolicy", jsonshape.Enum(networkPolicySet)),
		jsonshape.Required("parallelGroup", text),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("timeoutMs", jsonshape.IntegerMinimum(1)),
	)
}

func PlanStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	schema := jsonshape.Object(
		jsonshape.Required("commands", jsonshape.Array(CommandStructure(), 0)),
		jsonshape.Required("parallelGroups", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("commandIds", jsonshape.Array(text, 1)),
			jsonshape.Required("parallelGroup", text)), 0)),
	).JSONSchema()
	schema["description"] = "Commands and groups are sorted by identity; every command belongs to exactly its declared parallelGroup, and group commandIds are sorted unique. Empty plans contain two empty arrays. Native admission owns sortedness, identity uniqueness, vocabulary membership and environment-policy conjunction, canonical integer tokens and host range, caller timeout bounds, path and executable safety, and privacy. Structural success is neither execution nor policy approval."
	return schema
}

// VocabularyStructure refines the shared member inventory without changing
// the snapshot admission boundary or inserting native defaults into input.
func VocabularyStructure() map[string]any {
	schema := vocabularyShape.JSONSchema()
	fields := schema["properties"].(map[string]any)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	for _, key := range []string{"artifactKinds", "credentialClasses", "environmentClasses"} {
		fields[key] = texts.JSONSchema()
	}
	for _, key := range []string{"nonCacheableCredentialClasses", "parallelGroups"} {
		fields[key] = jsonshape.Nullable(texts).JSONSchema()
	}
	fields["maxTimeoutMs"] = jsonshape.Nullable(jsonshape.IntegerMinimum(1)).JSONSchema()
	fields["maxTimeoutMs"].(map[string]any)["default"] = 3600000
	fields["environmentClassPolicies"] = jsonshape.Nullable(jsonshape.Array(jsonshape.Object(
		jsonshape.Required("environmentClass", text),
		jsonshape.Required("credentialClasses", texts),
		jsonshape.Required("networkPolicies", jsonshape.Array(jsonshape.Enum(networkPolicySet), 0)),
		jsonshape.Required("cachePolicies", jsonshape.Array(jsonshape.Enum(cachePolicySet), 0)),
	), 0)).JSONSchema()
	schema["description"] = "The three required vocabularies may be empty. Missing or null optional lists become empty; missing or null maxTimeoutMs becomes 3600000. Native admission owns sorted unique strings, NUL and secret rejection, canonical positive integer spelling and host range, environment-class policy identity uniqueness and subset relations. Declared policies may be empty; using an environment class requires a matching admitted policy."
	return schema
}
