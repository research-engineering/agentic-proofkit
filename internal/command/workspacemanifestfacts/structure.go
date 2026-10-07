package workspacemanifestfacts

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/workspaceplanning"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var inputKeys = []string{"dependencyFields", "nonClaims", "packages", "projectionId", "root", "schemaVersion"}
var recordKeys = []string{"dirName", "manifest", "manifestPath", "packageDir"}

func InputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	record := func(root bool) jsonshape.Shape {
		fields := map[string]jsonshape.Shape{
			"dirName": id, "manifest": jsonshape.Object(jsonshape.Required("name", text)),
			"manifestPath": text, "packageDir": jsonshape.Nullable(text),
		}
		optional := []string{"packageDir"}
		if root {
			fields["dirName"] = jsonshape.Nullable(id)
			optional = append(optional, "dirName")
		}
		return jsonshape.ObjectFromKeys(recordKeys, fields, optional...)
	}
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"dependencyFields": jsonshape.Array(id, 1), "nonClaims": jsonshape.Array(text, 1),
		"packages": jsonshape.Array(record(false), 0), "projectionId": id,
		"root": record(true), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	fields := schema["properties"].(map[string]any)
	for _, key := range []string{"dependencyFields", "nonClaims"} {
		fields[key].(map[string]any)["uniqueItems"] = true
	}
	for _, source := range []map[string]any{fields["root"].(map[string]any), fields["packages"].(map[string]any)["items"].(map[string]any)} {
		manifest := source["properties"].(map[string]any)["manifest"].(map[string]any)
		textMap := func() map[string]any {
			return map[string]any{"anyOf": []any{
				map[string]any{"type": "null"},
				map[string]any{"type": "object", "propertyNames": text.JSONSchema(), "additionalProperties": text.JSONSchema()},
			}}
		}
		manifest["properties"].(map[string]any)["scripts"] = textMap()
		manifest["additionalProperties"] = textMap()
	}
	schema["description"] = "Every root field is required. dependencyFields and nonClaims are nonempty, sorted and unique after native admission. packages may be empty. Each package requires dirName; root dirName and all packageDir fields accept absence or null. Manifest name is required; scripts and the caller-selected dependency maps accept absence or null. Only name/scripts plus fields explicitly named in dependencyFields are admitted; that input-dependent key relation remains native-only. The structural additionalProperties map is not permission for unselected fields. Native admission trims map keys/values, rejects retained control characters and secrets, enforces safe paths, bounded ASCII IDs and package-name/dirName/manifestPath uniqueness. Integer token spelling, normalized uniqueness and ordering are native constraints. No manifest files are read and no package-manager policy is inferred."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	texts := jsonshape.Array(text, 0)
	scripts := jsonshape.Array(jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("name", text)), 0)
	refs := jsonshape.Array(jsonshape.Object(jsonshape.Required("field", id), jsonshape.Required("name", text), jsonshape.Required("version", text)), 0)
	facts := func(packageRecord bool) jsonshape.Shape {
		fields := []jsonshape.Property{jsonshape.Required("name", text), jsonshape.Required("scripts", scripts), jsonshape.Required("dependencyRefs", refs)}
		if packageRecord {
			fields = append(fields, jsonshape.Required("dirName", id))
		}
		return jsonshape.Object(fields...)
	}
	source := func(packageRecord bool) jsonshape.Shape {
		fields := []jsonshape.Property{jsonshape.Required("name", text), jsonshape.Required("manifestPath", text), jsonshape.Required("packageDir", jsonshape.String())}
		if packageRecord {
			fields = append(fields, jsonshape.Required("dirName", id))
		}
		return jsonshape.Object(fields...)
	}
	edge := jsonshape.Object(
		jsonshape.Required("field", id), jsonshape.Required("fromKind", jsonshape.Enum(map[string]struct{}{"root": {}, "package": {}})),
		jsonshape.Required("fromName", text), jsonshape.Required("toName", text), jsonshape.Required("version", text),
	)
	count := jsonshape.IntegerMinimum(0)
	summary := jsonshape.Object(
		jsonshape.Required("dependencyFieldCount", jsonshape.IntegerMinimum(1)), jsonshape.Required("packageCount", count),
		jsonshape.Required("packageDependencyRefCount", count), jsonshape.Required("packageScriptCount", count),
		jsonshape.Required("rootDependencyRefCount", count), jsonshape.Required("rootScriptCount", count),
		jsonshape.Required("workspaceDependencyEdgeCount", count),
	)
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)), jsonshape.Required("projectionId", id),
		jsonshape.Required("reportKind", jsonshape.StringLiteral("proofkit.workspace-manifest-facts")), jsonshape.Required("reportId", id),
		jsonshape.Required("state", jsonshape.StringLiteral("passed")), jsonshape.Required("summary", summary),
		jsonshape.Required("knownPackageNames", texts), jsonshape.Required("root", facts(false)),
		jsonshape.Required("packages", jsonshape.Array(facts(true), 0)),
		jsonshape.Required("manifestSources", jsonshape.Object(jsonshape.Required("root", source(false)), jsonshape.Required("packages", jsonshape.Array(source(true), 0)))),
		jsonshape.Required("packageUniverse", jsonshape.Object(
			jsonshape.Required("rootPackageName", text), jsonshape.Required("packageNames", texts),
			jsonshape.Required("packageDirNames", jsonshape.Array(id, 0)), jsonshape.Required("workspaceDependencyEdges", jsonshape.Array(edge, 0)),
		)),
		jsonshape.Required("changedPackagePlanPackages", jsonshape.Array(workspaceplanning.ChangedPlanPackageStructure(), 0)),
		jsonshape.Required("shardPartitionPackages", jsonshape.Array(workspaceplanning.ShardPackageStructure(), 0)),
		jsonshape.Required("diagnostics", jsonshape.Tuple()), jsonshape.Required("nonClaims", jsonshape.Array(text, len(commandNonClaims)+1)),
	).JSONSchema()
	claims := schema["properties"].(map[string]any)["nonClaims"].(map[string]any)
	prefix := make([]any, 0, len(commandNonClaims))
	for _, claim := range commandNonClaims {
		prefix = append(prefix, jsonshape.StringLiteral(claim).JSONSchema())
	}
	claims["prefixItems"] = prefix
	schema["description"] = "Admitted manifests produce only passed projections with empty diagnostics. projectionId and reportId are equal. Package records/names are sorted; dependencyRefs sort by field/name/version, scripts by name, edges by fromKind/fromName/toName/field/version. Workspace dependencies are known package names regardless of version syntax; external dependencies remain refs without workspace edges. Native admission owns dependent map keys, privacy and path semantics. Counts and cross-array identity are derived native relations. Missing/null packageDir becomes empty text. nonClaims begins with the three builtin denials, then caller claims; duplicates across that boundary are preserved. Both planning package arrays use their consumer-owned structural records. No dependency policy, graph freshness, execution or merge authority is claimed."
	return schema
}
