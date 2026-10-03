package publicapi

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

func InputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	condition := jsonshape.RequiredObject(conditionKeys, map[string]jsonshape.Shape{
		"condition": text, "path": text, "sourcePath": text,
	})
	entry := jsonshape.ObjectFromKeys(manifestEntryKeys, map[string]jsonshape.Shape{
		"deniedExportKeys": jsonshape.Nullable(texts), "exportConditions": jsonshape.Array(condition, 1),
		"exportKey": text, "packageManifestPath": text, "packageName": text,
		"runtimeExports": texts, "typeExports": texts,
	}, "deniedExportKeys")
	schema := jsonshape.RequiredObject(manifestKeys, map[string]jsonshape.Shape{
		"entries":         jsonshape.BoundedArray(entry, 0, maxManifestEntries),
		"machineContract": jsonshape.StringLiteral(defaultMachineContract), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	fields := schema["properties"].(map[string]any)["entries"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	for _, key := range []string{"runtimeExports", "typeExports", "exportConditions"} {
		fields[key].(map[string]any)["uniqueItems"] = true
	}
	fields["deniedExportKeys"].(map[string]any)["anyOf"].([]any)[1].(map[string]any)["uniqueItems"] = true
	schema["description"] = "The public CLI requires machineContract=public_api_surfaces. entries may be empty and contains at most 1024 records. deniedExportKeys accepts absence or null, both normalizing to an empty array; runtimeExports and typeExports require arrays but may be empty. Text is trimmed and secret-filtered by native admission. All export-name arrays and exportConditions must be sorted and unique after normalization; conditions are unique by condition name, not just complete object identity. Native path admission requires a safe repo-relative packageManifestPath ending in package.json and sourcePath ending in .ts, .mts or .cts; canonical resolved source targets must also satisfy the non-JSX rule. Package-name/export-key uniqueness, actual export-map equality, canonical confinement, regular-file admission, lexical grammar, file/aggregate budgets and filesystem currentness are native-only relations. Structural validity does not imply a passed verification report."
	return schema
}

func OutputStructure() map[string]any {
	claims := make([]jsonshape.Shape, len(commandNonClaims))
	for index, claim := range commandNonClaims {
		claims[index] = jsonshape.StringLiteral(claim)
	}
	schema := jsonshape.Object(
		jsonshape.Required("entryCount", jsonshape.IntegerRange(0, maxManifestEntries)),
		jsonshape.Required("failures", jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 0)),
		jsonshape.Required("inputAuthority", jsonshape.StringLiteral("caller_manifest_plus_filesystem_snapshot")),
		jsonshape.Required("nonClaims", jsonshape.Tuple(claims...)),
	).JSONSchema()
	schema["description"] = "The same closed report shape describes passed and failed filesystem verification. Empty failures implies exit 0; nonempty, sorted, redacted failures implies exit 1. A missing declared source is a failed verification report. Fatal admission or operational errors, including a missing referenced package manifest, return exit 1 without a JSON report. entryCount equals the original admitted manifest length, including entries that produce duplicate diagnostics. The five built-in nonClaims retain their exact order. Report values are derived observations of the explicitly selected filesystem snapshot, not compiler, registry or execution authority."
	return schema
}
