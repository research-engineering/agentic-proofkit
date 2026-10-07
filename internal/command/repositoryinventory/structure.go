package repositoryinventory

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

// OutputShape describes public inventory fields; native admission still owns
// identity replay, ordering, disjointness, count relations and byte budgets.
func OutputShape() jsonshape.Shape {
	digest := jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
	entries := make([]jsonshape.Shape, 0, len(rootCatalog))
	paths := make(map[string]struct{}, len(rootCatalog))
	for _, item := range rootCatalog {
		paths[item.Path] = struct{}{}
		entries = append(entries, jsonshape.Object(
			jsonshape.Required("byteLength", jsonshape.IntegerRange(0, MaximumFileBytes)),
			jsonshape.Required("contentSha256", digest),
			jsonshape.Required("path", jsonshape.StringLiteral(item.Path)),
			jsonshape.Required("role", jsonshape.StringLiteral(item.Role)),
			jsonshape.Required("syntaxState", jsonshape.StringLiteral("not_evaluated")),
		))
	}
	claims := make([]jsonshape.Shape, len(boundaryNonClaims))
	for i, claim := range boundaryNonClaims {
		claims[i] = jsonshape.StringLiteral(claim)
	}
	return jsonshape.Object(
		jsonshape.Required("entries", jsonshape.BoundedArray(jsonshape.OneOf(entries...), 0, len(rootCatalog))),
		jsonshape.Required("inventoryId", digest),
		jsonshape.Required("inventoryKind", jsonshape.StringLiteral(InventoryKind)),
		jsonshape.Required("nonClaims", jsonshape.Tuple(claims...)),
		jsonshape.Required("omissions", jsonshape.Object(
			jsonshape.Required("omittedRecognized", jsonshape.BoundedArray(jsonshape.Object(
				jsonshape.Required("path", jsonshape.Enum(paths)),
				jsonshape.Required("reason", jsonshape.Enum(map[string]struct{}{
					OmissionNonText: {}, OmissionOversize: {},
				})),
			), 0, len(rootCatalog))),
			jsonshape.Required("rootEntryCount", jsonshape.IntegerRange(0, MaximumRootEntries)),
			jsonshape.Required("unrecognizedCount", jsonshape.IntegerRange(0, MaximumRootEntries)),
		)),
		jsonshape.Required("policyId", jsonshape.StringLiteral(PolicyID)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(SchemaVersion)),
		jsonshape.Required("scope", jsonshape.Object(
			jsonshape.Required("class", jsonshape.StringLiteral("root_catalog")),
			jsonshape.Required("repositoryRootState", jsonshape.StringLiteral("caller_selected_not_disclosed")),
			jsonshape.Required("versionControlState", jsonshape.StringLiteral("not_evaluated")),
		)),
	)
}

func OutputStructure() map[string]any {
	schema := OutputShape().JSONSchema()
	schema["description"] = "Successful bounded root-catalog observations only. Native admission owns digest replay, path order/uniqueness/disjointness, count partition, aggregate bytes and output size. A structural pass does not authenticate scanning, filesystem origin, continuing freshness, stack or source semantics, evidence adequacy or readiness."
	return schema
}
