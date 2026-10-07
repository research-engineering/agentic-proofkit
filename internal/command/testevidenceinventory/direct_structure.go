package testevidenceinventory

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

var directInventoryShape = makeDirectInventoryShape(false)

// DirectInputShape excludes source sets, discovery drafts and command wrappers.
func DirectInputShape() jsonshape.Shape { return directInventoryShape }

// CanonicalInventoryShape describes InventoryValue, whose optional inputs have
// been normalized into present entry fields and absent optional identity fields.
func CanonicalInventoryShape() jsonshape.Shape { return makeDirectInventoryShape(true) }

// Child declarations share native vocabularies with derived views, without
// establishing execution or the strength of an oracle.
func EvidenceClassShape() jsonshape.Shape { return jsonshape.Enum(evidenceClassSet) }

func QualityFindingShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("class", jsonshape.Enum(qualityFindingClassSet)),
		jsonshape.Required("severity", jsonshape.Enum(qualityFindingSeveritySet)),
		jsonshape.Required("ownerReviewState", jsonshape.Enum(qualityFindingReviewStateSet)),
		jsonshape.Required("findingId", jsonshape.String()),
		jsonshape.Required("evidenceRefs", jsonshape.Array(jsonshape.String(), 1)),
		jsonshape.Required("nonClaims", jsonshape.Array(jsonshape.String(), 1)),
	)
}

func makeDirectInventoryShape(output bool) jsonshape.Shape {
	text := jsonshape.String()
	optionalID := jsonshape.Nullable(text)
	if output {
		optionalID = text
	}
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("authority", jsonshape.StringLiteral(directAuthority)),
		jsonshape.Required("inventoryId", text),
		jsonshape.Required("entries", jsonshape.Array(inventoryEntryShape(output), 0)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Optional("ownerId", optionalID),
		jsonshape.Optional("sourceId", optionalID),
	)
}

func inventoryEntryShape(output bool) jsonshape.Shape {
	text, texts := jsonshape.String(), jsonshape.Array(jsonshape.String(), 0)
	declaration := jsonshape.Nullable(text)
	if output {
		declaration = text
	}
	falsifier := jsonshape.Object(
		jsonshape.Required("dominanceGroup", text), jsonshape.Required("falsifierId", text),
		jsonshape.Required("negativeCaseId", text), jsonshape.Required("wrongImplementationClassId", text),
		jsonshape.Required("supersedes", texts), jsonshape.Optional("supersessionDeclarationRef", declaration),
	)
	oracle := jsonshape.Object(
		jsonshape.Required("oracleId", text), jsonshape.Required("oracleKind", text),
		jsonshape.Required("assertionSummary", text), jsonshape.Required("expectedPublicOutcome", text),
	)
	fields := []jsonshape.Property{
		jsonshape.Required("evidenceClass", EvidenceClassShape()),
	}
	if output {
		fields = append(fields, jsonshape.Required("falsifier", jsonshape.Nullable(falsifier)),
			jsonshape.Required("oracle", jsonshape.Nullable(oracle)),
			jsonshape.Required("qualityFindings", jsonshape.Array(QualityFindingShape(), 0)))
	} else {
		fields = append(fields, jsonshape.Optional("falsifier", jsonshape.Nullable(falsifier)),
			jsonshape.Optional("oracle", jsonshape.Nullable(oracle)),
			jsonshape.Optional("qualityFindings", jsonshape.Nullable(jsonshape.Array(QualityFindingShape(), 0))))
	}
	for _, name := range []string{"testId", "selector", "sourcePath", "ownerId"} {
		fields = append(fields, jsonshape.Required(name, text))
	}
	for _, name := range []string{"commandRefs", "nonClaims", "ownerInvariantRefs", "requirementRefs", "witnessRefs"} {
		fields = append(fields, jsonshape.Required(name, texts))
	}
	return jsonshape.Object(fields...)
}
