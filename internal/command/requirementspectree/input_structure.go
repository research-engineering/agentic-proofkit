package requirementspectree

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

var treeInputShape = makeTreeInputShape()

func InputShape() jsonshape.Shape    { return treeInputShape }
func InputStructure() map[string]any { return treeInputShape.JSONSchema() }

func makeTreeInputShape() jsonshape.Shape {
	text := jsonshape.String()
	annotations := jsonshape.Array(text, 0)
	node := treeNodeShape(1)
	edge := jsonshape.Object(jsonshape.Required("parentNodeId", text), jsonshape.Required("childNodeId", text))
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("treeId", text), jsonshape.Required("rootNodeId", text),
		jsonshape.Required("callerAnnotations", annotations),
		jsonshape.Required("nodes", jsonshape.BoundedArray(node, 1, maxSpecTreeNodes)),
		jsonshape.Required("edges", jsonshape.BoundedArray(edge, 0, maxSpecTreeEdges)),
		jsonshape.Required("overlays", jsonshape.BoundedArray(jsonshape.OneOf(overlayStructure(false), overlayStructure(true)), 0, maxSpecTreeOverlays)),
	)
}

func treeNodeShape(minRefs int) jsonshape.Shape {
	text := jsonshape.String()
	ref := jsonshape.DiscriminatedUnion("sourceRefKind", sourceRefStructure("source_id"), sourceRefStructure("path_digest"))
	return jsonshape.Object(
		jsonshape.Required("nodeId", text), jsonshape.Required("nodeKind", jsonshape.Enum(nodeKinds)),
		jsonshape.Required("label", text), jsonshape.Required("displayOrder", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("sourceRefs", jsonshape.Array(ref, minRefs)), jsonshape.Required("callerAnnotations", jsonshape.Array(text, 0)),
	)
}

func sourceRefStructure(kind string) jsonshape.Shape {
	text := jsonshape.String()
	fields := []jsonshape.Property{
		jsonshape.Required("sourceRefId", text), jsonshape.Required("sourceRole", jsonshape.Enum(sourceRoles)),
		jsonshape.Required("sourceRefKind", jsonshape.StringLiteral(kind)),
	}
	switch kind {
	case "source_id":
		fields = append(fields, jsonshape.Required("sourceId", text))
	case "path_digest":
		for _, key := range []string{"sourcePath", "recordedSourceDigest", "currentSourceDigest", "digestAlgorithm"} {
			fields = append(fields, jsonshape.Required(key, text))
		}
	default:
		panic("unsupported native source reference structure")
	}
	return jsonshape.Object(fields...)
}

func overlayStructure(withPath bool) jsonshape.Shape {
	text := jsonshape.String()
	fields := []jsonshape.Property{
		jsonshape.Required("overlayId", text), jsonshape.Required("overlayKind", jsonshape.Enum(overlayKinds)),
		jsonshape.Required("targetNodeId", text), jsonshape.Required("refKind", jsonshape.Enum(overlayRefKinds)),
		jsonshape.Required("refId", text), jsonshape.Required("label", text), jsonshape.Required("callerAnnotations", jsonshape.Array(text, 0)),
	}
	if withPath {
		for _, key := range []string{"refPath", "refDigest", "digestAlgorithm"} {
			fields = append(fields, jsonshape.Required(key, text))
		}
	}
	return jsonshape.Object(fields...)
}
