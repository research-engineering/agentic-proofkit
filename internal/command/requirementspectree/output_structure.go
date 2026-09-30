package requirementspectree

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func OutputStructure() map[string]any {
	id, text, annotations, overlay := outputDomains()
	node := jsonshape.Object(
		jsonshape.Required("callerAnnotations", annotations),
		jsonshape.Required("displayOrder", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("label", text), jsonshape.Required("nodeId", id),
		jsonshape.Required("nodeKind", jsonshape.Enum(nodeKinds)),
		jsonshape.Required("sourceRefIds", jsonshape.Array(id, 1)),
	)
	edge := jsonshape.Object(jsonshape.Required("childNodeId", id), jsonshape.Required("parentNodeId", id))
	claims := jsonshape.Object(
		jsonshape.Required("nodes", jsonshape.Array(jsonshape.Object(jsonshape.Required("nodeId", id), jsonshape.Required("annotations", jsonshape.Array(text, 1))), 0)),
		jsonshape.Required("overlays", jsonshape.Array(jsonshape.Object(jsonshape.Required("overlayId", id), jsonshape.Required("annotations", jsonshape.Array(text, 1))), 0)),
		jsonshape.Required("root", annotations),
	)
	counts := []jsonshape.Property{
		jsonshape.Required("callerAnnotationCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("edgeCount", jsonshape.IntegerRange(0, maxSpecTreeEdges)),
		jsonshape.Required("failureCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("maxDepth", jsonshape.IntegerRange(0, maxSpecTreeDepth)),
		jsonshape.Required("nodeCount", jsonshape.IntegerRange(1, maxSpecTreeNodes)),
		jsonshape.Required("overlayCount", jsonshape.IntegerRange(0, maxSpecTreeOverlays)),
		jsonshape.Required("sourceRefCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("staleSourceRefCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("visitedNodeCount", jsonshape.IntegerRange(0, maxSpecTreeEdges+1)),
	}
	rules := []jsonshape.Shape{}
	for _, suffix := range []string{"topology", "source_refs", "overlays"} {
		rules = append(rules, report.RuleStructure(jsonshape.StringLiteral(reportKind+"."+suffix),
			jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}), text,
			jsonshape.Tuple(report.DiagnosticStructure("failures", annotations))))
	}
	rules = append(rules, report.RuleStructure(jsonshape.StringLiteral(reportKind+".non_claims"), jsonshape.StringLiteral("passed"), text, jsonshape.Tuple()))
	schema := report.Structure(1, reportKind, jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}),
		jsonshape.Object(counts...),
		jsonshape.Tuple(
			report.DiagnosticStructure("boundaryNonClaims", outputNonClaims(boundaryNonClaims)),
			report.DiagnosticStructure("callerAnnotations", claims),
			report.DiagnosticStructure("edges", jsonshape.BoundedArray(edge, 0, maxSpecTreeEdges)),
			report.DiagnosticStructure("failures", annotations),
			report.DiagnosticStructure("nodes", jsonshape.BoundedArray(node, 1, maxSpecTreeNodes)),
			report.DiagnosticStructure("overlays", jsonshape.BoundedArray(overlay, 0, maxSpecTreeOverlays))),
		jsonshape.Tuple(rules...),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	properties["nonClaims"] = outputNonClaims(boundaryNonClaims).JSONSchema()
	schema["description"] = "Admitted reports have the fixed diagnostic/rule tuple and boundary nonClaims shown here. Passed reports exit 0; admitted semantic failures exit 1 with JSON. Admission errors produce stderr without a report. Failed reports may contain duplicate topology identifiers, unresolved edges or stale digest declarations; these must not be rejected by a schema pretending to prove topology. Native admission owns identifier/text/path normalization and nondisclosure. Native validation owns reference closure, ordering, counts and rule/state coherence. Structural validity does not establish requirement meaning, freshness, witness execution or merge authority."
	return schema
}

func ViewOutputStructure() map[string]any {
	id, text, annotations, overlay := outputDomains()
	ref := jsonshape.DiscriminatedUnion("sourceRefKind", viewSourceRefStructure("source_id"), viewSourceRefStructure("path_digest"))
	node := jsonshape.Object(
		jsonshape.Required("callerAnnotations", annotations), jsonshape.Required("childNodeIds", jsonshape.Array(id, 0)),
		jsonshape.Required("depth", jsonshape.IntegerRange(1, maxSpecTreeDepth)),
		jsonshape.Required("displayOrder", jsonshape.IntegerMinimum(1)), jsonshape.Required("label", text),
		jsonshape.Required("nodeId", id), jsonshape.Required("nodeKind", jsonshape.Enum(nodeKinds)),
		jsonshape.Required("overlays", jsonshape.BoundedArray(overlay, 0, maxSpecTreeOverlays)),
		jsonshape.Required("parentNodeId", jsonshape.OneOf(jsonshape.StringLiteral(""), id)),
		jsonshape.Required("sourceRefs", jsonshape.Array(ref, 1)),
	)
	fields := []jsonshape.Property{
		jsonshape.Required("authority", jsonshape.StringLiteral("presentation_only")),
		jsonshape.Required("callerAnnotationAuthority", jsonshape.StringLiteral("untrusted_caller_text")),
		jsonshape.Required("callerAnnotations", annotations),
		jsonshape.Required("nodes", jsonshape.BoundedArray(node, 1, maxSpecTreeNodes)),
		jsonshape.Required("nonClaims", outputNonClaims(append(slices.Clone(viewNonClaims), boundaryNonClaims...))),
		jsonshape.Required("rootNodeId", id), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(2)),
		jsonshape.Required("state", jsonshape.StringLiteral("passed")), jsonshape.Required("treeId", id),
		jsonshape.Required("viewKind", jsonshape.StringLiteral("proofkit.requirement-spec-tree-view")),
	}
	fields = append(fields,
		jsonshape.Required("callerAnnotationCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("edgeCount", jsonshape.IntegerRange(0, maxSpecTreeEdges)),
		jsonshape.Required("maxDepth", jsonshape.IntegerRange(1, maxSpecTreeDepth)),
		jsonshape.Required("nodeCount", jsonshape.IntegerRange(1, maxSpecTreeNodes)),
		jsonshape.Required("overlayCount", jsonshape.IntegerRange(0, maxSpecTreeOverlays)),
		jsonshape.Required("sourceRefCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("staleSourceRefCount", jsonshape.IntegerLiteral(0)),
	)
	schema := jsonshape.Object(fields...).JSONSchema()
	schema["description"] = "The JSON presentation is emitted only after native topology validation passes. The root parentNodeId is the empty string; other parent IDs resolve to the unique containing parent. Source-id and path-digest references remain distinct; fresh path-digest views retain staleDigest=false. Node order is the native display-order/ID preorder, and counts derive from the admitted tree. Caller annotations remain untrusted display text. Repo-relative path rules, secret rejection, normalized text/set ordering, reference closure and equality of digest pairs remain native obligations. HTML and Markdown are separate derived formats, not JSON-schema carriers. No view becomes proof or publication authority."
	return schema
}

func outputDomains() (jsonshape.Shape, jsonshape.Shape, jsonshape.Shape, jsonshape.Shape) {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	annotations := jsonshape.Array(text, 0)
	return id, text, annotations, jsonshape.OneOf(outputOverlayStructure(false), outputOverlayStructure(true))
}

func outputOverlayStructure(withPath bool) jsonshape.Shape {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	fields := []jsonshape.Property{
		jsonshape.Required("callerAnnotations", jsonshape.Array(text, 0)),
		jsonshape.Required("label", text), jsonshape.Required("overlayId", id),
		jsonshape.Required("overlayKind", jsonshape.Enum(overlayKinds)),
		jsonshape.Required("refId", id), jsonshape.Required("refKind", jsonshape.Enum(overlayRefKinds)),
		jsonshape.Required("targetNodeId", id),
	}
	if withPath {
		fields = append(fields, jsonshape.Required("digestAlgorithm", jsonshape.StringLiteral("sha256")),
			jsonshape.Required("refDigest", jsonshape.StringGrammar(`sha256:[a-f0-9]{64}`)), jsonshape.Required("refPath", text))
	}
	return jsonshape.Object(fields...)
}

func viewSourceRefStructure(kind string) jsonshape.Shape {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	fields := []jsonshape.Property{
		jsonshape.Required("sourceRefId", id), jsonshape.Required("sourceRefKind", jsonshape.StringLiteral(kind)),
		jsonshape.Required("sourceRole", jsonshape.Enum(sourceRoles)),
	}
	switch kind {
	case "source_id":
		fields = append(fields, jsonshape.Required("sourceId", id))
	case "path_digest":
		digest := jsonshape.StringGrammar(`sha256:[a-f0-9]{64}`)
		fields = append(fields, jsonshape.Required("currentSourceDigest", digest), jsonshape.Required("recordedSourceDigest", digest),
			jsonshape.Required("digestAlgorithm", jsonshape.StringLiteral("sha256")),
			jsonshape.Required("sourcePath", jsonshape.StringGrammar(`[\s\S]+`)), jsonshape.Required("staleDigest", jsonshape.BooleanLiteral(false)))
	default:
		panic("unsupported native view source reference structure")
	}
	return jsonshape.Object(fields...)
}

func outputNonClaims(values []string) jsonshape.Shape {
	values = sortedUnique(slices.Clone(values))
	items := make([]jsonshape.Shape, len(values))
	for i, value := range values {
		items[i] = jsonshape.StringLiteral(value)
	}
	return jsonshape.Tuple(items...)
}
