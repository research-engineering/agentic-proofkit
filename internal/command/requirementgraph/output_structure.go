package requirementgraph

import (
	"maps"
	"math"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// OutputStructure describes the wire carrier, not graph relation validity.
func OutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	nodes := []jsonshape.Shape{
		graphOutputNode("specification_coverage", jsonshape.Enum(specificationNodeKinds)),
		graphOutputNode("proof_coverage", jsonshape.StringLiteral("scenario"),
			jsonshape.Required("requirementId", text), jsonshape.Required("scenarioId", text),
			jsonshape.Required("witnessId", text), jsonshape.Required("witnessKind", text),
			jsonshape.Required("witnessPath", text)),
		graphOutputNode("native_execution_coverage", jsonshape.StringLiteral("execution_evidence"),
			jsonshape.Required("authorityClass", jsonshape.Enum(executionAuthorities)),
			jsonshape.Required("currentnessState", jsonshape.Enum(currentnessStates)),
			jsonshape.Required("producerId", text), jsonshape.Required("state", jsonshape.Enum(executionStates))),
	}
	for _, kind := range slices.Sorted(maps.Keys(codeLevels)) {
		fields := []jsonshape.Property{
			jsonshape.Required("currentnessState", jsonshape.Enum(currentnessStates)),
			jsonshape.Required("sourceDigest", jsonshape.StringGrammar(`sha256:[a-f0-9]{64}`)),
			jsonshape.Optional("symbolId", text),
		}
		if kind != "repository" {
			fields = append(fields, jsonshape.Required("parentNodeId", text))
		}
		if kind == "source_range" {
			fields = append(fields,
				jsonshape.Required("byteStart", jsonshape.IntegerRange(0, math.MaxInt64)),
				jsonshape.Required("byteEnd", jsonshape.IntegerRange(1, math.MaxInt64)),
				jsonshape.Required("coordinateUnit", jsonshape.StringLiteral("utf8_byte")),
				jsonshape.Required("rangeVerification", jsonshape.Enum(map[string]struct{}{"unverified": {}, "verified": {}})),
			)
		}
		nodes = append(nodes, graphOutputNode("code_traceability", jsonshape.StringLiteral(kind), fields...))
	}
	edges := []jsonshape.Shape{
		graphOutputEdge("specification_coverage", "contains"),
		graphOutputEdge("specification_coverage", "declares"),
		graphOutputEdge("proof_coverage", "proved_by_candidate"),
		graphOutputEdge("code_traceability", "contains"),
		graphOutputEdge("code_traceability", "traced_to",
			jsonshape.Required("authorityClass", jsonshape.Enum(traceAuthorities)),
			jsonshape.Required("currentnessState", jsonshape.Enum(currentnessStates)),
			jsonshape.Required("evidenceRefs", jsonshape.Array(text, 1))),
		graphOutputEdge("native_execution_coverage", "observed_by", jsonshape.Required("codeNodeId", text)),
	}
	denials := make([]jsonshape.Shape, len(nonClaims))
	for i, denial := range nonClaims {
		denials[i] = jsonshape.StringLiteral(denial)
	}
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("graphKind", jsonshape.StringLiteral("proofkit.requirement-traceability-graph")),
		jsonshape.Required("graphId", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
		jsonshape.Required("snapshotId", jsonshape.StringGrammar(`sha256:[a-f0-9]{64}`)),
		jsonshape.Required("nodes", jsonshape.BoundedArray(jsonshape.OneOf(nodes...), 0, maxGraphNodes)),
		jsonshape.Required("edges", jsonshape.BoundedArray(jsonshape.OneOf(edges...), 0, maxGraphEdges)),
		jsonshape.Required("nodeCount", jsonshape.IntegerRange(0, maxGraphNodes)),
		jsonshape.Required("edgeCount", jsonshape.IntegerRange(0, maxGraphEdges)),
		jsonshape.Required("nonClaims", jsonshape.Tuple(denials...)),
	).JSONSchema()
	schema["description"] = "Closed graph carrier with distinct specification, proof, code and native-execution planes. Repository code roots omit parentNodeId; other code levels require it. Only source_range code nodes carry half-open UTF-8 byte coordinates and verified/unverified range status. Native owners retain identifier/path normalization, secret rejection, integer lexical spelling and host range, reference closure, parent-edge bijection, level ordering, range alignment, content/digest coherence, derived hash identity, set ordering and count equality. JSON numeric consumers that round large integer tokens cannot establish native int64 identity. Structural validity is not freshness, witness execution, merge, release or rollout authority."
	return schema
}

func graphOutputNode(plane string, kind jsonshape.Shape, fields ...jsonshape.Property) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	base := []jsonshape.Property{
		jsonshape.Required("evidencePlane", jsonshape.StringLiteral(plane)), jsonshape.Required("kind", kind),
		jsonshape.Required("label", text), jsonshape.Required("nodeId", text), jsonshape.Required("sourceId", text),
	}
	return jsonshape.Object(append(base, fields...)...)
}

func graphOutputEdge(plane, kind string, fields ...jsonshape.Property) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	base := []jsonshape.Property{
		jsonshape.Required("edgeId", text), jsonshape.Required("edgeKind", jsonshape.StringLiteral(kind)),
		jsonshape.Required("evidencePlane", jsonshape.StringLiteral(plane)),
		jsonshape.Required("fromNodeId", text), jsonshape.Required("toNodeId", text),
	}
	return jsonshape.Object(append(base, fields...)...)
}
