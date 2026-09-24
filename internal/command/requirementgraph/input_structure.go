package requirementgraph

import (
	"maps"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var codeLevels = map[string]struct{}{"file": {}, "module": {}, "package": {}, "repository": {}, "source_range": {}, "symbol": {}}
var currentnessStates = map[string]struct{}{"current": {}, "stale": {}, "unverified": {}}
var traceAuthorities = map[string]struct{}{"caller_reported": {}, "owner_admitted": {}}
var executionAuthorities = map[string]struct{}{"caller_reported": {}, "receipt_admitted": {}}
var executionStates = map[string]struct{}{"failed": {}, "passed": {}, "skipped": {}, "unavailable": {}}

var graphInputShape = makeGraphInputShape()

func InputStructure() map[string]any { return graphInputShape.JSONSchema() }

func makeGraphInputShape() jsonshape.Shape {
	text := jsonshape.String()
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(3)),
		jsonshape.Required("graphId", text), jsonshape.Required("context", requirementcontext.SnapshotShape()),
		jsonshape.Optional("codeSources", jsonshape.Nullable(jsonshape.Array(jsonshape.Object(
			jsonshape.Required("path", text), jsonshape.Required("content", text),
		), 0))),
		jsonshape.Optional("codeTopology", jsonshape.Nullable(codeTopologyShape())),
	)
}

func codeTopologyShape() jsonshape.Shape {
	text := jsonshape.String()
	levels := slices.Sorted(maps.Keys(codeLevels))
	nodes := make([]jsonshape.Shape, 0, len(levels))
	for _, level := range levels {
		nodes = append(nodes, codeNodeShape(level))
	}
	return jsonshape.Object(
		jsonshape.Required("nodes", jsonshape.BoundedArray(jsonshape.DiscriminatedUnion("abstractionLevel", nodes...), 0, maxGraphNodes)),
		jsonshape.Required("edges", jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("codeNodeId", text), jsonshape.Required("requirementId", text),
			jsonshape.Required("evidenceRefs", jsonshape.Array(text, 1)),
			jsonshape.Required("authorityClass", jsonshape.Enum(traceAuthorities)),
			jsonshape.Required("currentnessState", jsonshape.Enum(currentnessStates)),
		), 0, maxGraphEdges)),
		jsonshape.Optional("nativeCoverage", jsonshape.Nullable(jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("codeNodeId", text), jsonshape.Required("requirementId", text),
			jsonshape.Required("evidenceRef", text), jsonshape.Required("producerId", text),
			jsonshape.Required("state", jsonshape.Enum(executionStates)),
			jsonshape.Required("authorityClass", jsonshape.Enum(executionAuthorities)),
			jsonshape.Required("currentnessState", jsonshape.Enum(currentnessStates)),
		), 0, maxGraphEdges))),
	)
}

func codeNodeShape(level string) jsonshape.Shape {
	text := jsonshape.String()
	fields := []jsonshape.Property{
		jsonshape.Required("abstractionLevel", jsonshape.StringLiteral(level)),
		jsonshape.Required("nodeId", text), jsonshape.Required("label", text),
		jsonshape.Required("sourcePath", text), jsonshape.Required("sourceDigest", text),
		jsonshape.Required("currentnessState", jsonshape.Enum(currentnessStates)),
		jsonshape.Optional("parentNodeId", jsonshape.Nullable(text)), jsonshape.Optional("symbolId", jsonshape.Nullable(text)),
	}
	if level == "source_range" {
		// Native range admission owns integer spelling, host bounds and UTF-8 alignment.
		fields = append(fields, jsonshape.Required("byteStart", jsonshape.Number()), jsonshape.Required("byteEnd", jsonshape.Number()))
	} else {
		fields = append(fields, jsonshape.Optional("byteStart", jsonshape.Null()), jsonshape.Optional("byteEnd", jsonshape.Null()))
	}
	return jsonshape.Object(fields...)
}
