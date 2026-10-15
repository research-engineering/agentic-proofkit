package requirementbrowser

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	coverageCompactInputID    = "urn:proofkit:requirement-browser-server:input:coverage-compact:schema:4"
	coverageStructuredInputID = "urn:proofkit:requirement-browser-server:input:coverage-structured:schema:4"
	workspaceInputID          = "urn:proofkit:requirement-browser-server:input:workspace:schema:4"
	workspaceContextResource  = "requirementContext"
	compactCoverageMember     = "compactProofContract"
)

// The source, compact proof and spec-tree views delegate their whole input to
// these owners; the browser adds no member and relaxes no constraint.
func SourceInputStructure() (map[string]any, error) {
	return requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
}

func CompactProofInputStructure() map[string]any { return requirementproofview.CompactInputStructure() }

func SpecTreeInputStructure() map[string]any { return requirementspectree.InputStructure() }

// StructuredProofInputStructure keeps the proof-view owner's structure. Only its
// description changes: browser local-environment flags are ignored, not refused.
func StructuredProofInputStructure() map[string]any {
	schema := requirementproofview.StructuredInputStructure()
	schema["description"] = "Structured requirement proof binding for --view proof. Native binding admission and evaluation must pass; failed binding reports refuse the input. " +
		"--scope selects graph or slice (default slice); local-environment flags do not change structured rendering. Structural validity neither evaluates binding semantics nor proves witness execution."
	return schema
}

// CoverageInputStructure specializes the coverage owner's exclusive proof-mode
// sum into one browser variant. Branch members come from that owner's sum.
func CoverageInputStructure(compact bool) (map[string]any, error) {
	schema, err := requirementcoverageview.InputStructure()
	if err != nil {
		return nil, err
	}
	branches, ok := schema["oneOf"].([]any)
	if !ok || len(branches) != 2 {
		return nil, fmt.Errorf("requirement coverage input no longer has exactly two proof modes")
	}
	var branch map[string]any
	for _, raw := range branches {
		candidate, ok := raw.(map[string]any)
		required, _ := candidate["required"].([]any)
		if !ok || slices.Contains(required, any(compactCoverageMember)) != compact {
			continue
		}
		if branch != nil {
			return nil, fmt.Errorf("requirement coverage proof modes are ambiguous")
		}
		branch = candidate
	}
	if branch == nil {
		return nil, fmt.Errorf("requirement coverage proof mode is absent")
	}
	properties := schema["properties"].(map[string]any)
	branchProperties, _ := branch["properties"].(map[string]any)
	if len(branch) != 2 || len(branchProperties) == 0 {
		return nil, fmt.Errorf("requirement coverage proof mode is not a member partition")
	}
	for _, name := range slices.Sorted(maps.Keys(branchProperties)) {
		member, _ := branchProperties[name].(map[string]any)
		switch {
		case len(member) == 1 && member["type"] == "null":
			properties[name] = map[string]any{"type": "null"}
		case len(member) == 1 && member["type"] == "object":
			properties[name], err = nonNullAlternative(properties[name])
			if err != nil {
				return nil, fmt.Errorf("requirement coverage %s: %w", name, err)
			}
		default:
			return nil, fmt.Errorf("requirement coverage proof mode constrains %s beyond presence", name)
		}
	}
	required := slices.Clone(schema["required"].([]any))
	branchRequired, _ := branch["required"].([]any)
	for _, name := range branchRequired {
		if !slices.Contains(required, name) {
			required = append(required, name)
		}
	}
	slices.SortFunc(required, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	schema["required"] = required
	delete(schema, "oneOf")
	schema["$id"] = coverageCompactInputID
	schema["description"] = "Coverage input with a compact proof contract: compactProofContract and localEnvironmentPolicy are non-null and requirementProofBinding is absent or null. " + coverageInputBoundary
	if !compact {
		// A null-only member cannot reach the compact resource; omit it whole.
		defs := schema["$defs"].(map[string]any)
		delete(defs, compactCoverageMember)
		if containsLocalReference(schema, "#/$defs/"+compactCoverageMember) {
			return nil, fmt.Errorf("structured coverage input still references the compact resource")
		}
		schema["$id"] = coverageStructuredInputID
		schema["description"] = "Coverage input with a structured requirement proof binding: requirementProofBinding is non-null and compactProofContract is absent or null. " + coverageInputBoundary
	}
	return schema, nil
}

const coverageInputBoundary = "The coverage owner retains source admission, scenario and binding links, inventory classification, provenance joins, canonical text and path rules and coverage semantics; " +
	"the CLI refuses proof scope and local-environment flags for --view coverage. Structural validity does not prove coverage or witness execution."

// WorkspaceInputStructure composes the workspace aggregate. Its context, the
// diff input contexts and the graph input context are one shared resource,
// checked equal to the requirement-context owner before each substitution.
func WorkspaceInputStructure() (map[string]any, error) {
	snapshot := requirementcontext.SnapshotShape().JSONSchema()
	delete(snapshot, "$schema")
	diff, err := withSharedContext(requirementdiff.InputStructure(), snapshot, "baseContext", "currentContext")
	if err != nil {
		return nil, fmt.Errorf("requirement semantic diff input: %w", err)
	}
	graph, err := withSharedContext(requirementgraph.InputStructure(), snapshot, "context")
	if err != nil {
		return nil, fmt.Errorf("requirement traceability graph input: %w", err)
	}
	properties := map[string]any{
		"context":       contextReference(),
		"diffInput":     nullableMember(diff),
		"graphInput":    nullableMember(graph),
		"schemaVersion": memberStructure(jsonshape.IntegerLiteral(workspaceInputSchemaVersion)),
		"workspaceId":   memberStructure(jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
	}
	if !slices.Equal(slices.Sorted(maps.Keys(properties)), workspaceInputKeys) {
		return nil, fmt.Errorf("requirement browser workspace structure differs from native member inventory")
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": workspaceInputID,
		"$defs": map[string]any{workspaceContextResource: snapshot},
		"type":  "object", "additionalProperties": false, "properties": properties,
		"required": []any{"context", "schemaVersion", "workspaceId"},
		"description": "Workspace input: a requirement context of catalog or project origin with optional semantic-diff and traceability-graph inputs; null optional inputs are absent. " +
			"Native admission owns context identity replay and size, diff and graph evaluation, equality of their current snapshot with this context, graph closure over it and refusal of secret-shaped or timestamp-like workspaceId values. " +
			"Structural validity neither serves the workspace nor executes witnesses.",
	}, nil
}

func withSharedContext(schema, snapshot map[string]any, names ...string) (map[string]any, error) {
	delete(schema, "$schema")
	properties, _ := schema["properties"].(map[string]any)
	for _, name := range names {
		if !reflect.DeepEqual(properties[name], snapshot) {
			return nil, fmt.Errorf("%s is not the requirement-context snapshot owner", name)
		}
		properties[name] = contextReference()
	}
	return schema, nil
}

func contextReference() map[string]any {
	return map[string]any{"$ref": "#/$defs/" + workspaceContextResource}
}

func memberStructure(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}

// Nullable members follow jsonshape's projection: absent and null are equal.
func nullableMember(schema map[string]any) map[string]any {
	return map[string]any{"anyOf": []any{map[string]any{"type": "null"}, schema}}
}

func nonNullAlternative(raw any) (any, error) {
	schema, _ := raw.(map[string]any)
	alternatives, ok := schema["anyOf"].([]any)
	if len(schema) != 1 || !ok || len(alternatives) != 2 {
		return nil, fmt.Errorf("member is not an exact nullable wrapper")
	}
	var result any
	for _, alternative := range alternatives {
		branch, _ := alternative.(map[string]any)
		if len(branch) == 1 && branch["type"] == "null" {
			continue
		}
		if result != nil {
			return nil, fmt.Errorf("member has more than one non-null alternative")
		}
		result = alternative
	}
	if result == nil {
		return nil, fmt.Errorf("member has no non-null alternative")
	}
	return result, nil
}

func containsLocalReference(raw any, reference string) bool {
	switch value := raw.(type) {
	case map[string]any:
		if value["$ref"] == reference {
			return true
		}
		for _, child := range value {
			if containsLocalReference(child, reference) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if containsLocalReference(child, reference) {
				return true
			}
		}
	}
	return false
}
