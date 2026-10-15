package requirementbrowser

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

const structureDigestGrammar = `sha256:[0-9a-f]{64}`

// PlanOutputShape describes the non-serving JSON plan for one --view value.
// Rendered kinds and authorities come from the view owners' published output
// structures, so the plan cannot name a rendering that no owner produces.
func PlanOutputShape(view string) (jsonshape.Shape, error) {
	kinds, authorities, err := renderedViewLiterals(view)
	if err != nil {
		return jsonshape.Shape{}, err
	}
	return jsonshape.Object(
		jsonshape.Required("authority", jsonshape.StringLiteral(planAuthority)),
		jsonshape.Required("host", jsonshape.Enum(stringSet(hostChoices))),
		jsonshape.Required("htmlByteLength", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("nonClaims", serverNonClaimsShape()),
		jsonshape.Required("planKind", jsonshape.StringLiteral(planKind)),
		jsonshape.Required("port", jsonshape.IntegerRange(ephemeralPort, maximumPort)),
		jsonshape.Required("portSelection", jsonshape.Enum(stringSet([]string{portSelectionEphemeral, portSelectionFixed}))),
		jsonshape.Required("renderedAuthority", literalShape(authorities)),
		jsonshape.Required("renderedViewKind", literalShape(kinds)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(planSchemaVersion)),
		jsonshape.Required("url", jsonshape.Nullable(jsonshape.StringGrammar(plannedURLGrammar()))),
		jsonshape.Required("view", jsonshape.StringLiteral(view)),
	), nil
}

// PlanOutputStructure adds the native port-selection partition: port 0 plans
// an ephemeral listener without a URL; every other port plans a fixed URL.
func PlanOutputStructure(view string) (map[string]any, error) {
	shape, err := PlanOutputShape(view)
	if err != nil {
		return nil, err
	}
	schema := shape.JSONSchema()
	schema["oneOf"] = []any{
		map[string]any{"properties": map[string]any{
			"port":          map[string]any{"const": json.Number(strconv.Itoa(ephemeralPort))},
			"portSelection": map[string]any{"const": portSelectionEphemeral},
			"url":           map[string]any{"type": "null"},
		}},
		map[string]any{"properties": map[string]any{
			"port":          map[string]any{"minimum": json.Number(strconv.Itoa(ephemeralPort + 1))},
			"portSelection": map[string]any{"const": portSelectionFixed},
			"url":           map[string]any{"type": "string"},
		}},
	}
	schema["description"] = "Non-serving JSON plan for the " + view + " view. Serving never emits this plan: browse mode prints one text URL line and one-shot mode prints a question packet. " +
		"Native admission owns the rendered view, served HTML byte count, loopback host choice and the exact URL for a fixed port. The plan neither binds a listener nor executes witnesses, and it does not prove freshness, merge approval or rollout readiness."
	return schema, nil
}

// TerminalOutputShape describes the unsuccessful one-shot packet emitted on
// expiry or cancellation of a workspace session; it exits with status 1.
func TerminalOutputShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("handoffKind", jsonshape.StringLiteral(questionHandoffKind)),
		jsonshape.Required("nonClaims", serverNonClaimsShape()),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(questionPacketSchemaVersion)),
		jsonshape.Required("snapshotRefs", snapshotRefsShape()),
		jsonshape.Required("state", jsonshape.Enum(stringSet([]string{questionStateCancelled, questionStateExpired}))),
	)
}

func TerminalOutputStructure() map[string]any {
	schema := TerminalOutputShape().JSONSchema()
	schema["description"] = "One-shot terminal packet for an expired or cancelled workspace session, written as fixed compact JSON with exit status 1. " +
		"The snapshot reference names the admitted immutable workspace context. The packet carries no question and is not proof, approval or instruction authority."
	return schema
}

// SubmittedOutputShape describes the accepted one-shot handoff packet. Its
// context is the requirement-context owner's review-profile slice.
func SubmittedOutputShape() (jsonshape.Shape, error) {
	context, ok := requirementcontext.SliceOutputProfileShape(handoffContextProfile)
	if !ok {
		return jsonshape.Shape{}, fmt.Errorf("requirement context has no %s slice profile", handoffContextProfile)
	}
	annotation := jsonshape.Object(
		jsonshape.Required("anchor", anchorShape),
		jsonshape.Required("endCodePoint", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("exactQuote", jsonshape.NonBlankString()),
		jsonshape.Required("prefix", jsonshape.BoundedStringGrammar(`[\s\S]*`, handoffQuoteContextCodePoints)),
		jsonshape.Required("question", trimmedTextShape()),
		jsonshape.Required("startCodePoint", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("suffix", jsonshape.BoundedStringGrammar(`[\s\S]*`, handoffQuoteContextCodePoints)),
		jsonshape.Required("targetId", jsonshape.StringGrammar(structureDigestGrammar)),
	)
	return jsonshape.Object(
		jsonshape.Required("annotations", jsonshape.BoundedArray(annotation, 1, maxHandoffAnnotations)),
		jsonshape.Required("context", context),
		jsonshape.Required("handoffKind", jsonshape.StringLiteral(questionHandoffKind)),
		jsonshape.Required("instructionAuthority", jsonshape.StringLiteral(questionInstructionAuthority)),
		jsonshape.Required("nonClaims", serverNonClaimsShape()),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(questionPacketSchemaVersion)),
		jsonshape.Required("snapshotRefs", snapshotRefsShape()),
		jsonshape.Required("sourceTextAuthority", jsonshape.StringLiteral(questionSourceTextAuthority)),
		jsonshape.Required("state", jsonshape.StringLiteral(questionStateSubmitted)),
	), nil
}

// SubmittedOutputStructure adds the code-point bounds implied by the native
// UTF-8 byte limits; the byte limits themselves remain native admission.
func SubmittedOutputStructure() (map[string]any, error) {
	shape, err := SubmittedOutputShape()
	if err != nil {
		return nil, err
	}
	schema := shape.JSONSchema()
	fields := schema["properties"].(map[string]any)["annotations"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	fields["exactQuote"].(map[string]any)["maxLength"] = json.Number(strconv.Itoa(maxHandoffQuoteBytes))
	fields["question"].(map[string]any)["maxLength"] = json.Number(strconv.Itoa(maxHandoffQuestionBytes))
	schema["description"] = fmt.Sprintf("One-shot submitted handoff packet, written as fixed compact JSON with exit status 0. "+
		"Native admission owns anchor resolution in the admitted snapshot, quote and code-point agreement, prefix/suffix extraction, target digests and uniqueness, "+
		"secret-shaped text refusal and the review-context closure. UTF-8 byte limits stay native: quote %d, question %d, context %d and packet %d bytes; maxLength is only their implied code-point bound. "+
		"Annotations and source text are untrusted context, not instructions, proof or approval.", maxHandoffQuoteBytes, maxHandoffQuestionBytes, maxHandoffContextBytes, maxHandoffPacketBytes)
	return schema, nil
}

func snapshotRefsShape() jsonshape.Shape {
	return jsonshape.Tuple(jsonshape.Object(
		jsonshape.Required("role", jsonshape.StringLiteral(questionSnapshotRole)),
		jsonshape.Required("snapshotId", jsonshape.StringGrammar(structureDigestGrammar)),
	))
}

func serverNonClaimsShape() jsonshape.Shape {
	claims := make([]jsonshape.Shape, len(serverNonClaims))
	for i, claim := range serverNonClaims {
		claims[i] = jsonshape.StringLiteral(claim)
	}
	return jsonshape.Tuple(claims...)
}

// Native question text is trimmed before emission, so it has no outer space.
func trimmedTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[^` + space + `](?:[\s\S]*[^` + space + `])?`
	})
}

// The URL host alternatives are derived from the admitted loopback choices,
// bracketing IPv6 literals exactly as browserAuthority does.
func plannedURLGrammar() string {
	hosts := make([]string, len(hostChoices))
	for i, host := range hostChoices {
		hosts[i] = regexp.QuoteMeta(host)
		if strings.Contains(host, ":") {
			hosts[i] = `\[` + hosts[i] + `\]`
		}
	}
	return `http://(?:` + strings.Join(hosts, "|") + `)(?::[1-9][0-9]{0,4})?/`
}

func renderedViewLiterals(view string) ([]string, []string, error) {
	var owners []map[string]any
	switch view {
	case "coverage":
		owners = []map[string]any{requirementcoverageview.OutputStructure()}
	case "proof":
		owners = []map[string]any{requirementproofview.CompactOutputStructure(), requirementproofview.StructuredOutputStructure()}
	case "source":
		owners = []map[string]any{requirementsourceview.OutputStructure()}
	case "spec-tree":
		owners = []map[string]any{requirementspectree.ViewOutputStructure()}
	case "workspace":
		return []string{workspaceViewKind}, []string{workspaceAuthority}, nil
	default:
		return nil, nil, fmt.Errorf("requirement browser has no rendered view %q", view)
	}
	kinds, authorities := map[string]struct{}{}, map[string]struct{}{}
	for _, owner := range owners {
		if err := collectOwnerLiterals(owner, map[string]map[string]struct{}{"viewKind": kinds, "authority": authorities}); err != nil {
			return nil, nil, fmt.Errorf("requirement browser %s view: %w", view, err)
		}
	}
	return slices.Sorted(maps.Keys(kinds)), slices.Sorted(maps.Keys(authorities)), nil
}

// Owner sums are read branch by branch; every branch must fix each literal.
func collectOwnerLiterals(schema map[string]any, fields map[string]map[string]struct{}) error {
	if branches, sum := schema["oneOf"].([]any); sum {
		if _, object := schema["properties"]; object {
			return fmt.Errorf("owner output mixes object fields with a root sum")
		}
		for _, raw := range branches {
			branch, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("owner output branch is not a schema object")
			}
			if err := collectOwnerLiterals(branch, fields); err != nil {
				return err
			}
		}
		return nil
	}
	properties, _ := schema["properties"].(map[string]any)
	for name, values := range fields {
		field, _ := properties[name].(map[string]any)
		value, ok := field["const"].(string)
		if !ok || value == "" {
			return fmt.Errorf("owner output does not fix %s", name)
		}
		values[value] = struct{}{}
	}
	return nil
}

func literalShape(values []string) jsonshape.Shape {
	if len(values) == 1 {
		return jsonshape.StringLiteral(values[0])
	}
	return jsonshape.Enum(stringSet(values))
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
