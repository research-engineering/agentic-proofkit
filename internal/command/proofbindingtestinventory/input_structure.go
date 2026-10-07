package proofbindingtestinventory

import (
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func InputStructure() (map[string]any, error) {
	source, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		return nil, err
	}
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(3)),
		jsonshape.Required("inventoryId", jsonshape.String()),
		jsonshape.Required("commandRefPolicy", jsonshape.Object(jsonshape.Required("prefix", jsonshape.String()))),
		jsonshape.Optional("nonClaims", jsonshape.Nullable(jsonshape.Array(jsonshape.String(), 0))),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["requirementSource"] = source
	properties["compactProofContract"] = compactproofcontract.InputStructure()
	required := append(schema["required"].([]any), "compactProofContract", "requirementSource")
	slices.SortFunc(required, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	schema["required"] = required
	schema["description"] = "The native projection requires passed source and compact proof admission, matching requirement owners and executable falsification routes. It emits proof-route candidates, not independently reviewed or executed semantic tests."
	return schema, nil
}
