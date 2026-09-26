// Package transactionresidue projects explicit preparation-residue operations.
package transactionresidue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

const inspectionKind = "proofkit.preparation-residue-inspection.v1"
const relocationKind = "proofkit.preparation-residue-relocation.v1"

var nonClaims = []string{
	"A residue observation does not authenticate its producer or establish absence of historical effects.",
	"Quarantine retains evidence; it does not roll back targets, validate their contents, or create a transaction receipt.",
	"These operations do not prove power-loss durability or protection from non-cooperative same-user writers.",
}

// Output is an immutable projection, not transaction execution authority.
type Output struct {
	kind, state, observationID string
}

func Inspect(ctx context.Context, root string) (Output, error) {
	observation, err := repositorytransaction.InspectPreparationResidue(ctx, root)
	if err != nil {
		return Output{}, err
	}
	output := Output{kind: inspectionKind, state: observation.State, observationID: observation.ObservationID}
	if _, err := inspectionShape.Admit(output.JSONValue(), "preparation residue inspection"); err != nil {
		return Output{}, fmt.Errorf("invalid native preparation residue observation")
	}
	return output, nil
}

func Quarantine(ctx context.Context, root, expectedObservation string) (Output, error) {
	relocation, err := repositorytransaction.QuarantinePreparationResidue(ctx, root, expectedObservation)
	if err != nil {
		return Output{}, err
	}
	output := Output{kind: relocationKind, state: relocation.State, observationID: relocation.ObservationID}
	if _, err := relocationShape.Admit(output.JSONValue(), "preparation residue relocation"); err != nil {
		return Output{}, fmt.Errorf("invalid native preparation residue relocation")
	}
	return output, nil
}

func (output Output) JSONValue() map[string]any {
	claims := make([]any, len(nonClaims))
	for i, claim := range nonClaims {
		claims[i] = claim
	}
	var observation any
	if output.observationID != "" {
		observation = output.observationID
	}
	return map[string]any{
		"kind": output.kind, "schemaVersion": json.Number("1"),
		"state": output.state, "observationId": observation, "nonClaims": claims,
	}
}

func (output Output) Text() string {
	text := "State: " + output.state + "\n"
	if output.observationID != "" {
		text += "Observation: " + output.observationID + "\n"
	}
	for _, claim := range nonClaims {
		text += "Non-claim: " + claim + "\n"
	}
	return text
}
