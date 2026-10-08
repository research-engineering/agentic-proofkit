package repositorytransaction

import "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"

func PlanShape() jsonshape.Shape {
	digest := jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
	text := transactionTextShape()
	snapshot := snapshotShape()
	return jsonshape.Object(
		jsonshape.Required("createdDirectories", jsonshape.Array(text, 0)),
		jsonshape.Required("desiredStateId", digest),
		jsonshape.Required("nonClaims", transactionNonClaimsShape()),
		jsonshape.Required("operations", jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("action", jsonshape.Enum(map[string]struct{}{
				ActionCreate: {}, ActionReplace: {}, ActionDelete: {}, ActionUnchanged: {},
			})),
			jsonshape.Required("after", snapshot),
			jsonshape.Required("before", snapshot),
			jsonshape.Required("path", text),
		), 1, MaximumOperations)),
		jsonshape.Required("rootId", digest),
		jsonshape.Required("schemaVersion", jsonshape.OneOf(
			jsonshape.IntegerLiteral(1), jsonshape.IntegerLiteral(2), jsonshape.IntegerLiteral(3))),
		jsonshape.Required("transactionId", digest),
		jsonshape.Required("transactionKind", jsonshape.StringLiteral("proofkit.repository-write-plan")),
	)
}

func ResultShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("appliedCount", jsonshape.Nullable(jsonshape.IntegerRange(0, MaximumOperations))),
		jsonshape.Required("failureClass", jsonshape.Nullable(transactionTextShape())),
		jsonshape.Required("nonClaims", transactionNonClaimsShape()),
		jsonshape.Required("recoveredBy", jsonshape.Nullable(jsonshape.Enum(map[string]struct{}{
			RecoveryResume: {}, RecoveryRollback: {},
		}))),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("state", jsonshape.Enum(resultStateSet)),
		jsonshape.Required("transactionId", jsonshape.Nullable(jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`))),
	)
}

func snapshotShape() jsonshape.Shape {
	return jsonshape.OneOf(
		jsonshape.Object(
			jsonshape.Required("byteCount", jsonshape.IntegerLiteral(0)),
			jsonshape.Required("exists", jsonshape.BooleanLiteral(false)),
			jsonshape.Required("mode", jsonshape.StringLiteral("0000")),
			jsonshape.Required("sha256", jsonshape.Null()),
		),
		jsonshape.Object(
			jsonshape.Required("byteCount", jsonshape.IntegerRange(0, MaximumFileBytes)),
			jsonshape.Required("exists", jsonshape.BooleanLiteral(true)),
			jsonshape.Required("mode", jsonshape.StringGrammar(`0[4-7][0-7]{2}`)),
			jsonshape.Required("sha256", jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)),
		),
	)
}

func transactionNonClaimsShape() jsonshape.Shape {
	claims := make([]jsonshape.Shape, len(boundaryNonClaims))
	for i, claim := range boundaryNonClaims {
		claims[i] = jsonshape.StringLiteral(claim)
	}
	return jsonshape.Tuple(claims...)
}

func transactionTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[^` + space + `](?:[\s\S]*[^` + space + `])?`
	})
}
