package agentintegration

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

func SourceOutputShape() jsonshape.Shape {
	branches := make([]jsonshape.Shape, len(tools))
	for i, tool := range tools {
		branches[i] = jsonshape.Object(
			jsonshape.Required("bodyBytes", jsonshape.IntegerRange(1, MaximumBodyBytes)),
			jsonshape.Required("capabilityDigest", integrationDigestShape()),
			jsonshape.Required("content", jsonshape.BoundedStringGrammar(`[\s\S]+`, MaximumMetadataBytes+MaximumBodyBytes)),
			jsonshape.Required("contentDigest", integrationDigestShape()),
			jsonshape.Required("integrationId", integrationDigestShape()),
			jsonshape.Required("kind", jsonshape.StringLiteral("proofkit.integration-source.v1")),
			jsonshape.Required("metadataBytes", jsonshape.IntegerLiteral(int64(len(frontmatter)))),
			jsonshape.Required("nonClaims", integrationClaimsShape(sourceNonClaims())),
			jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
			jsonshape.Required("targetPath", jsonshape.StringLiteral(tool.path)),
			jsonshape.Required("tool", jsonshape.StringLiteral(tool.name)),
		)
	}
	return jsonshape.DiscriminatedUnion("tool", branches...)
}

func SourceOutputStructure() map[string]any {
	return integrationToolStructure(SourceOutputShape(), "Pure generated bootstrap, not installation or host activation. Tool/path and ordered denials are literal owner projections. Native generation owns template framing, exact UTF-8 body/content byte budgets, registered capability closure and digest replay; character bounds do not prove those byte relations.")
}

func CheckOutputShape() jsonshape.Shape {
	branches := make([]jsonshape.Shape, len(tools))
	for i, tool := range tools {
		branches[i] = jsonshape.Object(
			jsonshape.Required("expectedContentDigest", integrationDigestShape()),
			jsonshape.Required("integrationId", integrationDigestShape()),
			jsonshape.Required("kind", jsonshape.StringLiteral("proofkit.integration-check.v1")),
			jsonshape.Required("nonClaims", integrationClaimsShape(checkNonClaims())),
			jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
			jsonshape.Required("state", integrationEnum("missing", "invalid", "stale", "current")),
			jsonshape.Required("targetPath", jsonshape.StringLiteral(tool.path)),
			jsonshape.Required("tool", jsonshape.StringLiteral(tool.name)),
		)
	}
	return jsonshape.DiscriminatedUnion("tool", branches...)
}

func CheckOutputStructure() map[string]any {
	return integrationToolStructure(CheckOutputShape(), "Read-only generated-byte freshness. Native inspection owns stable root/route/file observations, cancellation and cleanup; current does not prove installation, host activation or post-return stability. Classified non-current results exit 2, current exits 0, and operational errors emit no report.")
}

func integrationToolStructure(shape jsonshape.Shape, description string) map[string]any {
	schema := shape.JSONSchema()
	for _, raw := range schema["oneOf"].([]any) {
		raw.(map[string]any)["description"] = description
	}
	return schema
}

func PlanOutputShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("failureClass", jsonshape.Nullable(integrationTextShape())),
		jsonshape.Required("kind", jsonshape.StringLiteral("proofkit.integration-plan.v1")),
		jsonshape.Required("nonClaims", integrationClaimsShape(lifecycleNonClaims())),
		jsonshape.Required("operation", integrationOperationShape()),
		jsonshape.Required("recoveryTransactionId", jsonshape.Nullable(integrationDigestShape())),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("state", integrationEnum("ready", "blocked", "recovery_required")),
		jsonshape.Required("tool", integrationEnum(Tools()...)),
		jsonshape.Required("transaction", jsonshape.Nullable(repositorytransaction.PlanShape())),
	)
}

func PlanOutputStructure() map[string]any {
	schema := PlanOutputShape().JSONSchema()
	schema["description"] = "Classified managed-file plan with child-owned public transaction or null. Native planning owns canonical identities, cooperative baseline/current-file matching and state/failure/pending-transaction relations. Public fields contain no private payload or native construction authority; a ready plan is not execution or host activation."
	return schema
}

func ApplyOutputShape() jsonshape.Shape {
	return integrationReceiptShape(integrationEnum(Tools()...), integrationOperationShape(), integrationDigestShape())
}

func ApplyOutputStructure() map[string]any {
	return integrationReceiptStructure(ApplyOutputShape())
}

func RecoverOutputShape() jsonshape.Shape {
	return integrationReceiptShape(jsonshape.Null(), jsonshape.StringLiteral(OperationRecover), jsonshape.Null())
}

func RecoverOutputStructure() map[string]any {
	return integrationReceiptStructure(RecoverOutputShape())
}

func integrationReceiptShape(tool, operation, desired jsonshape.Shape) jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("expectedDesiredStateId", desired),
		jsonshape.Required("expectedTransactionId", integrationDigestShape()),
		jsonshape.Required("failureClass", jsonshape.Nullable(integrationTextShape())),
		jsonshape.Required("kind", jsonshape.StringLiteral("proofkit.integration-receipt.v1")),
		jsonshape.Required("nonClaims", integrationClaimsShape(lifecycleNonClaims())),
		jsonshape.Required("operation", operation),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("state", integrationEnum("passed", "blocked", "failed",
			repositorytransaction.StateRecoveryRequired, repositorytransaction.StateCleanupRequired, repositorytransaction.StateDurabilityUnknown)),
		jsonshape.Required("tool", tool),
		jsonshape.Required("transactionResult", jsonshape.Nullable(repositorytransaction.ResultShape())),
	)
}

func integrationReceiptStructure(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	schema["description"] = "Operation-specific managed-file receipt, including blocked/nonterminal outcomes. Native execution/recovery owns expected identity, state/failure/result/effect and cleanup relations. Recovery has no current tool or desired-state identity; its result is historical, not current host state. Structural success proves neither effects, durability nor authentication."
	return schema
}

func integrationOperationShape() jsonshape.Shape {
	return integrationEnum(OperationInstall, OperationRemove, OperationUpdate)
}

func integrationEnum(values ...string) jsonshape.Shape {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return jsonshape.Enum(set)
}

func integrationClaimsShape(values []any) jsonshape.Shape {
	claims := make([]jsonshape.Shape, len(values))
	for i, value := range values {
		claims[i] = jsonshape.StringLiteral(value.(string))
	}
	return jsonshape.Tuple(claims...)
}

func integrationDigestShape() jsonshape.Shape {
	return jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
}

func integrationTextShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[^` + space + `](?:[\s\S]*[^` + space + `])?`
	})
}
