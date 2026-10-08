package projectstatus

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func StatusOutputShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("issueCodes", issueCodesShape()),
		jsonshape.Required("manifestId", jsonshape.Nullable(statusDigestShape())),
		jsonshape.Required("nextAction", actionShape()),
		jsonshape.Required("nonClaims", boundaryClaimsShape()),
		jsonshape.Required("projectId", jsonshape.Nullable(statusRuleIDShape())),
		jsonshape.Required("projectState", jsonshape.Enum(projectStateSet)),
		jsonshape.Required("reportKind", jsonshape.StringLiteral(StatusKind)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(SchemaVersion)),
		jsonshape.Required("snapshotId", statusDigestShape()),
		jsonshape.Required("statusId", statusDigestShape()),
	)
}

func NextOutputShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("action", actionShape()),
		jsonshape.Required("issueCodes", issueCodesShape()),
		jsonshape.Required("nonClaims", boundaryClaimsShape()),
		jsonshape.Required("packetId", statusDigestShape()),
		jsonshape.Required("packetKind", jsonshape.StringLiteral(NextKind)),
		jsonshape.Required("projectState", jsonshape.Enum(projectStateSet)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(SchemaVersion)),
		jsonshape.Required("snapshotId", statusDigestShape()),
		jsonshape.Required("statusRef", statusDigestShape()),
	)
}

func StatusOutputStructure() map[string]any {
	return navigationStructure(StatusOutputShape())
}

func NextOutputStructure() map[string]any {
	return navigationStructure(NextOutputShape())
}

func navigationStructure(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	schema["description"] = "Bounded read-only project navigation and non-executable guidance. Native admission owns content-bound identities, state/issue/action/route/context relations, issue sorting and uniqueness, project/manifest co-presence and serialized byte limits. Filesystem inspection owns currentness and transaction precedence. Structural success neither executes witnesses nor approves merge, release, rollout, deployment or production readiness."
	return schema
}

func actionShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("actionClass", jsonshape.Enum(map[string]struct{}{
			ActionRepairControlState: {}, ActionChooseRecovery: {}, ActionChooseAdoptionMode: {},
			ActionRepairProjectRecords: {}, ActionRematerializeProject: {}, ActionRunRepositoryVerification: {},
		})),
		jsonshape.Required("actionId", statusRuleIDShape()),
		jsonshape.Required("commandRoute", jsonshape.BoundedArray(statusRuleIDShape(), 0, 4)),
		jsonshape.Required("contextRef", jsonshape.Nullable(statusDigestShape())),
		jsonshape.Required("executable", jsonshape.BooleanLiteral(false)),
		jsonshape.Required("requiredDecision", jsonshape.Nullable(jsonshape.Enum(map[string]struct{}{
			"adoption_mode": {}, "resume_or_rollback": {},
		}))),
	)
}

func issueCodesShape() jsonshape.Shape {
	return jsonshape.BoundedArray(jsonshape.Enum(issueCodeSet), 0, MaximumIssueCodes)
}

func boundaryClaimsShape() jsonshape.Shape {
	claims := make([]jsonshape.Shape, len(boundaryNonClaims))
	for i, value := range boundaryNonClaims {
		claims[i] = jsonshape.StringLiteral(value)
	}
	return jsonshape.Tuple(claims...)
}

func statusDigestShape() jsonshape.Shape {
	return jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
}

func statusRuleIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}
