package gradualadoption

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

func BootstrapContractInputStructure() map[string]any {
	input := structureOpenObject(map[string]any{
		"budget":          evaluatedObject("Forwarded into the generated adoption profile."),
		"module":          evaluatedJSON("Failure-collecting bootstrap module projection."),
		"nativeWitnesses": nativeWitnessStructure(), "packageVersionRef": textStructure(),
		"proofBinding": structureOpenObject(map[string]any{"bindingPath": textStructure()}),
		"repository":   evaluatedObject("Forwarded into the generated adoption profile."),
		"rollback":     evaluatedObject("Forwarded into the generated adoption profile."),
	}, "module")
	bootstrap := structureOpenObject(map[string]any{
		"bootstrapId": ruleIDStructure(), "commands": textArrayStructure(0),
		"defaultMode": jsonshape.Enum(adoptionmode.ValuesMap()).JSONSchema(), "nonClaims": textArrayStructure(0),
		"paths":         evaluatedObject("Bootstrap paths are projected with collected failures."),
		"scopeEvidence": structureOpenObject(map[string]any{"checkedScope": textStructure(), "touchedRuleIds": textArrayStructure(0)}),
	})
	return inputDescription(structureObject([]string{"bootstrap", "guidance", "input", "schema"}, map[string]any{
		"bootstrap": bootstrap, "guidance": structureOpenObject(map[string]any{"ownerRoute": evaluatedObject("Failure-collecting owner-route projection.")}),
		"input": input, "schema": jsonshape.StringLiteral("proofkit.gradual-adoption-profile.v1").JSONSchema(),
	}), "All four root members are required. Their accessed nested objects are open; unrelated adoption/guidance fields are ignored. Contract string-array extraction precedes direct bootstrap; display-only command failures refuse the envelope. Secret-safe detached bootstrap admission applies to the derived input, not ignored envelope members. Native path, ID, mode, numeric, ordering and witness policies remain authoritative.")
}

func BootstrapOutputStructure() map[string]any {
	profile := bootstrapProfileStructure()
	guidance := bootstrapGuidanceStructure()
	fields := map[string]any{
		"agentActionPlan": jsonshape.Tuple(actionPlanShape(), actionPlanShape(), actionPlanShape()).JSONSchema(),
		"exitCode":        jsonshape.IntegerRange(0, 1).JSONSchema(), "nextCommands": jsonshape.Tuple(jsonshape.String(), jsonshape.String(), jsonshape.String()).JSONSchema(),
		"payloads": structureObject([]string{"adoptionGuidance", "adoptionProfile", "proofBinding", "witnessPlanInput"}, map[string]any{
			"adoptionGuidance": guidance, "adoptionProfile": profile,
			"proofBinding": shapeFields(map[string]jsonshape.Shape{
				"bindingFormat": jsonshape.StringLiteral("requirement_to_witness"), "moduleId": jsonshape.String(),
				"nonClaims": stringsShape(), "requirementIds": stringsShape(), "schemaVersion": jsonshape.IntegerLiteral(1), "witnessCommandIds": stringsShape(),
			}).JSONSchema(), "witnessPlanInput": nativeWitnessStructure(),
		}),
		"plannedFiles": jsonshape.BoundedArray(shapeFields(map[string]jsonshape.Shape{
			"path": jsonshape.String(), "payloadKey": jsonshape.Nullable(statesShape("adoptionGuidance", "adoptionProfile", "proofBinding", "witnessPlanInput")), "purpose": jsonshape.String(),
		}), 6, 6).JSONSchema(),
		"report": bootstrapReportShape().JSONSchema(), "witnessPlan": witnesscommand.PlanStructure(),
	}
	return outputDescription(inputDescription(structureObject([]string{"agentActionPlan", "exitCode", "nextCommands", "payloads", "plannedFiles", "report", "witnessPlan"}, fields), "Bootstrap projects starter content without writing files."))
}

func bootstrapProfileStructure() map[string]any {
	schema := InputStructure()
	fields := schema["properties"].(map[string]any)
	t, a := jsonshape.String(), stringsShape()
	fields["adoptionMode"] = jsonshape.StringLiteral("non_blocking").JSONSchema()
	fields["rolloutClaim"] = jsonshape.BooleanLiteral(false).JSONSchema()
	fields["agentReport"] = shapeFields(map[string]jsonshape.Shape{
		"artifactPath": t, "outputMode": jsonshape.StringLiteral("non_blocking"),
		"reportKind": jsonshape.StringLiteral("proofkit.gradual-adoption"), "routeQuestions": a,
		"schemaId": jsonshape.StringLiteral("proofkit.gradual-adoption-profile.v1"),
	}).JSONSchema()
	fields["module"] = moduleShape().JSONSchema()
	fields["proofBinding"] = shapeFields(map[string]jsonshape.Shape{
		"bindingFormat": jsonshape.StringLiteral("requirement_to_witness"), "bindingPath": t,
		"requirementIds": a, "witnessCommandIds": a,
	}).JSONSchema()
	schema["description"] = "Generated profile fields are closed normalized outputs, including empty values after collected failures. Budget, repository, rollback and nativeWitnesses retain detached caller-owned JSON with native admission; their successful policy is not inserted into the output schema. No repository files are written."
	return schema
}

func bootstrapGuidanceStructure() map[string]any {
	t, a := jsonshape.String(), stringsShape()
	agent := shapeFields(map[string]jsonshape.Shape{
		"artifactPath": t, "blockedPreconditions": a, "callerSuggestedAutofixCandidates": a,
		"commands": a, "minimalAdoptionPath": a, "proofBindingsMissing": a,
		"reportKind":          jsonshape.StringLiteral("proofkit.gradual-adoption-guidance"),
		"requiredNextActions": a, "routeQuestions": a,
		"schemaId": jsonshape.StringLiteral("proofkit.gradual-adoption-guidance.v1"),
	})
	return outputDescription(shapeFields(map[string]jsonshape.Shape{
		"agentGuidance": agent, "guidanceId": t, "guidanceMode": jsonshape.Enum(adoptionmode.ValuesMap()),
		"nonClaims": a, "ownerRoute": ownerRouteShape(), "schemaVersion": jsonshape.IntegerLiteral(1),
		"scopeEvidence": shapeFields(map[string]jsonshape.Shape{
			"basis": jsonshape.StringLiteral("caller_provided_touched_rule_ids"), "checkedScope": t, "touchedRuleIds": a,
		}), "sourceReport": adoptionReportShape(),
	}).JSONSchema())
}

func BootstrapMaterializationStructure() map[string]any {
	t, a := jsonshape.String(), stringsShape()
	file := func(payload bool) jsonshape.Shape {
		fields := map[string]jsonshape.Shape{"path": t, "purpose": t, "nonClaims": a}
		if payload {
			fields["content"], fields["contentKind"] = t, jsonshape.StringLiteral("json")
			fields["contentSha256"] = jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
			fields["payloadKey"] = statesShape("adoptionGuidance", "adoptionProfile", "proofBinding", "witnessPlanInput")
			fields["materializationStatus"] = jsonshape.StringLiteral("payload_available")
		} else {
			fields["content"], fields["contentKind"] = jsonshape.Null(), jsonshape.StringLiteral("caller_owned")
			fields["contentSha256"], fields["payloadKey"] = jsonshape.Null(), jsonshape.Null()
			fields["materializationStatus"] = jsonshape.StringLiteral("caller_content_required")
		}
		return shapeFields(fields)
	}
	return outputDescription(shapeFields(map[string]jsonshape.Shape{
		"fileCount": jsonshape.IntegerLiteral(6), "files": jsonshape.BoundedArray(jsonshape.DiscriminatedUnion("contentKind", file(true), file(false)), 6, 6),
		"manifestId": t, "manifestKind": jsonshape.StringLiteral("proofkit.gradual-adoption-bootstrap-materialization-manifest"),
		"nextCommands": jsonshape.Tuple(t, t, t), "nonClaims": a, "payloadFileCount": jsonshape.IntegerLiteral(4),
		"schemaVersion": jsonshape.IntegerLiteral(1),
		"sourceReport": shapeFields(map[string]jsonshape.Shape{
			"nonClaim": t, "reportId": t, "reportKind": jsonshape.StringLiteral("proofkit.gradual-adoption-bootstrap"),
			"stableHash": jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`), "state": statesShape("passed", "failed"),
		}),
	}).JSONSchema())
}

func bootstrapReportShape() jsonshape.Shape {
	t, n := jsonshape.String(), jsonshape.IntegerMinimum(0)
	summary := shapeFields(map[string]jsonshape.Shape{
		"adoptionMode": jsonshape.StringLiteral("non_blocking"), "checkedScope": t, "guidanceMode": jsonshape.Enum(adoptionmode.ValuesMap()),
		"moduleId": t, "plannedFileCount": jsonshape.IntegerLiteral(6), "payloadCount": jsonshape.IntegerLiteral(4),
		"requirementCount": n, "rolloutClaim": jsonshape.BooleanLiteral(false), "witnessCommandCount": n,
	})
	file := shapeFields(map[string]jsonshape.Shape{
		"path": t, "payloadKey": jsonshape.Nullable(statesShape("adoptionGuidance", "adoptionProfile", "proofBinding", "witnessPlanInput")), "purpose": t,
	})
	diagnostics := jsonshape.Tuple(
		report.DiagnosticStructure("agentActionPlan", jsonshape.Tuple(actionPlanShape(), actionPlanShape(), actionPlanShape())),
		report.DiagnosticStructure("nextCommands", jsonshape.Tuple(t, t, t)),
		report.DiagnosticStructure("plannedFiles", jsonshape.BoundedArray(file, 6, 6)),
		report.DiagnosticStructure("sourceReports", shapeFields(map[string]jsonshape.Shape{
			"adoptionGuidanceState": statesShape("passed", "failed", "blocked"), "adoptionProfileState": statesShape("passed", "failed"),
		})),
	)
	return report.Structure(1, "proofkit.gradual-adoption-bootstrap", statesShape("passed", "failed"), summary, diagnostics,
		jsonshape.Array(report.RuleStructure(t, statesShape("passed", "failed"), t, jsonshape.Tuple()), 1))
}
