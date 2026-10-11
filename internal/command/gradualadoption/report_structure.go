package gradualadoption

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func OutputStructure() map[string]any {
	return outputDescription(adoptionReportShape().JSONSchema())
}

func GuidanceOutputStructure() map[string]any {
	return outputDescription(guidanceReportShape().JSONSchema())
}

func adoptionReportShape() jsonshape.Shape {
	t, a, n := jsonshape.String(), stringsShape(), jsonshape.IntegerMinimum(0)
	summary := shapeFields(map[string]jsonshape.Shape{
		"addedSecondsBudget": n, "copiedVerifierFileCount": jsonshape.IntegerLiteral(0),
		"customRuleCount": n, "moduleId": t, "outputMode": jsonshape.StringLiteral("non_blocking"),
		"profileLineCount": n, "repositoryClass": t, "requirementCount": n,
		"rolloutClaim": jsonshape.Boolean(), "setupMinutesBudget": n, "witnessCommandCount": n,
	})
	diagnostics := jsonshape.Tuple(
		report.DiagnosticStructure("agentReport", shapeFields(map[string]jsonshape.Shape{
			"artifactPath": t, "routeQuestions": a, "schemaId": t,
		})),
		report.DiagnosticStructure("module", moduleShape()),
		report.DiagnosticStructure("packageVersionRef", t),
		report.DiagnosticStructure("proofBinding", shapeFields(map[string]jsonshape.Shape{"bindingPath": t, "witnessCommandIds": a})),
		report.DiagnosticStructure("rollback", shapeFields(map[string]jsonshape.Shape{"disableCommand": t, "owner": t, "versionPin": t})),
		report.DiagnosticStructure("witnessPlan", shapeFields(map[string]jsonshape.Shape{
			"commandIds":     a,
			"parallelGroups": jsonshape.Array(shapeFields(map[string]jsonshape.Shape{"commandIds": a, "parallelGroup": t}), 0),
		})),
	)
	return report.Structure(1, "proofkit.gradual-adoption", statesShape("passed", "failed"), summary, diagnostics,
		jsonshape.Array(report.RuleStructure(t, statesShape("passed", "failed"), t, jsonshape.Tuple()), 1))
}

func guidanceReportShape() jsonshape.Shape {
	t, a, n := jsonshape.String(), stringsShape(), jsonshape.IntegerMinimum(0)
	fields := map[string]jsonshape.Shape{
		"checkedScope": t, "guidanceMode": jsonshape.Enum(adoptionmode.ValuesMap()), "sourceReportState": jsonshape.Enum(sourceReportStates),
	}
	for _, key := range []string{"blockedPreconditionCount", "callerSuggestedAutofixCandidateCount", "candidateBoundaryCount", "commandCount", "proofBindingMissingCount", "requiredNextActionCount", "sourceFailedRuleCount", "sourceWarningRuleCount", "touchedRuleCount"} {
		fields[key] = n
	}
	diagnostic := jsonshape.DiscriminatedUnion("key",
		report.DiagnosticStructure("enforcementFailedRuleIds", a), report.DiagnosticStructure("sourceFailedRuleIds", a),
		report.DiagnosticStructure("sourceReportState", jsonshape.Enum(sourceReportStates)),
		report.DiagnosticStructure("proofBindingsMissing", a), report.DiagnosticStructure("blockedPreconditions", a),
		report.DiagnosticStructure("sourceWarningRuleIds", a), report.DiagnosticStructure("candidateBoundaryIds", a),
	)
	return report.Structure(1, "proofkit.gradual-adoption-guidance", statesShape("passed", "failed", "blocked"), shapeFields(fields),
		jsonshape.Tuple(report.DiagnosticStructure("guidance", guidanceShape()), report.DiagnosticStructure("sourceReport", shapeFields(map[string]jsonshape.Shape{
			"reportId": t, "reportKind": t, "state": jsonshape.Enum(sourceReportStates),
		}))), jsonshape.Array(report.RuleStructure(t, jsonshape.Enum(sourceReportStates), t, jsonshape.Array(diagnostic, 0)), 1))
}

func guidanceShape() jsonshape.Shape {
	t, a := jsonshape.String(), stringsShape()
	fields := map[string]jsonshape.Shape{
		"agentActionPlan":     jsonshape.BoundedArray(actionPlanShape(), 4, 5),
		"candidateBoundaries": jsonshape.Array(candidateShape(), 0), "checkedScope": t,
		"guidanceMode": jsonshape.Enum(adoptionmode.ValuesMap()), "nonClaims": a, "ownerRoute": ownerRouteShape(),
	}
	for _, key := range []string{"blockedPreconditions", "callerSuggestedAutofixCandidates", "commands", "minimalAdoptionPath", "proofBindingsMissing", "requiredNextActions", "sourceFailedRuleIds", "sourceWarningRuleIds", "touchedRuleIds"} {
		fields[key] = a
	}
	return shapeFields(fields)
}

func candidateShape() jsonshape.Shape {
	t, a := jsonshape.String(), stringsShape()
	fields := map[string]jsonshape.Shape{
		"admissionState": jsonshape.StringLiteral("advisory"), "boundaryId": t, "candidateOwner": t,
	}
	for _, key := range []string{"affectedPaths", "blockedPreconditions", "contractWitnessRefs", "migrationRefs", "nativeWitnessRefs", "nonClaims", "observedFacts", "ownerQuestions", "proofBindingRefs", "requirementRefs", "uncertainties"} {
		fields[key] = a
	}
	return shapeFields(fields)
}

func ownerRouteShape() jsonshape.Shape {
	return shapeFields(map[string]jsonshape.Shape{
		"evidencePaths": stringsShape(), "primaryOwner": jsonshape.String(),
		"proofBindingPaths": stringsShape(), "specPaths": stringsShape(),
	})
}

func moduleShape() jsonshape.Shape {
	return shapeFields(map[string]jsonshape.Shape{
		"moduleId": jsonshape.String(), "requirementIds": stringsShape(), "specPath": jsonshape.String(),
	})
}

func actionPlanShape() jsonshape.Shape {
	return shapeFields(map[string]jsonshape.Shape{
		"commands": stringsShape(), "evidenceRefs": stringsShape(), "instruction": jsonshape.String(),
		"nonClaims": stringsShape(), "owner": jsonshape.StringLiteral("consumer_repository"),
		"phase": statesShape("route", "modernize-boundary", "bind", "verify", "promote"), "stepId": jsonshape.String(),
	})
}

func shapeFields(fields map[string]jsonshape.Shape) jsonshape.Shape {
	properties := make([]jsonshape.Property, 0, len(fields))
	for key, value := range fields {
		properties = append(properties, jsonshape.Required(key, value))
	}
	return jsonshape.Object(properties...)
}

func stringsShape() jsonshape.Shape { return jsonshape.Array(jsonshape.String(), 0) }

func statesShape(values ...string) jsonshape.Shape {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return jsonshape.Enum(set)
}

func outputDescription(schema map[string]any) map[string]any {
	schema["description"] = "Complete emitted carrier, including failed reports. Normalized strings/arrays may be empty after collected input failures. Native owners determine comparison results, identity, path and command safety, sortedness, reference closure, item positions, privacy and state/exit consistency. Structural validity does not prove native witness execution, currentness, caller approval or rollout readiness."
	return schema
}
