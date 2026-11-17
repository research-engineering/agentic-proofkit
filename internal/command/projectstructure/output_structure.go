package projectstructure

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

// Three scaffold-owned payload files plus the six bootstrap planned files.
const materializedFileCount = 9

// OutputStructure keeps the reused bootstrap and repo-profile plan owners as
// published by their own commands; only scaffold-owned carriers are declared here.
func OutputStructure() map[string]any {
	shapes := outputMemberShapes()
	properties := map[string]any{
		"adoptionWorkflowPlan":    workflowPlanStructure(),
		"bootstrapReport":         gradualadoption.BootstrapOutputStructure(),
		"repoProfileScaffoldPlan": scaffoldprofileplan.OutputStructure(),
	}
	for key, shape := range shapes {
		properties[key] = fragment(shape)
	}
	required := []any{}
	for _, key := range []string{"adoptionWorkflowInput", "adoptionWorkflowPlan", "bootstrapReport", "exitCode", "materializationManifest", "repoProfileScaffoldPlan", "report"} {
		if _, ok := properties[key]; !ok {
			panic("project structure output omits a member")
		}
		required = append(required, key)
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"properties": properties, "required": required,
		"description": "Complete scaffold result for admitted input, including failed reports with exitCode 1. The embedded bootstrap result, workflow plan and repo-profile plan use their own command output structures. The workflow input and plan describe the new_repository scenario with two scaffold-owned refs plus available child-operation refs; missing child operations or preset can block the plan. The manifest lists nine sorted unique files: three scaffold payloads plus six bootstrap files, one of which may be replaced by the repo-profile draft. Its next commands are three scaffold-owned commands plus zero to three prepared bootstrap commands. Native owners determine path consistency, hashes, ordering, renderer-specific commands and state/exit consistency; structural validity does not prove files exist, witnesses ran or caller approval.",
	}
}

func outputMemberShapes() map[string]jsonshape.Shape {
	// Output text is native-normalized; nonempty text is its structural claim.
	id, count := identifierShape(), jsonshape.IntegerMinimum(0)
	text, path := jsonshape.StringGrammar(`[\s\S]+`), jsonshape.StringGrammar(`[\s\S]+`)
	sha := jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`)
	scenario := jsonshape.StringLiteral("new_repository")
	workflowInput := jsonshape.Object(
		jsonshape.Required("inputRefs", workflowRefsShape()), jsonshape.Required("nonClaims", jsonshape.Array(text, len(workflowInputNonClaims))),
		jsonshape.Optional("presetId", scaffoldprofileplan.PresetShape()), jsonshape.Required("scenario", scenario),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)), jsonshape.Required("workflowId", id),
	)
	twoClaims := jsonshape.Tuple(text, text)
	file := jsonshape.DiscriminatedUnion("contentKind",
		jsonshape.Object(
			jsonshape.Required("content", path), jsonshape.Required("contentKind", jsonshape.StringLiteral("json")),
			jsonshape.Required("contentSha256", sha), jsonshape.Required("materializationStatus", jsonshape.StringLiteral("payload_available")),
			jsonshape.Required("nonClaims", twoClaims), jsonshape.Required("path", path), jsonshape.Required("purpose", text),
			jsonshape.Required("source", valuesShape("bootstrap_manifest", "project_scaffold", "repo_profile_scaffold")),
		),
		jsonshape.Object(
			jsonshape.Required("content", jsonshape.Null()), jsonshape.Required("contentKind", jsonshape.StringLiteral("caller_owned")),
			jsonshape.Required("contentSha256", jsonshape.Null()), jsonshape.Required("materializationStatus", jsonshape.StringLiteral("caller_content_required")),
			jsonshape.Required("nonClaims", twoClaims), jsonshape.Required("path", path), jsonshape.Required("purpose", text),
			jsonshape.Required("source", jsonshape.StringLiteral("bootstrap_manifest")),
		),
	)
	source := func(kind string, states ...string) jsonshape.Shape {
		return jsonshape.Object(jsonshape.Required("nonClaim", text), jsonshape.Required("reportId", id),
			jsonshape.Required("reportKind", jsonshape.StringLiteral(kind)), jsonshape.Required("stableHash", sha),
			jsonshape.Required("state", valuesShape(states...)))
	}
	manifestID, fileCount := jsonshape.StringSuffix(".materialization-manifest"), jsonshape.IntegerLiteral(materializedFileCount)
	manifest := jsonshape.Object(
		jsonshape.Required("callerContentRequiredCount", count), jsonshape.Required("fileCount", fileCount),
		jsonshape.Required("files", jsonshape.BoundedArray(file, materializedFileCount, materializedFileCount)),
		jsonshape.Required("manifestId", manifestID),
		jsonshape.Required("manifestKind", jsonshape.StringLiteral("proofkit.project-structure-scaffold-materialization-manifest")),
		jsonshape.Required("nextCommands", jsonshape.BoundedArray(text, 3, 6)),
		jsonshape.Required("nonClaims", jsonshape.Tuple(text, text, text, text)), jsonshape.Required("payloadFileCount", count),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("sourceReports", jsonshape.Tuple(
			source(scaffoldprofileplan.PlanKind, "passed"), source("proofkit.gradual-adoption-bootstrap", "passed", "failed"),
			source("proofkit.adoption-workflow-plan", "passed", "failed"),
		)),
	)
	summaryFile := jsonshape.DiscriminatedUnion("materializationStatus",
		jsonshape.Object(jsonshape.Required("contentSha256", sha), jsonshape.Required("materializationStatus", jsonshape.StringLiteral("payload_available")),
			jsonshape.Required("path", path), jsonshape.Required("source", valuesShape("bootstrap_manifest", "project_scaffold", "repo_profile_scaffold"))),
		jsonshape.Object(jsonshape.Required("contentSha256", jsonshape.Null()), jsonshape.Required("materializationStatus", jsonshape.StringLiteral("caller_content_required")),
			jsonshape.Required("path", path), jsonshape.Required("source", jsonshape.StringLiteral("bootstrap_manifest"))),
	)
	rules := jsonshape.OneOf(
		report.RuleStructure(jsonshape.StringLiteral(reportKind+".accepted"), jsonshape.StringLiteral("passed"), text, jsonshape.Tuple()),
		report.RuleStructure(jsonshape.StringGrammar(`proofkit\.project-structure-scaffold\.failure\.[0-9]{3}`), jsonshape.StringLiteral("failed"), text, jsonshape.Tuple()),
	)
	record := report.Structure(1, reportKind, valuesShape("passed", "failed"),
		jsonshape.Object(jsonshape.Required("callerContentRequiredCount", count), jsonshape.Required("fileCount", fileCount),
			jsonshape.Required("payloadFileCount", count), jsonshape.Required("sourceReportCount", jsonshape.IntegerLiteral(3))),
		jsonshape.Tuple(report.DiagnosticStructure("materializationManifestSummary", jsonshape.Object(
			jsonshape.Required("callerContentRequiredCount", count), jsonshape.Required("fileCount", fileCount),
			jsonshape.Required("files", jsonshape.BoundedArray(summaryFile, materializedFileCount, materializedFileCount)),
			jsonshape.Required("manifestId", manifestID), jsonshape.Required("payloadFileCount", count),
		))),
		jsonshape.Array(rules, 1),
	)
	return map[string]jsonshape.Shape{
		"adoptionWorkflowInput": workflowInput, "exitCode": jsonshape.IntegerRange(0, 1),
		"materializationManifest": manifest, "report": record,
	}
}

func workflowRefsShape() jsonshape.Shape {
	refs := make([]jsonshape.Shape, 0, len(workflowInputKinds))
	for _, kind := range workflowInputKinds {
		refs = append(refs, jsonshape.Object(jsonshape.Required("inputKind", jsonshape.StringLiteral(kind)),
			jsonshape.Required("path", jsonshape.StringGrammar(`[\s\S]+`)), jsonshape.Required("refId", jsonshape.StringLiteral(kind))))
	}
	// Only witness and guidance refs depend on child prepared operations.
	return jsonshape.OneOf(jsonshape.Tuple(refs...), jsonshape.Tuple(refs[0], refs[1], refs[3]),
		jsonshape.Tuple(refs[1], refs[2], refs[3]), jsonshape.Tuple(refs[1], refs[3]))
}

func workflowPlanStructure() map[string]any {
	schema := adoptionworkflow.OutputStructure()
	properties := schema["properties"].(map[string]any)
	properties["inputRefs"] = fragment(workflowRefsShape())
	properties["scenario"] = fragment(jsonshape.StringLiteral("new_repository"))
	// Retain child-owned blocker identities and repairs for this scenario.
	blockers := properties["blockers"].(map[string]any)
	items := blockers["items"].(map[string]any)
	cases := []any{}
	for _, raw := range items["oneOf"].([]any) {
		candidate := raw.(map[string]any)
		scenario := candidate["properties"].(map[string]any)["scenario"].(map[string]any)
		if scenario["const"] == "new_repository" {
			cases = append(cases, candidate)
		}
	}
	items["oneOf"] = cases
	blockers["maxItems"] = len(cases)
	return schema
}

// EnvelopeShape describes Build's sanitized carrier for one admitted scaffold.
func EnvelopeShape(envelopeID string) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	actions := []jsonshape.Shape{}
	for _, phase := range []string{"bind", "candidate-change", "route", "verify"} {
		actions = append(actions, agentenvelope.ActionStructure(jsonshape.StringLiteral(phase)))
	}
	return agentenvelope.Structure(envelopeID, agentenvelope.StructureParts{
		ActionPlan:             jsonshape.Tuple(actions...),
		BlockedPreconditions:   jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, envelopeBlockedLimit),
		Bounds:                 agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.StringLiteral("owner_decision")), 0, envelopeBlockedLimit),
		Commands: jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("argv", jsonshape.Array(text, 4)),
			jsonshape.Required("command", text), jsonshape.Required("commandId", text), jsonshape.Required("nonClaim", text),
			jsonshape.Required("owner", jsonshape.StringLiteral("consumer_repository")), jsonshape.Required("purpose", text),
		), 0, envelopeCommandLimit),
		ContextRefs: jsonshape.BoundedArray(agentenvelope.ContextRefStructure(jsonshape.StringLiteral("path"),
			valuesShape("command_registry", "owner_surface", "proof_binding", "router", "spec_source", "supporting")), 0, envelopeContextLimit),
		// Fixed file and command counts stay within this producer's limits, so
		// only envelope-owner degradation records can appear; the declared zero
		// bound caps them at one summarized record.
		Omitted: jsonshape.BoundedArray(agentenvelope.OmissionStructure(), 0, 1), ReceiptRefs: jsonshape.Tuple(),
		RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport: agentenvelope.SourceReportStructure(reportKind, identifierShape(),
			jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`), valuesShape("passed", "failed")),
	})
}

func EnvelopeStructure() map[string]any {
	schema := EnvelopeShape("placeholder").JSONSchema()
	// A suffixed admitted ID can become secret-shaped and is then redacted.
	schema["properties"].(map[string]any)["envelopeId"] = map[string]any{"anyOf": []any{
		fragment(jsonshape.StringSuffix(".agent-envelope")), fragment(jsonshape.StringLiteral(admit.DiagnosticRedactionMarker)),
	}}
	schema["description"] = "Agent envelope for an admitted scaffold, including failed scaffold reports. It has four fixed route, candidate-change, bind and verify actions, one path context ref per materialized file, the scaffold next commands with canonical argv and one blocked precondition plus owner-decision clarification per caller-content file or profile draft review. Commands share the manifest's canonical projection and actual invocation renderer; losing a materialized context prunes its dependent command. Payload bodies are omitted. Structural paths and argv retain exact admitted identity; descriptive strings are sanitized and may be redacted or truncated. Unsafe local references are summarized by at most one omission record and degradation bounds. Native Build owns ordering, limits, roles, source hashing and stop reasons. Refused input uses the separately declared invalid-input envelope."
	return schema
}

func valuesShape(values ...string) jsonshape.Shape {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return jsonshape.Enum(set)
}
