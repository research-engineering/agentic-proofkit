package changeworkflowplan

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// relationVocabulary is the projection of the native checkpoint relation for
// one plan variant. It binds value sets, not the relation's row semantics.
type relationVocabulary struct {
	actions, candidateActions, expectedNext, stages, states, stopConditions map[string]struct{}
	outputKind                                                              string
	subjectRequired, findingsPossible                                       bool
	minimumCompleted, maximumCompleted                                      int
}

func workflowRelationVocabulary(successor bool) relationVocabulary {
	vocabulary := relationVocabulary{
		actions: map[string]struct{}{}, candidateActions: map[string]struct{}{}, expectedNext: map[string]struct{}{},
		stages: map[string]struct{}{}, states: map[string]struct{}{}, stopConditions: map[string]struct{}{},
		subjectRequired: true, minimumCompleted: len(workflowCatalog.Stages),
	}
	for _, row := range checkpointRelation {
		if row.Terminal || row.EmitsSuccessor != successor {
			continue
		}
		profile, ok := actionProfileFor(row.Action)
		definition, known := checkpointDefinitionFor(row.CheckpointState)
		if !ok || !known {
			panic("workflow relation row has no catalog definition")
		}
		vocabulary.outputKind = row.OutputKind
		vocabulary.actions[row.Action] = struct{}{}
		vocabulary.candidateActions[profile.CandidateAction] = struct{}{}
		vocabulary.expectedNext[profile.ExpectedNextCheckpoint] = struct{}{}
		vocabulary.stages[row.ActiveStageID] = struct{}{}
		vocabulary.states[row.CheckpointState] = struct{}{}
		vocabulary.stopConditions[profile.StopCondition] = struct{}{}
		vocabulary.stopConditions[profile.StopCondition+" "+missingOwnerStop] = struct{}{}
		vocabulary.subjectRequired = vocabulary.subjectRequired && row.RequiresSubject
		vocabulary.findingsPossible = vocabulary.findingsPossible || definition.RequiresFindingRefs
		vocabulary.minimumCompleted = min(vocabulary.minimumCompleted, row.CompletedCount)
		vocabulary.maximumCompleted = max(vocabulary.maximumCompleted, row.CompletedCount)
	}
	if vocabulary.outputKind == "" {
		panic("workflow relation variant is empty")
	}
	return vocabulary
}

func terminalOutputKind() string {
	for _, row := range checkpointRelation {
		if row.Terminal {
			return row.OutputKind
		}
	}
	panic("workflow relation has no terminal row")
}

func planFields(outputKind string, minimumCompleted, maximumCompleted int) map[string]jsonshape.Shape {
	return map[string]jsonshape.Shape{
		"authority":             jsonshape.StringLiteral(planAuthority),
		"completedStageIds":     workflowStagePrefixShape(minimumCompleted, maximumCompleted),
		"nonClaims":             literalTupleShape(boundaryNonClaims),
		"omittedContextCount":   jsonshape.IntegerRange(0, maxCandidateContextRefs),
		"omittedContextRefIds":  workflowRefIDsShape(0, maxCandidateContextRefs),
		"outputKind":            jsonshape.StringLiteral(outputKind),
		"reportId":              jsonshape.StringLiteral(reportKind),
		"reportKind":            jsonshape.StringLiteral(reportKind),
		"retainedContextRefIds": workflowRefIDsShape(0, maxRetainedContextRefs),
		"retainedContextRefs":   jsonshape.BoundedArray(workflowContextRefShape(false), 0, maxRetainedContextRefs),
		"schemaVersion":         jsonshape.IntegerLiteral(1),
		"workflowProfileId":     jsonshape.StringLiteral(workflowProfileID),
	}
}

func promptShape(vocabulary relationVocabulary) jsonshape.Shape {
	coordinates := []jsonshape.Property{
		jsonshape.Required("activeStageId", jsonshape.Enum(vocabulary.stages)),
		jsonshape.Required("checkpointState", jsonshape.Enum(vocabulary.states)),
		jsonshape.Optional("governingAuthorityRefId", workflowRefIDShape()),
		jsonshape.Required("retainedArtifactPaths", jsonshape.BoundedArray(workflowPathShape(), 0, maxRetainedContextRefs)),
		jsonshape.Required("retainedContextRefIds", workflowRefIDsShape(0, maxRetainedContextRefs)),
	}
	subject := jsonshape.Optional
	if vocabulary.subjectRequired {
		subject = jsonshape.Required
	}
	coordinates = append(coordinates, subject("subjectDigest", workflowDigestShape()), subject("subjectRefId", workflowRefIDShape()))
	if vocabulary.findingsPossible {
		coordinates = append(coordinates, jsonshape.Optional("findingRefs", workflowRefIDsShape(1, maxFindings)))
	}
	return jsonshape.Object(
		jsonshape.Required("candidateAction", jsonshape.Enum(vocabulary.candidateActions)),
		jsonshape.Required("coordinates", jsonshape.Object(coordinates...)),
		jsonshape.Required("expectedNextCheckpoint", jsonshape.Enum(vocabulary.expectedNext)),
		jsonshape.Required("nonClaim", jsonshape.StringLiteral(promptNonClaim)),
		jsonshape.Required("observedFact", jsonshape.Object(
			jsonshape.Required("activeStageId", jsonshape.Enum(vocabulary.stages)),
			jsonshape.Required("checkpointState", jsonshape.Enum(vocabulary.states)),
			jsonshape.Required("completedStageIds", workflowStagePrefixShape(vocabulary.minimumCompleted, vocabulary.maximumCompleted)),
			jsonshape.Required("governingAuthorityRefId", jsonshape.Nullable(workflowRefIDShape())),
			jsonshape.Required("omittedContextRefIds", workflowRefIDsShape(0, maxCandidateContextRefs)),
			jsonshape.Required("retainedContextRefIds", workflowRefIDsShape(0, maxRetainedContextRefs)),
		)),
		jsonshape.Required("ownerOrEscalationTarget", workflowRefIDShape()),
		jsonshape.Required("proofCommandOrMissingWitness", jsonshape.DiscriminatedUnion("state",
			jsonshape.Object(jsonshape.Required("state", jsonshape.StringLiteral(missingConsumerWitness))),
			jsonshape.Object(jsonshape.Required("state", jsonshape.StringLiteral(retainedConsumerWitness)),
				jsonshape.Required("witnessRefIds", workflowRefIDsShape(1, maxRetainedContextRefs))),
		)),
		jsonshape.Required("stopCondition", jsonshape.Enum(vocabulary.stopConditions)),
		jsonshape.Required("uncertainty", jsonshape.StringLiteral(promptUncertainty)),
	)
}

func successorShape() jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("checkpoint", jsonshape.Nullable(jsonshape.Object(
			jsonshape.Required("state", jsonshape.StringLiteral(initialCheckpointDefinition().State)),
			jsonshape.Required("subjectDigest", workflowDigestShape()),
			jsonshape.Required("subjectRefId", workflowRefIDShape()),
		))),
		jsonshape.Required("completedStageIds", workflowStagePrefixShape(1, len(workflowCatalog.Stages))),
	)
}

// NextActionOutputShape, AcceptStageOutputShape and WorkflowCompleteOutputShape
// are the jsonshape cores of the three JSON plan variants.
func NextActionOutputShape() jsonshape.Shape { return nextActionPlanShape(false) }

func AcceptStageOutputShape() jsonshape.Shape { return nextActionPlanShape(true) }

func nextActionPlanShape(successor bool) jsonshape.Shape {
	vocabulary := workflowRelationVocabulary(successor)
	fields := planFields(vocabulary.outputKind, vocabulary.minimumCompleted, vocabulary.maximumCompleted)
	fields["action"] = jsonshape.Enum(vocabulary.actions)
	fields["activeStageId"] = jsonshape.Enum(vocabulary.stages)
	fields["checkpointState"] = jsonshape.Enum(vocabulary.states)
	fields["prompt"] = promptShape(vocabulary)
	if successor {
		fields["successorStateDelta"] = successorShape()
	}
	properties := make([]jsonshape.Property, 0, len(fields))
	for _, key := range sortedSet(keysOf(fields)) {
		properties = append(properties, jsonshape.Required(key, fields[key]))
	}
	return jsonshape.Object(properties...)
}

func WorkflowCompleteOutputShape() jsonshape.Shape {
	count := len(workflowCatalog.Stages)
	fields := planFields(terminalOutputKind(), count, count)
	properties := make([]jsonshape.Property, 0, len(fields))
	for _, key := range sortedSet(keysOf(fields)) {
		properties = append(properties, jsonshape.Required(key, fields[key]))
	}
	return jsonshape.Object(properties...)
}

const planDescription = " The plan is derived from one admitted snapshot by the native checkpoint relation and least dependency closure; native owners keep the exact action/stage/checkpoint rows, retained/omitted partition and ordering, ID/path correspondence, owner or escalation target, witness availability and byte caps. Text mode (--format text) emits a bounded non-JSON presentation that this schema does not describe. Refused input emits stderr without JSON. The plan does not authenticate caller context or prove execution, review quality, merge, release or readiness."

func NextActionOutputStructure() map[string]any {
	schema := refineWorkflowStructure(NextActionOutputShape().JSONSchema())
	coordinates := schema["properties"].(map[string]any)["prompt"].(map[string]any)["properties"].(map[string]any)["coordinates"].(map[string]any)
	coordinates["dependentRequired"] = map[string]any{
		"findingRefs":   []any{"subjectDigest", "subjectRefId"},
		"subjectDigest": []any{"subjectRefId"},
		"subjectRefId":  []any{"subjectDigest"},
	}
	schema["description"] = "JSON next-action plan for every non-terminal checkpoint row whose action does not emit a successor delta. Prompt coordinates carry the subject pair together, and finding refs only with a subject." + planDescription
	return schema
}

func AcceptStageOutputStructure() map[string]any {
	schema := refineWorkflowStructure(AcceptStageOutputShape().JSONSchema())
	schema["description"] = "JSON next-action plan for the stage-acceptance rows: successorStateDelta carries the extended stage prefix and the next stage's initial checkpoint bound to the accepted subject, or null after the final stage." + planDescription
	return schema
}

func WorkflowCompleteOutputStructure() map[string]any {
	schema := refineWorkflowStructure(WorkflowCompleteOutputShape().JSONSchema())
	schema["description"] = "JSON terminal plan for the complete stage prefix with a null checkpoint; it carries no action or prompt." + planDescription
	return schema
}

// blockerCatalog obtains every blocker and clarification the producer can emit
// from the native blocker function itself, with no admitted caller references.
func blockerCatalog() ([]map[string]any, []map[string]any) {
	return envelopeBlockers(projection{Decision: stateDecision{
		OutputKind: workflowRelationVocabulary(false).outputKind, RequiresSubject: true, RequiresWitness: true,
	}}, workflowCatalog)
}

// literalRecordShape binds every producer-constant member literally and leaves
// the caller-derived evidence references to the named shape.
func literalRecordShape(record map[string]any, evidence jsonshape.Shape) jsonshape.Shape {
	properties := make([]jsonshape.Property, 0, len(record))
	for _, key := range sortedSet(keysOf(record)) {
		switch value := record[key].(type) {
		case string:
			properties = append(properties, jsonshape.Required(key, jsonshape.StringLiteral(value)))
		case bool:
			properties = append(properties, jsonshape.Required(key, jsonshape.BooleanLiteral(value)))
		case []any:
			if key != "evidenceRefs" || len(value) != 0 {
				panic("workflow envelope record has an unexpected list")
			}
			properties = append(properties, jsonshape.Required(key, evidence))
		default:
			panic("workflow envelope record has an unexpected member")
		}
	}
	return jsonshape.Object(properties...)
}

func literalRecordUnion(key string, records []map[string]any, evidence func(map[string]any) jsonshape.Shape) jsonshape.Shape {
	alternatives := make([]jsonshape.Shape, len(records))
	for index, record := range records {
		alternatives[index] = literalRecordShape(record, evidence(record))
	}
	if len(alternatives) == 1 {
		return alternatives[0]
	}
	return jsonshape.DiscriminatedUnion(key, alternatives...)
}

func contextRoles() map[string]struct{} {
	roles := map[string]struct{}{}
	for kind := range contextRefKinds {
		governing := "governing"
		roles[contextRole(contextRef{RefID: governing, RefKind: kind}, &governing)] = struct{}{}
		roles[contextRole(contextRef{RefKind: kind}, nil)] = struct{}{}
	}
	return roles
}

func envelopeActionShape() jsonshape.Shape {
	next := workflowRelationVocabulary(false)
	accept := workflowRelationVocabulary(true)
	instructions := map[string]struct{}{}
	for _, values := range []map[string]struct{}{next.candidateActions, accept.candidateActions} {
		for value := range values {
			instructions[value] = struct{}{}
		}
	}
	evidence := workflowRefIDsShape(0, maxRetainedContextRefs)
	nonClaims := jsonshape.Tuple(jsonshape.StringLiteral(promptNonClaim))
	return jsonshape.DiscriminatedUnion("stepId",
		jsonshape.Object(
			jsonshape.Required("commandIds", jsonshape.Tuple()), jsonshape.Required("evidenceRefs", evidence),
			jsonshape.Required("instruction", jsonshape.Enum(instructions)), jsonshape.Required("nonClaims", nonClaims),
			jsonshape.Required("outputKind", jsonshape.StringLiteral(next.outputKind)), jsonshape.Required("owner", workflowRefIDShape()),
			jsonshape.Required("phase", jsonshape.Enum(setOf(workflowStageIDs()...))), jsonshape.Required("rationale", jsonshape.StringLiteral(nextActionRationale)),
			jsonshape.Required("stepId", jsonshape.StringLiteral(nextActionStepID)), jsonshape.Optional("successorStateDelta", successorShape()),
			jsonshape.Optional("subjectDigest", workflowDigestShape()), jsonshape.Optional("subjectRefId", workflowRefIDShape()),
		),
		jsonshape.Object(
			jsonshape.Required("commandIds", jsonshape.Tuple()), jsonshape.Required("evidenceRefs", evidence),
			jsonshape.Required("instruction", jsonshape.StringLiteral(terminalStop)), jsonshape.Required("nonClaims", nonClaims),
			jsonshape.Required("outputKind", jsonshape.StringLiteral(terminalOutputKind())), jsonshape.Required("owner", jsonshape.StringLiteral(envelopeOwner)),
			jsonshape.Required("phase", jsonshape.StringLiteral(terminalPhase)), jsonshape.Required("rationale", jsonshape.StringLiteral(terminalRationale)),
			jsonshape.Required("stepId", jsonshape.StringLiteral(terminalStepID)),
		),
	)
}

// EnvelopeShape is the jsonshape core of EnvelopeStructure; the published
// projection additionally fixes the merged non-claim tuple and list refinements.
func EnvelopeShape() jsonshape.Shape {
	blocked, clarifications := blockerCatalog()
	retainedEvidence := func(map[string]any) jsonshape.Shape { return workflowRefIDsShape(0, maxRetainedContextRefs) }
	const retainedMarker, governingMarker = "retained", "governing"
	questions := workflowRouteQuestions([]string{retainedMarker}, []string{governingMarker})
	questionShapes := make([]jsonshape.Shape, len(questions))
	for index, question := range questions {
		evidence := workflowRefIDsShape(0, maxRetainedContextRefs)
		if refs := question["evidenceRefs"].([]any); len(refs) == 1 && refs[0] == governingMarker {
			evidence = workflowRefIDsShape(0, 1)
		}
		literal := map[string]any{}
		for key, value := range question {
			literal[key] = value
		}
		literal["evidenceRefs"] = []any{}
		questionShapes[index] = literalRecordShape(literal, evidence)
	}
	fanout := setOf(envelopeFanout(0, 0), envelopeFanout(1, 0), envelopeFanout(0, 1))
	bounds := jsonshape.Object(
		jsonshape.Required("escalation", jsonshape.StringLiteral(envelopeBoundsEscalation)),
		jsonshape.Required("fanout", jsonshape.Enum(fanout)),
		jsonshape.Required("maxActionEvidenceRefs", jsonshape.IntegerRange(0, maxRetainedContextRefs)),
		jsonshape.Required("maxActionItems", jsonshape.IntegerRange(0, 1)),
		jsonshape.Required("maxBlockedPreconditions", jsonshape.IntegerRange(0, int64(len(blocked)))),
		jsonshape.Required("maxClarificationQuestions", jsonshape.IntegerRange(0, int64(len(clarifications)))),
		jsonshape.Required("maxCommandRefs", jsonshape.IntegerLiteral(0)),
		jsonshape.Required("maxContextRefs", jsonshape.IntegerRange(0, maxRetainedContextRefs)),
		jsonshape.Required("maxOmittedItems", jsonshape.IntegerRange(0, 1)),
		jsonshape.Required("maxReceiptRefs", jsonshape.IntegerLiteral(0)),
		jsonshape.Required("maxRouteQuestions", jsonshape.IntegerLiteral(int64(len(questions)))),
		jsonshape.Required("maxTokenBudget", jsonshape.Null()),
		jsonshape.Required("nonClaim", jsonshape.StringLiteral(envelopeBoundsNonClaim)),
		jsonshape.Required("omittedCount", jsonshape.IntegerRange(0, maxCandidateContextRefs)),
		jsonshape.Optional("truncated", jsonshape.BooleanLiteral(true)),
	)
	return agentenvelope.Structure(envelopeID, agentenvelope.StructureParts{
		ActionPlan:             jsonshape.BoundedArray(envelopeActionShape(), 0, 1),
		BlockedPreconditions:   jsonshape.BoundedArray(literalRecordUnion("preconditionId", blocked, retainedEvidence), 0, len(blocked)),
		Bounds:                 bounds,
		ClarificationQuestions: jsonshape.BoundedArray(literalRecordUnion("questionId", clarifications, retainedEvidence), 0, len(clarifications)),
		Commands:               jsonshape.Tuple(),
		ContextRefs: jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("kind", jsonshape.Enum(contextRefKinds)), jsonshape.Required("nonClaim", jsonshape.StringLiteral(envelopeContextNonClaim)),
			jsonshape.Required("owner", jsonshape.StringLiteral(envelopeOwner)), jsonshape.Required("purpose", jsonshape.StringLiteral(envelopeContextPurpose)),
			jsonshape.Required("ref", workflowPathShape()), jsonshape.Required("refId", workflowRefIDShape()),
			jsonshape.Required("role", jsonshape.Enum(contextRoles())), jsonshape.Required("subjectDigest", workflowDigestShape()),
		), 0, maxRetainedContextRefs),
		Omitted: jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("kind", jsonshape.StringLiteral(envelopeOmissionKind)), jsonshape.Required("nonClaim", jsonshape.StringLiteral(envelopeOmissionNonClaim)),
			jsonshape.Required("omissionId", jsonshape.StringLiteral(envelopeOmissionID)), jsonshape.Required("omittedCount", jsonshape.IntegerRange(1, maxCandidateContextRefs)),
			jsonshape.Required("reason", jsonshape.StringLiteral(envelopeOmissionReason)),
		), 0, 1),
		ReceiptRefs:    jsonshape.Tuple(),
		RouteQuestions: jsonshape.Tuple(questionShapes...),
		SourceReport: agentenvelope.SourceReportStructure(reportKind, jsonshape.StringLiteral(reportKind),
			workflowDigestShape(), jsonshape.StringLiteral("passed")),
	})
}

// envelopeNonClaims is the producer's merged, sorted kernel and boundary claim set.
func envelopeNonClaims() []string {
	merged := agentenvelope.Build(agentenvelope.Input{NonClaims: boundaryNonClaims})["nonClaims"].([]any)
	result := make([]string, len(merged))
	for index, value := range merged {
		result[index] = value.(string)
	}
	return result
}

func EnvelopeStructure() map[string]any {
	schema := refineWorkflowStructure(EnvelopeShape().JSONSchema())
	schema["properties"].(map[string]any)["nonClaims"] = nestedSchema(literalTupleShape(envelopeNonClaims()))
	schema["description"] = "Agent envelope (--agent-envelope, JSON only) for one admitted snapshot. Retained context refs are projected with their kind-derived role; one omission record counts omitted candidates. A next-action step appears only when no precondition blocks it; missing governing authority, a missing action subject and a missing verification witness each add one blocker and one clarification (admission already requires the action subject, so that pair is a defensive producer branch). The terminal snapshot carries one terminal step. Three fixed route questions cite retained IDs or the governing authority. The source report binds the plan's stable SHA-256 hash. Native Build and the envelope kernel own ordering, counts, fanout/stop-reason relations, sanitization and the output byte cap. Refused input emits stderr without JSON; there is no invalid-input envelope. Envelopes are derived guidance, not execution, approval or authority."
	return schema
}

func keysOf[V any](values map[string]V) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for key := range values {
		result[key] = struct{}{}
	}
	return result
}
