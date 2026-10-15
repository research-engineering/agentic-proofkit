package agentroute

import (
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// Structure owners project the route table and producer literals. Admission,
// routing and envelope construction remain native; nothing here evaluates input.

func routeIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, maxRouteIDRunes)
}

// routeDerivedIDShape binds an identity formed by appending a fixed grammar to
// the admitted route ID. A negative suffix bound leaves the total unbounded.
func routeDerivedIDShape(suffixPattern string, maxSuffixRunes int) jsonshape.Shape {
	body := `(?:` + admit.RuleIDPatternBody + `)` + suffixPattern
	if maxSuffixRunes < 0 {
		return jsonshape.StringGrammar(body)
	}
	return jsonshape.BoundedStringGrammar(body, maxRouteIDRunes+maxSuffixRunes)
}

func routeTextShape() jsonshape.Shape { return jsonshape.StringGrammar(`[\s\S]+`) }

func routeDigestShape() jsonshape.Shape { return jsonshape.StringGrammar(`sha256:[0-9a-f]{64}`) }

// Caller non-claims are preserved trimmed text; the rune bound is a schema
// refinement because jsonshape cannot bound a whitespace-aware grammar.
func callerClaimShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[^` + space + `](?:[\s\S]*[^` + space + `])?`
	})
}

func launcherProfiles() map[string]struct{} {
	return setOf(cliexec.ProfilePath, cliexec.ProfileNPMOffline, cliexec.ProfilePythonModule)
}

func setOf(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortedNames(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

// literalShape binds a producer-built constant JSON value exactly.
func literalShape(value any) jsonshape.Shape {
	switch typed := value.(type) {
	case string:
		return jsonshape.StringLiteral(typed)
	case bool:
		return jsonshape.BooleanLiteral(typed)
	case int:
		return jsonshape.IntegerLiteral(int64(typed))
	case []any:
		items := make([]jsonshape.Shape, len(typed))
		for index, item := range typed {
			items[index] = literalShape(item)
		}
		return jsonshape.Tuple(items...)
	case map[string]any:
		properties := make([]jsonshape.Property, 0, len(typed))
		for key, item := range typed {
			properties = append(properties, jsonshape.Required(key, literalShape(item)))
		}
		return jsonshape.Object(properties...)
	default:
		panic(fmt.Sprintf("agent route literal has unsupported type %T", value))
	}
}

// routeVocabulary is the value-set projection of the route table. It does not
// encode the goal-to-route relation, which remains native routing semantics.
type routeVocabulary struct {
	goals, families, sliceIDs, sliceSummaries, sliceNonClaims, escalations, stopConditions map[string]struct{}
	commands, commandSuffixes, browserCommands, otherCommands, browserWhys, otherWhys      map[string]struct{}
	omittedReasons, requiredLabels, kindReasons, anyReasons, bundleReasons                 map[string]struct{}
	escalationCount, stopConditionCount, sliceNonClaimCount                                [2]int
	maxNextCommands, maxRequiredInputs, maxAnyGroup, maxBundles, maxBundleSize             int
}

func countRange(current [2]int, count int, first bool) [2]int {
	if first {
		return [2]int{count, count}
	}
	return [2]int{min(current[0], count), max(current[1], count)}
}

func structuralRouteVocabulary() routeVocabulary {
	vocabulary := routeVocabulary{
		goals: map[string]struct{}{}, families: map[string]struct{}{}, sliceIDs: map[string]struct{}{}, sliceSummaries: map[string]struct{}{},
		sliceNonClaims: map[string]struct{}{}, escalations: map[string]struct{}{}, stopConditions: map[string]struct{}{},
		commands: map[string]struct{}{}, commandSuffixes: map[string]struct{}{}, browserCommands: map[string]struct{}{}, otherCommands: map[string]struct{}{},
		browserWhys: map[string]struct{}{}, otherWhys: map[string]struct{}{}, omittedReasons: map[string]struct{}{},
		requiredLabels: map[string]struct{}{}, kindReasons: map[string]struct{}{}, anyReasons: map[string]struct{}{}, bundleReasons: map[string]struct{}{},
	}
	first := true
	for _, goal := range sortedNames(keysOf(routeSpecs)) {
		spec := routeSpecs[goal]
		slice := guidanceSliceReport(goal, spec)
		vocabulary.goals[goal] = struct{}{}
		vocabulary.families[string(spec.RouteFamily)] = struct{}{}
		vocabulary.sliceIDs[slice["sliceId"].(string)] = struct{}{}
		vocabulary.sliceSummaries[spec.SliceSummary] = struct{}{}
		for _, values := range []struct {
			target map[string]struct{}
			items  []string
			count  *[2]int
		}{
			{vocabulary.sliceNonClaims, spec.SliceNonClaims, &vocabulary.sliceNonClaimCount},
			{vocabulary.escalations, spec.Escalations, &vocabulary.escalationCount},
			{vocabulary.stopConditions, spec.StopConditions, &vocabulary.stopConditionCount},
		} {
			for _, item := range values.items {
				values.target[item] = struct{}{}
			}
			*values.count = countRange(*values.count, len(values.items), first)
		}
		first = false
		vocabulary.maxNextCommands = max(vocabulary.maxNextCommands, len(spec.NextCommands))
		for _, command := range spec.NextCommands {
			vocabulary.commands[command.Command] = struct{}{}
			vocabulary.commandSuffixes[sanitizeRefID(command.Command)] = struct{}{}
			vocabulary.omittedReasons[omittedReason(command)] = struct{}{}
			if browserModeForCommand(command, routeInput{BrowserMode: "view_plan"}) != nil {
				vocabulary.browserCommands[command.Command] = struct{}{}
				vocabulary.browserWhys[command.Why] = struct{}{}
			} else {
				vocabulary.otherCommands[command.Command] = struct{}{}
				vocabulary.otherWhys[command.Why] = struct{}{}
			}
		}
		for _, changedPaths := range [][]string{nil, {"diagnostic"}} {
			missing := missingRequiredInputs(spec, routeInput{AvailableInputs: map[string]string{}, KnownChangedPaths: changedPaths})
			vocabulary.maxRequiredInputs = max(vocabulary.maxRequiredInputs, len(missing))
			for _, item := range missing {
				vocabulary.requiredLabels[requiredInputLabel(item)] = struct{}{}
				reason := item["reason"].(string)
				switch {
				case item["kind"] != nil:
					vocabulary.kindReasons[reason] = struct{}{}
				case item["oneOf"] != nil:
					vocabulary.anyReasons[reason] = struct{}{}
					vocabulary.maxAnyGroup = max(vocabulary.maxAnyGroup, len(item["oneOf"].([]any)))
				default:
					vocabulary.bundleReasons[reason] = struct{}{}
					bundles := item["oneOfBundles"].([]any)
					vocabulary.maxBundles = max(vocabulary.maxBundles, len(bundles))
					for _, bundle := range bundles {
						vocabulary.maxBundleSize = max(vocabulary.maxBundleSize, len(bundle.([]any)))
					}
				}
			}
		}
	}
	return vocabulary
}

func keysOf[V any](values map[string]V) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for key := range values {
		result[key] = struct{}{}
	}
	return result
}

// commandIdentityShape binds reportID + infix + sanitized command + "." + hash.
// The sanitized token keeps its own grammar; commandRef binds the command name.
func commandIdentityShape(infix string, vocabulary routeVocabulary) jsonshape.Shape {
	longest := 0
	for suffix := range vocabulary.commandSuffixes {
		longest = max(longest, utf8.RuneCountInString(suffix))
	}
	return routeDerivedIDShape(regexp.QuoteMeta(infix)+sanitizedRefPattern+`\.`+shortHashPattern,
		utf8.RuneCountInString(infix)+longest+1+len(shortTextHash("")))
}

// InputShape is the jsonshape core of InputStructure, before the caller-claim
// rune bound, duplicate-free lists and the openBrowser/browserMode relation.
func InputShape() jsonshape.Shape {
	text := jsonshape.NonBlankString()
	available := jsonshape.RequiredObject(availableInputKeys, map[string]jsonshape.Shape{"kind": jsonshape.Enum(inputKindValues), "ref": text})
	observed := jsonshape.RequiredObject(observedReportKeys, map[string]jsonshape.Shape{
		"kind": jsonshape.Enum(reportKindValues), "ref": text, "state": jsonshape.Enum(reportStateValues),
	})
	return jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		"availableInputs":   jsonshape.Nullable(jsonshape.BoundedArray(available, 0, len(inputKindValues))),
		"browserMode":       jsonshape.Nullable(jsonshape.Enum(browserModeValues)),
		"goal":              jsonshape.Enum(goalValues),
		"knownChangedPaths": jsonshape.Nullable(jsonshape.Array(routeTextShape(), 0)),
		"mode":              jsonshape.Enum(modeValues),
		"nonClaims":         jsonshape.Nullable(jsonshape.BoundedArray(callerClaimShape(), 0, maxCallerNonClaims)),
		"observedReports":   jsonshape.Nullable(jsonshape.Array(observed, 0)),
		"openBrowser":       jsonshape.Nullable(jsonshape.Boolean()),
		"routeId":           routeIDShape(),
		"schemaVersion":     jsonshape.IntegerLiteral(1),
	}, "availableInputs", "browserMode", "knownChangedPaths", "nonClaims", "observedReports", "openBrowser")
}

func nullableBranch(schema map[string]any, field string) map[string]any {
	return schema["properties"].(map[string]any)[field].(map[string]any)["anyOf"].([]any)[1].(map[string]any)
}

// InputStructure describes every root native agent-route admission accepts.
func InputStructure() map[string]any {
	schema := InputShape().JSONSchema()
	claims := nullableBranch(schema, "nonClaims")
	claims["uniqueItems"] = true
	claims["items"].(map[string]any)["maxLength"] = maxCallerNonClaimTextRunes
	nullableBranch(schema, "knownChangedPaths")["uniqueItems"] = true
	schema["if"] = map[string]any{"required": []any{"openBrowser"}, "properties": map[string]any{"openBrowser": map[string]any{"const": true}}}
	schema["then"] = map[string]any{"required": []any{"browserMode"}, "properties": map[string]any{"browserMode": map[string]any{"const": "serve_local_view"}}}
	schema["description"] = fmt.Sprintf("schemaVersion, routeId, goal and mode are required; every other member may be absent or null, which native admission treats as its default (empty lists, browserMode view_plan, openBrowser false). openBrowser true requires browserMode serve_local_view. Available inputs are at most one per kind; refs are nonblank text that native admission trims. Caller nonClaims are at most %d distinct preserved-trimmed texts of at most %d code points; knownChangedPaths are distinct. Native admission additionally owns RuleID secret/timestamp exclusions, unique input kinds and unique observed-report refs, sorted order of nonClaims and knownChangedPaths, canonical safe repository-relative paths (the stdin sentinel is refused; '.' is admitted only for repo-root input kinds), and secret-shaped text refusal. Refused input emits stderr, or the invalid-input repair envelope under --agent-envelope. Admission reads no referenced file.", maxCallerNonClaims, maxCallerNonClaimTextRunes)
	return schema
}

// BriefShape is the exact structural core of the bounded brief packet.
func BriefShape() jsonshape.Shape {
	vocabulary := structuralRouteVocabulary()
	pointer := func(field string, positive bool) jsonshape.Shape {
		index := `(?:0|[1-9][0-9]*)`
		if positive {
			index = `[1-9][0-9]*`
		}
		return jsonshape.StringGrammar(regexp.QuoteMeta(field) + index)
	}
	blocked := map[string]struct{}{}
	for state := range reportStateValues {
		if state != "passed" {
			blocked[state] = struct{}{}
		}
	}
	blockers := jsonshape.DiscriminatedUnion("kind",
		jsonshape.Object(
			jsonshape.Required("blockerId", routeDerivedIDShape(regexp.QuoteMeta(briefUnknownGoalBlockerSuffix), utf8.RuneCountInString(briefUnknownGoalBlockerSuffix))),
			jsonshape.Required("kind", jsonshape.StringLiteral(briefBlockerUnknownGoal)),
		),
		jsonshape.Object(
			jsonshape.Required("blockerId", routeDerivedIDShape(regexp.QuoteMeta(briefRequiredInputBlockerInfix)+`[0-9]{2,}`, -1)),
			jsonshape.Required("kind", jsonshape.StringLiteral(briefBlockerMissingInput)),
			jsonshape.Required("sourceReportPointer", pointer("/requiredInputs/", false)),
			jsonshape.Required("subject", jsonshape.Enum(vocabulary.requiredLabels)),
		),
		jsonshape.Object(
			jsonshape.Required("blockerId", routeDerivedIDShape(regexp.QuoteMeta(briefObservedReportBlockerInfix)+`[0-9]{2,}`, -1)),
			jsonshape.Required("kind", jsonshape.StringLiteral(briefBlockerObservedReport)),
			jsonshape.Required("sourceReportPointer", pointer("/observedReports/", false)),
			jsonshape.Required("state", jsonshape.Enum(blocked)),
			jsonshape.Required("subject", jsonshape.Enum(reportKindValues)),
		),
	)
	roles := map[string]struct{}{}
	for _, role := range briefOperandRoles {
		roles[role] = struct{}{}
	}
	identity := []jsonshape.Property{
		jsonshape.Required("actionId", commandIdentityShape(actionIDInfix, vocabulary)),
		jsonshape.Required("commandId", commandIdentityShape(commandIDInfix, vocabulary)),
		jsonshape.Required("commandRef", jsonshape.Enum(vocabulary.commands)),
		jsonshape.Required("owner", jsonshape.StringLiteral(consumerOwner)),
	}
	inline := append(slices.Clone(identity), jsonshape.Required("argv", jsonshape.Array(routeTextShape(), 1)),
		jsonshape.Required("argvState", jsonshape.StringLiteral(argvStateInline)))
	deferred := append(slices.Clone(identity), jsonshape.Required("argvState", jsonshape.StringLiteral(argvStateDetailRequired)))
	omission := briefOmissionSummary(map[string]any{}, 0, 0)
	return jsonshape.Object(
		jsonshape.Required("blockers", jsonshape.BoundedArray(blockers, 0, maxBriefBlockerItems)),
		jsonshape.Required("boundaryPolicyRefs", literalShape(briefBoundaryPolicyRefs())),
		jsonshape.Required("contextRefs", jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("refId", routeDerivedIDShape(regexp.QuoteMeta(inputRefIDInfix)+shortHashPattern, utf8.RuneCountInString(inputRefIDInfix)+len(shortTextHash("")))),
			jsonshape.Required("role", jsonshape.Enum(roles)),
			jsonshape.Required("sourceReportPointer", pointer("/nextCommands/0/argv/", true)),
		), 0, len(briefOperandRoles))),
		jsonshape.Required("detailAccess", jsonshape.Object(
			jsonshape.Required("commandRef", jsonshape.StringLiteral(briefCommandRef)),
			jsonshape.Required("launcherProfile", jsonshape.Enum(launcherProfiles())),
			jsonshape.Required("outputArgs", literalShape(briefDetailOutputArgs())),
			jsonshape.Required("requiresOriginalInput", jsonshape.BooleanLiteral(true)),
			jsonshape.Required("requiresOriginalLauncherContext", jsonshape.BooleanLiteral(true)),
			jsonshape.Required("sourceReportDigest", routeDigestShape()),
			jsonshape.Required("sourceReportId", routeIDShape()),
		)),
		jsonshape.Required("nextAction", jsonshape.Nullable(jsonshape.DiscriminatedUnion("argvState",
			jsonshape.Object(inline...), jsonshape.Object(deferred...)))),
		jsonshape.Required("omissionSummary", jsonshape.Object(
			jsonshape.Required("availableAlternativeCommandCount", jsonshape.IntegerRange(0, int64(vocabulary.maxNextCommands))),
			jsonshape.Required("detailClasses", literalShape(omission["detailClasses"])),
			jsonshape.Required("omittedBlockerCount", jsonshape.IntegerMinimum(0)),
			jsonshape.Required("sourceOmittedCommandCount", jsonshape.IntegerRange(0, int64(vocabulary.maxNextCommands))),
		)),
		jsonshape.Required("packetId", routeDerivedIDShape(regexp.QuoteMeta(briefPacketIDSuffix), utf8.RuneCountInString(briefPacketIDSuffix))),
		jsonshape.Required("packetKind", jsonshape.StringLiteral(briefPacketKind)),
		jsonshape.Required("routeFamily", jsonshape.Enum(setOf(admit.AnySliceToString(routeFamilyContractValues())...))),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(briefSchemaVersion)),
		jsonshape.Required("state", jsonshape.Enum(setOf(stateRouted, stateBlockedMissingInput, stateBlockedAmbiguousState, stateBlockedUnknownGoal))),
	)
}

func BriefStructure() map[string]any {
	schema := BriefShape().JSONSchema()
	schema["description"] = fmt.Sprintf("Default --agent-envelope packet (or --agent-envelope-mode brief) for admitted route input. nextAction is null for blocked states; otherwise it is the first available command with inline argv, or argvState detail_required without argv when the canonical packet would exceed %d bytes. At most %d blockers are retained and the remainder is counted. Native projection owns state/action/blocker/context correspondence, blocker ordering, exact omission counts, the source report digest over the exact route report, the packet byte bound and launcher identity. If the packet cannot be bounded the command emits the invalid-input repair envelope. The brief is derived route guidance, not execution, proof, merge, release or readiness authority.", maxAgentBriefBytes, maxBriefBlockerItems)
	return schema
}

// FullEnvelopeShape is the core of FullEnvelopeStructure; the published
// envelopeId admits the redaction marker because the suffix can make an
// admitted route ID secret-shaped after construction.
func FullEnvelopeShape() jsonshape.Shape {
	vocabulary := structuralRouteVocabulary()
	text := routeTextShape()
	authority := guidanceSliceReport("", routeSpec{})["authorityRefs"].([]any)
	roles := setOf(guidanceSliceRole, callerOwnedInputRole)
	for _, raw := range authority {
		roles[raw.(map[string]any)["role"].(string)] = struct{}{}
	}
	questions := routeQuestions("route")
	alternatives := make([]jsonshape.Shape, len(questions))
	for index, question := range questions {
		alternatives[index] = jsonshape.Object(
			jsonshape.Required("evidenceRefs", jsonshape.BoundedArray(text, 0, len(question["evidenceRefs"].([]any)))),
			jsonshape.Required("nonClaim", jsonshape.StringLiteral(question["nonClaim"].(string))),
			jsonshape.Required("question", jsonshape.StringLiteral(question["question"].(string))),
			jsonshape.Required("questionId", text),
		)
	}
	commandShape := jsonshape.Object(
		jsonshape.Required("argv", jsonshape.Array(text, 1)),
		jsonshape.Required("commandId", commandIdentityShape(commandIDInfix, vocabulary)),
		jsonshape.Required("display", text), jsonshape.Required("nonClaim", jsonshape.StringLiteral(commandRefNonClaim)),
		jsonshape.Required("owner", jsonshape.StringLiteral(consumerOwner)), jsonshape.Required("proofkitRoute", jsonshape.Enum(vocabulary.commands)),
	)
	omission := func(reasons map[string]struct{}, subject jsonshape.Shape) jsonshape.Shape {
		return jsonshape.Object(
			jsonshape.Required("escalation", jsonshape.StringLiteral(omittedCommandEscalation)), jsonshape.Required("omissionId", text),
			jsonshape.Required("omittedCount", jsonshape.IntegerLiteral(1)), jsonshape.Required("reason", jsonshape.Enum(reasons)),
			jsonshape.Required("subject", subject),
		)
	}
	// The unknown-goal report omits a route, not a command, so its projected
	// omission names no command subject.
	unknownReasons := map[string]struct{}{}
	for _, raw := range unknownGoalTemplate()["omitted"].([]any) {
		unknownReasons[raw.(map[string]any)["reason"].(string)] = struct{}{}
	}
	return agentenvelope.Structure("placeholder", agentenvelope.StructureParts{
		ActionPlan:             jsonshape.BoundedArray(agentenvelope.ActionStructure(jsonshape.StringLiteral(routeActionPhase)), 0, vocabulary.maxRequiredInputs+vocabulary.maxNextCommands),
		BlockedPreconditions:   jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, agentenvelope.MaxBlockedPreconditions),
		Bounds:                 agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.StringLiteral(clarificationAnswerKind)), 0, vocabulary.maxRequiredInputs),
		Commands:               jsonshape.BoundedArray(commandShape, 0, vocabulary.maxNextCommands),
		ContextRefs: jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("description", text), jsonshape.Required("path", text),
			jsonshape.Required("refId", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
			jsonshape.Required("role", jsonshape.Enum(roles)), jsonshape.Required("selector", text),
		), 0, 1+len(authority)+vocabulary.maxNextCommands),
		Omitted: jsonshape.BoundedArray(jsonshape.OneOf(omission(vocabulary.omittedReasons, jsonshape.Enum(vocabulary.commands)),
			omission(unknownReasons, jsonshape.StringLiteral("")), agentenvelope.OmissionStructure()), 0, vocabulary.maxNextCommands),
		ReceiptRefs:    jsonshape.Tuple(),
		RouteQuestions: jsonshape.BoundedArray(jsonshape.DiscriminatedUnion("question", alternatives...), len(questions), len(questions)),
		SourceReport:   agentenvelope.SourceReportStructure(reportKind, routeIDShape(), jsonshape.Null(), jsonshape.Enum(setOf("passed", "failed"))),
	})
}

// FullEnvelopeIDShape is the envelopeId member of FullEnvelopeStructure.
func FullEnvelopeIDShape() jsonshape.Shape {
	const suffix = ".agent-envelope"
	return jsonshape.OneOf(
		routeDerivedIDShape(regexp.QuoteMeta(suffix), utf8.RuneCountInString(suffix)),
		jsonshape.StringLiteral(admit.DiagnosticRedactionMarker),
	)
}

func FullEnvelopeStructure() map[string]any {
	schema := FullEnvelopeShape().JSONSchema()
	id := FullEnvelopeIDShape().JSONSchema()
	delete(id, "$schema")
	schema["properties"].(map[string]any)["envelopeId"] = id
	schema["description"] = "Explicit --agent-envelope-mode full projection of the admitted route report through the generic envelope kernel. Required-input actions precede selected-command actions; non-passed observed reports and missing inputs become blockers; omitted commands become omission records (for goal unknown, one record with an empty subject names the unrouted goal); three fixed route questions cite the report. The kernel sanitizes every string (unsafe or secret-shaped text becomes a redaction marker and long text is truncated), drops local targets whose identity is not a lossless RuleID, and may add typed truncation or identity omissions. The source report carries passed only for routed state. Native routing and the kernel own counts, ordering, reference closure, fanout and stop reasons. Refused input uses the invalid-input repair envelope."
	return schema
}

func summaryShape(goal, availableCommands jsonshape.Shape) jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("availableCommandCount", availableCommands),
		jsonshape.Required("availableInputCount", jsonshape.IntegerRange(0, int64(len(inputKindValues)))),
		jsonshape.Required("browserMode", jsonshape.Enum(browserModeValues)),
		jsonshape.Required("callerNonClaimCount", jsonshape.IntegerRange(0, maxCallerNonClaims)),
		jsonshape.Required("goal", goal),
		jsonshape.Required("knownChangedPaths", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("launcherProfile", jsonshape.Enum(launcherProfiles())),
		jsonshape.Required("mode", jsonshape.Enum(modeValues)),
		jsonshape.Required("observedReportCount", jsonshape.IntegerMinimum(0)),
		jsonshape.Required("openBrowser", jsonshape.Boolean()),
	)
}

func reportCommonFields() map[string]jsonshape.Shape {
	return map[string]jsonshape.Shape{
		"callerNonClaims": jsonshape.BoundedArray(callerClaimShape(), 0, maxCallerNonClaims),
		"nonClaims":       jsonshape.BoundedArray(routeTextShape(), len(nonClaims), len(nonClaims)+maxCallerNonClaims),
		"observedReports": jsonshape.Array(jsonshape.Object(
			jsonshape.Required("kind", jsonshape.Enum(reportKindValues)), jsonshape.Required("ref", routeTextShape()),
			jsonshape.Required("state", jsonshape.Enum(reportStateValues)),
		), 0),
		"reportId":      routeIDShape(),
		"reportKind":    jsonshape.StringLiteral(reportKind),
		"schemaVersion": jsonshape.IntegerLiteral(reportSchemaVersion),
	}
}

func objectShape(fields map[string]jsonshape.Shape) jsonshape.Shape {
	properties := make([]jsonshape.Property, 0, len(fields))
	for _, key := range sortedNames(keysOf(fields)) {
		properties = append(properties, jsonshape.Required(key, fields[key]))
	}
	return jsonshape.Object(properties...)
}

// RoutedReportShape covers every known goal: routed and both blocked states.
func RoutedReportShape() jsonshape.Shape {
	vocabulary := structuralRouteVocabulary()
	text := routeTextShape()
	knownStates := setOf(stateRouted, stateBlockedMissingInput, stateBlockedAmbiguousState)
	diagnostic := func(key string, value jsonshape.Shape) jsonshape.Shape {
		return jsonshape.Object(jsonshape.Required("key", jsonshape.StringLiteral(key)), jsonshape.Required("value", value))
	}
	base := []jsonshape.Shape{
		diagnostic("goal", jsonshape.Enum(vocabulary.goals)), diagnostic("mode", jsonshape.Enum(modeValues)),
		diagnostic("state", jsonshape.Enum(knownStates)),
	}
	missing := diagnostic("missingRequiredInputCount", jsonshape.IntegerRange(1, int64(vocabulary.maxRequiredInputs)))
	blocking := diagnostic("blockingObservedReportCount", jsonshape.IntegerMinimum(1))
	diagnostics := jsonshape.OneOf(
		jsonshape.Tuple(base...), jsonshape.Tuple(append(slices.Clone(base), missing)...),
		jsonshape.Tuple(append(slices.Clone(base), blocking)...), jsonshape.Tuple(append(slices.Clone(base), missing, blocking)...),
	)
	slice := guidanceSliceReport("", routeSpec{})
	command := jsonshape.OneOf(
		jsonshape.Object(
			jsonshape.Required("argv", jsonshape.Array(text, 1)), jsonshape.Required("browserMode", jsonshape.Enum(browserModeValues)),
			jsonshape.Required("command", jsonshape.Enum(vocabulary.browserCommands)), jsonshape.Required("why", jsonshape.Enum(vocabulary.browserWhys)),
		),
		jsonshape.Object(
			jsonshape.Required("argv", jsonshape.Array(text, 1)),
			jsonshape.Required("command", jsonshape.Enum(vocabulary.otherCommands)), jsonshape.Required("why", jsonshape.Enum(vocabulary.otherWhys)),
		),
	)
	kinds := jsonshape.Enum(inputKindValues)
	required := jsonshape.OneOf(
		jsonshape.Object(jsonshape.Required("kind", kinds), jsonshape.Required("reason", jsonshape.Enum(vocabulary.kindReasons))),
		jsonshape.Object(jsonshape.Required("oneOf", jsonshape.BoundedArray(kinds, 2, vocabulary.maxAnyGroup)), jsonshape.Required("reason", jsonshape.Enum(vocabulary.anyReasons))),
		jsonshape.Object(jsonshape.Required("oneOfBundles", jsonshape.BoundedArray(jsonshape.BoundedArray(kinds, 1, vocabulary.maxBundleSize), 1, vocabulary.maxBundles)),
			jsonshape.Required("reason", jsonshape.Enum(vocabulary.bundleReasons))),
	)
	fields := reportCommonFields()
	fields["diagnostics"] = diagnostics
	fields["escalations"] = jsonshape.BoundedArray(jsonshape.Enum(vocabulary.escalations), vocabulary.escalationCount[0], vocabulary.escalationCount[1])
	fields["guidanceSlice"] = jsonshape.Object(
		jsonshape.Required("authorityRefs", literalShape(slice["authorityRefs"])),
		jsonshape.Required("lookupOnly", literalShape(slice["lookupOnly"])),
		jsonshape.Required("nonClaims", jsonshape.BoundedArray(jsonshape.Enum(vocabulary.sliceNonClaims), vocabulary.sliceNonClaimCount[0], vocabulary.sliceNonClaimCount[1])),
		jsonshape.Required("routeFamily", jsonshape.Enum(vocabulary.families)),
		jsonshape.Required("sliceId", jsonshape.Enum(vocabulary.sliceIDs)),
		jsonshape.Required("sliceSummary", jsonshape.Enum(vocabulary.sliceSummaries)),
		jsonshape.Required("sourceAuthority", literalShape(slice["sourceAuthority"])),
	)
	fields["nextCommands"] = jsonshape.BoundedArray(command, 0, vocabulary.maxNextCommands)
	fields["omitted"] = jsonshape.BoundedArray(jsonshape.Object(
		jsonshape.Required("command", jsonshape.Enum(vocabulary.commands)), jsonshape.Required("missingInputKind", kinds),
		jsonshape.Required("reason", jsonshape.Enum(vocabulary.omittedReasons)), jsonshape.Required("safePlaceholderUse", jsonshape.BooleanLiteral(false)),
	), 0, vocabulary.maxNextCommands)
	fields["requiredInputs"] = jsonshape.BoundedArray(required, 0, vocabulary.maxRequiredInputs)
	fields["selectedRouteFamily"] = jsonshape.Enum(vocabulary.families)
	fields["state"] = jsonshape.Enum(knownStates)
	fields["stopConditions"] = jsonshape.BoundedArray(jsonshape.Enum(vocabulary.stopConditions), vocabulary.stopConditionCount[0], vocabulary.stopConditionCount[1])
	fields["summary"] = summaryShape(jsonshape.Enum(vocabulary.goals), jsonshape.IntegerRange(0, int64(vocabulary.maxNextCommands)))
	return objectShape(fields)
}

// unknownGoalTemplate obtains the constant unknown-goal members from the
// native producer; caller-derived members are replaced by their shapes.
func unknownGoalTemplate() map[string]any {
	return buildUnknownGoal(routeInput{Goal: "unknown", Mode: "observe", BrowserMode: "view_plan", AvailableInputs: map[string]string{}}, cliexec.PathRenderer())
}

func UnknownGoalReportShape() jsonshape.Shape {
	template := unknownGoalTemplate()
	fields := reportCommonFields()
	for _, key := range []string{"diagnostics", "escalations", "guidanceSlice", "nextCommands", "omitted", "requiredInputs", "selectedRouteFamily", "state", "stopConditions"} {
		fields[key] = literalShape(template[key])
	}
	summary := template["summary"].(map[string]any)
	fields["summary"] = summaryShape(literalShape(summary["goal"]), literalShape(summary["availableCommandCount"]))
	return objectShape(fields)
}

func refineReportStructure(schema map[string]any) map[string]any {
	properties := schema["properties"].(map[string]any)
	callerClaims := properties["callerNonClaims"].(map[string]any)
	callerClaims["uniqueItems"] = true
	callerClaims["items"].(map[string]any)["maxLength"] = maxCallerNonClaimTextRunes
	merged := properties["nonClaims"].(map[string]any)
	merged["uniqueItems"] = true
	contains := make([]any, 0, len(nonClaims))
	for _, claim := range nonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	merged["allOf"] = contains
	return schema
}

const reportDescription = " nonClaims is the sorted union of the builtin route claims and the caller claims. Native routing owns the goal-to-route relation, command availability, argv rendering for the admitted launcher, report ordering, the state/exit relation and the count correspondences. Refused input emits stderr without JSON. A route report is command-selection evidence only, not execution, proof, merge, release or readiness authority."

func RoutedReportStructure() map[string]any {
	schema := refineReportStructure(RoutedReportShape().JSONSchema())
	schema["description"] = "Route report without --agent-envelope for a known goal: routed (exit 0) or blocked by missing input or a non-passed observed report (exit 1, with no next commands). Each next command carries its exact argv; requirement-browser-server commands also carry the admitted browserMode. Diagnostics hold goal, mode and state, then the missing-input count and blocking-report count when nonzero." + reportDescription
	return schema
}

func UnknownGoalReportStructure() map[string]any {
	schema := refineReportStructure(UnknownGoalReportShape().JSONSchema())
	schema["description"] = "Route report without --agent-envelope for goal unknown: the fixed blocked_unknown_goal projection with no next commands (exit 1)." + reportDescription
	return schema
}
