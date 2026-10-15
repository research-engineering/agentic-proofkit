package capabilitymapadmission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func TestCapabilityOutputsSelectExactlyTheirModeStateBranch(t *testing.T) {
	cases := []struct {
		name, mode string
		passed     bool
		mutate     func(map[string]any)
	}{
		{"baseline", TrustModeCodeBaseline, true, nil},
		{"audit", TrustModeAuditFromCode, true, nil},
		{"baseline-missing-candidate-and-anchor", TrustModeCodeBaseline, false, func(input map[string]any) {
			delete(firstScenarioShape(input), "candidateRequirementId")
			input["scenarioAnchors"] = []any{}
		}},
		{"audit-missing-anchor-action", TrustModeAuditFromCode, true, func(input map[string]any) { input["scenarioAnchors"] = nil }},
		{"audit-undeclared-scenario", TrustModeAuditFromCode, false, func(input map[string]any) {
			firstScenarioAnchor(input)["scenarioId"] = "sample.backend.auth.other"
		}},
		{"audit-unresolved-command", TrustModeAuditFromCode, false, func(input map[string]any) { input["requiredVerification"] = nil }},
		{"baseline-both-witness-kinds", TrustModeCodeBaseline, true, func(input map[string]any) {
			firstScenarioShape(input)["requiredEvidence"] = []any{"negative_test", "positive_test"}
			firstScenarioAnchor(input)["positiveWitness"] = true
		}},
		{"baseline-positive-only", TrustModeCodeBaseline, true, func(input map[string]any) {
			firstScenarioShape(input)["requiredEvidence"] = []any{"positive_test"}
			firstScenarioAnchor(input)["positiveWitness"], firstScenarioAnchor(input)["falsificationWitness"] = true, nil
		}},
		{"baseline-non-executable", TrustModeCodeBaseline, false, func(input map[string]any) { firstScenarioAnchor(input)["commandRefs"] = []any{} }},
		{"audit-minimal", TrustModeAuditFromCode, true, func(input map[string]any) {
			for _, key := range []string{"nonClaims", "requiredVerification", "scenarioAnchors"} {
				delete(input, key)
			}
			input["repository"] = map[string]any{"repositoryId": "sample_repo"}
			input["proofScope"] = map[string]any{"scopeId": "sample.scope", "dirtyState": "unknown"}
			capability := firstCapability(input)
			delete(capability, "nonClaims")
			delete(capability, "riskClasses")
			firstCapability(input)["scenarioShapes"] = []any{map[string]any{"scenarioId": "sample.scenario", "summary": " Padded summary. "}}
		}},
		{"baseline-retired-anchor", TrustModeCodeBaseline, false, func(input map[string]any) { firstScenarioAnchor(input)["status"] = "retired" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := validCapabilityMapInput(test.mode)
			if test.mutate != nil {
				test.mutate(input)
			}
			record, code, err := Build(input)
			if err != nil || (code == 0) != test.passed {
				t.Fatalf("native phase changed: code=%d err=%v", code, err)
			}
			value := capabilityWireValue(t, record.JSONValue())
			if err := OutputShape().CheckGenerated(value, "report"); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{TrustModeAuditFromCode, TrustModeCodeBaseline} {
				for _, passed := range []bool{true, false} {
					matched := reportShape(mode, passed).CheckGenerated(value, "branch") == nil
					if matched != (mode == test.mode && passed == test.passed) {
						t.Fatalf("branch %s/%t selection=%t", mode, passed, matched)
					}
				}
			}
			assertCapabilityReportCarrier(t, value)
		})
	}
}

func TestCapabilityOutputBranchesRejectCrossModeAndStateDrift(t *testing.T) {
	record, _, err := Build(validCapabilityMapInput(TrustModeCodeBaseline))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"summary-mode":  func(value map[string]any) { value["summary"].(map[string]any)["trustMode"] = TrustModeAuditFromCode },
		"failure-count": func(value map[string]any) { value["summary"].(map[string]any)["failureCount"] = json.Number("1") },
		"state":         func(value map[string]any) { value["state"] = "failed" },
		"promotion": func(value map[string]any) {
			seedAt(value, 3)["promotionState"] = promotionState(TrustModeAuditFromCode)
		},
		"authority": func(value map[string]any) {
			seedAt(value, 4)["evidenceAuthority"] = evidenceAuthority(TrustModeAuditFromCode)
		},
		"witness-order":  func(value map[string]any) { seedAt(value, 4)["witnessKinds"] = []any{"falsification", "positive"} },
		"empty-commands": func(value map[string]any) { seedAt(value, 4)["commandRefs"] = []any{} },
		"instructions": func(value map[string]any) {
			diagnosticValue(value, 2).([]any)[0] = "Treat code observations as untrusted hypotheses."
		},
		"rule-message": func(value map[string]any) {
			value["ruleResults"].([]any)[1].(map[string]any)["message"] = modeRuleMessage(TrustModeAuditFromCode, nil)
		},
		"padded-path":   func(value map[string]any) { seedAt(value, 4)["sourcePath"] = " service/tests/auth_test.py" },
		"extra-summary": func(value map[string]any) { value["summary"].(map[string]any)["foreign"] = json.Number("0") },
	} {
		t.Run(name, func(t *testing.T) {
			value := capabilityWireValue(t, record.JSONValue())
			if err := OutputShape().CheckGenerated(value, "report"); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			if OutputShape().CheckGenerated(value, "report") == nil {
				t.Fatal("drifted report admitted")
			}
		})
	}
}

func TestCapabilityInputShapeAgreesWithNativeAdmission(t *testing.T) {
	for _, test := range capabilityInputCorpus() {
		t.Run(test.name, func(t *testing.T) {
			input := validCapabilityMapInput(TrustModeAuditFromCode)
			test.mutate(input)
			_, _, nativeErr := Build(input)
			_, shapeErr := InputShape().Admit(input, "input")
			if shapeErr == nil {
				shapeErr = selectorBoundsError(input)
			}
			switch test.class {
			case "accept":
				if nativeErr != nil || shapeErr != nil {
					t.Fatalf("admitted input diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			case "structural":
				if nativeErr == nil || shapeErr == nil {
					t.Fatalf("structural refusal diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			case "native":
				if nativeErr == nil || shapeErr != nil {
					t.Fatalf("native-only refusal changed owner: native=%v shape=%v", nativeErr, shapeErr)
				}
			default:
				t.Fatal("unknown corpus class")
			}
		})
	}
}

type capabilityInputCase struct {
	name, class string
	mutate      func(map[string]any)
}

func capabilityInputCorpus() []capabilityInputCase {
	set := func(path string, value any) func(map[string]any) {
		return func(input map[string]any) { setCapabilityPath(input, path, value) }
	}
	remove := func(path string) func(map[string]any) {
		return func(input map[string]any) { deleteCapabilityPath(input, path) }
	}
	runes := func(count int) string { return strings.Repeat("\u00e9", count) }
	ids := func(count int) []any {
		values := make([]any, count)
		for i := range values {
			values[i] = fmt.Sprintf("id_%03d", i)
		}
		return values
	}
	texts := func(count int) []any {
		values := make([]any, count)
		for i := range values {
			values[i] = fmt.Sprintf("Claim %03d.", i)
		}
		return values
	}
	cases := []capabilityInputCase{
		{"fixture", "accept", func(map[string]any) {}},
		{"baseline-mode", "accept", set("trustMode", TrustModeCodeBaseline)},
		{"padded-summary", "accept", set("capabilities.0.summary", "\u3000\t"+runes(maxSummaryRunes)+" \u0085")},
		{"padded-reason", "accept", set("requiredVerification.0.reason", " "+runes(maxSummaryRunes)+"\n")},
		{"padded-command", "accept", set("requiredVerification.0.command", "\t"+strings.Repeat("c", maxCommandRunes)+" ")},
		{"bounded-claims", "accept", set("nonClaims", append(texts(maxNonClaims-1), runes(maxNonClaimRunes)))},
		{"bounded-questions", "accept", set("capabilities.0.scenarioShapes.0.ownerQuestions", append(texts(maxQuestionsPerScenario-1), runes(maxQuestionRunes)))},
		{"bounded-ids", "accept", set("repository.primaryLanguages", ids(maxTextItems))},
		{"boundary-map-id", "accept", set("mapId", "m"+strings.Repeat("a", admit.MaxRuleIDBytes-1))},
		{"padded-selector", "accept", func(input map[string]any) {
			setCapabilityPath(input, "scenarioAnchors.0.selector", " \u3000service/tests/auth_test.py::"+strings.Repeat("a", admit.MaxRuleIDBytes)+"\n")
			setCapabilityPath(input, "scenarioAnchors.0.sourcePath", "\tservice/tests/auth_test.py ")
		}},
		{"colon-path-selector", "accept", func(input map[string]any) {
			setCapabilityPath(input, "scenarioAnchors.0.selector", "x/a:b/:c::anchor:part")
			setCapabilityPath(input, "scenarioAnchors.0.sourcePath", "x/a:b/:c")
		}},
		{"null-optionals", "accept", func(input map[string]any) {
			for _, path := range []string{"nonClaims", "requiredVerification", "scenarioAnchors", "repository.nonClaims", "repository.primaryLanguages",
				"proofScope.baseRef", "proofScope.headRef", "proofScope.nonClaims", "capabilities.0.nonClaims", "capabilities.0.riskClasses",
				"capabilities.0.scenarioShapes.0.candidateRequirementId", "capabilities.0.scenarioShapes.0.nonClaims",
				"capabilities.0.scenarioShapes.0.ownerQuestions", "capabilities.0.scenarioShapes.0.requiredEvidence"} {
				setCapabilityPath(input, path, nil)
			}
		}},
		{"null-anchor-optionals", "accept", func(input map[string]any) {
			for _, key := range []string{"commandRefs", "falsificationWitness", "nonClaims", "positiveWitness"} {
				setCapabilityPath(input, "scenarioAnchors.0."+key, nil)
			}
			setCapabilityPath(input, "requiredVerification.0.nonClaims", nil)
		}},
		{"absent-optionals", "accept", func(input map[string]any) {
			for _, path := range []string{"nonClaims", "requiredVerification", "scenarioAnchors", "repository.nonClaims", "proofScope.baseRef", "capabilities.0.riskClasses"} {
				deleteCapabilityPath(input, path)
			}
		}},
		{"maximum-capabilities", "accept", func(input map[string]any) {
			first := firstCapability(input)
			capabilities := make([]any, maxCapabilities)
			for i := range capabilities {
				copy := cloneCapabilityJSON(first).(map[string]any)
				copy["capabilityId"] = fmt.Sprintf("sample.capability_%02d", i)
				capabilities[i] = copy
			}
			input["capabilities"] = capabilities
		}},
		{"maximum-scenarios", "accept", func(input map[string]any) {
			shapes := make([]any, maxScenarioShapesPerCapability)
			for i := range shapes {
				shapes[i] = map[string]any{"scenarioId": fmt.Sprintf("sample.scenario_%02d", i), "summary": "Scenario."}
			}
			firstCapability(input)["scenarioShapes"] = shapes
		}},
		{"maximum-anchors", "accept", func(input map[string]any) { input["scenarioAnchors"] = anchors(maxScenarioAnchors) }},
		{"maximum-verification", "accept", func(input map[string]any) {
			input["requiredVerification"] = verificationCommands(maxRequiredVerificationCommands)
		}},
		{"all-evidence", "accept", set("capabilities.0.scenarioShapes.0.requiredEvidence", []any{"negative_test", "positive_test"})},
	}
	for _, key := range []string{"authority", "capabilities", "mapId", "proofScope", "repository", "schemaVersion", "trustMode"} {
		cases = append(cases, capabilityInputCase{"missing-" + key, "structural", remove(key)})
	}
	for _, path := range []string{"repository.repositoryId", "proofScope.scopeId", "proofScope.dirtyState", "capabilities.0.capabilityId",
		"capabilities.0.ownerId", "capabilities.0.summary", "capabilities.0.sourcePaths", "capabilities.0.scenarioShapes",
		"capabilities.0.scenarioShapes.0.scenarioId", "capabilities.0.scenarioShapes.0.summary", "scenarioAnchors.0.scenarioId",
		"scenarioAnchors.0.selector", "scenarioAnchors.0.sourcePath", "scenarioAnchors.0.status", "requiredVerification.0.command",
		"requiredVerification.0.commandId", "requiredVerification.0.environmentClass", "requiredVerification.0.reason"} {
		cases = append(cases, capabilityInputCase{"missing-" + path, "structural", remove(path)})
	}
	for _, path := range []string{"", "repository", "proofScope", "capabilities.0", "capabilities.0.scenarioShapes.0", "scenarioAnchors.0", "requiredVerification.0"} {
		target := "foreign"
		if path != "" {
			target = path + ".foreign"
		}
		cases = append(cases, capabilityInputCase{"unknown-" + path, "structural", set(target, true)})
	}
	for _, test := range []struct {
		path  string
		value any
	}{
		{"schemaVersion", json.Number("2")}, {"schemaVersion", json.Number("1.0")}, {"schemaVersion", "1"},
		{"authority", "caller_owned"}, {"trustMode", "trust_me"}, {"proofScope.dirtyState", "dirty"},
		{"scenarioAnchors.0.status", "active"}, {"capabilities.0.scenarioShapes.0.requiredEvidence", []any{"mutation_test"}},
		{"capabilities", []any{}}, {"capabilities.0.scenarioShapes", []any{}}, {"capabilities.0.sourcePaths", []any{}},
		{"capabilities.0.sourcePaths", []any{""}}, {"capabilities.0.summary", " \t\u3000"}, {"capabilities.0.summary", runes(maxSummaryRunes + 1)},
		{"requiredVerification.0.reason", runes(maxSummaryRunes + 1)}, {"requiredVerification.0.command", strings.Repeat("c", maxCommandRunes+1)},
		{"nonClaims", texts(maxNonClaims + 1)}, {"nonClaims", []any{runes(maxNonClaimRunes + 1)}}, {"nonClaims", []any{" padded claim"}},
		{"nonClaims", []any{""}}, {"capabilities.0.scenarioShapes.0.ownerQuestions", texts(maxQuestionsPerScenario + 1)},
		{"capabilities.0.scenarioShapes.0.ownerQuestions", []any{runes(maxQuestionRunes + 1)}},
		{"repository.primaryLanguages", ids(maxTextItems + 1)}, {"capabilities.0.riskClasses", []any{"bad id"}},
		{"mapId", "m" + strings.Repeat("a", admit.MaxRuleIDBytes)}, {"mapId", "1bad"}, {"mapId", " padded"},
		{"proofScope.baseRef", ""}, {"proofScope.headRef", " "}, {"scenarioAnchors.0.positiveWitness", "true"},
		{"scenarioAnchors.0.selector", "service/tests/auth_test.py"}, {"scenarioAnchors.0.selector", "a::b::c"},
		{"scenarioAnchors.0.selector", "a:::b"}, {"scenarioAnchors.0.selector", "::anchor"}, {"scenarioAnchors.0.selector", "path::"},
		{"scenarioAnchors.0.selector", "path::1anchor"}, {"scenarioAnchors.0.sourcePath", " "},
		{"capabilities.0.scenarioShapes.0.candidateRequirementId", ""}, {"requiredVerification.0.nonClaims", []any{false}},
	} {
		cases = append(cases, capabilityInputCase{fmt.Sprintf("invalid-%s-%v", test.path, test.value), "structural", set(test.path, test.value)})
	}
	cases = append(cases,
		capabilityInputCase{"maximum-capabilities-exceeded", "structural", func(input map[string]any) {
			input["capabilities"] = slices.Repeat([]any{firstCapability(input)}, maxCapabilities+1)
		}},
		capabilityInputCase{"maximum-scenarios-exceeded", "structural", func(input map[string]any) {
			shape := firstScenarioShape(input)
			firstCapability(input)["scenarioShapes"] = slices.Repeat([]any{shape}, maxScenarioShapesPerCapability+1)
		}},
		capabilityInputCase{"maximum-anchors-exceeded", "structural", func(input map[string]any) { input["scenarioAnchors"] = anchors(maxScenarioAnchors + 1) }},
		capabilityInputCase{"maximum-verification-exceeded", "structural", func(input map[string]any) {
			input["requiredVerification"] = verificationCommands(maxRequiredVerificationCommands + 1)
		}},
		capabilityInputCase{"anchor-bound-exceeded", "structural", func(input map[string]any) {
			setCapabilityPath(input, "scenarioAnchors.0.selector", "service/tests/auth_test.py::"+strings.Repeat("a", admit.MaxRuleIDBytes+1))
		}},
		// Native admission owns these privacy, path, order, keyed uniqueness and cross-field rules.
		capabilityInputCase{"secret-summary", "native", set("capabilities.0.summary", "Bearer abcdefghijklmnopqrstuvwxyz")},
		capabilityInputCase{"timestamp-id", "native", set("mapId", "sample.20240101")},
		capabilityInputCase{"unsafe-source-path", "native", set("capabilities.0.sourcePaths", []any{"../backend"})},
		capabilityInputCase{"absolute-anchor-path", "native", func(input map[string]any) {
			setCapabilityPath(input, "scenarioAnchors.0.selector", "/abs::anchor")
			setCapabilityPath(input, "scenarioAnchors.0.sourcePath", "/abs")
		}},
		capabilityInputCase{"selector-path-drift", "native", set("scenarioAnchors.0.selector", "service/tests/other_test.py::test_missing_bearer_fails_closed")},
		capabilityInputCase{"unsorted-ids", "native", set("repository.primaryLanguages", []any{"typescript", "python"})},
		capabilityInputCase{"duplicate-ids", "native", set("repository.primaryLanguages", []any{"python", "python"})},
		capabilityInputCase{"duplicate-capability", "native", func(input map[string]any) {
			input["capabilities"] = []any{firstCapability(input), cloneCapabilityJSON(firstCapability(input))}
		}},
		capabilityInputCase{"duplicate-command", "native", func(input map[string]any) {
			command := input["requiredVerification"].([]any)[0]
			input["requiredVerification"] = []any{command, cloneCapabilityJSON(command)}
		}},
		capabilityInputCase{"shell-command", "native", set("requiredVerification.0.command", "uv run pytest && curl example.test")},
	)
	return cases
}

func TestCapabilityTextGrammarsMatchNativeTrimmedBounds(t *testing.T) {
	alphabet := []string{"a", "\u00e9", " ", "\t", "\u0085", "\u3000"}
	for _, maximum := range []int{2, 3, 4} {
		trimmed, canonical := trimmedTextShape(maximum), canonicalTextShape(maximum)
		forEachString(alphabet, 6, func(value string) {
			_, nativeErr := boundedText(value, "text", maximum)
			if (nativeErr == nil) != (trimmed.CheckGenerated(value, "text") == nil) {
				t.Fatalf("trimmed bound %d diverged for %q: %v", maximum, value, nativeErr)
			}
			_, canonicalErr := admit.PreserveSortedText([]string{value}, "text", true)
			canonicalNative := canonicalErr == nil && len([]rune(value)) <= maximum
			if canonicalNative != (canonical.CheckGenerated(value, "text") == nil) {
				t.Fatalf("canonical bound %d diverged for %q", maximum, value)
			}
		})
	}
	unbounded := canonicalTextShape(0)
	forEachString(alphabet, 6, func(value string) {
		_, err := admit.PreserveSortedText([]string{value}, "text", true)
		if (err == nil) != (unbounded.CheckGenerated(value, "text") == nil) {
			t.Fatalf("canonical text diverged for %q", value)
		}
	})
}

func TestCapabilitySelectorGrammarMatchesNativeSplit(t *testing.T) {
	shape := selectorInputShape()
	forEachString([]string{"a", "b", ":", "/", ".", " ", "\u3000", "1"}, 6, func(value string) {
		if want := selectorSplitDomain(value); want != (shape.CheckGenerated(value, "selector") == nil) {
			t.Fatalf("selector split diverged for %q: want %t", value, want)
		}
	})
	random := rand.New(rand.NewPCG(7, 11))
	alphabet := []rune("ab:/._- \u3000\t1")
	for range 20000 {
		runes := make([]rune, 1+random.IntN(14))
		for i := range runes {
			runes[i] = alphabet[random.IntN(len(alphabet))]
		}
		value := string(runes)
		accepted := shape.CheckGenerated(value, "selector") == nil
		if accepted != selectorSplitDomain(value) {
			t.Fatalf("random selector diverged for %q", value)
		}
		trimmed := strings.TrimSpace(value)
		path, _, _ := strings.Cut(trimmed, "::")
		if _, err := admit.SafeRepoRelativePath(path, "path"); err != nil || strings.TrimSpace(path) != path {
			continue // Path safety and sourcePath equality are native relations.
		}
		anchor := map[string]any{"scenarioId": "sample.scenario", "selector": value, "sourcePath": path, "status": "candidate"}
		if _, err := admitScenarioAnchor(anchor, 0); (err == nil) != accepted {
			t.Fatalf("native anchor admission diverged for %q: %v", value, err)
		}
	}
	bound := selectorAnchorBoundShape()
	for _, length := range []int{1, admit.MaxRuleIDBytes, admit.MaxRuleIDBytes + 1} {
		value := " path/x::a" + strings.Repeat("b", length-1) + "\u3000"
		_, err := admitScenarioAnchor(map[string]any{"scenarioId": "sample.scenario", "selector": value, "sourcePath": "path/x", "status": "candidate"}, 0)
		structural := shape.CheckGenerated(value, "selector") == nil && bound.CheckGenerated(value, "selector") == nil
		if (err == nil) != structural || structural != (length <= admit.MaxRuleIDBytes) {
			t.Fatalf("anchor bound %d diverged: %v", length, err)
		}
	}
}

func TestCapabilityStructuresAreDetachedAndExposeSharedOwners(t *testing.T) {
	for _, factory := range []func() map[string]any{InputStructure, OutputStructure} {
		first, second := factory(), factory()
		if !reflect.DeepEqual(first, second) {
			t.Fatal("unstable structure projection")
		}
		mutateNestedStructure(first)
		if !reflect.DeepEqual(second, factory()) {
			t.Fatal("projection aliases a shared declaration")
		}
	}
	schema := InputStructure()
	if !reflect.DeepEqual(schema["required"], []any{"authority", "capabilities", "mapId", "proofScope", "repository", "schemaVersion", "trustMode"}) {
		t.Fatalf("required root members changed: %v", schema["required"])
	}
	for _, path := range uniqueInputLists {
		if structureNode(schema, path...)["uniqueItems"] != true {
			t.Fatalf("%v lost sorted-unique structure", path)
		}
	}
	if structureNode(schema, "scenarioAnchors", "*", "selector")["allOf"] == nil {
		t.Fatal("selector anchor bound is not projected")
	}
	output := OutputStructure()
	if len(output["oneOf"].([]any)) != 4 {
		t.Fatal("trust mode by state partition changed")
	}
}

func mutateNestedStructure(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "pattern" || key == "const" {
				typed[key] = "caller mutation"
			}
			mutateNestedStructure(child)
		}
	case []any:
		for _, child := range typed {
			mutateNestedStructure(child)
		}
	}
}

func assertCapabilityReportCarrier(t *testing.T, value map[string]any) {
	t.Helper()
	if err := ruleIDShape().CheckGenerated(value["reportId"], "reportId"); err != nil {
		t.Fatal(err)
	}
	if err := jsonshape.Array(canonicalTextShape(0), len(commandNonClaims)).CheckGenerated(value["nonClaims"], "nonClaims"); err != nil {
		t.Fatal(err)
	}
	claims := value["nonClaims"].([]any)
	for _, claim := range commandNonClaims {
		if !slices.Contains(claims, any(claim)) {
			t.Fatalf("builtin nonClaim missing: %s", claim)
		}
	}
	for i := 1; i < len(claims); i++ {
		if claims[i-1].(string) >= claims[i].(string) {
			t.Fatal("report nonClaims are not sorted unique")
		}
	}
}

// InputStructure intersects the selector grammar with its anchor byte bound.
func selectorBoundsError(input map[string]any) error {
	anchors, _ := input["scenarioAnchors"].([]any)
	for _, raw := range anchors {
		if err := selectorAnchorBoundShape().CheckGenerated(raw.(map[string]any)["selector"], "selector"); err != nil {
			return err
		}
	}
	return nil
}

func selectorSplitDomain(value string) bool {
	trimmed := strings.TrimSpace(value)
	parts := strings.Split(trimmed, "::")
	if trimmed == "" || len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	_, err := admit.RuleID(parts[1], "anchor")
	return err == nil
}

func forEachString(alphabet []string, maximum int, visit func(string)) {
	var walk func(string, int)
	walk = func(prefix string, depth int) {
		visit(prefix)
		if depth == maximum {
			return
		}
		for _, item := range alphabet {
			walk(prefix+item, depth+1)
		}
	}
	walk("", 0)
}

func anchors(count int) []any {
	values := make([]any, count)
	for i := range values {
		values[i] = map[string]any{
			"scenarioId": "sample.backend.auth.missing_bearer_fails_closed", "status": "missing",
			"selector": fmt.Sprintf("service/tests/auth_test.py::anchor_%03d", i), "sourcePath": "service/tests/auth_test.py",
		}
	}
	return values
}

func verificationCommands(count int) []any {
	values := make([]any, count)
	for i := range values {
		values[i] = map[string]any{
			"commandId": fmt.Sprintf("sample.command_%03d", i), "command": "uv run pytest", "environmentClass": "local_python", "reason": "Fixture.",
		}
	}
	return values
}

func capabilityWireValue(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func cloneCapabilityJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = cloneCapabilityJSON(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for i, item := range typed {
			result[i] = cloneCapabilityJSON(item)
		}
		return result
	default:
		return typed
	}
}

func seedAt(value map[string]any, diagnostic int) map[string]any {
	return diagnosticValue(value, diagnostic).([]any)[0].(map[string]any)
}

func diagnosticValue(value map[string]any, index int) any {
	return value["diagnostics"].([]any)[index].(map[string]any)["value"]
}

func setCapabilityPath(input map[string]any, path string, value any) {
	parent, key := capabilityParent(input, path)
	switch typed := parent.(type) {
	case map[string]any:
		typed[key] = value
	case []any:
		var index int
		fmt.Sscan(key, &index)
		typed[index] = value
	}
}

func deleteCapabilityPath(input map[string]any, path string) {
	parent, key := capabilityParent(input, path)
	delete(parent.(map[string]any), key)
}

func capabilityParent(input map[string]any, path string) (any, string) {
	segments := strings.Split(path, ".")
	var current any = input
	for _, segment := range segments[:len(segments)-1] {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[segment]
		case []any:
			var index int
			fmt.Sscan(segment, &index)
			current = typed[index]
		}
	}
	return current, segments[len(segments)-1]
}
