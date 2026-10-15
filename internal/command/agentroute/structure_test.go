package agentroute

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

type structuralRouteCase struct {
	input    map[string]any
	renderer cliexec.Renderer
}

// structuralRouteInput supplies every input kind a goal can consume so each
// command of the route table is rendered at least once.
func structuralRouteInput(goal string, available bool) map[string]any {
	input := map[string]any{"schemaVersion": jsonNumber("1"), "routeId": "consumer.route." + goal, "goal": goal, "mode": "observe"}
	if !available {
		return input
	}
	kinds := map[string]struct{}{}
	for _, command := range routeSpecs[goal].NextCommands {
		kinds[command.InputKind] = struct{}{}
		for _, argument := range command.ArgInputs {
			kinds[argument.InputKind] = struct{}{}
		}
	}
	refs := []any{}
	for _, kind := range sortedNames(kinds) {
		ref := "inputs/" + kind + ".json"
		if strings.HasSuffix(kind, "_repo_root") {
			ref = "."
		}
		refs = append(refs, map[string]any{"kind": kind, "ref": ref})
	}
	input["availableInputs"] = refs
	return input
}

func structuralRouteCorpus(t *testing.T) map[string]structuralRouteCase {
	t.Helper()
	python, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, "/opt/python/bin/python3")
	if err != nil {
		t.Fatal(err)
	}
	npm, err := cliexec.AdmitLauncherProfile(cliexec.ProfileNPMOffline, "")
	if err != nil {
		t.Fatal(err)
	}
	corpus := map[string]structuralRouteCase{}
	for goal := range goalValues {
		corpus[goal+"/available"] = structuralRouteCase{structuralRouteInput(goal, true), cliexec.PathRenderer()}
		corpus[goal+"/missing"] = structuralRouteCase{structuralRouteInput(goal, false), npm}
		failed := structuralRouteInput(goal, true)
		failed["observedReports"] = []any{
			map[string]any{"kind": "adoption", "ref": "reports/a.json", "state": "passed"},
			map[string]any{"kind": "release", "ref": "reports/b.json", "state": "failed"},
		}
		corpus[goal+"/observed"] = structuralRouteCase{failed, python}
	}
	serve := structuralRouteInput("render_human_view", true)
	serve["browserMode"], serve["openBrowser"] = "serve_local_view", true
	serve["nonClaims"] = []any{"Caller claim.", strings.Repeat("c", maxCallerNonClaimTextRunes)}
	corpus["serve"] = structuralRouteCase{serve, python}
	diagnostic := structuralRouteInput("plan_selective_checks", false)
	diagnostic["knownChangedPaths"] = []any{"a.go", "b.go"}
	corpus["diagnostic-paths"] = structuralRouteCase{diagnostic, cliexec.PathRenderer()}
	nulls := structuralRouteInput("validate_requirement_source", true)
	for _, key := range []string{"browserMode", "openBrowser", "knownChangedPaths", "nonClaims", "observedReports"} {
		nulls[key] = nil
	}
	corpus["nulls"] = structuralRouteCase{nulls, cliexec.PathRenderer()}
	long := structuralRouteInput("validate_requirement_source", false)
	long["availableInputs"] = []any{map[string]any{"kind": "requirement_source", "ref": "docs/" + strings.Repeat("a", 5000) + ".json"}}
	corpus["long-ref"] = structuralRouteCase{long, cliexec.PathRenderer()}
	unsafe := structuralRouteInput("validate_requirement_source", false)
	unsafe["availableInputs"] = []any{map[string]any{"kind": "requirement_source", "ref": " docs/\u202ereport.json "}}
	corpus["unsafe-ref"] = structuralRouteCase{unsafe, cliexec.PathRenderer()}
	secret := structuralRouteInput("validate_requirement_source", true)
	secret["routeId"] = "eyJa.b"
	corpus["secret-shaped-suffix"] = structuralRouteCase{secret, cliexec.PathRenderer()}
	many := structuralRouteInput("validate_requirement_source", true)
	reports := []any{}
	for index := range agentEnvelopeBlockerOverflow() {
		reports = append(reports, map[string]any{"kind": "evidence", "ref": fmt.Sprintf("reports/%03d.json", index), "state": "warning"})
	}
	many["observedReports"] = reports
	corpus["blocker-overflow"] = structuralRouteCase{many, cliexec.PathRenderer()}
	return corpus
}

// agentEnvelopeBlockerOverflow exceeds the kernel blocker bound by two.
func agentEnvelopeBlockerOverflow() []struct{} { return make([]struct{}, 14) }

func TestRouteStructuresAdmitEveryNativeProjection(t *testing.T) {
	routed, unknown, brief, full, envelopeID := RoutedReportShape(), UnknownGoalReportShape(), BriefShape(), FullEnvelopeShape(), FullEnvelopeIDShape()
	for name, item := range structuralRouteCorpus(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := InputShape().Admit(item.input, "input"); err != nil {
				t.Fatal(err)
			}
			report, _, err := BuildWithRenderer(item.input, item.renderer)
			if err != nil {
				t.Fatal(err)
			}
			want, other := routed, unknown
			if item.input["goal"] == "unknown" {
				want, other = unknown, routed
			}
			if err := want.CheckGenerated(report, "report"); err != nil {
				t.Fatal(err)
			}
			if other.CheckGenerated(report, "report") == nil {
				t.Fatal("report variants are not exclusive")
			}
			assertReportRefinements(t, report)
			packet, err := AgentBrief(report)
			if err != nil {
				t.Fatal(err)
			}
			if err := brief.CheckGenerated(packet, "brief"); err != nil {
				t.Fatal(err)
			}
			envelope := FullAgentEnvelope(report)
			if err := envelopeID.CheckGenerated(envelope["envelopeId"], "envelopeId"); err != nil {
				t.Fatal(err)
			}
			placeholder := maps.Clone(envelope)
			placeholder["envelopeId"] = "placeholder"
			if err := full.CheckGenerated(placeholder, "full envelope"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertReportRefinements(t *testing.T, report map[string]any) {
	t.Helper()
	claims := report["nonClaims"].([]any)
	for _, claim := range nonClaims {
		if !slices.Contains(claims, claim) {
			t.Fatal("report lost a builtin non-claim")
		}
	}
	for _, key := range []string{"nonClaims", "callerNonClaims"} {
		values := report[key].([]any)
		if len(slices.Compact(slices.Clone(values))) != len(values) {
			t.Fatalf("%s is not duplicate-free", key)
		}
	}
	for _, claim := range report["callerNonClaims"].([]any) {
		if utf8.RuneCountInString(claim.(string)) > maxCallerNonClaimTextRunes {
			t.Fatal("caller claim exceeds its rune bound")
		}
	}
}

func TestRouteProjectionPremisesHoldForTheRouteTable(t *testing.T) {
	if !maps.Equal(keysOf(routeSpecs), func() map[string]struct{} {
		known := maps.Clone(goalValues)
		delete(known, "unknown")
		return known
	}()) {
		t.Fatal("every non-unknown goal must own exactly one route spec")
	}
	// Each brief context ref consumes one rendered operand flag. No command
	// renders an operand flag twice, so the role vocabulary bounds the refs.
	for goal, spec := range routeSpecs {
		for _, command := range spec.NextCommands {
			rendered := map[string]int{"--input": 1}
			for _, argument := range command.ArgInputs {
				rendered[argument.Flag]++
			}
			for _, extra := range command.ExtraArgs {
				rendered[extra]++
			}
			for flag := range briefOperandRoles {
				if rendered[flag] > 1 {
					t.Fatalf("%s renders operand flag %s more than once", goal, flag)
				}
			}
		}
	}
	vocabulary := structuralRouteVocabulary()
	if vocabulary.maxNextCommands == 0 || vocabulary.maxRequiredInputs == 0 || vocabulary.escalationCount[0] == 0 {
		t.Fatal("route vocabulary is empty")
	}
	if !maps.Equal(vocabulary.browserCommands, setOf("requirement-browser-server")) {
		t.Fatal("browser-mode command partition drifted")
	}
	if len(shortTextHash("route")) != 16 || strings.Trim(shortTextHash("route"), "abcdefghijklmnop") != "" {
		t.Fatal("short hash alphabet differs from its declared pattern")
	}
}

func TestRouteInputStructureAgreesWithNativeRefusals(t *testing.T) {
	core := InputShape()
	base := func() map[string]any {
		input := structuralRouteInput("validate_requirement_source", true)
		input["observedReports"] = []any{map[string]any{"kind": "evidence", "ref": "reports/a.json", "state": "passed"}}
		input["knownChangedPaths"] = []any{"a.go"}
		input["nonClaims"] = []any{"Caller claim."}
		return input
	}
	if _, _, err := Build(base()); err != nil {
		t.Fatal(err)
	}
	item := func(value map[string]any, key string) map[string]any {
		return value[key].([]any)[0].(map[string]any)
	}
	tooManyKinds := []any{}
	for range len(inputKindValues) + 1 {
		tooManyKinds = append(tooManyKinds, map[string]any{"kind": "requirement_source", "ref": "a.json"})
	}
	for name, mutate := range map[string]func(map[string]any){
		"foreign root":             func(value map[string]any) { value["foreign"] = true },
		"missing goal":             func(value map[string]any) { delete(value, "goal") },
		"missing mode":             func(value map[string]any) { delete(value, "mode") },
		"missing route":            func(value map[string]any) { delete(value, "routeId") },
		"missing version":          func(value map[string]any) { delete(value, "schemaVersion") },
		"version":                  func(value map[string]any) { value["schemaVersion"] = jsonNumber("2") },
		"version text":             func(value map[string]any) { value["schemaVersion"] = "1" },
		"route grammar":            func(value map[string]any) { value["routeId"] = "1route" },
		"route length":             func(value map[string]any) { value["routeId"] = strings.Repeat("r", maxRouteIDRunes+1) },
		"goal":                     func(value map[string]any) { value["goal"] = "foreign" },
		"mode":                     func(value map[string]any) { value["mode"] = "foreign" },
		"browser mode":             func(value map[string]any) { value["browserMode"] = "foreign" },
		"open browser":             func(value map[string]any) { value["openBrowser"] = "true" },
		"available kind":           func(value map[string]any) { value["availableInputs"] = map[string]any{} },
		"available item":           func(value map[string]any) { value["availableInputs"] = []any{"a.json"} },
		"available field":          func(value map[string]any) { item(value, "availableInputs")["foreign"] = true },
		"available missing":        func(value map[string]any) { delete(item(value, "availableInputs"), "kind") },
		"available enum":           func(value map[string]any) { item(value, "availableInputs")["kind"] = "foreign" },
		"available blank":          func(value map[string]any) { item(value, "availableInputs")["ref"] = " \t" },
		"available count":          func(value map[string]any) { value["availableInputs"] = tooManyKinds },
		"changed path kind":        func(value map[string]any) { value["knownChangedPaths"] = []any{false} },
		"changed path empty":       func(value map[string]any) { value["knownChangedPaths"] = []any{""} },
		"observed state":           func(value map[string]any) { item(value, "observedReports")["state"] = "foreign" },
		"observed kind":            func(value map[string]any) { item(value, "observedReports")["kind"] = "foreign" },
		"observed missing":         func(value map[string]any) { delete(item(value, "observedReports"), "state") },
		"observed field":           func(value map[string]any) { item(value, "observedReports")["foreign"] = true },
		"claims count":             func(value map[string]any) { value["nonClaims"] = repeatedClaims(maxCallerNonClaims + 1) },
		"claims untrimmed":         func(value map[string]any) { value["nonClaims"] = []any{" Caller claim."} },
		"claims empty":             func(value map[string]any) { value["nonClaims"] = []any{""} },
		"claims kind":              func(value map[string]any) { value["nonClaims"] = []any{json.Number("1")} },
		"claims container":         func(value map[string]any) { value["nonClaims"] = "Caller claim." },
		"observed reports wrapper": func(value map[string]any) { value["observedReports"] = map[string]any{} },
	} {
		t.Run(name, func(t *testing.T) {
			value := base()
			mutate(value)
			if _, _, err := Build(value); err == nil {
				t.Fatal("native admission accepted a structural mutant")
			}
			if _, err := core.Admit(value, "input"); err == nil {
				t.Fatal("structural core accepted a native structural refusal")
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"open without serve": func(value map[string]any) { value["openBrowser"] = true },
		"duplicate paths":    func(value map[string]any) { value["knownChangedPaths"] = []any{"a.go", "a.go"} },
		"duplicate claims":   func(value map[string]any) { value["nonClaims"] = []any{"Caller claim.", "Caller claim."} },
		"claim rune bound": func(value map[string]any) {
			value["nonClaims"] = []any{strings.Repeat("\u00e9", maxCallerNonClaimTextRunes+1)}
		},
		"unsafe ref":      func(value map[string]any) { item(value, "availableInputs")["ref"] = "../escape.json" },
		"stdin ref":       func(value map[string]any) { item(value, "availableInputs")["ref"] = "-" },
		"dot ref":         func(value map[string]any) { item(value, "availableInputs")["ref"] = "." },
		"duplicate kinds": func(value map[string]any) { value["availableInputs"] = tooManyKinds[:2] },
		"unsorted claims": func(value map[string]any) { value["nonClaims"] = []any{"b", "a"} },
		"timestamp route": func(value map[string]any) { value["routeId"] = "route.20240101" },
		"duplicate observed ref": func(value map[string]any) {
			value["observedReports"] = append(value["observedReports"].([]any), item(value, "observedReports"))
		},
	} {
		t.Run("native-only/"+name, func(t *testing.T) {
			value := base()
			mutate(value)
			if _, err := core.Admit(value, "input"); err != nil {
				t.Fatalf("structural core refused a refinement or semantic mutant: %v", err)
			}
			if _, _, err := Build(value); err == nil {
				t.Fatal("native admission accepted the mutant")
			}
		})
	}
}

func repeatedClaims(count int) []any {
	claims := make([]any, count)
	for index := range claims {
		claims[index] = fmt.Sprintf("Claim %02d.", index)
	}
	return claims
}

func pointerValue(schema map[string]any, path ...any) any {
	var current any = schema
	for _, segment := range path {
		switch key := segment.(type) {
		case string:
			current = current.(map[string]any)[key]
		case int:
			current = current.([]any)[key]
		}
	}
	return current
}

func TestRouteStructureRefinementsAndIdentities(t *testing.T) {
	input := InputStructure()
	for _, row := range []struct {
		path []any
		want any
	}{
		{[]any{"properties", "nonClaims", "anyOf", 1, "uniqueItems"}, true},
		{[]any{"properties", "nonClaims", "anyOf", 1, "items", "maxLength"}, maxCallerNonClaimTextRunes},
		{[]any{"properties", "knownChangedPaths", "anyOf", 1, "uniqueItems"}, true},
		{[]any{"then", "properties", "browserMode", "const"}, "serve_local_view"},
		{[]any{"if", "properties", "openBrowser", "const"}, true},
	} {
		if got := pointerValue(input, row.path...); !reflect.DeepEqual(got, row.want) {
			t.Fatalf("input refinement %v = %#v", row.path, got)
		}
	}
	if !slices.Equal(stringsFromAny(input["required"]), []string{"goal", "mode", "routeId", "schemaVersion"}) {
		t.Fatal("input required members drifted from native admission")
	}
	for _, schema := range []map[string]any{RoutedReportStructure(), UnknownGoalReportStructure()} {
		if pointerValue(schema, "properties", "nonClaims", "uniqueItems") != true || len(pointerValue(schema, "properties", "nonClaims", "allOf").([]any)) != len(nonClaims) {
			t.Fatal("report non-claim refinements are missing")
		}
		if pointerValue(schema, "properties", "callerNonClaims", "items", "maxLength") != maxCallerNonClaimTextRunes {
			t.Fatal("caller claim rune bound is missing")
		}
	}
	full := FullEnvelopeStructure()
	if _, ok := pointerValue(full, "properties", "envelopeId", "oneOf").([]any); !ok {
		t.Fatal("full envelope identity does not admit the redaction marker alternative")
	}
	for _, value := range []string{"consumer.route.agent-envelope", admit.DiagnosticRedactionMarker} {
		if FullEnvelopeIDShape().CheckGenerated(value, "id") != nil {
			t.Fatalf("envelope identity refused %s", value)
		}
	}
	for _, value := range []string{"consumer.route.agent-brief", "1consumer.agent-envelope", "consumer.route.agent-envelope "} {
		if FullEnvelopeIDShape().CheckGenerated(value, "id") == nil {
			t.Fatalf("envelope identity accepted %s", value)
		}
	}
	brief := BriefShape()
	packet, err := AgentBrief(mustRoute(t, structuralRouteInput("validate_requirement_source", true)))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"packet suffix": func(value map[string]any) { value["packetId"] = "consumer.route.agent-briefx" },
		"route length": func(value map[string]any) {
			value["packetId"] = strings.Repeat("r", maxRouteIDRunes+1) + briefPacketIDSuffix
		},
		"command token": func(value map[string]any) {
			value["nextAction"].(map[string]any)["commandId"] = "consumer.command.Requirement--source.aaaaaaaaaaaaaaaa"
		},
		"command hash width": func(value map[string]any) {
			value["nextAction"].(map[string]any)["commandId"] = "consumer.command.requirement-source.aaaaaaaaaaaaaaa"
		},
		"action infix": func(value map[string]any) {
			value["nextAction"].(map[string]any)["actionId"] = "consumer.command.requirement-source.aaaaaaaaaaaaaaaa"
		},
		"hash alphabet": func(value map[string]any) {
			value["contextRefs"].([]any)[0].(map[string]any)["refId"] = "consumer.input.qqqqqqqqqqqqqqqq"
		},
		"argv with deferral": func(value map[string]any) {
			value["nextAction"].(map[string]any)["argvState"] = argvStateDetailRequired
		},
		"pointer": func(value map[string]any) {
			value["contextRefs"].([]any)[0].(map[string]any)["sourceReportPointer"] = "/nextCommands/0/argv/0"
		},
		"launcher":    func(value map[string]any) { value["detailAccess"].(map[string]any)["launcherProfile"] = "foreign" },
		"state":       func(value map[string]any) { value["state"] = "foreign" },
		"policy refs": func(value map[string]any) { value["boundaryPolicyRefs"] = []any{"REQ-PROOFKIT-SPEC-005"} },
		"foreign":     func(value map[string]any) { value["foreign"] = true },
	} {
		value := cloneJSON(t, packet)
		mutate(value)
		if brief.CheckGenerated(value, "brief") == nil {
			t.Fatalf("brief structure accepted %s", name)
		}
	}
	var decoded any
	encoded, err := json.Marshal(InputStructure())
	if err != nil || json.Unmarshal(encoded, &decoded) != nil {
		t.Fatal("input structure is not plain JSON")
	}
	fresh := RoutedReportStructure()
	fresh["properties"].(map[string]any)["state"] = map[string]any{}
	if reflect.DeepEqual(fresh, RoutedReportStructure()) {
		t.Fatal("report structure shares mutable projection state")
	}
	if brief.CheckGenerated(cloneJSON(t, packet), "brief") != nil {
		t.Fatal("brief clone lost its native carriers")
	}
}

func mustRoute(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	report, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// cloneJSON deep-copies a producer value while preserving its Go int carriers.
func cloneJSON(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	var clone func(any) any
	clone = func(raw any) any {
		switch typed := raw.(type) {
		case map[string]any:
			result := make(map[string]any, len(typed))
			for key, child := range typed {
				result[key] = clone(child)
			}
			return result
		case []any:
			result := make([]any, len(typed))
			for index, child := range typed {
				result[index] = clone(child)
			}
			return result
		default:
			return typed
		}
	}
	return clone(value).(map[string]any)
}
