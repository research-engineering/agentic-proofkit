package conformanceprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func conformanceWire(t *testing.T, value any) any {
	t.Helper()
	data, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := admission.DecodeJSON(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func assertOutputShape(t *testing.T, shape jsonshape.Shape, value any) map[string]any {
	t.Helper()
	if err := shape.CheckGenerated(value, "conformance output"); err != nil {
		t.Fatal(err)
	}
	wire := conformanceWire(t, value).(map[string]any)
	if _, err := shape.Admit(wire, "conformance wire output"); err != nil {
		t.Fatal(err)
	}
	for _, key := range slices.Sorted(maps.Keys(wire)) {
		missing := maps.Clone(wire)
		delete(missing, key)
		if _, err := shape.Admit(missing, "conformance output"); err == nil {
			t.Fatalf("missing %s admitted", key)
		}
	}
	foreign := maps.Clone(wire)
	foreign["foreign"] = true
	if _, err := shape.Admit(foreign, "conformance output"); err == nil {
		t.Fatal("foreign output field admitted")
	}
	return wire
}

// structuralAdmission applies the projected shape and its published scenario refinement.
func structuralAdmission(wire any) error {
	if _, err := InputShape().Admit(wire, "conformance structure"); err != nil {
		return err
	}
	for _, raw := range wire.(map[string]any)["proofContract"].(map[string]any)["bindings"].([]any) {
		if _, err := ScenarioBoundShape().Admit(raw.(map[string]any)["scenarioId"], "scenario bound"); err != nil {
			return err
		}
	}
	return nil
}

func TestOutputStructuresCoverEveryModeAndState(t *testing.T) {
	duplicate := validConformanceProfileInput()
	profiles := duplicate["manifest"].(map[string]any)["profiles"].([]any)
	duplicate["manifest"].(map[string]any)["profiles"] = append(profiles, profiles[0])
	empty := validConformanceProfileInput()
	empty["manifest"].(map[string]any)["profiles"] = []any{}
	invalid := validConformanceProfileInput()
	invalid["manifest"].(map[string]any)["profiles"].([]any)[0].(map[string]any)["requiredSurfaceIds"] = []any{"surface.missing"}
	for _, input := range []map[string]any{validConformanceProfileInput(), duplicate, empty, invalid} {
		ids, err := List(conformanceWire(t, input))
		if err != nil {
			t.Fatal(err)
		}
		assertOutputShape(t, ListOutputShape(), map[string]any{"profiles": admit.StringSliceToAny(ids)})
	}
	for _, row := range []struct {
		input map[string]any
		state string
	}{{validConformanceProfileInput(), profileResolved}, {invalid, profileInvalid}} {
		result, err := BuildProfile(conformanceWire(t, row.input), "local")
		if err != nil || result.ProfileReport.ProfileResolutionState != row.state || (result.ExitCode == 0) != (row.state == profileResolved) {
			t.Fatalf("profile state changed: %v %#v", err, result.ProfileReport)
		}
		wire := assertOutputShape(t, ProfileOutputShape(), result.ProfileReport.JSONValue())
		wire["profileResolutionState"] = "foreign"
		if _, err := ProfileOutputShape().Admit(wire, "profile"); err == nil {
			t.Fatal("foreign resolution state admitted")
		}
	}
	states := map[string]bool{}
	for _, raw := range []any{validConformanceProfileInput(), duplicate, invalid, map[string]any{}, []any{json.Number("1")}, "text", nil} {
		record, code, err := BuildVerification(conformanceWire(t, raw))
		if err != nil || (code == 0) != (record.State == "passed") {
			t.Fatalf("verification exit drift: %d %v", code, err)
		}
		states[record.State] = true
		value := record.JSONValue()
		assertOutputShape(t, VerifyOutputShape(), value)
		if value["reportId"] != verificationReportID {
			t.Fatal("verification report ID drifted from its published literal")
		}
		for _, claim := range record.NonClaims {
			if _, err := outputTextShape().Admit(claim, "verification nonClaim"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !states["passed"] || !states["failed"] {
		t.Fatalf("verification states are not all reachable: %v", states)
	}
}

func TestVerificationStructureRejectsMixedRuleStates(t *testing.T) {
	record, _, err := BuildVerification(conformanceWire(t, validConformanceProfileInput()))
	if err != nil || record.State != "passed" {
		t.Fatal("fixture must pass verification")
	}
	value := conformanceWire(t, record.JSONValue()).(map[string]any)
	failure := map[string]any{"diagnostics": []any{}, "message": "profile local failed", "ruleId": failureRuleIDPrefix + "001", "status": "failed"}
	for name, rules := range map[string][]any{
		"mixed": {value["ruleResults"].([]any)[0], failure}, "empty": {},
		"two resolved": {value["ruleResults"].([]any)[0], value["ruleResults"].([]any)[0]},
		"ordinal zero": {map[string]any{"diagnostics": []any{}, "message": "x", "ruleId": failureRuleIDPrefix + "000", "status": "failed"}},
		"diagnostic":   {map[string]any{"diagnostics": []any{map[string]any{"key": "x", "value": "y"}}, "message": "x", "ruleId": failureRuleIDPrefix + "001", "status": "failed"}},
	} {
		changed := maps.Clone(value)
		changed["ruleResults"] = rules
		if _, err := VerifyOutputShape().Admit(changed, "verification"); err == nil {
			t.Fatalf("%s rule results admitted", name)
		}
	}
	ordinal := regexp.MustCompile(`\A` + failureOrdinalPattern + `\z`)
	for _, index := range []int{1, 9, 10, 99, 100, 999, 1000, 12345} {
		if !ordinal.MatchString(fmt.Sprintf("%03d", index)) {
			t.Fatalf("native ordinal %d is outside the described grammar", index)
		}
	}
	for _, spelling := range []string{"000", "1", "01", "0001", "-01"} {
		if ordinal.MatchString(spelling) {
			t.Fatalf("non-native ordinal %q admitted", spelling)
		}
	}
}

func TestProfileIDGrammarIsNativeRuleIDLowerDashIntersection(t *testing.T) {
	grammar := regexp.MustCompile(`\A` + profileIDPatternBody + `\z`)
	ruleID := regexp.MustCompile(`\A` + admit.RuleIDPatternBody + `\z`)
	alphabet := []string{"a", "z", "0", "-", ".", "_", "A", ":"}
	values := []string{""}
	for range 4 {
		next := []string{}
		for _, prefix := range values {
			for _, letter := range alphabet {
				next = append(next, prefix+letter)
			}
		}
		values = append(values, next...)
	}
	for _, value := range values {
		if grammar.MatchString(value) != (ruleID.MatchString(value) && lowerDashID(value)) {
			t.Fatalf("profile ID grammar differs from the native predicates for %q", value)
		}
	}
	for _, value := range []string{"local", "local-go", "a" + strings.Repeat("b", 255)} {
		if _, err := profileIDShape().Admit(value, "profile"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := profileIDShape().Admit("a"+strings.Repeat("b", 256), "profile"); err == nil {
		t.Fatal("profile ID bound is not the native RuleID bound")
	}
}

func TestInputStructureAgreesWithNativeAdmission(t *testing.T) {
	type mutation struct {
		name   string
		mutate func(map[string]any)
		// nativeOnly marks semantic predicates the structure names but cannot express.
		accepted, nativeOnly bool
	}
	object := func(input map[string]any, path ...any) map[string]any {
		var current any = input
		for _, segment := range path {
			switch key := segment.(type) {
			case string:
				current = current.(map[string]any)[key]
			case int:
				current = current.([]any)[key]
			}
		}
		return current.(map[string]any)
	}
	set := func(value any, key string, path ...any) func(map[string]any) {
		return func(input map[string]any) { object(input, path...)[key] = value }
	}
	remove := func(key string, path ...any) func(map[string]any) {
		return func(input map[string]any) { delete(object(input, path...), key) }
	}
	binding := []any{"proofContract", "bindings", 0}
	witness := func(index int) []any { return append(slices.Clone(binding), "witnessRefs", index) }
	profile := []any{"manifest", "profiles", 0}
	both := func(key string, value any) func(map[string]any) {
		return func(input map[string]any) {
			object(input, "manifest")[key] = value
			object(input, "policy", "expectedManifest")[key] = value
		}
	}
	cases := []mutation{
		{name: "valid", mutate: func(map[string]any) {}, accepted: true},
		{name: "foreign root", mutate: set(true, "foreign")},
		{name: "version one", mutate: set(json.Number("1"), "schemaVersion")},
		{name: "profileId absent", mutate: remove("profileId"), accepted: true},
		{name: "profileId padded", mutate: set(" local ", "profileId"), accepted: true},
		{name: "profileId null", mutate: set(nil, "profileId")},
		{name: "profileId NUL", mutate: set("lo\x00cal", "profileId")},
		{name: "policy fail flag absent", mutate: remove("failOnUnusedAllowedEnvironmentClass", "policy"), accepted: true},
		{name: "policy fail flag null", mutate: set(nil, "failOnUnusedAllowedEnvironmentClass", "policy")},
		{name: "policy foreign", mutate: set(true, "foreign", "policy")},
		{name: "policy known empty", mutate: set([]any{}, "knownEnvironmentClasses", "policy")},
		{name: "policy known unsorted", mutate: func(input map[string]any) {
			object(input, "policy")["knownEnvironmentClasses"] = []any{"local-go", "a-env"}
		}, nativeOnly: true},
		{name: "policy local unknown", mutate: set([]any{"remote"}, "localEnvironmentClasses", "policy"), nativeOnly: true},
		{name: "policy blocking blank", mutate: set([]any{" "}, "blockingStatuses", "policy")},
		{name: "expected manifest foreign", mutate: set(true, "foreign", "policy", "expectedManifest")},
		{name: "expected manifest missing source", mutate: remove("sourceContract", "policy", "expectedManifest")},
		{name: "manifest version two", mutate: set(json.Number("2"), "schemaVersion", "manifest")},
		{name: "manifest drift", mutate: set("other", "contractId", "manifest"), nativeOnly: true},
		{name: "manifest padded identity", mutate: both("contractId", "\tproofkit.test.conformance "), accepted: true},
		{name: "manifest NUL identity", mutate: both("contractId", "proofkit\x00conformance")},
		{name: "manifest secret identity", mutate: both("contractId", "token=ghp_secretvalue"), nativeOnly: true},
		{name: "manifest profiles empty", mutate: set([]any{}, "profiles", "manifest"), accepted: true},
		{name: "manifest profiles null", mutate: set(nil, "profiles", "manifest")},
		{name: "profile id uppercase", mutate: set("Local", "profileId", profile...)},
		{name: "profile id dotted", mutate: set("local.go", "profileId", profile...)},
		{name: "profile id padded", mutate: set(" local", "profileId", profile...)},
		{name: "profile id timestamp", mutate: set("local-20260101", "profileId", profile...), nativeOnly: true},
		{name: "profile policy padded", mutate: set(" local_only\n", "preconditionPolicy", profile...), accepted: true},
		{name: "profile policy foreign", mutate: set("remote_only", "preconditionPolicy", profile...)},
		{name: "profile required empty", mutate: set([]any{}, "requiredSurfaceIds", profile...)},
		{name: "profile optional overlap", mutate: set([]any{"surface.local"}, "optionalSurfaceIds", profile...), nativeOnly: true},
		{name: "profile foreign", mutate: set(true, "foreign", profile...)},
		{name: "profile item null", mutate: func(input map[string]any) { object(input, "manifest")["profiles"].([]any)[0] = nil }},
		{name: "proof declaration kind", mutate: set("proofkit.other", "declarationKind", "proofContract")},
		{name: "proof version one", mutate: set(json.Number("1"), "schemaVersion", "proofContract")},
		{name: "proof empty", mutate: func(input map[string]any) {
			object(input, "proofContract")["surfaces"] = []any{}
			object(input, "proofContract")["bindings"] = []any{}
		}, accepted: true},
		{name: "surface id grammar", mutate: set("surface local", "surfaceId", "proofContract", "surfaces", 0)},
		{name: "surface required empty", mutate: set([]any{}, "requiredEnvironmentClasses", "proofContract", "surfaces", 0)},
		{name: "surface duplicate classes", mutate: set([]any{"local-go", "local-go"}, "requiredEnvironmentClasses", "proofContract", "surfaces", 0), accepted: true},
		{name: "surface foreign", mutate: set(true, "foreign", "proofContract", "surfaces", 0)},
		{name: "binding foreign", mutate: set(true, "foreign", binding...)},
		{name: "binding digest padded", mutate: func(input map[string]any) {
			record := object(input, binding...)
			record["bindingRecordId"] = " sha256:\t" + strings.TrimPrefix(record["bindingRecordId"].(string), "sha256:") + "\n"
		}, accepted: true},
		{name: "binding digest uppercase", mutate: func(input map[string]any) {
			record := object(input, binding...)
			record["bindingRecordId"] = strings.ToUpper(record["bindingRecordId"].(string))
		}},
		{name: "binding digest mismatch", mutate: set("sha256:"+strings.Repeat("a", 64), "bindingRecordId", binding...), nativeOnly: true},
		{name: "binding scenario unscoped", mutate: set("scenario", "scenarioId", binding...)},
		{name: "binding scenario padded", mutate: set(" surface.local::scenario\t", "scenarioId", binding...), accepted: true},
		{name: "binding scenario other surface", mutate: set("surface.other::scenario", "scenarioId", binding...), nativeOnly: true},
		{name: "binding scenario long anchor", mutate: set("surface.local::a"+strings.Repeat("b", 256), "scenarioId", binding...)},
		{name: "binding commands empty", mutate: set([]any{}, "verifyCommands", binding...)},
		{name: "binding command shell control", mutate: set([]any{"go test ./... && curl example.test"}, "verifyCommands", binding...), nativeOnly: true},
		{name: "binding status grammar", mutate: set("blocking status", "blockingStatus", binding...)},
		{name: "witness one", mutate: func(input map[string]any) {
			record := object(input, binding...)
			record["witnessRefs"] = record["witnessRefs"].([]any)[:1]
		}},
		{name: "witness reversed", mutate: func(input map[string]any) {
			refs := object(input, binding...)["witnessRefs"].([]any)
			refs[0], refs[1] = refs[1], refs[0]
		}, accepted: true},
		{name: "witness same role", mutate: set("positive", "role", witness(0)...)},
		{name: "witness role foreign", mutate: set("negative", "role", witness(0)...)},
		{name: "witness order negative", mutate: set(json.Number("-1"), "resolutionOrderIndex", witness(0)...)},
		{name: "witness order unsafe", mutate: set(json.Number("9007199254740992"), "resolutionOrderIndex", witness(0)...)},
		{name: "witness order safe max", mutate: set(json.Number("9007199254740991"), "resolutionOrderIndex", witness(0)...), accepted: true},
		{name: "witness order decimal", mutate: set(json.Number("1.0"), "resolutionOrderIndex", witness(0)...)},
		{name: "witness order negative zero", mutate: set(json.Number("-0"), "resolutionOrderIndex", witness(0)...), nativeOnly: true},
		{name: "witness selector unsafe", mutate: func(input map[string]any) {
			for index := range 2 {
				object(input, witness(index)...)["selector"] = "../outside.go::TestOutside"
			}
		}, nativeOnly: true},
		{name: "witness environments empty", mutate: set([]any{}, "environmentClasses", witness(0)...)},
		{name: "witness foreign", mutate: set(true, "foreign", witness(0)...)},
	}
	for _, key := range []string{"manifest", "policy", "proofContract", "schemaVersion"} {
		cases = append(cases, mutation{name: "missing " + key, mutate: remove(key)})
	}
	for _, row := range []struct {
		keys []string
		path []any
	}{{bindingKeys, binding}, {witnessRefKeys, witness(1)}, {profileKeys, profile}, {surfaceKeys, []any{"proofContract", "surfaces", 0}},
		{proofContractKeys, []any{"proofContract"}}, {manifestKeys, []any{"manifest"}}, {expectedManifestKeys, []any{"policy", "expectedManifest"}}} {
		for _, key := range row.keys {
			cases = append(cases, mutation{name: fmt.Sprint(row.path...) + " missing " + key, mutate: remove(key, row.path...)})
		}
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validConformanceProfileInput()
			item.mutate(input)
			wire := conformanceWire(t, input)
			_, nativeErr := admitInput(wire)
			structuralErr := structuralAdmission(wire)
			if (nativeErr == nil) != item.accepted {
				t.Fatalf("native admission=%v want accepted=%v", nativeErr, item.accepted)
			}
			verification, code, err := BuildVerification(wire)
			if err != nil {
				t.Fatal(err)
			}
			if nativeErr != nil && (code != 1 || verification.State != "failed" || len(verification.RuleResults) != 1 || verification.RuleResults[0].Message != nativeErr.Error()) {
				t.Fatal("verification no longer reports the admission refusal as its single failure")
			}
			if err := VerifyOutputShape().CheckGenerated(verification.JSONValue(), "verification"); err != nil {
				t.Fatal(err)
			}
			if item.nativeOnly {
				if structuralErr != nil {
					t.Fatalf("structure refused a native-only predicate: %v", structuralErr)
				}
				return
			}
			if (structuralErr == nil) != item.accepted {
				t.Fatalf("structure=%v native=%v", structuralErr, nativeErr)
			}
		})
	}
}

func TestPublishedStructuresAreShapeProjections(t *testing.T) {
	input := InputStructure()
	scenario := input["properties"].(map[string]any)["proofContract"].(map[string]any)["properties"].(map[string]any)["bindings"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["scenarioId"].(map[string]any)
	if !reflect.DeepEqual(scenario["allOf"], []any{map[string]any{"pattern": ScenarioBoundShape().JSONSchema()["pattern"]}}) {
		t.Fatal("scenario bound refinement drifted")
	}
	delete(scenario, "allOf")
	delete(input, "description")
	if !reflect.DeepEqual(input, InputShape().JSONSchema()) {
		t.Fatal("published input is not the native shape projection")
	}
	for _, row := range []struct {
		structure map[string]any
		shape     jsonshape.Shape
	}{{ListOutputStructure(), ListOutputShape()}, {ProfileOutputStructure(), ProfileOutputShape()}} {
		delete(row.structure, "description")
		if !reflect.DeepEqual(row.structure, row.shape.JSONSchema()) {
			t.Fatal("published output is not the native shape projection")
		}
	}
	verify := VerifyOutputStructure()
	properties := verify["properties"].(map[string]any)
	if properties["reportId"].(map[string]any)["const"] != verificationReportID || properties["nonClaims"].(map[string]any)["items"] == nil {
		t.Fatal("verification refinements drifted")
	}
	profile := ProfileOutputShape().JSONSchema()["properties"].(map[string]any)
	if !reflect.DeepEqual(slices.Sorted(maps.Keys(profile)), slices.Sorted(maps.Keys((ProfileReport{}).JSONValue()))) {
		t.Fatal("profile output inventory differs from JSONValue")
	}
}
