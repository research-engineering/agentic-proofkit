package gradualadoption

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

type invocationProfile struct {
	name     string
	renderer cliexec.Renderer
	prefix   []string
}

func invocationProfiles(t *testing.T) []invocationProfile {
	t.Helper()
	profiles := []invocationProfile{
		{name: "path", prefix: []string{"agentic-proofkit"}},
		{name: "npm_offline", prefix: []string{"npm", "exec", "--offline", "--", "agentic-proofkit"}},
		{name: "python ordinary", prefix: []string{"/opt/venv/bin/python", "-m", "agentic_proofkit"}},
		{name: "python path privacy", prefix: []string{"/opt/task-validation/bin/python", "-m", "agentic_proofkit"}},
		{name: "python spaces", prefix: []string{"/opt/proofkit venv/bin/python", "-m", "agentic_proofkit"}},
	}
	for index := range profiles {
		profile, executable := profiles[index].name, ""
		if strings.HasPrefix(profile, "python ") {
			profile, executable = cliexec.ProfilePythonModule, profiles[index].prefix[0]
		}
		renderer, err := cliexec.AdmitLauncherProfile(profile, executable)
		if err != nil {
			t.Fatal(err)
		}
		profiles[index].renderer = renderer
	}
	return profiles
}

func TestGuidancePortableSourceAndPublicRendererReadmission(t *testing.T) {
	var canonical []byte
	profiles := invocationProfiles(t)
	for _, sourceProfile := range profiles {
		t.Run(sourceProfile.name, func(t *testing.T) {
			input := validBootstrapInput()
			paths := input["paths"].(map[string]any)
			paths["adoptionProfilePath"] = "inputs/adoption profile.json "
			paths["adoptionGuidancePath"] = "inputs/adoption guidance.json "
			paths["witnessPlanInputPath"] = "inputs/witness plan.json "
			result, err := BuildBootstrapResultWithRenderer(invocationJSON(t, input), sourceProfile.renderer)
			if err != nil || result.ExitCode != 0 {
				t.Fatalf("bootstrap exit=%d err=%v", result.ExitCode, err)
			}
			payload := result.Payloads["adoptionGuidance"]
			encoded, err := stablejson.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if canonical == nil {
				canonical = encoded
			} else if !bytes.Equal(encoded, canonical) {
				t.Fatal("portable guidance JSON depends on the invocation profile")
			}
			wantSource := map[string]any{
				"gradual-adoption":          "inputs/adoption profile.json ",
				"gradual-adoption-guidance": "inputs/adoption guidance.json ",
				"witness-plan":              "inputs/witness plan.json ",
			}
			source := payload.(map[string]any)["agentGuidance"].(map[string]any)
			if !reflect.DeepEqual(source["proofkitCommands"], wantSource) || !reflect.DeepEqual(source["commands"], input["commands"]) {
				t.Fatal("portable source must retain only exact operation/path pairs and caller text")
			}
			manifest, err := BootstrapMaterializationManifest(result)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, raw := range manifest["files"].([]any) {
				file := raw.(map[string]any)
				if file["payloadKey"] == "adoptionGuidance" {
					found = true
					if file["content"] != string(canonical) || file["contentSha256"] != fmt.Sprintf("sha256:%x", sha256.Sum256(canonical)) {
						t.Fatal("portable manifest content/hash depends on its producer profile")
					}
				}
			}
			if !found {
				t.Fatal("guidance materialization was not exercised")
			}
			bootstrapEnvelope := BootstrapEnvelope(result)
			assertInvocationEnvelope(t, bootstrapEnvelope, sourceProfile, wantSource)
			if err := schemacheck.Validate(BootstrapEnvelopeStructure(), bootstrapEnvelope); err != nil {
				t.Fatal(err)
			}
			if err := schemacheck.Validate(BootstrapOutputStructure(), result.JSONValue()); err != nil {
				t.Fatal(err)
			}
			for _, target := range profiles {
				decoded := invocationJSON(t, payload)
				options := GuidanceOptions{Renderer: target.renderer}
				report, code, err := BuildGuidance(decoded, options)
				if err != nil || code != 0 {
					t.Fatalf("%s readmission exit=%d err=%v", target.name, code, err)
				}
				want := []string{"go test ./internal/command/gradualadoption"}
				for _, operation := range []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"} {
					argv := append(append([]string{}, target.prefix...), operation, "--input", wantSource[operation].(string))
					want = append(want, cliexec.DisplayArgv(argv))
				}
				assertInvocationCommands(t, report, want)
				assertInvocationNativeCommands(t, report, []string{"go test ./internal/command/gradualadoption"})
				envelope, code, err := BuildGuidanceEnvelope(decoded, options)
				if err != nil || code != 0 {
					t.Fatalf("%s envelope exit=%d err=%v", target.name, code, err)
				}
				assertInvocationEnvelope(t, envelope, target, wantSource)
				if err := schemacheck.Validate(GuidanceEnvelopeStructure(), envelope); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestGuidancePreparedCommandAdmissionRetainsCollectedFailures(t *testing.T) {
	cases := []struct {
		name    string
		present bool
		value   any
		failed  bool
	}{
		{"absent", false, nil, false}, {"empty", true, map[string]any{}, false},
		{"null", true, nil, true}, {"array", true, []any{}, true}, {"text", true, "witness-plan", true},
		{"boolean", true, false, true}, {"number", true, json.Number("1"), true},
		{"unknown", true, map[string]any{"witness-plan": "inputs/valid.json", "other": "inputs/other.json"}, true},
	}
	for _, operation := range []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"} {
		for index, value := range []any{nil, false, json.Number("1"), []any{}, map[string]any{}, "", "-", "../outside", "/outside", "./inputs/file", "inputs//file", `inputs\file`, "inputs/line\nbreak", "api_key=synthetic-fixture"} {
			cases = append(cases, struct {
				name    string
				present bool
				value   any
				failed  bool
			}{fmt.Sprintf("%s/%d", operation, index), true, map[string]any{operation: value}, true})
		}
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validGuidanceInput()
			if item.present {
				input["agentGuidance"].(map[string]any)["proofkitCommands"] = item.value
			}
			for _, build := range []func(any, GuidanceOptions) (map[string]any, int, error){BuildGuidance, BuildGuidanceEnvelope} {
				output, code, err := build(invocationJSON(t, input), GuidanceOptions{})
				if err != nil || (code != 0) != item.failed {
					t.Fatalf("collected failure changed phase: exit=%d err=%v", code, err)
				}
				for _, raw := range anyArrayFromMap(output, "commands") {
					if _, typed := raw.(map[string]any)["argv"]; typed {
						t.Fatal("invalid or absent operation produced argv")
					}
				}
				assertNoBootstrapDisclosure(t, output, err, []string{"synthetic-fixture"})
				schema := GuidanceOutputStructure()
				if _, envelope := output["sourceReport"]; envelope {
					schema = GuidanceEnvelopeStructure()
				}
				if err := schemacheck.Validate(schema, output); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestGuidancePreparedPathsAndCallerPrivacyStayIndependent(t *testing.T) {
	profile := invocationProfiles(t)[3]
	for _, path := range []string{"inputs/witness file.json ", " - ", "inputs/-", "inputs/task-validation.json", "inputs/quoted'file;name.json"} {
		input := validGuidanceInput()
		input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": path}
		envelope, code, err := BuildGuidanceEnvelope(invocationJSON(t, input), GuidanceOptions{Renderer: profile.renderer})
		if err != nil || code != 0 {
			t.Fatalf("canonical input path refused: exit=%d err=%v", code, err)
		}
		assertInvocationEnvelope(t, envelope, profile, map[string]any{"witness-plan": path})
	}
	for _, fixture := range admit.ReportVisibleRedactionFixtures() {
		input := validGuidanceInput()
		agent := input["agentGuidance"].(map[string]any)
		agent["commands"] = []any{fixture.Input}
		agent["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness.json"}
		for _, build := range []func(any, GuidanceOptions) (map[string]any, int, error){BuildGuidance, BuildGuidanceEnvelope} {
			output, code, err := build(invocationJSON(t, input), GuidanceOptions{Renderer: profile.renderer})
			if err != nil || code != 1 {
				t.Fatalf("caller privacy was weakened: exit=%d err=%v", code, err)
			}
			assertNoBootstrapDisclosure(t, output, err, fixture.SensitiveNeedles)
		}
	}
	input := validGuidanceInput()
	input["agentGuidance"].(map[string]any)["commands"] = []any{"go test ./... && curl example.test"}
	input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness.json"}
	if _, code, err := BuildGuidance(input, GuidanceOptions{}); err != nil || code != 1 {
		t.Fatal("typed source bypassed caller shell-control policy")
	}
	input = validGuidanceInput()
	input["agentGuidance"].(map[string]any)["commands"] = []any{profile.renderer.DisplayCommand("witness-plan", "--input", "inputs/witness.json")}
	input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness.json"}
	if _, code, err := BuildGuidance(input, GuidanceOptions{Renderer: profile.renderer}); err != nil || code != 1 {
		t.Fatal("equal generated display text bypassed caller scalar privacy")
	}
	input = validGuidanceInput()
	input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{
		"gradual-adoption": "../outside", "witness-plan": "inputs/witness.json",
	}
	envelope, code, err := BuildGuidanceEnvelope(input, GuidanceOptions{Renderer: profile.renderer})
	if err != nil || code != 1 {
		t.Fatal("mixed path failures did not remain collected")
	}
	assertInvocationEnvelope(t, envelope, profile, map[string]any{"witness-plan": "inputs/witness.json"})
}

func TestGuidanceDuplicateOperationsAreRejectedByJSONAdmission(t *testing.T) {
	input := validGuidanceInput()
	input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(encoded), `"proofkitCommands":{}`, `"proofkitCommands":{"witness-plan":"inputs/a","witness-plan":"inputs/b"}`, 1)
	if text == string(encoded) {
		t.Fatal("duplicate-key witness did not modify its target")
	}
	if _, err := admission.DecodeJSON(strings.NewReader(text), int64(len(text))); err == nil {
		t.Fatal("duplicate operation escaped native JSON admission")
	}
}

func TestPreparedCommandProjectionOwnsCopiesAndNoTextConfersAuthority(t *testing.T) {
	bootstrap := validBootstrapInput()
	result, err := BuildBootstrapResult(bootstrap)
	if err != nil || result.ExitCode != 0 {
		t.Fatal(err)
	}
	before := result.PreparedCommands()
	if len(before) != 3 {
		t.Fatal("prepared command projection is incomplete")
	}
	argv := before[0].Argv()
	argv[len(argv)-1] = "changed"
	before[0] = PreparedCommand{}
	bootstrap["paths"].(map[string]any)["adoptionProfilePath"] = "inputs/mutated.json"
	result.Payloads["adoptionGuidance"].(map[string]any)["agentGuidance"].(map[string]any)["proofkitCommands"].(map[string]any)["gradual-adoption"] = "inputs/mutated.json"
	if result.PreparedCommands()[0].InputRef() != "proofkit/profile.json" || result.PreparedCommands()[0].Argv()[3] != "proofkit/profile.json" {
		t.Fatal("getter exposed mutable canonical command storage")
	}
	input := validGuidanceInput()
	input["agentGuidance"].(map[string]any)["commands"] = []any{result.PreparedCommands()[0].DisplayCommand()}
	envelope, code, err := BuildGuidanceEnvelope(input, GuidanceOptions{})
	if err != nil || code != 0 {
		t.Fatal(err)
	}
	for _, raw := range envelope["commands"].([]any) {
		if _, typed := raw.(map[string]any)["argv"]; typed {
			t.Fatal("equal text without a declaration acquired argv authority")
		}
	}
}

func TestBootstrapInvalidPreparedPathsRetainFailedReports(t *testing.T) {
	for _, field := range []string{"adoptionProfilePath", "adoptionGuidancePath", "witnessPlanInputPath"} {
		for _, value := range []any{nil, false, "", "../outside"} {
			input := validBootstrapInput()
			input["paths"].(map[string]any)[field] = value
			result, err := BuildBootstrapResult(input)
			if err != nil || result.ExitCode != 1 {
				t.Fatalf("collected bootstrap failure became Go error: %v", err)
			}
			if len(result.PreparedCommands()) != 2 {
				t.Fatal("invalid path became a prepared command")
			}
			for _, command := range result.PreparedCommands() {
				if command.InputRef() == "" {
					t.Fatal("empty normalized path produced argv")
				}
			}
			if _, code, err := BuildBootstrapEnvelope(input); err != nil || code != 1 {
				t.Fatal("failed envelope changed refusal phase")
			}
		}
	}
}

func TestGuidancePreparedEnvelopeBoundsPruneExactDependencies(t *testing.T) {
	input := validGuidanceInput()
	input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness.json"}
	input["ownerRoute"].(map[string]any)["evidencePaths"] = []any{}
	for index := 0; index < agentenvelope.MaxContextRefs+4; index++ {
		input["ownerRoute"].(map[string]any)["evidencePaths"] = append(input["ownerRoute"].(map[string]any)["evidencePaths"].([]any), fmt.Sprintf("inputs/evidence-%03d.json", index))
	}
	envelope, _, err := BuildGuidanceEnvelope(input, GuidanceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope["contextRefs"].([]any)) > agentenvelope.MaxContextRefs {
		t.Fatal("context bound exceeded")
	}
	if omitted := envelope["omitted"].([]any); len(omitted) == 0 {
		t.Fatal("bounds witness did not exercise omissions")
	}
	refs := map[any]bool{}
	for _, raw := range envelope["contextRefs"].([]any) {
		refs[raw.(map[string]any)["ref"]] = true
	}
	for _, raw := range envelope["commands"].([]any) {
		command := raw.(map[string]any)
		if _, typed := command["argv"]; typed && !refs["inputs/witness.json"] {
			t.Fatal("typed command survived without its exact input context")
		}
	}
	input = validGuidanceInput()
	input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{
		"gradual-adoption": "inputs/profile.json", "witness-plan": "inputs/witness.json",
	}
	result, err := buildGuidance(input, GuidanceOptions{})
	if err != nil || result.ExitCode != 0 {
		t.Fatal(err)
	}
	// A projection fault must not let one invalid context authorize its argv.
	result.preparedCommands[0].inputRef = "../outside"
	result.Guidance["commands"] = admit.StringSliceToAny(preparedCommandDisplays(nil, result.preparedCommands))
	envelope = guidanceEnvelope(result)
	assertInvocationEnvelope(t, envelope, invocationProfiles(t)[0], map[string]any{"witness-plan": "inputs/witness.json"})
	if len(envelope["omitted"].([]any)) == 0 {
		t.Fatal("invalid context did not report its exact dependent omission")
	}
	bootstrap, err := BuildBootstrapResult(validBootstrapInput())
	if err != nil || bootstrap.ExitCode != 0 {
		t.Fatal(err)
	}
	for index, raw := range bootstrap.PlannedFiles {
		file := raw.(map[string]any)
		if file["payloadKey"] == "witnessPlanInput" {
			bootstrap.PlannedFiles = append(bootstrap.PlannedFiles[:index], bootstrap.PlannedFiles[index+1:]...)
			break
		}
	}
	envelope = BootstrapEnvelope(bootstrap)
	assertInvocationEnvelope(t, envelope, invocationProfiles(t)[0], map[string]any{
		"gradual-adoption": "proofkit/profile.json", "gradual-adoption-guidance": "proofkit/guidance.json",
	})
	if len(envelope["omitted"].([]any)) == 0 {
		t.Fatal("missing materialized role did not prune its exact command")
	}
}

func invocationJSON(t *testing.T, value any) any {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func invocationGuidance(t *testing.T, report map[string]any) map[string]any {
	t.Helper()
	for _, raw := range report["diagnostics"].([]any) {
		diagnostic := raw.(map[string]any)
		if diagnostic["key"] == "guidance" {
			return diagnostic["value"].(map[string]any)
		}
	}
	t.Fatal("report has no guidance projection")
	return nil
}

func assertInvocationCommands(t *testing.T, report map[string]any, want []string) {
	t.Helper()
	guidance := invocationGuidance(t, report)
	if !reflect.DeepEqual(anyStrings(guidance["commands"]), want) || report["summary"].(map[string]any)["commandCount"] != len(want) {
		t.Fatalf("derived union/totals disagree: want %#v", want)
	}
}

func assertInvocationNativeCommands(t *testing.T, report map[string]any, native []string) {
	t.Helper()
	guidance := invocationGuidance(t, report)
	found := false
	for _, raw := range guidance["agentActionPlan"].([]any) {
		action := raw.(map[string]any)
		if action["phase"] == "verify" {
			found = true
			if !reflect.DeepEqual(anyStrings(action["commands"]), native) {
				t.Fatal("verify action must contain only independently admitted caller commands")
			}
		}
	}
	if !found {
		t.Fatal("verify action was not exercised")
	}
}

func TestGuidanceActionsKeepPreparedAndCallerCommandsSeparate(t *testing.T) {
	prepared := "agentic-proofkit witness-plan --input inputs/witness.json"
	caller := "go test ./internal/command/gradualadoption -count=1"
	for _, item := range []struct {
		name     string
		caller   []string
		prepared bool
		union    []string
	}{
		{"only prepared", []string{}, true, []string{prepared}},
		{"only caller", []string{caller}, false, []string{caller}},
		{"mixed", []string{caller}, true, []string{caller, prepared}},
		{"dual display", []string{prepared}, true, []string{prepared}},
	} {
		t.Run(item.name, func(t *testing.T) {
			input := validGuidanceInput()
			agent := input["agentGuidance"].(map[string]any)
			agent["commands"] = admit.StringSliceToAny(item.caller)
			if item.prepared {
				agent["proofkitCommands"] = map[string]any{"witness-plan": "inputs/witness.json"}
			}
			report, code, err := BuildGuidance(input, GuidanceOptions{})
			if err != nil || code != 0 {
				t.Fatalf("guidance exit=%d err=%v", code, err)
			}
			assertInvocationCommands(t, report, item.union)
			assertInvocationNativeCommands(t, report, item.caller)
			guidance := invocationGuidance(t, report)
			wantPrepared := []string{}
			if item.prepared {
				wantPrepared = append(wantPrepared, prepared)
			}
			for _, raw := range guidance["agentActionPlan"].([]any) {
				action := raw.(map[string]any)
				if action["stepId"] == "proofkit.agent.route-owner" && !reflect.DeepEqual(anyStrings(action["commands"]), wantPrepared) {
					t.Fatal("planning operations must remain available on the route step")
				}
			}
			envelope, code, err := BuildGuidanceEnvelope(input, GuidanceOptions{})
			if err != nil || code != 0 {
				t.Fatalf("envelope exit=%d err=%v", code, err)
			}
			byID := map[any]string{}
			for _, raw := range envelope["commands"].([]any) {
				command := raw.(map[string]any)
				byID[command["commandId"]] = command["command"].(string)
				if item.prepared && command["command"] == prepared && !strings.Contains(command["purpose"].(string), "planning or inspection") {
					t.Fatal("prepared operation was labelled as only a native witness")
				}
			}
			for _, raw := range envelope["actionPlan"].([]any) {
				action := raw.(map[string]any)
				want := []string{}
				switch action["stepId"] {
				case "proofkit.agent.route-owner":
					want = wantPrepared
				case "proofkit.agent.run-native-witnesses":
					want = item.caller
				}
				got := []string{}
				for _, id := range action["commandIds"].([]any) {
					command, exists := byID[id]
					if !exists {
						t.Fatal("action retained an unresolved command ID")
					}
					got = append(got, command)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: commands=%#v want %#v", action["stepId"], got, want)
				}
			}
			if err := schemacheck.Validate(GuidanceOutputStructure(), report); err != nil {
				t.Fatal(err)
			}
			if err := schemacheck.Validate(GuidanceEnvelopeStructure(), envelope); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertInvocationEnvelope(t *testing.T, envelope map[string]any, profile invocationProfile, source map[string]any) {
	t.Helper()
	want := map[string]bool{}
	for operation, path := range source {
		argv := append(append([]string{}, profile.prefix...), operation, "--input", path.(string))
		bytes, _ := json.Marshal(argv)
		want[string(bytes)] = true
	}
	contexts := map[any]bool{}
	for _, raw := range envelope["contextRefs"].([]any) {
		contexts[raw.(map[string]any)["ref"]] = true
	}
	found := 0
	for _, raw := range envelope["commands"].([]any) {
		command := raw.(map[string]any)
		argv, typed := command["argv"]
		if !typed {
			continue
		}
		bytes, _ := json.Marshal(argv)
		if !want[string(bytes)] {
			t.Fatalf("%s: unexpected typed argv %s", profile.name, bytes)
		}
		delete(want, string(bytes))
		values := argv.([]any)
		if !contexts[values[len(values)-1]] {
			t.Fatal("prepared argv lost its materialized input context")
		}
		found++
	}
	if len(want) != 0 || found != len(source) {
		t.Fatalf("%s: typed commands=%d want %d", profile.name, found, len(source))
	}
}
