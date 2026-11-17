package app

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type guidanceInvocationProfile struct {
	name     string
	renderer cliexec.Renderer
}

func guidanceInvocationProfiles(t *testing.T) []guidanceInvocationProfile {
	t.Helper()
	profiles := []struct{ name, profile, executable string }{
		{"path", cliexec.ProfilePath, ""},
		{"npm offline", cliexec.ProfileNPMOffline, ""},
		{"python ordinary", cliexec.ProfilePythonModule, "/opt/venv/bin/python"},
		{"python path privacy", cliexec.ProfilePythonModule, "/opt/task-validation/bin/python"},
		{"python spaces", cliexec.ProfilePythonModule, "/opt/proofkit venv/bin/python"},
	}
	result := make([]guidanceInvocationProfile, 0, len(profiles))
	for _, profile := range profiles {
		renderer, err := cliexec.AdmitLauncherProfile(profile.profile, profile.executable)
		if err != nil {
			t.Fatalf("admit %s: %v", profile.name, err)
		}
		result = append(result, guidanceInvocationProfile{profile.name, renderer})
	}
	return result
}

func TestGuidanceInvocationPortableSourceCLIReadmission(t *testing.T) {
	aggregate := invocationProfileObject(t, invocationProfileJSON(t, cliAdoptionContractEnvelopeInput()))
	gradual := invocationProfileObjectValue(t, aggregate["gradual"], "gradual contract")
	paths := invocationProfileObjectValue(t, invocationProfileObjectValue(t, gradual["bootstrap"], "bootstrap contract")["paths"], "bootstrap paths")
	paths["adoptionProfilePath"] = "inputs/adoption profile.json "
	paths["adoptionGuidancePath"] = "inputs/adoption guidance.json "
	paths["witnessPlanInputPath"] = "inputs/witness plan.json "
	bootstrap, err := gradualadoption.BootstrapInputFromContractEnvelope(gradual)
	if err != nil {
		t.Fatal(err)
	}
	source := invocationProfilePreparedSource(t, bootstrap)
	caller := invocationProfileStrings(t, bootstrap["commands"], "caller commands")
	profiles := guidanceInvocationProfiles(t)
	var canonical string
	for _, producer := range profiles {
		t.Run(producer.name, func(t *testing.T) {
			baseline := invocationProfileRun(t, producer.renderer, []string{"gradual-adoption-bootstrap", "--input", "-"}, invocationProfileEncode(t, bootstrap))
			adoptionProfile := invocationProfileObjectValue(t, baseline["payloads"], "bootstrap payloads")["adoptionProfile"]
			manifest := invocationProfileRun(t, producer.renderer, []string{"gradual-adoption-bootstrap", "--input", "-", "--materialization-manifest"}, invocationProfileEncode(t, bootstrap))
			saved := guidanceInvocationSavedSource(t, manifest, source)
			if canonical == "" {
				canonical = saved
			}
			if saved != canonical {
				t.Fatal("saved guidance JSON depends on its producer renderer")
			}
			routes := []struct {
				name  string
				args  []string
				input any
			}{
				{"direct", []string{"gradual-adoption-bootstrap", "--input", "-"}, bootstrap},
				{"pointer", []string{"gradual-adoption-bootstrap", "--input", "-", "--input-pointer", "/payload/bootstrap~1input"}, map[string]any{"payload": map[string]any{"bootstrap/input": bootstrap}}},
				{"contract", []string{"gradual-adoption-bootstrap", "--input", "-", "--contract-envelope"}, gradual},
				{"aggregate", []string{"adoption-contract-envelope", "--input", "-", "--mode", "bootstrap"}, aggregate},
			}
			for _, route := range routes {
				t.Run("bootstrap/"+route.name, func(t *testing.T) {
					output := invocationProfileRun(t, producer.renderer, route.args, invocationProfileEncode(t, route.input))
					invocationProfileAssertSourceInventory(t, output, []string{"$.payloads.adoptionGuidance.agentGuidance"}, caller, source)
					guidanceInvocationAssertBootstrapCommands(t, producer.renderer, output, source)
					payloads := invocationProfileObjectValue(t, output["payloads"], "bootstrap payloads")
					payload, err := stablejson.Marshal(payloads["adoptionGuidance"])
					if err != nil {
						t.Fatal(err)
					}
					manifest := invocationProfileRun(t, producer.renderer, append(append([]string{}, route.args...), "--materialization-manifest"), invocationProfileEncode(t, route.input))
					invocationProfileAssertSourceInventory(t, manifest, []string{"$.files[?payloadKey=adoptionGuidance].content::$.agentGuidance"}, caller, source)
					content := guidanceInvocationSavedSource(t, manifest, source)
					if content != string(payload) {
						t.Fatal("materialized guidance bytes differ from the bootstrap source payload")
					}
					if content != canonical {
						t.Fatal("saved guidance JSON depends on its CLI carrier or producer renderer")
					}
					envelope := invocationProfileRun(t, producer.renderer, append(append([]string{}, route.args...), "--agent-envelope"), invocationProfileEncode(t, route.input))
					ids := guidanceInvocationAssertEnvelope(t, producer.renderer, envelope, source, nil, map[string]string{
						"gradual-adoption": "owner_surface", "gradual-adoption-guidance": "supporting", "witness-plan": "command_registry",
					})
					guidanceInvocationAssertActionCommands(t, envelope["actionPlan"], "verify", "commandIds", ids)
				})
			}
			prepared, err := gradualadoption.BuildBootstrapResultWithRenderer(invocationProfileJSON(t, bootstrap), producer.renderer)
			if err != nil || prepared.ExitCode != 0 {
				t.Fatalf("canonical bootstrap projection exit=%d err=%v", prepared.ExitCode, err)
			}
			commands := prepared.PreparedCommands()
			if len(commands) != len(source) {
				t.Fatalf("prepared command count=%d want %d", len(commands), len(source))
			}
			for index, operation := range []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"} {
				command := commands[index]
				wantArgv := producer.renderer.Argv(operation, "--input", source[operation].(string))
				if command.Command() != operation || command.InputRef() != source[operation] || !reflect.DeepEqual(command.Argv(), wantArgv) || command.DisplayCommand() != cliexec.DisplayArgv(wantArgv) {
					t.Fatalf("canonical command %s lost its exact operation, input or actual renderer", operation)
				}
			}
			for _, consumer := range profiles {
				t.Run("readmit/"+consumer.name, func(t *testing.T) {
					guidanceInvocationReadmitCLI(t, consumer.renderer, saved, adoptionProfile, caller, source)
				})
			}
		})
	}
}

func guidanceInvocationSavedSource(t *testing.T, manifest map[string]any, source map[string]any) string {
	t.Helper()
	payloadPaths := map[string]any{}
	content := ""
	for _, raw := range invocationProfileArray(t, manifest["files"], "manifest files") {
		file := invocationProfileObjectValue(t, raw, "manifest file")
		key, ok := file["payloadKey"].(string)
		if !ok {
			continue
		}
		if _, duplicate := payloadPaths[key]; duplicate {
			t.Fatalf("duplicate materialized payload %s", key)
		}
		payloadPaths[key] = file["path"]
		if key == "adoptionGuidance" {
			content, ok = file["content"].(string)
			if !ok || content == "" || file["contentSha256"] != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content))) {
				t.Fatal("saved guidance content/hash is missing or inconsistent")
			}
		}
	}
	for operation, key := range map[string]string{"gradual-adoption": "adoptionProfile", "gradual-adoption-guidance": "adoptionGuidance", "witness-plan": "witnessPlanInput"} {
		if payloadPaths[key] != source[operation] {
			t.Fatalf("%s input=%#v is not the materialized %s path %#v", operation, source[operation], key, payloadPaths[key])
		}
	}
	if content == "" {
		t.Fatal("guidance materialization was not exercised")
	}
	return content
}

func guidanceInvocationReadmitCLI(t *testing.T, renderer cliexec.Renderer, saved string, adoptionProfile any, caller []string, source map[string]any) {
	t.Helper()
	input := invocationProfileObject(t, invocationProfileJSON(t, saved))
	contract := map[string]any{
		"schema": "proofkit.gradual-adoption-profile.v1", "input": adoptionProfile,
		"guidance": map[string]any{
			"guidanceId": input["guidanceId"], "defaultMode": input["guidanceMode"],
			"agentGuidance": input["agentGuidance"], "ownerRoute": input["ownerRoute"],
			"nonClaims": input["nonClaims"], "scopeEvidence": map[string]any{"checkedScope": "all", "touchedRuleIds": []any{}},
		},
	}
	aggregate := invocationProfileObject(t, invocationProfileJSON(t, cliAdoptionContractEnvelopeInput()))
	aggregateGradual := invocationProfileObject(t, invocationProfileJSON(t, contract))
	aggregateGradual["bootstrap"] = map[string]any{}
	aggregate["gradual"] = aggregateGradual
	type route struct {
		name, stdin string
		args        []string
		mode, scope string
	}
	routes := []route{
		{"direct", saved, []string{"gradual-adoption-guidance", "--input", "-"}, "observe", "none"},
		{"pointer", invocationProfileEncode(t, map[string]any{"payload": map[string]any{"guidance/input": input}}), []string{"gradual-adoption-guidance", "--input", "-", "--input-pointer", "/payload/guidance~1input"}, "observe", "none"},
	}
	for mask := 0; mask < 8; mask++ {
		flags := []string{}
		mode, scope := "observe", "all"
		if mask&1 != 0 {
			flags = append(flags, "--guidance-mode", "warn")
			mode = "warn"
		}
		if mask&2 != 0 {
			flags = append(flags, "--checked-scope", "touched")
			scope = "touched"
		}
		if mask&4 != 0 {
			flags = append(flags, "--touched-rule-id", "proofkit.cli.guidance.changed")
		}
		routes = append(routes,
			route{fmt.Sprintf("contract-%03b", mask), invocationProfileEncode(t, contract), append([]string{"gradual-adoption-guidance", "--input", "-", "--contract-envelope"}, flags...), mode, scope},
			route{fmt.Sprintf("aggregate-%03b", mask), invocationProfileEncode(t, aggregate), append([]string{"adoption-contract-envelope", "--input", "-", "--mode", "guidance"}, flags...), mode, scope},
		)
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			report := invocationProfileRun(t, renderer, route.args, route.stdin)
			guidance := invocationProfileObjectValue(t, invocationProfileDiagnostic(t, report, "guidance"), "guidance diagnostic")
			invocationProfileAssertCallerAndGenerated(t, renderer, invocationProfileStrings(t, guidance["commands"], "guidance commands"), caller)
			want := append(append([]string{}, caller...), guidanceInvocationDisplays(renderer, source)...)
			guidanceInvocationAssertCommands(t, guidance["commands"], want)
			summary := invocationProfileObjectValue(t, report["summary"], "guidance summary")
			if summary["guidanceMode"] != route.mode || summary["checkedScope"] != route.scope || summary["commandCount"] != json.Number(fmt.Sprint(len(want))) {
				t.Fatalf("guidance override/count projection drifted: %#v", summary)
			}
			guidanceInvocationAssertActionCommands(t, guidance["agentActionPlan"], "verify", "commands", caller)
			guidanceInvocationAssertActionCommands(t, guidance["agentActionPlan"], "route", "commands", guidanceInvocationDisplays(renderer, source))
			envelope := invocationProfileRun(t, renderer, append(append([]string{}, route.args...), "--agent-envelope"), route.stdin)
			ids := guidanceInvocationAssertEnvelope(t, renderer, envelope, source, caller, nil)
			guidanceInvocationAssertActionCommands(t, envelope["actionPlan"], "verify", "commandIds", ids[:len(caller)])
			guidanceInvocationAssertActionCommands(t, envelope["actionPlan"], "route", "commandIds", ids[len(caller):])
		})
	}
}

func guidanceInvocationDisplays(renderer cliexec.Renderer, source map[string]any) []string {
	commands := []string{}
	for _, operation := range []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"} {
		commands = append(commands, renderer.DisplayCommand(operation, "--input", source[operation].(string)))
	}
	return commands
}

func guidanceInvocationAssertCommands(t *testing.T, raw any, want []string) {
	t.Helper()
	if got := invocationProfileStrings(t, raw, "commands"); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands=%#v want exact %#v", got, want)
	}
}

func guidanceInvocationAssertActionCommands(t *testing.T, raw any, phase, field string, want []string) {
	t.Helper()
	found := 0
	for _, raw := range invocationProfileArray(t, raw, "action plan") {
		action := invocationProfileObjectValue(t, raw, "action")
		if action["phase"] == phase {
			found++
			guidanceInvocationAssertCommands(t, action[field], want)
		}
	}
	if found != 1 {
		t.Fatalf("%s actions=%d want 1", phase, found)
	}
}

func guidanceInvocationAssertBootstrapCommands(t *testing.T, renderer cliexec.Renderer, output map[string]any, source map[string]any) {
	t.Helper()
	want := guidanceInvocationDisplays(renderer, source)
	guidanceInvocationAssertCommands(t, output["nextCommands"], want)
	guidanceInvocationAssertActionCommands(t, output["agentActionPlan"], "verify", "commands", want)
	report := invocationProfileObjectValue(t, output["report"], "bootstrap report")
	guidanceInvocationAssertCommands(t, invocationProfileDiagnostic(t, report, "nextCommands"), want)
	guidanceInvocationAssertActionCommands(t, invocationProfileDiagnostic(t, report, "agentActionPlan"), "verify", "commands", want)
}

func guidanceInvocationAssertEnvelope(t *testing.T, renderer cliexec.Renderer, envelope map[string]any, source map[string]any, caller []string, roles map[string]string) []string {
	t.Helper()
	want := append(append([]string{}, caller...), guidanceInvocationDisplays(renderer, source)...)
	displays, ids := []string{}, []string{}
	contexts := map[any]map[string]any{}
	for _, raw := range invocationProfileArray(t, envelope["contextRefs"], "context refs") {
		context := invocationProfileObjectValue(t, raw, "context ref")
		contexts[context["ref"]] = context
	}
	commands := invocationProfileArray(t, envelope["commands"], "envelope commands")
	if len(commands) != len(want) {
		t.Fatalf("envelope command count=%d want %d", len(commands), len(want))
	}
	for index, raw := range commands {
		command := invocationProfileObjectValue(t, raw, "envelope command")
		displays = append(displays, command["command"].(string))
		ids = append(ids, command["commandId"].(string))
		if index < len(caller) {
			if _, typed := command["argv"]; typed {
				t.Fatal("caller-only command text acquired argv authority")
			}
			continue
		}
		operation := []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"}[index-len(caller)]
		argv := invocationProfileStrings(t, command["argv"], "typed argv")
		if !reflect.DeepEqual(argv, renderer.Argv(operation, "--input", source[operation].(string))) || command["command"] != cliexec.DisplayArgv(argv) {
			t.Fatalf("%s lost its exact command/input or actual renderer: %#v", operation, command)
		}
		context, exists := contexts[source[operation]]
		if !exists || context["kind"] != "path" || context["owner"] != "consumer_repository" {
			t.Fatalf("%s input context is missing or changed: %#v", operation, context)
		}
		role := "command_registry"
		if roles != nil {
			role = roles[operation]
		}
		if context["role"] != role {
			t.Fatalf("%s input context role=%v want %s", operation, context["role"], role)
		}
	}
	if !reflect.DeepEqual(displays, want) {
		t.Fatalf("envelope commands=%#v want exact %#v", displays, want)
	}
	if omitted := invocationProfileArray(t, envelope["omitted"], "omitted items"); len(omitted) != 0 {
		t.Fatalf("valid exact invocations were omitted: %#v", omitted)
	}
	return ids
}
