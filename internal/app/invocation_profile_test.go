package app

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestGeneratedCommandInvocationProfileFieldInventory(t *testing.T) {
	aggregate := invocationProfileObject(t, invocationProfileJSON(t, cliAdoptionContractEnvelopeInput()))
	gradual := invocationProfileObjectValue(t, aggregate["gradual"], "aggregate gradual")
	bootstrapInput, err := gradualadoption.BootstrapInputFromContractEnvelope(gradual)
	if err != nil {
		t.Fatalf("derive bootstrap input: %v", err)
	}
	callerCommands := invocationProfileStrings(t, bootstrapInput["commands"], "bootstrap caller commands")
	projectInput := invocationProfileProjectInput(bootstrapInput)

	profiles := []struct {
		name             string
		profile          string
		pythonExecutable string
	}{
		{name: "npm offline", profile: cliexec.ProfileNPMOffline},
		{name: "python module", profile: cliexec.ProfilePythonModule, pythonExecutable: "/tmp/proofkit venv/bin/python"},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			renderer, err := cliexec.AdmitLauncherProfile(profile.profile, profile.pythonExecutable)
			if err != nil {
				t.Fatalf("admit renderer: %v", err)
			}

			stack := invocationProfileRun(t, renderer, []string{"stack-preset", "--preset", "typescript_workspace"}, "")
			invocationProfileAssertInventory(t, renderer, stack, map[string]int{
				"$.diagnostics[?key=preset].value.suggestedCommands[*]": 2,
			}, len(callerCommands))
			preset := invocationProfileDiagnostic(t, stack, "preset")
			invocationProfileAssertGenerated(t, renderer, invocationProfileStrings(t, invocationProfileObjectValue(t, preset, "preset diagnostic")["suggestedCommands"], "preset suggested commands"))

			directBootstrap := invocationProfileRun(t, renderer, []string{"gradual-adoption-bootstrap", "--input", "-", "--contract-envelope"}, invocationProfileEncode(t, gradual))
			bootstrapInventory := invocationProfileBootstrapInventory("$")
			invocationProfileAssertInventory(t, renderer, directBootstrap, bootstrapInventory, len(callerCommands))
			invocationProfileAssertBootstrap(t, renderer, directBootstrap, callerCommands)
			invocationProfileAssertInventoryMutants(t, renderer, directBootstrap, bootstrapInventory, callerCommands)

			directEnvelope := invocationProfileRun(t, renderer, []string{"gradual-adoption-bootstrap", "--input", "-", "--contract-envelope", "--agent-envelope"}, invocationProfileEncode(t, gradual))
			invocationProfileAssertInventory(t, renderer, directEnvelope, map[string]int{
				"$.commands[*].command": 3,
			}, len(callerCommands))
			invocationProfileAssertEnvelope(t, renderer, directEnvelope)

			directManifest := invocationProfileRun(t, renderer, []string{"gradual-adoption-bootstrap", "--input", "-", "--contract-envelope", "--materialization-manifest"}, invocationProfileEncode(t, gradual))
			invocationProfileAssertInventory(t, renderer, directManifest, map[string]int{
				"$.files[?payloadKey=adoptionGuidance].content::$.agentGuidance.commands[callerCommandCount:]": 3,
				"$.nextCommands[*]": 3,
			}, len(callerCommands))
			invocationProfileAssertManifest(t, renderer, directManifest, callerCommands)

			aggregateBootstrap := invocationProfileRun(t, renderer, []string{"adoption-contract-envelope", "--input", "-", "--mode", "bootstrap"}, invocationProfileEncode(t, aggregate))
			if !reflect.DeepEqual(aggregateBootstrap, directBootstrap) {
				t.Fatal("adoption aggregate bootstrap route did not preserve the admitted renderer")
			}
			aggregateEnvelope := invocationProfileRun(t, renderer, []string{"adoption-contract-envelope", "--input", "-", "--mode", "bootstrap", "--agent-envelope"}, invocationProfileEncode(t, aggregate))
			if !reflect.DeepEqual(aggregateEnvelope, directEnvelope) {
				t.Fatal("adoption aggregate envelope route did not preserve the admitted renderer")
			}
			aggregateManifest := invocationProfileRun(t, renderer, []string{"adoption-contract-envelope", "--input", "-", "--mode", "bootstrap", "--materialization-manifest"}, invocationProfileEncode(t, aggregate))
			if !reflect.DeepEqual(aggregateManifest, directManifest) {
				t.Fatal("adoption aggregate materialization route did not preserve the admitted renderer")
			}

			project := invocationProfileRun(t, renderer, []string{"scaffold-project-structure", "--input", "-"}, invocationProfileEncode(t, projectInput))
			projectInventory := invocationProfileBootstrapInventory("$.bootstrapReport")
			projectInventory["$.materializationManifest.files[?purpose=caller-owned gradual adoption guidance input].content::$.agentGuidance.commands[callerCommandCount:]"] = 3
			projectInventory["$.materializationManifest.nextCommands[*]"] = 6
			invocationProfileAssertInventory(t, renderer, project, projectInventory, len(callerCommands))
			invocationProfileAssertBootstrap(t, renderer, invocationProfileObjectValue(t, project["bootstrapReport"], "project bootstrap report"), callerCommands)
			invocationProfileAssertManifest(t, renderer, invocationProfileObjectValue(t, project["materializationManifest"], "project materialization manifest"), callerCommands)

			projectEnvelope := invocationProfileRun(t, renderer, []string{"scaffold-project-structure", "--input", "-", "--agent-envelope"}, invocationProfileEncode(t, projectInput))
			invocationProfileAssertInventory(t, renderer, projectEnvelope, map[string]int{
				"$.commands[*].command": 6,
			}, len(callerCommands))
			invocationProfileAssertEnvelope(t, renderer, projectEnvelope)
		})
	}
}

func TestGeneratedCommandInvocationProfileRouteClosure(t *testing.T) {
	aggregate := invocationProfileObject(t, invocationProfileJSON(t, cliAdoptionContractEnvelopeInput()))
	gradual := invocationProfileObjectValue(t, aggregate["gradual"], "aggregate gradual")
	bootstrapInput, err := gradualadoption.BootstrapInputFromContractEnvelope(gradual)
	if err != nil {
		t.Fatalf("derive bootstrap input: %v", err)
	}
	projectInput := invocationProfileProjectInput(bootstrapInput)

	profiles := []struct {
		name             string
		profile          string
		pythonExecutable string
	}{
		{name: "path", profile: cliexec.ProfilePath},
		{name: "npm offline", profile: cliexec.ProfileNPMOffline},
		{name: "python module", profile: cliexec.ProfilePythonModule, pythonExecutable: "/tmp/proofkit venv/bin/python"},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			renderer, err := cliexec.AdmitLauncherProfile(profile.profile, profile.pythonExecutable)
			if err != nil {
				t.Fatalf("admit renderer: %v", err)
			}
			invocationProfileAssertHelpRouteClosure(t, renderer)

			agentRouteInput := map[string]any{
				"schemaVersion": json.Number("1"),
				"routeId":       "proofkit.cli.invocation-profile-route",
				"goal":          "validate_requirement_source",
				"mode":          "observe",
				"availableInputs": []any{
					map[string]any{"kind": "requirement_source", "ref": "docs/specs/module/requirements.v1.json"},
				},
			}
			agentRoute := invocationProfileRun(t, renderer, []string{"agent-route", "--input", "-"}, invocationProfileEncode(t, agentRouteInput))
			agentRouteInventory := map[string]int{"$.nextCommands[*].argv": 1}
			invocationProfileAssertArgvInventory(t, renderer, agentRoute, agentRouteInventory)
			invocationProfileAssertArgvInventoryMutants(t, renderer, agentRoute, agentRouteInventory)

			agentRouteEnvelope := invocationProfileRun(t, renderer, []string{"agent-route", "--input", "-", "--agent-envelope", "--agent-envelope-mode", "full"}, invocationProfileEncode(t, agentRouteInput))
			agentRouteEnvelopeInventory := map[string]int{"$.commands[*].argv": 1}
			invocationProfileAssertArgvInventory(t, renderer, agentRouteEnvelope, agentRouteEnvelopeInventory)
			invocationProfileAssertArgvInventoryMutantsAt(t, renderer, agentRouteEnvelope, agentRouteEnvelopeInventory, "commands")
			invocationProfileAssertDisplayMatchesArgvField(t, agentRouteEnvelope, "display")
			agentRouteDisplayMutant := invocationProfileObject(t, invocationProfileJSON(t, invocationProfileEncode(t, agentRouteEnvelope)))
			agentRouteDisplayCommand := invocationProfileArgvCommand(t, agentRouteDisplayMutant, "commands")
			agentRouteDisplayCommand["display"] = agentRouteDisplayCommand["proofkitRoute"]
			if invocationProfileDisplayMatchesArgv(agentRouteDisplayMutant, "display") {
				t.Fatal("agent-route bare-display mutant survived exact display/argv closure")
			}

			workflowInput := cliAdoptionWorkflowInput()
			directWorkflow := invocationProfileRun(t, renderer, []string{"adoption-workflow-plan", "--input", "-"}, invocationProfileEncode(t, workflowInput))
			workflowInventory := map[string]int{"$.phases[?phase=release].commands[*].argv": 2}
			invocationProfileAssertArgvInventory(t, renderer, directWorkflow, workflowInventory)

			aggregateInput := invocationProfileObject(t, invocationProfileJSON(t, cliAdoptionContractEnvelopeInput()))
			aggregateWorkflow := invocationProfileRun(t, renderer, []string{"adoption-contract-envelope", "--input", "-", "--mode", "workflow"}, invocationProfileEncode(t, aggregateInput))
			if !reflect.DeepEqual(aggregateWorkflow, directWorkflow) {
				t.Fatal("adoption aggregate workflow route did not preserve the admitted renderer")
			}

			directWorkflowEnvelope := invocationProfileRun(t, renderer, []string{"adoption-workflow-plan", "--input", "-", "--agent-envelope"}, invocationProfileEncode(t, workflowInput))
			workflowEnvelopeInventory := map[string]int{"$.commands[*].argv": 2}
			invocationProfileAssertArgvInventory(t, renderer, directWorkflowEnvelope, workflowEnvelopeInventory)
			invocationProfileAssertDisplayMatchesArgv(t, directWorkflowEnvelope)
			aggregateWorkflowEnvelope := invocationProfileRun(t, renderer, []string{"adoption-contract-envelope", "--input", "-", "--mode", "workflow", "--agent-envelope"}, invocationProfileEncode(t, aggregateInput))
			if !reflect.DeepEqual(aggregateWorkflowEnvelope, directWorkflowEnvelope) {
				t.Fatal("adoption aggregate workflow envelope did not preserve the admitted renderer")
			}

			coverageEnvelope := invocationProfileRunStatus(t, renderer, []string{"requirement-coverage-view", "--input", "-", "--agent-envelope"}, cliCoverageInput("null"), 1)
			invocationProfileAssertArgvInventory(t, renderer, coverageEnvelope, map[string]int{"$.commands[*].argv": 1})

			project := invocationProfileRun(t, renderer, []string{"scaffold-project-structure", "--input", "-"}, invocationProfileEncode(t, projectInput))
			invocationProfileAssertProjectCallerArgvPreserved(t, bootstrapInput, project)
			projectWorkflow := invocationProfileObjectValue(t, project["adoptionWorkflowPlan"], "project adoption workflow plan")
			invocationProfileAssertArgvInventory(t, renderer, projectWorkflow, map[string]int{
				"$.phases[?phase=bind].commands[*].argv":      3,
				"$.phases[?phase=bootstrap].commands[*].argv": 2,
				"$.phases[?phase=profile].commands[*].argv":   2,
			})
		})
	}
}

func invocationProfileAssertProjectCallerArgvPreserved(t *testing.T, bootstrapInput map[string]any, project map[string]any) {
	t.Helper()
	inputWitnesses := invocationProfileObjectValue(t, bootstrapInput["nativeWitnesses"], "bootstrap input native witnesses")
	inputCommands := invocationProfileArray(t, inputWitnesses["commands"], "bootstrap input native witness commands")
	bootstrap := invocationProfileObjectValue(t, project["bootstrapReport"], "project bootstrap report")
	payloads := invocationProfileObjectValue(t, bootstrap["payloads"], "project bootstrap payloads")
	adoptionProfile := invocationProfileObjectValue(t, payloads["adoptionProfile"], "project adoption profile")
	witnessOwners := []struct {
		name string
		raw  any
	}{
		{name: "adoption profile", raw: invocationProfileObjectValue(t, adoptionProfile["nativeWitnesses"], "project adoption profile native witnesses")["commands"]},
		{name: "witness plan input", raw: invocationProfileObjectValue(t, payloads["witnessPlanInput"], "project witness plan input")["commands"]},
		{name: "witness plan", raw: invocationProfileObjectValue(t, bootstrap["witnessPlan"], "project witness plan")["commands"]},
	}
	for _, owner := range witnessOwners {
		commands := invocationProfileArray(t, owner.raw, owner.name+" commands")
		if !reflect.DeepEqual(commands, inputCommands) {
			t.Fatalf("%s caller-owned argv changed: got %#v want %#v", owner.name, commands, inputCommands)
		}
	}
}

func invocationProfileAssertHelpRouteClosure(t *testing.T, renderer cliexec.Renderer) {
	t.Helper()
	root := invocationProfileRunText(t, renderer, []string{"help"})
	rootRoute := renderer.DisplayCommand("help", "families")
	if !invocationProfileRootHelpRouteMatches(root, rootRoute) {
		t.Fatalf("root help did not expose exactly the admitted family route %q", rootRoute)
	}
	for _, mutant := range []string{
		strings.Replace(root, rootRoute, "npx agentic-proofkit help families", 1),
		root + "  npx agentic-proofkit help families\n",
		strings.Replace(root, rootRoute, "", 1),
	} {
		if invocationProfileRootHelpRouteMatches(mutant, rootRoute) {
			t.Fatal("root help route mutant survived exact launcher-profile closure")
		}
	}

	families := invocationProfileRunText(t, renderer, []string{"help", "families"})
	catalog := generatedCommandFamilyCatalog()
	if strings.Count(families, " help family ") != len(catalog.Families) {
		t.Fatalf("family help route count=%d, want %d", strings.Count(families, " help family "), len(catalog.Families))
	}
	for _, family := range catalog.Families {
		route := renderer.DisplayCommand("help", "family", family.ID)
		routeLine := "    " + route + "\n"
		if strings.Count(families, routeLine) != 1 {
			t.Fatalf("family route %q count=%d, want 1", route, strings.Count(families, routeLine))
		}
		familyHelp := invocationProfileRunText(t, renderer, []string{"help", "family", family.ID})
		if strings.Count(familyHelp, " help ") != len(family.Commands) {
			t.Fatalf("family %s leaf route count=%d, want %d", family.ID, strings.Count(familyHelp, " help "), len(family.Commands))
		}
		for _, command := range family.Commands {
			descriptor, ok := commandDescriptorFor(command)
			if !ok {
				t.Fatalf("family %s command %s has no descriptor", family.ID, command)
			}
			leafRoute := renderer.DisplayCommand(append([]string{"help"}, descriptor.routeTokens...)...)
			leafRouteLine := "    " + leafRoute + "\n"
			if strings.Count(familyHelp, leafRouteLine) != 1 {
				t.Fatalf("family %s leaf route %q count=%d, want 1", family.ID, leafRoute, strings.Count(familyHelp, leafRouteLine))
			}
			leafHelp := invocationProfileRunText(t, renderer, append([]string{"help"}, descriptor.routeTokens...))
			installedUsage := "Installed invocation:\n  " + installedCommandUsageLineWithRenderer(descriptor, renderer) + "\n"
			if strings.Count(leafHelp, installedUsage) != 1 {
				t.Fatalf("command %s installed usage %q count=%d, want 1", command, installedUsage, strings.Count(leafHelp, installedUsage))
			}
			if command == "help" {
				for _, form := range catalog.HelpForms {
					route := "  " + renderer.DisplayCommand() + " " + form + "\n"
					if strings.Count(leafHelp, route) != 1 {
						t.Fatalf("help form %q count=%d, want 1", route, strings.Count(leafHelp, route))
					}
				}
			}
		}
	}

	stackDescriptor, ok := commandDescriptorFor("stack-preset")
	if !ok {
		t.Fatal("stack-preset descriptor missing")
	}
	stackHelp := invocationProfileRunText(t, renderer, []string{"help", "stack-preset"})
	installedUsage := installedCommandUsageLineWithRenderer(stackDescriptor, renderer)
	if !strings.Contains(stackHelp, "Installed invocation:\n  "+installedUsage+"\n") {
		t.Fatalf("stack-preset help missing admitted installed usage %q", installedUsage)
	}
	for _, presetID := range stackDescriptor.flagValueChoices["--preset"] {
		route := renderer.DisplayCommand("stack-preset", "--preset", presetID)
		routeLine := "  " + route + "\n"
		if strings.Count(stackHelp, routeLine) != 1 {
			t.Fatalf("stack-preset route %q count=%d, want 1", route, strings.Count(stackHelp, routeLine))
		}
	}
}

func invocationProfileRootHelpRouteMatches(output string, route string) bool {
	return strings.Count(output, " help families") == 1 &&
		strings.Contains(output, "Discover command families:\n  "+route+"\n")
}

func invocationProfileAssertArgvInventory(t *testing.T, renderer cliexec.Renderer, output any, expected map[string]int) {
	t.Helper()
	actual, invalid := invocationProfileArgvInventory(t, output, renderer.Argv())
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("generated argv inventory=%v, want exact %v", actual, expected)
	}
	if len(invalid) != 0 {
		t.Fatalf("generated argv fields contain non-active invocation profiles: %v", invalid)
	}
}

func invocationProfileAssertArgvInventoryMutants(t *testing.T, renderer cliexec.Renderer, output map[string]any, expected map[string]int) {
	invocationProfileAssertArgvInventoryMutantsAt(t, renderer, output, expected, "nextCommands")
}

func invocationProfileAssertArgvInventoryMutantsAt(t *testing.T, renderer cliexec.Renderer, output map[string]any, expected map[string]int, collectionKey string) {
	t.Helper()
	mutants := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "missing argv",
			mutate: func(mutant map[string]any) {
				command := invocationProfileArgvCommand(t, mutant, collectionKey)
				delete(command, "argv")
			},
		},
		{
			name: "unknown argv prefix",
			mutate: func(mutant map[string]any) {
				command := invocationProfileArgvCommand(t, mutant, collectionKey)
				argv := invocationProfileArray(t, command["argv"], "mutant argv")
				command["argv"] = append([]any{"npx", cliexec.BinaryName}, argv[len(renderer.Argv()):]...)
			},
		},
		{
			name: "bare or wrong-profile argv",
			mutate: func(mutant map[string]any) {
				command := invocationProfileArgvCommand(t, mutant, collectionKey)
				argv := invocationProfileArray(t, command["argv"], "mutant argv")
				if renderer.Profile() == cliexec.ProfilePath {
					command["argv"] = append([]any{"npm", "exec", "--offline", "--", cliexec.BinaryName}, argv[len(renderer.Argv()):]...)
					return
				}
				command["argv"] = append([]any{cliexec.BinaryName}, argv[len(renderer.Argv()):]...)
			},
		},
		{
			name: "surplus argv",
			mutate: func(mutant map[string]any) {
				command := invocationProfileArgvCommand(t, mutant, collectionKey)
				mutant["surplus"] = map[string]any{"argv": command["argv"]}
			},
		},
		{
			name: "relocated argv",
			mutate: func(mutant map[string]any) {
				command := invocationProfileArgvCommand(t, mutant, collectionKey)
				mutant["relocated"] = map[string]any{"argv": command["argv"]}
				delete(command, "argv")
			},
		},
	}
	for _, item := range mutants {
		t.Run("argv mutant/"+item.name, func(t *testing.T) {
			mutant := invocationProfileObject(t, invocationProfileJSON(t, invocationProfileEncode(t, output)))
			item.mutate(mutant)
			actual, invalid := invocationProfileArgvInventory(t, mutant, renderer.Argv())
			if reflect.DeepEqual(actual, expected) && len(invalid) == 0 {
				t.Fatalf("%s mutant survived exact generated argv inventory", item.name)
			}
		})
	}
}

func invocationProfileArgvCommand(t *testing.T, output map[string]any, collectionKey string) map[string]any {
	t.Helper()
	commands := invocationProfileArray(t, output[collectionKey], "mutant "+collectionKey)
	if len(commands) == 0 {
		t.Fatalf("mutant %s must contain at least one command", collectionKey)
	}
	return invocationProfileObjectValue(t, commands[0], "mutant command")
}

func invocationProfileArgvInventory(t *testing.T, output any, expectedPrefix []string) (map[string]int, map[string]int) {
	t.Helper()
	inventory := map[string]int{}
	invalid := map[string]int{}
	var walk func(any, string)
	walk = func(raw any, path string) {
		switch value := raw.(type) {
		case map[string]any:
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if key == "argv" {
					argv := invocationProfileStrings(t, value[key], path+".argv")
					inventory[path+".argv"]++
					if len(argv) < len(expectedPrefix) || !reflect.DeepEqual(argv[:len(expectedPrefix)], expectedPrefix) {
						invalid[path+".argv"]++
					}
					continue
				}
				walk(value[key], path+"."+key)
			}
		case []any:
			for _, item := range value {
				selector := "[*]"
				if object, ok := item.(map[string]any); ok {
					if phase, ok := object["phase"].(string); ok {
						selector = "[?phase=" + phase + "]"
					}
				}
				walk(item, path+selector)
			}
		}
	}
	walk(output, "$")
	return inventory, invalid
}

func invocationProfileAssertDisplayMatchesArgv(t *testing.T, envelope map[string]any) {
	t.Helper()
	invocationProfileAssertDisplayMatchesArgvField(t, envelope, "command")
}

func invocationProfileAssertDisplayMatchesArgvField(t *testing.T, envelope map[string]any, displayField string) {
	t.Helper()
	if !invocationProfileDisplayMatchesArgv(envelope, displayField) {
		t.Fatalf("envelope %s fields do not exactly render argv", displayField)
	}
}

func invocationProfileDisplayMatchesArgv(envelope map[string]any, displayField string) bool {
	rawCommands, ok := envelope["commands"].([]any)
	if !ok || len(rawCommands) == 0 {
		return false
	}
	for _, raw := range rawCommands {
		command, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		rawArgv, ok := command["argv"].([]any)
		if !ok || len(rawArgv) == 0 {
			return false
		}
		argv := make([]string, 0, len(rawArgv))
		for _, rawValue := range rawArgv {
			value, ok := rawValue.(string)
			if !ok || value == "" {
				return false
			}
			argv = append(argv, value)
		}
		display, ok := command[displayField].(string)
		if !ok || display != cliexec.DisplayArgv(argv) {
			return false
		}
	}
	return true
}

func invocationProfileBootstrapInventory(root string) map[string]int {
	return map[string]int{
		root + ".agentActionPlan[?phase=verify].commands[*]":                                3,
		root + ".nextCommands[*]":                                                           3,
		root + ".payloads.adoptionGuidance.agentGuidance.commands[callerCommandCount:]":     3,
		root + ".report.diagnostics[?key=agentActionPlan].value[?phase=verify].commands[*]": 3,
		root + ".report.diagnostics[?key=nextCommands].value[*]":                            3,
	}
}

func invocationProfileAssertInventory(t *testing.T, renderer cliexec.Renderer, output any, expected map[string]int, callerCommandCount int) {
	t.Helper()
	actual, wrongProfiles := invocationProfileCommandInventory(t, output, renderer.DisplayCommand(), callerCommandCount)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("generated command inventory=%v, want exact %v", actual, expected)
	}
	if len(wrongProfiles) != 0 {
		t.Fatalf("generated command fields contain non-active invocation profiles: %v", wrongProfiles)
	}
}

func invocationProfileAssertInventoryMutants(t *testing.T, renderer cliexec.Renderer, output map[string]any, expected map[string]int, callerCommands []string) {
	t.Helper()
	nextCommands := invocationProfileArray(t, output["nextCommands"], "bootstrap nextCommands")
	generatedCommand := nextCommands[0].(string)
	bareCommand := cliexec.PathRenderer().DisplayCommand("self-check", "--input", "proofkit/input.json")
	wrongProfile, err := cliexec.AdmitLauncherProfile(cliexec.ProfileNPMOffline, "")
	if renderer.Profile() == cliexec.ProfileNPMOffline {
		wrongProfile, err = cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, "/tmp/wrong-profile/bin/python")
	}
	if err != nil {
		t.Fatalf("construct wrong-profile mutant: %v", err)
	}
	wrongProfileCommand := wrongProfile.DisplayCommand("self-check", "--input", "proofkit/input.json")

	mutants := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "surplus field",
			mutate: func(mutant map[string]any) {
				mutant["surplusGeneratedCommand"] = generatedCommand
			},
		},
		{
			name: "bare surplus field",
			mutate: func(mutant map[string]any) {
				mutant["surplusBareCommand"] = bareCommand
			},
		},
		{
			name: "wrong profile surplus field",
			mutate: func(mutant map[string]any) {
				mutant["surplusWrongProfileCommand"] = wrongProfileCommand
			},
		},
		{
			name: "field relocation",
			mutate: func(mutant map[string]any) {
				mutant["relocatedNextCommands"] = mutant["nextCommands"]
				delete(mutant, "nextCommands")
			},
		},
		{
			name: "missing command",
			mutate: func(mutant map[string]any) {
				commands := invocationProfileArray(t, mutant["nextCommands"], "mutant nextCommands")
				mutant["nextCommands"] = commands[1:]
			},
		},
		{
			name: "wrong profile in expected field",
			mutate: func(mutant map[string]any) {
				commands := invocationProfileArray(t, mutant["nextCommands"], "mutant nextCommands")
				commands[0] = wrongProfileCommand
			},
		},
	}
	for _, item := range mutants {
		t.Run("inventory mutant/"+item.name, func(t *testing.T) {
			mutant := invocationProfileObject(t, invocationProfileJSON(t, invocationProfileEncode(t, output)))
			item.mutate(mutant)
			if invocationProfileInventoryMatches(t, mutant, renderer.DisplayCommand(), len(callerCommands), expected) {
				t.Fatalf("%s mutant survived exact generated-command inventory", item.name)
			}
		})
	}

	callerMutant := invocationProfileObject(t, invocationProfileJSON(t, invocationProfileEncode(t, output)))
	payloads := invocationProfileObjectValue(t, callerMutant["payloads"], "caller mutant payloads")
	guidance := invocationProfileObjectValue(t, payloads["adoptionGuidance"], "caller mutant adoption guidance")
	agentGuidance := invocationProfileObjectValue(t, guidance["agentGuidance"], "caller mutant agent guidance")
	commands := invocationProfileArray(t, agentGuidance["commands"], "caller mutant guidance commands")
	commands[0] = generatedCommand
	mutatedCaller := invocationProfileStrings(t, agentGuidance["commands"], "caller mutant guidance commands")
	if reflect.DeepEqual(mutatedCaller[:len(callerCommands)], callerCommands) {
		t.Fatal("caller rewrite mutant survived caller/generated partition oracle")
	}
}

func invocationProfileInventoryMatches(t *testing.T, output any, prefix string, callerCommandCount int, expected map[string]int) bool {
	t.Helper()
	actual, wrongProfiles := invocationProfileCommandInventory(t, output, prefix, callerCommandCount)
	return reflect.DeepEqual(actual, expected) && len(wrongProfiles) == 0
}

func invocationProfileCommandInventory(t *testing.T, output any, prefix string, callerCommandCount int) (map[string]int, map[string]int) {
	t.Helper()
	inventory := map[string]int{}
	wrongProfiles := map[string]int{}
	var walk func(any, string)
	walk = func(raw any, path string) {
		switch value := raw.(type) {
		case string:
			if invocationProfileIsKnownGeneratedCommand(value) {
				inventory[path]++
				if !strings.HasPrefix(value, prefix+" ") {
					wrongProfiles[path]++
				}
			}
		case map[string]any:
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if key == "content" && invocationProfileIsAdoptionGuidanceFile(value) {
					content, ok := value[key].(string)
					if !ok {
						t.Fatalf("%s.content=%#v, want JSON string", path, value[key])
					}
					walk(invocationProfileJSON(t, content), path+".content::$")
					continue
				}
				walk(value[key], path+"."+key)
			}
		case []any:
			for index, item := range value {
				if strings.HasSuffix(path, ".agentGuidance.commands") && index < callerCommandCount {
					continue
				}
				selector := "[*]"
				if object, ok := item.(map[string]any); ok {
					switch {
					case strings.HasSuffix(path, ".diagnostics"):
						if key, ok := object["key"].(string); ok {
							selector = "[?key=" + key + "]"
						}
					case strings.HasSuffix(path, ".agentActionPlan") || strings.Contains(path, "[?key=agentActionPlan].value"):
						if phase, ok := object["phase"].(string); ok {
							selector = "[?phase=" + phase + "]"
						}
					case strings.HasSuffix(path, ".files"):
						if payloadKey, ok := object["payloadKey"].(string); ok {
							selector = "[?payloadKey=" + payloadKey + "]"
						} else if purpose, ok := object["purpose"].(string); ok {
							selector = "[?purpose=" + purpose + "]"
						}
					}
				}
				if strings.HasSuffix(path, ".agentGuidance.commands") {
					selector = "[callerCommandCount:]"
				}
				walk(item, path+selector)
			}
		}
	}
	walk(output, "$")
	return inventory, wrongProfiles
}

func invocationProfileIsKnownGeneratedCommand(value string) bool {
	switch {
	case strings.HasPrefix(value, cliexec.BinaryName+" "):
		return true
	case strings.HasPrefix(value, "npm exec --offline -- "+cliexec.BinaryName+" "):
		return true
	}
	moduleMarker := " -m agentic_proofkit "
	moduleIndex := strings.Index(value, moduleMarker)
	if moduleIndex <= 0 {
		return false
	}
	executable := value[:moduleIndex]
	return strings.HasPrefix(executable, "/") || strings.HasPrefix(executable, "'/")
}

func invocationProfileRun(t *testing.T, renderer cliexec.Renderer, args []string, stdin string) map[string]any {
	return invocationProfileRunStatus(t, renderer, args, stdin, 0)
}

func invocationProfileRunStatus(t *testing.T, renderer cliexec.Renderer, args []string, stdin string, expectedStatus int) map[string]any {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := RunWithRenderer(t.Context(), args, strings.NewReader(stdin), &stdout, &stderr, renderer)
	if status != expectedStatus || stderr.Len() != 0 {
		t.Fatalf("RunWithRenderer(%v) status=%d stderr=%s stdout=%s", args, status, stderr.String(), stdout.String())
	}
	return invocationProfileObject(t, invocationProfileJSON(t, stdout.String()))
}

func invocationProfileRunText(t *testing.T, renderer cliexec.Renderer, args []string) string {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := RunWithRenderer(t.Context(), args, panicReader{}, &stdout, &stderr, renderer)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("RunWithRenderer(%v) status=%d stderr=%s stdout=%s", args, status, stderr.String(), stdout.String())
	}
	return stdout.String()
}

func invocationProfileAssertBootstrap(t *testing.T, renderer cliexec.Renderer, output map[string]any, callerCommands []string) {
	t.Helper()
	invocationProfileAssertGenerated(t, renderer, invocationProfileStrings(t, output["nextCommands"], "bootstrap nextCommands"))

	for _, rawAction := range invocationProfileArray(t, output["agentActionPlan"], "bootstrap agentActionPlan") {
		action := invocationProfileObjectValue(t, rawAction, "bootstrap action")
		if action["phase"] == "verify" {
			invocationProfileAssertGenerated(t, renderer, invocationProfileStrings(t, action["commands"], "bootstrap verify commands"))
		}
	}

	payloads := invocationProfileObjectValue(t, output["payloads"], "bootstrap payloads")
	guidance := invocationProfileObjectValue(t, payloads["adoptionGuidance"], "bootstrap adoption guidance")
	agentGuidance := invocationProfileObjectValue(t, guidance["agentGuidance"], "bootstrap agent guidance")
	invocationProfileAssertCallerAndGenerated(t, renderer, invocationProfileStrings(t, agentGuidance["commands"], "bootstrap guidance commands"), callerCommands)

	report := invocationProfileObjectValue(t, output["report"], "bootstrap report")
	invocationProfileAssertGenerated(t, renderer, invocationProfileStrings(t, invocationProfileDiagnostic(t, report, "nextCommands"), "report nextCommands"))
	for _, rawAction := range invocationProfileArray(t, invocationProfileDiagnostic(t, report, "agentActionPlan"), "report agentActionPlan") {
		action := invocationProfileObjectValue(t, rawAction, "report action")
		if action["phase"] == "verify" {
			invocationProfileAssertGenerated(t, renderer, invocationProfileStrings(t, action["commands"], "report verify commands"))
		}
	}
}

func invocationProfileAssertManifest(t *testing.T, renderer cliexec.Renderer, manifest map[string]any, callerCommands []string) {
	t.Helper()
	invocationProfileAssertGenerated(t, renderer, invocationProfileStrings(t, manifest["nextCommands"], "manifest nextCommands"))
	for _, rawFile := range invocationProfileArray(t, manifest["files"], "manifest files") {
		file := invocationProfileObjectValue(t, rawFile, "manifest file")
		if !invocationProfileIsAdoptionGuidanceFile(file) {
			continue
		}
		content, ok := file["content"].(string)
		if !ok {
			t.Fatalf("adoptionGuidance content=%#v, want JSON string", file["content"])
		}
		guidance := invocationProfileObject(t, invocationProfileJSON(t, content))
		agentGuidance := invocationProfileObjectValue(t, guidance["agentGuidance"], "materialized agent guidance")
		invocationProfileAssertCallerAndGenerated(t, renderer, invocationProfileStrings(t, agentGuidance["commands"], "materialized guidance commands"), callerCommands)
		return
	}
	t.Fatal("manifest missing adoptionGuidance payload identity")
}

func invocationProfileIsAdoptionGuidanceFile(file map[string]any) bool {
	return file["payloadKey"] == "adoptionGuidance" ||
		file["purpose"] == "caller-owned gradual adoption guidance input"
}

func invocationProfileAssertEnvelope(t *testing.T, renderer cliexec.Renderer, envelope map[string]any) {
	t.Helper()
	commands := []string{}
	for _, rawCommand := range invocationProfileArray(t, envelope["commands"], "envelope commands") {
		command := invocationProfileObjectValue(t, rawCommand, "envelope command")
		value, ok := command["command"].(string)
		if !ok {
			t.Fatalf("envelope command=%#v, want string", command["command"])
		}
		commands = append(commands, value)
	}
	invocationProfileAssertGenerated(t, renderer, commands)
}

func invocationProfileAssertCallerAndGenerated(t *testing.T, renderer cliexec.Renderer, commands []string, callerCommands []string) {
	t.Helper()
	if len(commands) <= len(callerCommands) {
		t.Fatalf("commands=%#v, want caller prefix and generated suffix", commands)
	}
	if !reflect.DeepEqual(commands[:len(callerCommands)], callerCommands) {
		t.Fatalf("caller command prefix=%#v, want unchanged %#v", commands[:len(callerCommands)], callerCommands)
	}
	invocationProfileAssertGenerated(t, renderer, commands[len(callerCommands):])
}

func invocationProfileAssertGenerated(t *testing.T, renderer cliexec.Renderer, commands []string) {
	t.Helper()
	if len(commands) == 0 {
		t.Fatal("generated command field must not be empty")
	}
	prefix := renderer.DisplayCommand()
	for _, command := range commands {
		if !strings.HasPrefix(command, prefix+" ") {
			t.Fatalf("generated command=%q, want exact admitted prefix %q", command, prefix)
		}
	}
}

func invocationProfileDiagnostic(t *testing.T, report map[string]any, key string) any {
	t.Helper()
	for _, rawDiagnostic := range invocationProfileArray(t, report["diagnostics"], "diagnostics") {
		diagnostic := invocationProfileObjectValue(t, rawDiagnostic, "diagnostic")
		if diagnostic["key"] == key {
			return diagnostic["value"]
		}
	}
	t.Fatalf("diagnostic %q missing", key)
	return nil
}

func invocationProfileProjectInput(bootstrap map[string]any) map[string]any {
	bootstrap["paths"].(map[string]any)["adoptionProfilePath"] = "proofkit/adoption-profile.json"
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"scaffoldId":    "proofkit.cli.invocation-profile-project",
		"nonClaims":     []any{"Invocation profile fixture does not write files."},
		"paths": map[string]any{
			"bootstrapInputPath":           "proofkit/bootstrap.v1.json",
			"repoProfileScaffoldInputPath": "proofkit/repo-profile-scaffold.v1.json",
			"workflowInputPath":            "proofkit/adoption-workflow.v1.json",
		},
		"workflow": map[string]any{
			"nonClaims":  []any{"Invocation profile workflow fixture does not execute commands."},
			"scenario":   "new_repository",
			"workflowId": "proofkit.cli.invocation-profile-workflow",
		},
		"repoProfileScaffold": map[string]any{
			"schemaVersion": json.Number("1"),
			"planId":        "proofkit.cli.invocation-profile-repo-plan",
			"presetId":      "typescript_workspace",
			"repository": map[string]any{
				"name":             "consumer-repo",
				"primaryLanguages": []any{"go"},
				"profilePath":      "proofkit/profile.json",
				"rootPackageName":  "consumer-repo",
			},
			"paths": map[string]any{
				"bindingPath":           "proofkit/proof-bindings.json",
				"generatedArtifacts":    []any{},
				"policyPath":            "proofkit/profile.json",
				"proofLikePaths":        []any{"docs/specs/cli-adoption/requirements.v1.json"},
				"retiredProofLikePaths": []any{},
				"routerPath":            "AGENTS.md",
				"specGlobs":             []any{"docs/specs/**/*.json"},
			},
			"requirements":       map[string]any{"idPattern": "REQ-CONSUMER-[0-9]+"},
			"environmentClasses": []any{"local-go"},
			"commandMatcherHints": []any{
				map[string]any{
					"allowedScripts":  []any{"check"},
					"credentialClass": "none",
					"id":              "consumer.check",
					"kind":            "bun_repo_script",
					"networkPolicy":   "none",
					"parallelGroup":   "local",
				},
			},
			"nonClaims": []any{"Invocation profile scaffold fixture does not prove repository facts."},
		},
		"bootstrap": bootstrap,
	}
}

func invocationProfileJSON(t *testing.T, raw any) any {
	t.Helper()
	var encoded []byte
	switch value := raw.(type) {
	case string:
		encoded = []byte(value)
	default:
		var err error
		encoded, err = json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal JSON: %v", err)
		}
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, encoded)
	}
	return decoded
}

func invocationProfileEncode(t *testing.T, raw any) string {
	t.Helper()
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return string(encoded)
}

func invocationProfileObject(t *testing.T, raw any) map[string]any {
	t.Helper()
	return invocationProfileObjectValue(t, raw, "JSON object")
}

func invocationProfileObjectValue(t *testing.T, raw any, context string) map[string]any {
	t.Helper()
	value, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("%s=%#v, want object", context, raw)
	}
	return value
}

func invocationProfileArray(t *testing.T, raw any, context string) []any {
	t.Helper()
	value, ok := raw.([]any)
	if !ok {
		t.Fatalf("%s=%#v, want array", context, raw)
	}
	return value
}

func invocationProfileStrings(t *testing.T, raw any, context string) []string {
	t.Helper()
	values := invocationProfileArray(t, raw, context)
	result := make([]string, 0, len(values))
	for _, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok {
			t.Fatalf("%s item=%#v, want string", context, rawValue)
		}
		result = append(result, value)
	}
	return result
}
