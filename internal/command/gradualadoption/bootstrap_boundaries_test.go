package gradualadoption

import (
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestBootstrapPartialPreparedCommandsHaveOneBoundedCarrierShape(t *testing.T) {
	fields := []string{"adoptionProfilePath", "adoptionGuidancePath", "witnessPlanInputPath"}
	operations := []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"}
	for mask := 0; mask < 8; mask++ {
		input := validBootstrapInput()
		paths := input["paths"].(map[string]any)
		want := []string{}
		for index, field := range fields {
			if mask&(1<<index) == 0 {
				delete(paths, field)
			} else {
				want = append(want, cliexec.PathRenderer().DisplayCommand(operations[index], "--input", paths[field].(string)))
			}
		}
		output, code, err := BuildBootstrap(input)
		if err != nil || (code == 0) != (mask == 7) {
			t.Fatalf("mask=%d: collected failure changed phase: exit=%d err=%v", mask, code, err)
		}
		if !reflect.DeepEqual(anyStrings(output["nextCommands"]), want) {
			t.Fatalf("mask=%d: missing paths produced fake or lost commands", mask)
		}
		report := output["report"].(map[string]any)
		diagnostic := report["diagnostics"].([]any)[1].(map[string]any)
		if diagnostic["key"] != "nextCommands" || !reflect.DeepEqual(anyStrings(diagnostic["value"]), want) {
			t.Fatal("report diagnostics disagree with the actual prepared commands")
		}
		if err := schemacheck.Validate(BootstrapOutputStructure(), output); err != nil {
			t.Fatalf("mask=%d: actual report carrier refused: %v", mask, err)
		}
		manifest, manifestCode, err := BuildBootstrapMaterializationManifest(input)
		if err != nil || manifestCode != code || !reflect.DeepEqual(anyStrings(manifest["nextCommands"]), want) {
			t.Fatalf("mask=%d: manifest changed commands or failure phase: exit=%d err=%v", mask, manifestCode, err)
		}
		if err := schemacheck.Validate(BootstrapMaterializationStructure(), manifest); err != nil {
			t.Fatalf("mask=%d: actual manifest refused: %v", mask, err)
		}
		four := []any{"one", "two", "three", "four"}
		output["nextCommands"] = four
		if err := schemacheck.Validate(BootstrapOutputStructure(), output); err == nil {
			t.Fatal("root carrier admitted a fourth prepared command")
		}
		output["nextCommands"] = admit.StringSliceToAny(want)
		diagnostic["value"] = four
		if err := schemacheck.Validate(BootstrapOutputStructure(), output); err == nil {
			t.Fatal("report diagnostic admitted a fourth prepared command")
		}
		manifest["nextCommands"] = four
		if err := schemacheck.Validate(BootstrapMaterializationStructure(), manifest); err == nil {
			t.Fatal("manifest admitted a fourth prepared command")
		}
	}
}

func TestPreparedCommandUnicodeSafetyIsSharedByBothProducers(t *testing.T) {
	fields := []string{"adoptionProfilePath", "adoptionGuidancePath", "witnessPlanInputPath"}
	operations := []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"}
	unsafe := []string{"\u202e", "\u2066", "\u200b", "\u00ad", "\u0085", "\u2028", "\u2029", "\n", "\x7f"}
	for index, operation := range operations {
		for _, scalar := range unsafe {
			path := "inputs/unsafe" + scalar + "path.json"
			input := validGuidanceInput()
			input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{operation: path}
			for _, build := range []func(any, GuidanceOptions) (map[string]any, int, error){BuildGuidance, BuildGuidanceEnvelope} {
				output, code, err := build(input, GuidanceOptions{})
				if err != nil || code != 1 {
					t.Fatalf("guidance accepted an unsafe prepared path or changed failure phase: exit=%d err=%v", code, err)
				}
				if commands, envelope := output["commands"].([]any); envelope {
					for _, raw := range commands {
						if _, typed := raw.(map[string]any)["argv"]; typed {
							t.Fatal("unsafe prepared input survived as argv")
						}
					}
				} else {
					for _, command := range anyStrings(invocationGuidance(t, output)["commands"]) {
						if unicodepolicy.ContainsUnsafeScalar(command) {
							t.Fatal("unsafe path survived in the ordinary display projection")
						}
					}
				}
			}
			bootstrap := validBootstrapInput()
			bootstrap["paths"].(map[string]any)[fields[index]] = path
			result, err := BuildBootstrapResult(bootstrap)
			if err != nil || result.ExitCode != 1 || result.Record.State != "failed" || len(result.PreparedCommands()) != 2 {
				t.Fatalf("bootstrap did not collect the unsafe path: exit=%d err=%v", result.ExitCode, err)
			}
			for _, command := range result.NextCommands {
				if unicodepolicy.ContainsUnsafeScalar(command) {
					t.Fatal("bootstrap constructed an unsafe display command")
				}
			}
			if err := schemacheck.Validate(BootstrapOutputStructure(), result.JSONValue()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, path := range []string{"inputs/bad\xff.json", "inputs/bad\xed\xa0\x80.json"} {
		command, err := admitPreparedCommand("witness-plan", path, cliexec.PathRenderer(), "prepared test input")
		if err == nil || command.Argv() != nil {
			t.Fatal("non-scalar UTF-8 acquired a prepared invocation")
		}
	}
	if _, err := admit.SafeRepoRelativePath("inputs/ordinary\u202e.json", "POSIX-only test input"); err != nil {
		t.Fatal("prepared-command safety must not become a global POSIX path policy")
	}
}

func TestPreparedCommandSafetyPreservesLegalPathsAndCallerPrivacy(t *testing.T) {
	for _, path := range []string{"inputs/file.json ", "inputs/quoted'file.json", "inputs/task-validation.json", "inputs/caf\u00e9.json", " - "} {
		input := validGuidanceInput()
		input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": path}
		output, code, err := BuildGuidance(input, GuidanceOptions{})
		if err != nil || code != 0 || !containsString(anyStrings(invocationGuidance(t, output)["commands"]), cliexec.PathRenderer().DisplayCommand("witness-plan", "--input", path)) {
			t.Fatalf("legal exact prepared path was narrowed: exit=%d err=%v", code, err)
		}
		bootstrap := validBootstrapInput()
		bootstrap["paths"].(map[string]any)["witnessPlanInputPath"] = path
		result, err := BuildBootstrapResult(bootstrap)
		if path == "inputs/task-validation.json" {
			if err == nil || !strings.Contains(err.Error(), "must not contain secret-shaped keys or values") {
				t.Fatal("pre-existing whole-source scalar privacy was weakened")
			}
			continue
		}
		if err != nil || result.ExitCode != 0 || result.PreparedCommands()[2].InputRef() != path {
			t.Fatalf("bootstrap changed a legal exact path: exit=%d err=%v", result.ExitCode, err)
		}
	}
	input := validGuidanceInput()
	input["agentGuidance"].(map[string]any)["commands"] = []any{"go test --input inputs/task-validation.json"}
	input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": "inputs/task-validation.json"}
	output, code, err := BuildGuidance(input, GuidanceOptions{})
	if err != nil || code != 1 || !ruleMessageContains(output["ruleResults"], "agentGuidance commands must not contain secret-like values") {
		t.Fatal("structural path admission weakened strict caller command privacy")
	}
}

func TestPreparedCommandFinalDisplayPolicyMatchesTheEnvelope(t *testing.T) {
	path := "inputs/a b/authorization:"
	if _, err := admit.MaterializedInputPath(path, "raw path control"); err != nil {
		t.Fatal("counterexample no longer reaches the final-display boundary")
	}
	if !admit.ContainsSecretLikePathValue(cliexec.PathRenderer().DisplayCommand("witness-plan", "--input", path)) {
		t.Fatal("quoting did not create the protected contextual signature")
	}
	control := validGuidanceInput()
	control["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{"witness-plan": "inputs/authorization:"}
	if _, code, err := BuildGuidance(control, GuidanceOptions{}); err != nil || code != 0 {
		t.Fatal("safe unquoted leaf control was narrowed")
	}
	fields := []string{"adoptionProfilePath", "adoptionGuidancePath", "witnessPlanInputPath"}
	for index, operation := range []string{"gradual-adoption", "gradual-adoption-guidance", "witness-plan"} {
		input := validGuidanceInput()
		input["agentGuidance"].(map[string]any)["proofkitCommands"] = map[string]any{operation: path}
		for _, build := range []func(any, GuidanceOptions) (map[string]any, int, error){BuildGuidance, BuildGuidanceEnvelope} {
			output, code, err := build(input, GuidanceOptions{})
			if err != nil || code != 1 {
				t.Fatalf("protected final display changed collected failure phase: exit=%d err=%v", code, err)
			}
			if commands, envelope := output["commands"].([]any); envelope {
				if len(commands) != 0 {
					t.Fatal("rejected final display retained an envelope command")
				}
			} else if len(anyStrings(invocationGuidance(t, output)["commands"])) != 0 {
				t.Fatal("ordinary report retained a command refused by its envelope")
			}
		}
		bootstrap := validBootstrapInput()
		bootstrap["paths"].(map[string]any)[fields[index]] = path
		// Full bootstrap JSON already refuses this signature before construction.
		output, code, err := BuildBootstrap(bootstrap)
		if output != nil || code != 1 || err == nil || !strings.Contains(err.Error(), "must not contain secret-shaped keys or values") {
			t.Fatalf("bootstrap snapshot refusal changed phase: exit=%d err=%v", code, err)
		}
		failures := []string{}
		prepared := bootstrapPreparedCommands(bootstrap["paths"].(map[string]any), cliexec.PathRenderer(), &failures)
		if len(prepared) != 2 || len(failures) != 1 {
			t.Fatal("bootstrap producer did not apply the shared final-display admission")
		}
		for _, command := range prepared {
			if admit.ContainsSecretLikePathValue(command.DisplayCommand()) {
				t.Fatal("bootstrap display disagrees with the envelope policy")
			}
		}
	}
}

func TestBootstrapMaterializationRolesArePrivatePolicyCopies(t *testing.T) {
	input := validBootstrapInput()
	paths := input["paths"].(map[string]any)
	paths["witnessPlanInputPath"] = "inputs/check.json"
	result, err := BuildBootstrapResult(input)
	if err != nil || result.ExitCode != 0 {
		t.Fatal(err)
	}
	want := map[string]string{
		input["module"].(map[string]any)["specPath"].(string): "spec_source",
		input["proofBindingPath"].(string):                    "proof_binding",
		result.RepositoryProfilePath():                        "owner_surface",
		paths["adoptionProfilePath"].(string):                 "owner_surface",
		paths["adoptionGuidancePath"].(string):                "supporting",
		"inputs/check.json":                                   "command_registry",
	}
	roles := result.MaterializationFileRoles()
	if !reflect.DeepEqual(roles, want) {
		t.Fatalf("child roles=%#v want %#v", roles, want)
	}
	roles["inputs/check.json"] = "owner_surface"
	delete(roles, result.RepositoryProfilePath())
	paths["witnessPlanInputPath"] = "changed-input.json"
	for _, raw := range result.PlannedFiles {
		file := raw.(map[string]any)
		file["path"], file["payloadKey"], file["purpose"] = "changed-file.json", nil, "profile"
	}
	if !reflect.DeepEqual(result.MaterializationFileRoles(), want) {
		t.Fatal("mutable caller/output data changed admitted file roles")
	}
	if _, leaked := result.JSONValue()["materializationFileRoles"]; leaked {
		t.Fatal("private materialization roles became a wire field")
	}
}

func TestBootstrapRepositoryProfilePathOwnsItsAdmittedIdentity(t *testing.T) {
	input := validBootstrapInput()
	want := "proofkit/repository profile.json "
	input["repository"].(map[string]any)["profilePath"] = want
	result, err := BuildBootstrapResult(input)
	if err != nil || result.ExitCode != 0 || result.RepositoryProfilePath() != want {
		t.Fatalf("profile identity was not admitted exactly: exit=%d err=%v", result.ExitCode, err)
	}
	found := false
	for _, raw := range result.PlannedFiles {
		file := raw.(map[string]any)
		if file["purpose"] == "caller-owned proofkit profile" {
			found = true
			if file["path"] != result.RepositoryProfilePath() {
				t.Fatal("profile getter differs from its planned file")
			}
			file["path"] = "changed-planned.json"
		}
	}
	if !found {
		t.Fatal("repository-profile planned-file role was not exercised")
	}
	input["repository"].(map[string]any)["profilePath"] = "changed-input.json"
	result.Payloads["adoptionProfile"].(map[string]any)["repository"].(map[string]any)["profilePath"] = "changed-payload.json"
	if result.RepositoryProfilePath() != want {
		t.Fatal("mutable input/output changed the admitted repository profile identity")
	}
	if _, leaked := result.JSONValue()["repositoryProfilePath"]; leaked {
		t.Fatal("private profile identity became a wire field")
	}
	input = validBootstrapInput()
	input["repository"].(map[string]any)["profilePath"] = "../outside"
	failed, err := BuildBootstrapResult(input)
	if err != nil || failed.Record.State != "failed" || failed.RepositoryProfilePath() != "" {
		t.Fatal("getter retained an unadmitted path or changed collected failures")
	}
	if strings.TrimSpace((BootstrapResult{}).RepositoryProfilePath()) != "" {
		t.Fatal("zero result invented a profile identity")
	}
}
