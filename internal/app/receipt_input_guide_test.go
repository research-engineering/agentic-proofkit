package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func receiptHelpTemplate(t *testing.T, command string) (map[string]any, string) {
	t.Helper()
	var canonical string
	for _, args := range [][]string{{command, "--help"}, {command, "-h"}, {"help", command}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || len(output) > 12<<10 || strings.Contains(output, "\x1b[") {
			t.Fatalf("help is not bounded, input-free plain text: %v, %d, %q", args, code, diagnostic)
		}
		if canonical != "" && canonical != output {
			t.Fatal("receipt help aliases differ")
		}
		canonical = output
	}
	_, body, ok := strings.Cut(canonical, "```json\n")
	if !ok || strings.Count(canonical, "```json\n") != 1 {
		t.Fatal("help must expose exactly one input template")
	}
	input, _, ok := strings.Cut(body, "\n```")
	if !ok {
		t.Fatal("unclosed template")
	}
	return decodeCLIJSON(t, input).(map[string]any), canonical
}

func TestReceiptInputGuidesAreLazyAndUseInstalledRoutes(t *testing.T) {
	expected := map[string]struct {
		marker   string
		commands [][]string
	}{
		"proof-receipt-admission": {"Proof receipt input guide:", [][]string{{"proof-receipt-admission", "--input", "<receipt-input>"}}},
		"spec-proof-bundle-admission": {"Spec proof bundle input guide:", [][]string{
			{"requirement-bindings", "--input", "<binding-input>"},
			{"witness-scheduler-plan", "--input", "<scheduler-input>"},
			{"proof-receipt-admission", "--input", "<receipt-input>"},
			{"spec-proof-bundle-admission", "--input", "<bundle-input>"},
		}},
	}
	for command, want := range expected {
		packet, _ := receiptHelpTemplate(t, command)
		code, output, diagnostic := executeAgentWorkflowCLI(t, []string{command, "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
		if code != 1 || output != "" || diagnostic == "" {
			t.Fatal("unfilled template fabricated admissible evidence")
		}
		for _, carrier := range []struct{ profile, python string }{
			{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/example/python 3"},
		} {
			renderer, err := cliexec.AdmitLauncherProfile(carrier.profile, carrier.python)
			if err != nil {
				t.Fatal(err)
			}
			descriptor, _ := commandDescriptorFor(command)
			help := commandUsageWithRenderer(descriptor, renderer)
			if commands := guideCommands(t, help, want.marker, renderer); !reflect.DeepEqual(commands, want.commands) {
				t.Fatalf("guide commands differ: got %v, want %v", commands, want.commands)
			}
		}
	}
	for _, args := range [][]string{{"help"}, {"help", "families"}, {"native-evidence-guidance"}, {"native-evidence-guidance", "--help"}, {"changed-path-set", "--help"}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || strings.Contains(output, "Receipt template (") || strings.Contains(output, "Bundle template (") {
			t.Fatal("input templates must remain demand-loaded")
		}
		if reflect.DeepEqual(args, []string{"native-evidence-guidance", "--help"}) && !strings.Contains(output, "proof-receipt-admission --help") {
			t.Fatal("native guidance help lacks receipt continuation")
		}
	}
}

func TestReceiptInputGuideNativeHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "receipt-guide-helper" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "passed":
		fmt.Print("empty input rejected\n")
		os.Exit(0)
	case "failed":
		fmt.Print("empty input accepted\n")
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

func TestReceiptInputGuideExecutionAndBundleChain(t *testing.T) {
	for _, status := range []string{"passed", "failed", "blocked", "not_run"} {
		t.Run(status, func(t *testing.T) {
			packet, receiptHelp := receiptHelpTemplate(t, "proof-receipt-admission")
			bundle, bundleHelp := receiptHelpTemplate(t, "spec-proof-bundle-admission")
			binding := readJSONFile(t, "proofkit/requirement-bindings.json").(map[string]any)
			plan := readJSONFile(t, "proofkit/witness-plan.json").(map[string]any)
			commands := guideCommands(t, bundleHelp, "Spec proof bundle input guide:", cliexec.PathRenderer())
			root := t.TempDir()
			args := []string{os.Args[0], "-test.run=^TestReceiptInputGuideNativeHelper$", "--", "receipt-guide-helper", status}
			var output bytes.Buffer
			var exitCode any
			started := time.Now().UTC().Format(time.RFC3339Nano)
			if status == "passed" || status == "failed" {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				process := exec.CommandContext(ctx, args[0], args[1:]...)
				process.Dir, process.Env, process.WaitDelay = root, []string{}, time.Second
				process.Stdout = &output
				var diagnostic bytes.Buffer
				process.Stderr = &diagnostic
				err := process.Run()
				if ctx.Err() != nil || diagnostic.Len() != 0 || process.ProcessState == nil {
					t.Fatalf("native helper did not complete: %v %s", err, diagnostic.String())
				}
				exitCode = process.ProcessState.ExitCode()
				wantCode, wantOutput := 0, "empty input rejected\n"
				if status == "failed" {
					wantCode, wantOutput = 1, "empty input accepted\n"
				}
				if exitCode != wantCode || output.String() != wantOutput {
					t.Fatalf("native outcome differs: %v %q", exitCode, output.String())
				}
			}
			finished := time.Now().UTC().Format(time.RFC3339Nano)
			// This is an observed helper run, not execution of the self-hosting plan.
			// Only its named command is replaced in the synthetic linkage inputs.
			for _, raw := range binding["witnessCommands"].([]any) {
				command := raw.(map[string]any)
				if command["commandId"] == "proofkit.go-test" {
					command["command"] = strings.Join(args, " ")
				}
			}
			for _, raw := range plan["commands"].([]any) {
				command := raw.(map[string]any)
				if command["id"] == "proofkit.go-test" {
					argv := make([]any, len(args))
					for i, arg := range args {
						argv[i] = arg
					}
					command["argv"] = argv
				}
			}
			scenario := ""
			for _, raw := range binding["bindings"].([]any) {
				row := raw.(map[string]any)
				for _, command := range row["commandIds"].([]any) {
					if command == "proofkit.go-test" {
						scenario = row["scenarioId"].(string)
					}
				}
			}
			if scenario == "" {
				t.Fatal("fixture requires an explicit bound command")
			}
			packet["receiptSetId"] = "example.receipts"
			r := receipt(packet)
			for key, value := range map[string]any{
				"receiptId": "example.receipt", "receiptKind": "proofkit.go-test", "proofPlanId": plan["schedulerPlanId"],
				"sourceRevision": "synthetic-helper-source", "environmentClass": "local-go", "witnessSelectors": []any{scenario},
				"runnerIdentity": "example.helper", "runnerClass": "local", "producerId": "example.local",
				"startedAt": started, "finishedAt": finished, "status": status, "exitCode": exitCode,
			} {
				r[key] = value
			}
			for field, subject := range map[string]any{
				"proofBindingDigest": binding, "commandDigest": map[string]any{"argv": args, "cwd": root},
				"environmentDigest":     map[string]any{"class": "local-go", "environment": []string{}},
				"preconditionDigest":    map[string]any{"attempt": status, "syntheticPolicy": true},
				"witnessSelectorDigest": r["witnessSelectors"],
				"toolchainDigest":       []string{runtime.Version(), runtime.GOOS, runtime.GOARCH},
			} {
				data := adoptionHelpJSON(t, subject)
				path := field + ".json"
				if err := os.WriteFile(filepath.Join(root, path), data, 0600); err != nil {
					t.Fatal(err)
				}
				r[field] = fmt.Sprintf("sha256:%x", sha256.Sum256(data))
			}
			r["evidenceRefs"] = []any{"commandDigest.json", "environmentDigest.json", "preconditionDigest.json", "proofBindingDigest.json", "toolchainDigest.json", "witnessSelectorDigest.json"}
			if exitCode != nil {
				if err := os.WriteFile(filepath.Join(root, "run.log"), output.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				r["artifactRefs"] = []any{map[string]any{"kind": "log", "path": "run.log", "sha256": fmt.Sprintf("sha256:%x", sha256.Sum256(output.Bytes()))}}
			}
			r["nonClaims"] = []any{"Synthetic linkage inputs do not prove execution under the scheduler policy.", "This helper observation is not self-hosting proof or authenticated producer evidence."}
			payload := adoptionHelpJSON(t, packet)
			receiptCommands := guideCommands(t, receiptHelp, "Proof receipt input guide:", cliexec.PathRenderer())
			report := runAdoptionHelpCLI(t, payload, fillGuideOperands(t, receiptCommands[0], map[string]string{"<receipt-input>": "-"})...)
			if report["reportKind"] != "proofkit.proof-receipt-admission" || report["reportId"] != packet["receiptSetId"] || report["state"] != "passed" {
				t.Fatal("receipt report identity or structural outcome differs")
			}
			if got := report["summary"].(map[string]any)[map[string]string{"passed": "passedReceiptCount", "failed": "failedReceiptCount", "blocked": "blockedReceiptCount", "not_run": "notRunReceiptCount"}[status]]; fmt.Sprint(got) != "1" {
				t.Fatal("structural pass erased the native status")
			}
			bundle["bundleId"], bundle["requirementBindings"], bundle["witnessPlan"] = "example.bundle", binding, plan
			child := bundle["receiptAdmission"].(map[string]any)
			child["exitCode"], child["report"], child["receipts"], child["nonClaims"] = 0, report, packet["receipts"], packet["nonClaims"]
			for _, raw := range report["diagnostics"].([]any) {
				row := raw.(map[string]any)
				if row["key"] == "failures" {
					child["failures"] = row["value"]
				}
			}
			for i, input := range []map[string]any{binding, plan, packet, bundle} {
				operands := map[string]string{"<binding-input>": "-", "<scheduler-input>": "-", "<receipt-input>": "-", "<bundle-input>": "-"}
				result := runAdoptionHelpCLI(t, adoptionHelpJSON(t, input), fillGuideOperands(t, commands[i], operands)...)
				if result["state"] != "passed" {
					t.Fatalf("documented chain failed at %v: %v", commands[i], result)
				}
			}
			if !bytes.Equal(payload, adoptionHelpJSON(t, packet)) {
				t.Fatal("composition modified the source receipt")
			}
			checkReceiptGuideMutations(t, packet, bundle)
		})
	}
}

func checkReceiptGuideMutations(t *testing.T, packet, bundle map[string]any) {
	t.Helper()
	for _, field := range []string{"proofPlanId", "receiptKind", "witnessSelectors", "report", "source-receipt", "merge"} {
		t.Run(field, func(t *testing.T) {
			invalid := cloneMap(t, bundle)
			child := invalid["receiptAdmission"].(map[string]any)
			if field == "merge" {
				invalid["mergeRequiredReceiptIds"] = []any{receipt(packet)["receiptId"]}
			} else if field == "report" {
				child["report"].(map[string]any)["summary"].(map[string]any)["receiptCount"] = 999
			} else if field == "source-receipt" {
				child["receipts"].([]any)[0].(map[string]any)["receiptId"] = "example.changed"
			} else {
				changed := cloneMap(t, packet)
				if field == "witnessSelectors" {
					receipt(changed)[field] = []any{"native.path.selector"}
				} else {
					receipt(changed)[field] = "example.wrong"
				}
				child["receipts"] = changed["receipts"]
				child["report"] = runAdoptionHelpCLI(t, adoptionHelpJSON(t, changed), "proof-receipt-admission", "--input", "-")
			}
			code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"spec-proof-bundle-admission", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, invalid)), PresentationCapabilities{})
			if code != 1 {
				t.Fatalf("invalid %s accepted", field)
			}
			if field == "report" || field == "source-receipt" {
				if output != "" || !strings.Contains(diagnostic, "report body does not match") {
					t.Fatalf("wrong child mismatch: %q %q", output, diagnostic)
				}
			} else if diagnostic != "" || decodeCLIJSON(t, output).(map[string]any)["state"] != "failed" {
				t.Fatalf("missing failed linkage report: %q %q", output, diagnostic)
			}
		})
	}
}

func TestNativeTraceabilityGuideIsLazyAndCarrierBound(t *testing.T) {
	var canonical string
	for _, args := range [][]string{{"native-evidence-guidance", "--help"}, {"native-evidence-guidance", "-h"}, {"help", "native-evidence-guidance"}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || len(output) > 10<<10 || strings.Contains(output, "\x1b[") {
			t.Fatalf("native help must be bounded and input-free: %v %q", code, diagnostic)
		}
		if canonical != "" && canonical != output {
			t.Fatal("native help aliases differ")
		}
		canonical = output
	}
	for _, boundary := range []string{
		"(requirementId, scenarioId, witnessId)", "not scenarioId alone",
		"many-to-many", "missing optional selectors", "not a guessed match",
		"independently authored expectations", "Index once",
		"Declaration coverage, actual execution, currentness, producer trust",
		"sourcePlan may remain", "Neither command below reads native files",
		"Compact proof contracts use", "do not feed them to this v1 recipe",
	} {
		if !strings.Contains(canonical, boundary) {
			t.Fatalf("guide lost boundary %q", boundary)
		}
	}
	for _, carrier := range []struct{ profile, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/example/python 3"},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(carrier.profile, carrier.python)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, _ := commandDescriptorFor("native-evidence-guidance")
		help := commandUsageWithRenderer(descriptor, renderer)
		want := [][]string{
			{"requirement-bindings", "--input", "<packet>", "--input-pointer", "/requirementProofBinding/record"},
			{"evidence-graph", "--input", "<packet>", "--input-pointer", "/requirementProofBinding/record"},
		}
		// Two-space indentation marks executable steps; four spaces mark lazy help.
		if got := guideCommands(t, help, "Native traceability cookbook:", renderer); !reflect.DeepEqual(got, want) {
			t.Fatalf("native recipe commands differ: %v", got)
		}
		var actualLazy, expectedLazy []string
		for _, line := range strings.Split(help, "\n") {
			if strings.HasPrefix(line, "    "+renderer.DisplayCommand()+" ") {
				actualLazy = append(actualLazy, line)
			}
		}
		for _, command := range [][]string{{"adopt", "materialize", "plan", "--help"}, {"requirement-authoring-plan", "--help"}, {"proof-receipt-admission", "--help"}, {"spec-proof-bundle-admission", "--help"}, {"requirement-impact-input-compose", "--help"}} {
			expectedLazy = append(expectedLazy, "    "+renderer.DisplayCommand(command...))
			code, output, diagnostic := executeAgentWorkflowCLI(t, command, panicReader{}, PresentationCapabilities{})
			if code != 0 || output == "" || diagnostic != "" {
				t.Fatalf("lazy help route is not executable: %v", command)
			}
		}
		if !reflect.DeepEqual(actualLazy, expectedLazy) {
			t.Fatalf("lazy help commands differ: %v", actualLazy)
		}
	}
	for _, args := range [][]string{{"help"}, {"help", "families"}, {"native-evidence-guidance"}, {"native-evidence-guidance", "--format", "text"}, {"changed-path-set", "--help"}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || strings.Contains(output, "Native traceability cookbook:") {
			t.Fatal("long recipe must remain demand-loaded")
		}
	}
}

func TestNativeGuidanceDefaultBytesMatchReleasedBaseline(t *testing.T) {
	// Independent installed v0.14.13 outputs, from source cde95855deb6.
	for _, item := range []struct {
		args   []string
		bytes  int
		digest string
	}{
		{[]string{"native-evidence-guidance"}, 9877, "366f2f37482506b8c94042dbd974469fceda79e2141b4faec61071893190b3ea"},
		{[]string{"native-evidence-guidance", "--format", "text"}, 5712, "e7e69bd94b4f70962621f0cce57b872c306d9a811ee355b5135d3aec1a3a28c2"},
	} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, item.args, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || len(output) != item.bytes || fmt.Sprintf("%x", sha256.Sum256([]byte(output))) != item.digest {
			t.Fatalf("default guidance differs from released bytes: %v", item.args)
		}
	}
}

func TestNativeTraceabilityGuidePreservesQualifiedRows(t *testing.T) {
	packet := adoptionHelpPacket(t, t.TempDir(), "fresh")
	packet["sourcePlan"] = nil // Child inspection does not require a materialization plan.
	binding := packet["requirementProofBinding"].(map[string]any)["record"].(map[string]any)
	first := binding["bindings"].([]any)[0].(map[string]any)
	first["witnessSelectors"] = []any{map[string]any{"command": "go test ./src -run TestRejectEmptyInput", "selector": "TestRejectEmptyInput"}}
	secondRequirement := cloneMap(t, binding["requirements"].([]any)[0].(map[string]any))
	secondRequirement["requirementId"] = "REQ-EXAMPLE-002"
	binding["requirements"] = append(binding["requirements"].([]any), secondRequirement)
	second := cloneMap(t, first)
	second["requirementId"] = "REQ-EXAMPLE-002"
	delete(second, "witnessSelectors")
	third := cloneMap(t, first)
	third["witnessId"] = "example.witness.shared"
	third["witnessPath"] = "src/shared_test.go"
	third["commandIds"] = []any{"example.test.shared"}
	third["environmentClasses"] = []any{"ci-go"}
	third["witnessSelectors"] = []any{map[string]any{"command": "go test ./src -run TestShared", "selector": "TestShared"}}
	binding["witnessCommands"] = append(binding["witnessCommands"].([]any), map[string]any{
		"commandId": "example.test.shared", "command": "go test ./src -run TestShared", "environmentClasses": []any{"ci-go"},
	})
	binding["bindings"] = []any{first, third, second}
	payload := adoptionHelpJSON(t, packet)
	_, help, _ := executeAgentWorkflowCLI(t, []string{"native-evidence-guidance", "--help"}, panicReader{}, PresentationCapabilities{})
	commands := guideCommands(t, help, "Native traceability cookbook:", cliexec.PathRenderer())
	operands := map[string]string{"<packet>": "-"}
	report := runAdoptionHelpCLI(t, payload, fillGuideOperands(t, commands[0], operands)...)
	if report["state"] != "passed" {
		t.Fatal("qualified input did not pass declaration admission")
	}
	graph := runAdoptionHelpCLI(t, payload, fillGuideOperands(t, commands[1], operands)...)
	if graph["graphKind"] != "proofkit.requirement-evidence-graph" || fmt.Sprint(graph["bindingCount"]) != "3" || fmt.Sprint(graph["requirementCount"]) != "2" || fmt.Sprint(graph["commandCount"]) != "2" {
		t.Fatalf("graph lost its qualified domain: %v", graph)
	}
	rows := graph["requirements"].([]any)
	for index, witnessIDs := range [][]string{{"example.witness.empty", "example.witness.shared"}, {"example.witness.empty"}} {
		row := rows[index].(map[string]any)
		if row["requirementId"] != []string{"REQ-EXAMPLE-001", "REQ-EXAMPLE-002"}[index] {
			t.Fatal("graph moved an edge to the wrong requirement")
		}
		want := make([]any, 0, len(witnessIDs))
		for _, id := range witnessIDs {
			expected := map[string]any{
				"scenarioId": "example.requests.empty", "witnessId": id, "witnessKind": "contract", "witnessPath": "src/request_test.go",
				"commandIds": []any{"example.test.requests"}, "environmentClasses": []any{"local-go"},
				"witnessSelectors": []any{map[string]any{"command": "go test ./src -run TestRejectEmptyInput", "selector": "TestRejectEmptyInput"}},
			}
			if id == "example.witness.shared" {
				expected["witnessPath"] = "src/shared_test.go"
				expected["commandIds"] = []any{"example.test.shared"}
				expected["environmentClasses"] = []any{"ci-go"}
				expected["witnessSelectors"] = []any{map[string]any{"command": "go test ./src -run TestShared", "selector": "TestShared"}}
			}
			if index == 1 {
				delete(expected, "witnessSelectors")
			}
			want = append(want, expected)
		}
		if !reflect.DeepEqual(row["scenarios"], want) {
			t.Fatalf("qualified scenario rows differ: got %v want %v", row["scenarios"], want)
		}
	}
	if !bytes.Equal(payload, adoptionHelpJSON(t, packet)) {
		t.Fatal("read-only recipe changed the input")
	}
	first["commandIds"] = []any{"example.missing"}
	code, output, diagnostic := executeAgentWorkflowCLI(t, fillGuideOperands(t, commands[1], operands), bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
	if code != 1 || output != "" || !strings.Contains(diagnostic, "unknown commandId") {
		t.Fatalf("unresolved command must not become a graph: %d %q %q", code, output, diagnostic)
	}
}
