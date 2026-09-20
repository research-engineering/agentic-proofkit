package app

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestChangeInputGuideIsLazyAndExecutable(t *testing.T) {
	packet, help := receiptHelpTemplate(t, "change", "plan")
	if len(help) > 10<<10 {
		t.Fatal("current-subject help exceeds its bounded context")
	}
	for _, boundary := range []string{
		"does not read", "Do not hash only IDs", "source-qualified pairs",
		"required consumer check", "not authenticated approval", "empty prefix reviews architecture",
		"working tree, Git index, immutable", "different staged bytes", "executable modes",
		"untracked inputs and filter effects", "neither Git inspection",
		"requirement-context-compose --help", "excludes undeclared native dependencies",
	} {
		if !strings.Contains(help, boundary) {
			t.Fatalf("guide lost boundary %q", boundary)
		}
	}
	normalized := strings.Join(strings.Fields(help), " ")
	for _, sentence := range []string{
		"Read that exact plane; a working-tree check alone cannot approve different staged bytes.",
		"If partial staging is unsupported, require exact index/worktree bytes and executable modes for the complete input scope, including untracked inputs and filter effects.",
		"Otherwise materialize and check the selected index/commit separately.",
		"Proofkit performs neither Git inspection nor this consumer precondition.",
	} {
		if !strings.Contains(normalized, sentence) {
			t.Fatalf("publication-plane policy changed: %s", sentence)
		}
	}
	code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"change", "plan", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
	if code != 1 || output != "" || diagnostic == "" {
		t.Fatal("unfilled template fabricated an admissible assessment")
	}
	for _, carrier := range []struct{ profile, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/example/python 3"},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(carrier.profile, carrier.python)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, _ := commandDescriptorFor("change-workflow-plan")
		got := guideCommands(t, commandUsageWithRenderer(descriptor, renderer), "Current-subject review input guide:", renderer)
		if !reflect.DeepEqual(got, [][]string{{"change", "plan", "--input", "<checkpoint>"}}) {
			t.Fatalf("guide command is not carrier-bound: %v", got)
		}
	}
	for _, args := range [][]string{{"help"}, {"help", "families"}, {"native-evidence-guidance"}, {"changed-path-set", "--help"}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || strings.Contains(output, "Current-subject review input guide:") {
			t.Fatal("current-subject template must remain demand-loaded")
		}
	}
}

func TestChangeGuideActualFilesInvalidateOldAssessment(t *testing.T) {
	template, _ := receiptHelpTemplate(t, "change", "plan")
	// This finite consumer owns these inputs. It is not a universal dependency scanner.
	files := map[string]string{
		"meaning.json":  `{"namespace":"alpha","requirementId":"REQ-ONE","invariant":"Reject empty input","scenarioId":"empty","scenarioContext":"empty string"}`,
		"bindings.json": `{"witnessId":"native.one","path":"request.test.ts","selector":"test_empty"}`,
		"test.ts":       `assert.equal(normalize(""), null);`,
		"helper.ts":     `export const normalize = value => value || null;`,
		"command.json":  `["node","--test","request.test.ts"]`,
		"runtime.json":  `{"environment":"local-node","toolchain":"node-fixture-1"}`,
		"policy.json":   `{"receiptKind":"fixture.native","requireCurrent":true}`,
	}
	root := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range files {
		write(name, value)
	}
	// Structured fixtures have JSON value semantics; native code is byte-sensitive.
	current := func() string {
		t.Helper()
		values := map[string]any{}
		for name := range files {
			data, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(name, ".json") {
				values[name] = decodeCLIJSON(t, string(data))
			} else {
				values[name] = string(data)
			}
		}
		return fmt.Sprintf("sha256:%x", sha256.Sum256(adoptionHelpJSON(t, values)))
	}
	baseline := current()
	checkpoint := func(subject, assessment string) map[string]any {
		packet := cloneMap(t, template)
		value := packet["checkpoint"].(map[string]any)
		value["subjectDigest"], value["assessmentSubjectDigest"] = subject, assessment
		refs := packet["contextRefs"].([]any)
		refs[0].(map[string]any)["subjectDigest"] = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("fixture owner policy")))
		refs[1].(map[string]any)["subjectDigest"] = subject
		return packet
	}
	invoke := func(packet map[string]any, wantCode int, wantError string) map[string]any {
		t.Helper()
		code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"change", "plan", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
		if code != wantCode || (wantError != "" && !strings.Contains(diagnostic, wantError)) || (wantError == "" && diagnostic != "") {
			t.Fatalf("unexpected checkpoint result: %d %q %q", code, output, diagnostic)
		}
		if wantCode != 0 {
			if output != "" {
				t.Fatal("rejected checkpoint emitted a success packet")
			}
			return nil
		}
		return decodeCLIJSON(t, output).(map[string]any)
	}
	prior := checkpoint(baseline, baseline)
	action := invoke(prior, 0, "")
	if action["action"] != "accept_stage" {
		t.Fatalf("unchanged reviewed subject not accepted: %v", action)
	}
	// A public consumer applies the actual returned delta, without internal Go APIs.
	merged := cloneMap(t, prior)
	for key, value := range action["successorStateDelta"].(map[string]any) {
		merged[key] = value
	}
	if next := invoke(merged, 0, ""); next["activeStageId"] != "design" {
		t.Fatalf("merged successor did not reach design: %v", next)
	}
	mutations := []struct{ name, file, before, after string }{
		{"namespace", "meaning.json", "alpha", "beta"},
		{"requirement", "meaning.json", "REQ-ONE", "REQ-TWO"},
		{"invariant", "meaning.json", "Reject empty input", "Accept empty input"},
		{"scenario", "meaning.json", `"scenarioId":"empty"`, `"scenarioId":"blank"`},
		{"scenario-context", "meaning.json", "empty string", "whitespace"},
		{"witness", "bindings.json", "native.one", "native.two"},
		{"path", "bindings.json", "request.test.ts", "other.test.ts"},
		{"selector", "bindings.json", "test_empty", "test_preserve"},
		{"assertion", "test.ts", "null", "true"},
		{"helper", "helper.ts", "null", "true"},
		{"argv", "command.json", "request.test.ts", "other.test.ts"},
		{"environment", "runtime.json", "local-node", "remote-node"},
		{"toolchain", "runtime.json", "node-fixture-1", "node-fixture-2"},
		{"receipt-policy", "policy.json", "true", "false"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			before := files[mutation.file]
			after := strings.Replace(before, mutation.before, mutation.after, 1)
			if before == after {
				t.Fatal("mutation failed to change the intended operand")
			}
			write(mutation.file, after)
			defer write(mutation.file, before)
			digest := current()
			if digest == baseline {
				t.Fatal("actual semantic change did not invalidate the current subject")
			}
			invoke(checkpoint(digest, baseline), 1, "proofkit.workflow.assessment_digest_mismatch")
			if got := invoke(checkpoint(digest, digest), 0, ""); got["action"] != "accept_stage" {
				t.Fatal("matching retained assessment is not accepted")
			}
			// CLI admits declared equality, not files. The consumer must recompute.
			invoke(prior, 0, "")
			if prior["checkpoint"].(map[string]any)["subjectDigest"] == digest {
				t.Fatal("consumer failed to detect all-old caller hashes")
			}
		})
	}
	write("unrelated.ts", "independent scope changed")
	write("meaning.json", "\n  "+files["meaning.json"]+"\n")
	if current() != baseline {
		t.Fatal("unaffected scope or JSON layout invalidated semantic subject")
	}
	invoke(checkpoint(current(), baseline), 0, "")
}
