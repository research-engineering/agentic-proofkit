package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/agentroute"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

var processTestBinary = struct {
	once    sync.Once
	path    string
	tempDir string
	err     error
}{}

func TestMain(m *testing.M) {
	code := m.Run()
	if processTestBinary.tempDir != "" {
		_ = os.RemoveAll(processTestBinary.tempDir)
	}
	os.Exit(code)
}

func TestSelfCheckReadsExplicitJSONAndEmitsReport(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"self-check", "--input", "-"}, strings.NewReader(`{"ok":true}`), &stdout, &stderr)
	if status != 0 {
		t.Fatalf("unexpected status %d, stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty: %s", stderr.String())
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("stdout must be JSON: %v", err)
	}
	if output["reportKind"] != "proofkit.go-runtime.self-check" {
		t.Fatalf("unexpected report kind: %v", output["reportKind"])
	}
	if output["state"] != "passed" {
		t.Fatalf("unexpected state: %v", output["state"])
	}
}

func TestSelfCheckRejectsDuplicateKeys(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.061049109061347524269448772857617649849822202469664158122537165529475398131547")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"self-check", "--input", "-"}, strings.NewReader(`{"schemaVersion":1,"schemaVersion":2}`), &stdout, &stderr)
	if status != 1 {
		t.Fatalf("expected failure, got %d", status)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty on admission failure: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "duplicate object key") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "schemaVersion") {
		t.Fatalf("stderr must not echo duplicate key: %s", stderr.String())
	}
}

func TestSelfCheckAcceptsRepositoryScalePayload(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	payload := `{"value":"` + strings.Repeat("x", 2<<20) + `"}`
	status := Run(t.Context(), []string{"self-check", "--input", "-"}, strings.NewReader(payload), &stdout, &stderr)
	if status != 0 {
		t.Fatalf("unexpected status %d, stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty: %s", stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"state": "passed"`)) {
		t.Fatalf("unexpected output:\n%s", stdout.String())
	}
}

func TestSelfCheckRejectsInputPointer(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"self-check", "--input", "-", "--input-pointer", "/ok"}, strings.NewReader(`{"ok":true}`), &stdout, &stderr)
	if status != 1 {
		t.Fatalf("expected argument failure, got %d", status)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must be empty on argument failure: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "does not support --input-pointer") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestAgentRouteAgentEnvelopeCLIABI(t *testing.T) {
	input := `{"schemaVersion":1,"routeId":"consumer.route.requirement_source","goal":"validate_requirement_source","mode":"observe","availableInputs":[{"kind":"requirement_source","ref":"docs/specs/module/requirements.v1.json"}],"nonClaims":["Caller route fixture is not merge proof."]}`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"agent-route", "--input", "-", "--agent-envelope"}, strings.NewReader(input), &stdout, &stderr)
	if status != 0 {
		t.Fatalf("agent-route envelope failed status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty: %s", stderr.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("stdout must be JSON envelope: %v", err)
	}
	if envelope["envelopeId"] != "consumer.route.requirement_source.agent-envelope" {
		t.Fatalf("unexpected envelopeId: %v", envelope["envelopeId"])
	}
	source := envelope["sourceReport"].(map[string]any)
	if source["reportKind"] != "proofkit.agent-route" || source["state"] != "passed" {
		t.Fatalf("unexpected source report: %#v", source)
	}
	cost := envelope["costContract"].(map[string]any)
	if cost["stopReason"] == "merge_ready" || cost["stopReason"] == "proof_passed" {
		t.Fatalf("agent-route envelope overclaimed stopReason: %#v", cost)
	}
	nonClaims := stringListFromAny(t, envelope["nonClaims"])
	if !stringListContains(nonClaims, "Caller route fixture is not merge proof.") {
		t.Fatalf("caller non-claim not preserved: %#v", nonClaims)
	}
	commands := envelope["commands"].([]any)
	if len(commands) != 1 {
		t.Fatalf("commands length=%d want 1: %#v", len(commands), commands)
	}
}

func TestAgentRouteAgentEnvelopeInvalidInputUsesJSONRepairPacket(t *testing.T) {
	input := `{"schemaVersion":1,"routeId":"consumer.route.unsafe","goal":"validate_requirement_source","mode":"observe","availableInputs":[{"kind":"requirement_source","ref":"../requirements.v1.json"}]}`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"agent-route", "--input", "-", "--agent-envelope"}, strings.NewReader(input), &stdout, &stderr)
	if status != 1 {
		t.Fatalf("expected invalid-input status 1, got %d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty for invalid-input envelope: %s", stderr.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("stdout must be invalid-input JSON envelope: %v", err)
	}
	if envelope["envelopeId"] != "proofkit.agent-envelope.invalid-input" {
		t.Fatalf("unexpected invalid-input envelopeId: %v", envelope["envelopeId"])
	}
	if len(envelope["blockedPreconditions"].([]any)) == 0 {
		t.Fatalf("invalid-input envelope must expose a blocked precondition: %#v", envelope)
	}
}

func TestAgentRouteAgentEnvelopeDecodeFailuresUseJSONRepairPacket(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
	}{
		{
			name:  "malformed json",
			input: `{"schemaVersion":1`,
		},
		{
			name:  "duplicate key",
			input: `{"schemaVersion":1,"schemaVersion":1}`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), []string{"agent-route", "--input", "-", "--agent-envelope"}, strings.NewReader(tt.input), &stdout, &stderr)
			if status != 1 {
				t.Fatalf("expected decode repair status 1, got %d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr must be empty for decode repair envelope: %s", stderr.String())
			}
			var envelope map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatalf("stdout must be invalid-input JSON envelope: %v", err)
			}
			if envelope["envelopeId"] != "proofkit.agent-envelope.invalid-input" {
				t.Fatalf("unexpected invalid-input envelopeId: %v", envelope["envelopeId"])
			}
			cost := envelope["costContract"].(map[string]any)
			if cost["stopReason"] != "blocked_precondition" {
				t.Fatalf("stopReason = %v, want blocked_precondition", cost["stopReason"])
			}
		})
	}
}

func stringListFromAny(t *testing.T, raw any) []string {
	t.Helper()
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("value is not a string array: %#v", raw)
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("value contains non-string item: %#v", raw)
		}
		values = append(values, text)
	}
	return values
}

func stringListContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestRunFailsClosedWhenStdoutWriteFails(t *testing.T) {
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"self-check", "--input", "-"}, strings.NewReader(`{"ok":true}`), failingWriter{}, &stderr)
	if status != 1 {
		t.Fatalf("expected write failure status, got %d", status)
	}
	if !strings.Contains(stderr.String(), "write output") {
		t.Fatalf("stderr must classify output write failure: %s", stderr.String())
	}
}

func TestConformanceProfileRejectsAmbiguousModesAndHTML(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing mode",
			args: []string{"conformance-profile", "--input", "-"},
			want: "requires exactly one",
		},
		{
			name: "combined modes",
			args: []string{"conformance-profile", "--input", "-", "--verify", "--list"},
			want: "requires exactly one",
		},
		{
			name: "html format",
			args: []string{"conformance-profile", "--input", "-", "--profile", "sample", "--format", "html"},
			want: "--format must be json or markdown",
		},
		{
			name: "markdown without profile",
			args: []string{"conformance-profile", "--input", "-", "--list", "--format", "markdown"},
			want: "--format markdown requires --profile",
		},
		{
			name: "duplicate input",
			args: []string{"conformance-profile", "--input", "-", "--input", "-", "--profile", "sample"},
			want: "--input requires a path",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), item.args, strings.NewReader(`{}`), &stdout, &stderr)
			if status != 1 {
				t.Fatalf("expected failure, got %d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout must be empty on argument failure: %s", stdout.String())
			}
			if !strings.Contains(stderr.String(), item.want) {
				t.Fatalf("stderr %q does not contain %q", stderr.String(), item.want)
			}
		})
	}
}

func TestRepresentativeCLICommandsPreserveFileStdinAndPointerABI(t *testing.T) {
	cases := []struct {
		command string
		path    string
	}{
		{command: "requirement-bindings", path: "proofkit/requirement-bindings.json"},
		{command: "witness-scheduler-plan", path: "proofkit/witness-plan.json"},
	}
	for _, item := range cases {
		t.Run(item.command, func(t *testing.T) {
			path := filepath.Join(repoRoot(t), item.path)
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", item.path, err)
			}
			fileOutput := runCLI(t, []string{item.command, "--input", path}, "")
			stdinOutput := runCLI(t, []string{item.command, "--input", "-"}, string(source))
			wrapped := `{"payload":` + string(source) + `}`
			pointerOutput := runCLI(t, []string{item.command, "--input", "-", "--input-pointer", "/payload"}, wrapped)
			if !bytes.Equal(fileOutput, stdinOutput) {
				t.Fatalf("file/stdin output mismatch\nfile=%s\nstdin=%s", fileOutput, stdinOutput)
			}
			if !bytes.Equal(fileOutput, pointerOutput) {
				t.Fatalf("file/pointer output mismatch\nfile=%s\npointer=%s", fileOutput, pointerOutput)
			}
		})
	}
}

func TestCLIRejectsUnadvertisedFlagsWithoutStdout(t *testing.T) {
	cases := []struct {
		args          []string
		wantStderrHas string
	}{
		{args: []string{"self-check", "--input", "-", "--agent-envelope"}, wantStderrHas: "unsupported argument for self-check: --agent-envelope"},
		{args: []string{"typescript-public-api-surfaces", "--input", "-", "--repo-root", ".", "--agent-envelope"}, wantStderrHas: "unsupported argument for typescript-public-api-surfaces: --agent-envelope"},
		{args: []string{"help", "--input", "-"}, wantStderrHas: "help supports only --help or -h"},
		{args: []string{"stack-preset", "--preset", "typescript_workspace", "--agent-envelope"}, wantStderrHas: "stack-preset supports only --preset <id>"},
		{args: []string{"gradual-adoption-guidance", "--input", "-", "--format", "json"}, wantStderrHas: "unsupported argument for gradual-adoption-guidance: --format"},
		{args: []string{"gradual-adoption-guidance", "--input", "-", "--contract-envelope", "--guidance-mode", "audit"}, wantStderrHas: "--guidance-mode requires observe, warn, enforce-touched, or enforce-all"},
		{args: []string{"gradual-adoption-guidance", "--input", "-", "--contract-envelope", "--checked-scope", "partial"}, wantStderrHas: "--checked-scope requires none, touched, or all"},
		{args: []string{"adoption-workflow-plan", "--input", "-", "--format", "json"}, wantStderrHas: "unsupported argument for adoption-workflow-plan: --format"},
		{args: []string{"requirement-coverage-view", "--input", "-", "--format", "html", "--agent-envelope"}, wantStderrHas: "--agent-envelope requires --format json"},
		{args: []string{"test-evidence-inventory", "--input", "-", "--format", "json"}, wantStderrHas: "unsupported argument for test-evidence-inventory: --format"},
		{args: []string{"test-evidence-inventory", "--input", "-", "--normalized-inventory", "--normalized-inventory"}, wantStderrHas: "test-evidence-inventory accepts --normalized-inventory at most once"},
		{args: []string{"test-evidence-inventory", "--input", "-", "--projection", "unknown"}, wantStderrHas: "test-evidence-inventory --projection must be proof-binding-derived or discovery-draft"},
		{args: []string{"test-evidence-inventory", "--input", "-", "--projection"}, wantStderrHas: "test-evidence-inventory --projection requires proof-binding-derived or discovery-draft"},
		{args: []string{"selective-gate-obligation-decision-input", "--input", "missing.json", "--agent-envelope"}, wantStderrHas: "unsupported argument for selective-gate-obligation-decision-input: --agent-envelope"},
	}
	for _, item := range cases {
		t.Run(strings.Join(item.args, " "), func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), item.args, strings.NewReader(`{}`), &stdout, &stderr)
			if status != 1 {
				t.Fatalf("expected failure, got %d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout must be empty on flag admission failure: %s", stdout.String())
			}
			if !strings.Contains(stderr.String(), item.wantStderrHas) {
				t.Fatalf("stderr=%q does not classify flag admission failure as %q", stderr.String(), item.wantStderrHas)
			}
		})
	}
}

func TestCLIDiagnosticsRedactSecretLikeCallerLabels(t *testing.T) {
	secret := "ghp_FAKEFAKE1234567890"
	cases := []struct {
		name  string
		args  []string
		stdin string
	}{
		{
			name: "unsupported command",
			args: []string{secret},
		},
		{
			name: "input file path",
			args: []string{"self-check", "--input", "proofkit/" + secret + "/input.json"},
		},
		{
			name:  "missing pointer segment",
			args:  []string{"requirement-source-admission", "--input", "-", "--input-pointer", "/" + secret},
			stdin: `{}`,
		},
		{
			name:  "invalid pointer escape",
			args:  []string{"requirement-source-admission", "--input", "-", "--input-pointer", "/bad~2" + secret},
			stdin: `{}`,
		},
	}
	for _, item := range cases {
		item := item
		t.Run(item.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), item.args, strings.NewReader(item.stdin), &stdout, &stderr)
			if status != 1 {
				t.Fatalf("expected failure, got %d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout must be empty on CLI diagnostic failure: %s", stdout.String())
			}
			if strings.Contains(stderr.String(), secret) {
				t.Fatalf("stderr leaked secret-shaped caller label: %s", stderr.String())
			}
			if !strings.Contains(stderr.String(), "<redacted-secret-like-value>") {
				t.Fatalf("stderr=%q, want redaction placeholder", stderr.String())
			}
		})
	}
}

func TestLocalEnvironmentClassAdmissionRejectsSecretsAcrossResolverAndViews(t *testing.T) {
	secret := "api_key=local-environment-secret-sentinel"
	cases := [][]string{
		{"requirement-proof-resolver", "--input", "-", "--local-environment-class", secret},
		{"requirement-proof-view", "--input", "-", "--local-environment-class", secret},
		{"requirement-browser-server", "--input", "-", "--view", "proof", "--local-environment-class", secret},
	}
	for _, args := range cases {
		t.Run(args[0], func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), args, strings.NewReader(`{}`), &stdout, &stderr)
			combined := stdout.String() + stderr.String()
			if status != 1 || !strings.Contains(stderr.String(), "must not contain secret-like values") {
				t.Fatalf("Run(%s) status=%d stdout=%q stderr=%q", args[0], status, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || strings.Contains(combined, secret) || strings.Contains(combined, "local-environment-secret-sentinel") {
				t.Fatalf("Run(%s) disclosed rejected local environment class: stdout=%q stderr=%q", args[0], stdout.String(), stderr.String())
			}
		})
	}
}

func TestEveryAgentRouteArgvSatisfiesCommandDescriptorAdmission(t *testing.T) {
	contract := agentroute.InputContract()
	fields := contract["fields"].(map[string]any)
	goals := fields["goal"].(map[string]any)["enum"].([]any)
	kinds := fields["availableInputs"].(map[string]any)["item"].(map[string]any)["kind"].(map[string]any)["enum"].([]any)
	available := make([]any, 0, len(kinds))
	for _, value := range kinds {
		kind := value.(string)
		ref := "inputs/" + kind + ".json"
		if kind == "typescript_public_api_repo_root" {
			ref = "."
		}
		available = append(available, map[string]any{"kind": kind, "ref": ref})
	}
	for _, value := range goals {
		goal := value.(string)
		t.Run(goal, func(t *testing.T) {
			report, _, err := agentroute.Build(map[string]any{
				"schemaVersion":   json.Number("1"),
				"routeId":         "proofkit.test.route." + strings.ReplaceAll(goal, "_", "-"),
				"goal":            goal,
				"mode":            "observe",
				"availableInputs": available,
			})
			if err != nil {
				t.Fatalf("agentroute.Build() error = %v", err)
			}
			for _, rawCommand := range report["nextCommands"].([]any) {
				command := rawCommand.(map[string]any)
				rawArgv := command["argv"].([]any)
				argv := make([]string, len(rawArgv))
				for index, raw := range rawArgv {
					argv[index] = raw.(string)
				}
				assertDescriptorAdmitsAgentArgv(t, argv)
			}
		})
	}
}

func assertDescriptorAdmitsAgentArgv(t *testing.T, argv []string) {
	t.Helper()
	if len(argv) < 2 || argv[0] != "agentic-proofkit" {
		t.Fatalf("agent route emitted invalid process argv: %v", argv)
	}
	descriptor, ok := commandDescriptorFor(argv[1])
	if !ok {
		t.Fatalf("agent route emitted unknown command argv: %v", argv)
	}
	for index := 2; index < len(argv); index++ {
		flag := argv[index]
		if !slices.Contains(descriptor.allowedFlags, flag) {
			t.Fatalf("agent route emitted unsupported flag %q for %s: %v", flag, descriptor.name, argv)
		}
		if flagRequiresValue(flag) {
			if index+1 >= len(argv) || slices.Contains(descriptor.allowedFlags, argv[index+1]) {
				t.Fatalf("agent route emitted flag %q without value for %s: %v", flag, descriptor.name, argv)
			}
			index++
		}
	}
	if err := validateFlagConstraints(descriptor, argv[2:]); err != nil {
		t.Fatalf("agent route argv is rejected by %s descriptor: %v; argv=%v", descriptor.name, err, argv)
	}
}

func TestCLIDiagnosticsRedactControlAndOversizedCallerLabels(t *testing.T) {
	cases := []struct {
		name       string
		command    string
		forbidden  string
		wantMarker string
		maxStderr  int
	}{
		{
			name:       "control rune",
			command:    "bad\ncommand",
			forbidden:  "bad\ncommand",
			wantMarker: "<redacted-control-rune>",
			maxStderr:  128,
		},
		{
			name:       "oversized",
			command:    "bad" + strings.Repeat("x", 900),
			forbidden:  strings.Repeat("x", 900),
			wantMarker: "<truncated-diagnostic>",
			maxStderr:  620,
		},
	}
	for _, item := range cases {
		item := item
		t.Run(item.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), []string{item.command}, strings.NewReader(""), &stdout, &stderr)
			if status != 1 {
				t.Fatalf("expected failure, got %d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout must be empty on unsupported command: %s", stdout.String())
			}
			if strings.Contains(stderr.String(), item.forbidden) {
				t.Fatalf("stderr leaked unsafe caller label: %q", stderr.String())
			}
			if !strings.Contains(stderr.String(), item.wantMarker) {
				t.Fatalf("stderr=%q, want %s", stderr.String(), item.wantMarker)
			}
			if stderr.Len() > item.maxStderr {
				t.Fatalf("stderr length=%d, want <= %d: %q", stderr.Len(), item.maxStderr, stderr.String())
			}
		})
	}
}

func TestAdoptionDoctorAgentEnvelopeRejectsSecretShapedPathsBeforePathBearingStdout(t *testing.T) {
	secret := "ghp_FAKEFAKE1234567890"
	payload := adoptionDoctorEnvelopeInput(t, "packages/"+secret+"/src/index.ts")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"adoption-doctor", "--input", "-", "--agent-envelope"}, strings.NewReader(payload), &stdout, &stderr)
	if status != 1 {
		t.Fatalf("expected failure, got %d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatalf("CLI leaked secret-shaped path stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"envelopeId": "proofkit.agent-envelope.invalid-input"`) {
		t.Fatalf("stdout=%s, want invalid-input envelope", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"state": "failed"`) {
		t.Fatalf("stdout=%s, want failed invalid-input source report", stdout.String())
	}
}

func TestGradualAdoptionGuidanceCLIEnforcesCandidateBoundaries(t *testing.T) {
	payload := candidateBoundaryGuidanceInput(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"gradual-adoption-guidance", "--input", "-", "--contract-envelope", "--guidance-mode", "enforce-all", "--checked-scope", "all"}, strings.NewReader(payload), &stdout, &stderr)
	if status != 1 {
		t.Fatalf("expected candidate boundaries to block CLI enforcement, got status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be empty for report-level enforcement failure: %s", stderr.String())
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("stdout must be JSON: %v\n%s", err, stdout.String())
	}
	if output["state"] != "failed" {
		t.Fatalf("state=%v want failed output=%#v", output["state"], output)
	}
	summary := output["summary"].(map[string]any)
	if summary["checkedScope"] != "all" {
		t.Fatalf("checkedScope=%v want CLI override all", summary["checkedScope"])
	}
	if !strings.Contains(stdout.String(), "enforcement modes require candidate boundaries to be owner-admitted before enforcement") {
		t.Fatalf("stdout missing candidate-boundary enforcement failure: %s", stdout.String())
	}
}

func TestGradualAdoptionGuidanceCLIRejectsInvalidModeScopePairs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "enforce all requires full scope",
			args: []string{"gradual-adoption-guidance", "--input", "-", "--contract-envelope", "--guidance-mode", "enforce-all", "--checked-scope", "touched"},
			want: "enforce-all requires checkedScope all",
		},
		{
			name: "enforce touched rejects none scope",
			args: []string{"gradual-adoption-guidance", "--input", "-", "--contract-envelope", "--guidance-mode", "enforce-touched", "--checked-scope", "none"},
			want: "enforce-touched requires checkedScope touched or all",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := Run(t.Context(), item.args, strings.NewReader(candidateBoundaryGuidanceInput(t)), &stdout, &stderr)
			if status != 1 {
				t.Fatalf("expected invalid mode/scope pair to fail, got status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr must be empty for report-level mode/scope failure: %s", stderr.String())
			}
			if !strings.Contains(stdout.String(), item.want) {
				t.Fatalf("stdout=%s, want failure %q", stdout.String(), item.want)
			}
		})
	}
}

func TestGoRunSelfCheckProcess(t *testing.T) {
	root := t.TempDir()
	inputPath := filepath.Join(root, "input.json")
	if err := os.WriteFile(inputPath, []byte("{\"ok\":true}\n"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	command := exec.CommandContext(t.Context(), buildTestBinary(t), "self-check", "--input", inputPath)
	command.Dir = repoRoot(t)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("self-check process failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("\"reportKind\": \"proofkit.go-runtime.self-check\"")) {
		t.Fatalf("unexpected output:\n%s", output)
	}
}

func candidateBoundaryGuidanceInput(t *testing.T) string {
	t.Helper()
	guidance := map[string]any{
		"agentGuidance": map[string]any{
			"artifactPath":                     "artifacts/guidance.json",
			"blockedPreconditions":             []any{},
			"callerSuggestedAutofixCandidates": []any{},
			"commands":                         []any{"npm run check"},
			"minimalAdoptionPath":              []any{"Keep proofkit guidance advisory until owner routes are admitted."},
			"proofBindingsMissing":             []any{},
			"reportKind":                       "proofkit.gradual-adoption-guidance",
			"requiredNextActions":              []any{},
			"routeQuestions":                   []any{"what changed", "what proves it", "who owns it"},
			"schemaId":                         "proofkit.gradual-adoption-guidance.v1",
		},
		"defaultMode": "warn",
		"guidanceId":  "proofkit.test.guidance",
		"modernization": map[string]any{
			"candidateBoundaries": []any{map[string]any{
				"admissionState":       "advisory",
				"affectedPaths":        []any{"src/auth/webhook.ts"},
				"blockedPreconditions": []any{},
				"boundaryId":           "candidate.auth-webhook-boundary",
				"candidateOwner":       "repository owner",
				"contractWitnessRefs":  []any{"docs/contracts/auth-webhook.json"},
				"migrationRefs":        []any{"docs/plans/auth-boundary.md"},
				"nativeWitnessRefs":    []any{"test/auth-webhook.test.ts"},
				"nonClaims":            []any{"Candidate boundary guidance is advisory until the consuming repository owner admits it in stable requirements and proof bindings."},
				"observedFacts":        []any{"Webhook admission and signature checks change together."},
				"ownerQuestions":       []any{"Should auth own the webhook request admission boundary?"},
				"proofBindingRefs":     []any{"docs/contracts/requirement-proof-bindings.v1.json"},
				"requirementRefs":      []any{"REQ-AUTH-001"},
				"uncertainties":        []any{"Runtime ownership is not yet declared in stable requirements."},
			}},
			"promoteOnlyAfterOwnerReview": true,
		},
		"nonClaims": []any{
			"Guidance reports do not execute native witnesses.",
			"Guidance reports do not own repository proof truth.",
			"Guidance reports do not prove rollout readiness.",
		},
		"ownerRoute": map[string]any{
			"evidencePaths":     []any{"artifacts/guidance.json"},
			"primaryOwner":      "repository owner",
			"proofBindingPaths": []any{"docs/contracts/requirement-proof-bindings.v1.json"},
			"specPaths":         []any{"docs/specs/auth/requirements.v1.json"},
		},
		"schemaVersion": json.Number("1"),
		"scopeEvidence": map[string]any{
			"basis":          "caller_provided_touched_rule_ids",
			"checkedScope":   "none",
			"touchedRuleIds": []any{},
		},
	}
	payload := map[string]any{
		"guidance": guidance,
		"input":    appMinimalAdoptionInput(),
		"schema":   "proofkit.gradual-adoption-profile.v1",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal candidate boundary guidance input: %v", err)
	}
	return string(raw)
}

func adoptionDoctorEnvelopeInput(t *testing.T, affectedPath string) string {
	t.Helper()
	payload := map[string]any{
		"blockedPreconditions": []any{},
		"checkedScope":         "touched",
		"childReports": []any{
			map[string]any{
				"evidenceRefs":   []any{"docs/specs/proofkit-consumer-infra-retirement/requirements.v1.json"},
				"nonClaim":       "Child report state is caller-provided evidence only.",
				"reportId":       "consumer.source-admission",
				"reportKind":     "proofkit.requirement-source-admission",
				"state":          "passed",
				"summary":        "Requirement source admission passed.",
				"touchedRuleIds": []any{"REQ-CONSUMER-001"},
			},
		},
		"doctorId": "consumer.adoption-doctor",
		"mode":     "observe",
		"modernization": map[string]any{
			"candidateBoundaries": []any{
				map[string]any{
					"admissionState":       "advisory",
					"affectedPaths":        []any{affectedPath},
					"blockedPreconditions": []any{},
					"boundaryId":           "consumer.example-boundary",
					"candidateOwner":       "consumer.repository",
					"contractWitnessRefs":  []any{},
					"nativeWitnessRefs":    []any{},
					"nonClaims":            []any{"Candidate boundaries are advisory until owner admission."},
					"observedFacts":        []any{"A cohesive module candidate was observed."},
					"ownerQuestions":       []any{"Should this candidate become a stable requirement owner?"},
					"proofBindingRefs":     []any{},
					"requirementRefs":      []any{"REQ-CONSUMER-001"},
					"uncertainties":        []any{"Proof ownership still needs owner review."},
				},
			},
		},
		"nonClaims": []any{"The consuming repository owns native witness execution."},
		"ownerRoutes": []any{
			map[string]any{
				"commands":          []any{},
				"nativeWitnessRefs": []any{},
				"nonClaims":         []any{"Owner route evidence is caller-provided."},
				"owner":             "consumer.repository",
				"proofBindingPaths": []any{},
				"routeId":           "consumer.example-route",
				"specPaths":         []any{"docs/specs/example/requirements.v1.json"},
				"touchedRuleIds":    []any{"REQ-CONSUMER-001"},
			},
		},
		"schemaVersion":  json.Number("1"),
		"touchedRuleIds": []any{"REQ-CONSUMER-001"},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal adoption doctor input: %v", err)
	}
	return string(raw)
}

func appMinimalAdoptionInput() map[string]any {
	return map[string]any{
		"adoptionId":        "proofkit.test.adoption",
		"adoptionMode":      "non_blocking",
		"agentReport":       appMinimalAgentReport(),
		"budget":            appMinimalBudget(),
		"module":            appMinimalModule(),
		"nativeWitnesses":   appMinimalNativeWitnesses(),
		"nonClaims":         []any{"Gradual adoption does not prove rollout readiness."},
		"packageVersionRef": "agentic-proofkit@local",
		"proofBinding":      appMinimalProofBinding(),
		"repository":        appMinimalRepository(),
		"rollback":          map[string]any{"disableCommand": "remove proofkit command", "owner": "repository owner", "versionPin": "package.json"},
		"rolloutClaim":      false,
		"schemaVersion":     json.Number("1"),
	}
}

func appMinimalAgentReport() map[string]any {
	return map[string]any{
		"artifactPath":   "artifacts/adoption.json",
		"outputMode":     "non_blocking",
		"reportKind":     "proofkit.gradual-adoption",
		"routeQuestions": []any{"what changed", "what proves it", "who owns it"},
		"schemaId":       "proofkit.gradual-adoption.v1",
	}
}

func appMinimalBudget() map[string]any {
	return map[string]any{
		"copiedVerifierFileCount": json.Number("0"),
		"customRuleCount":         json.Number("0"),
		"maxAddedSeconds":         json.Number("5"),
		"maxCustomRuleCount":      json.Number("0"),
		"maxProfileLines":         json.Number("10"),
		"maxSetupMinutes":         json.Number("5"),
		"profileLines":            json.Number("1"),
	}
}

func appMinimalModule() map[string]any {
	return map[string]any{
		"moduleId":       "proofkit.test.module",
		"requirementIds": []any{"REQ-AUTH-001"},
		"specPath":       "docs/specs/auth/requirements.v1.json",
	}
}

func appMinimalProofBinding() map[string]any {
	return map[string]any{
		"bindingFormat":     "requirement_to_witness",
		"bindingPath":       "docs/contracts/requirement-proof-bindings.v1.json",
		"requirementIds":    []any{"REQ-AUTH-001"},
		"witnessCommandIds": []any{"proofkit.test.witness"},
	}
}

func appMinimalNativeWitnesses() map[string]any {
	return map[string]any{
		"commands": []any{map[string]any{
			"argv":            []any{"npm", "run", "check"},
			"cachePolicy":     "disabled",
			"credentialClass": "none",
			"cwd":             ".",
			"environment": map[string]any{
				"allowlist": []any{},
				"classes":   []any{"local-go"},
				"inherit":   "none",
			},
			"exitCodePolicy": map[string]any{
				"kind":         "zero",
				"successCodes": []any{json.Number("0")},
			},
			"expectedArtifacts": []any{map[string]any{
				"kind":     "report",
				"path":     "artifacts/proofkit/report.json",
				"required": true,
			}},
			"id":            "proofkit.test.witness",
			"networkPolicy": "none",
			"parallelGroup": "local",
			"schemaVersion": json.Number("1"),
			"timeoutMs":     json.Number("60000"),
		}},
		"vocabulary": map[string]any{
			"artifactKinds":                 []any{"report"},
			"credentialClasses":             []any{"none"},
			"environmentClasses":            []any{"local-go"},
			"maxTimeoutMs":                  json.Number("60000"),
			"nonCacheableCredentialClasses": []any{},
			"parallelGroups":                []any{"local"},
			"environmentClassPolicies": []any{map[string]any{
				"cachePolicies":     []any{"disabled"},
				"credentialClasses": []any{"none"},
				"environmentClass":  "local-go",
				"networkPolicies":   []any{"none"},
			}},
		},
	}
}

func appMinimalRepository() map[string]any {
	return map[string]any{
		"customRuleBoundary": "profile_only",
		"primaryLanguages":   []any{"go"},
		"profilePath":        "proofkit/adoption-profile.json",
		"repositoryClass":    "go-cli",
		"repositoryId":       "proofkit.test.repository",
		"verifierCodeCopied": false,
	}
}

func TestGoRunRequirementBrowserServerProcess(t *testing.T) {
	root := t.TempDir()
	inputPath := filepath.Join(root, "requirements.json")
	if err := os.WriteFile(inputPath, []byte(`{
  "schemaVersion": 1,
  "sourceId": "proofkit.app.browser",
  "specPackagePath": "docs/specs/browser",
  "overviewPath": "docs/specs/browser/overview.md",
  "requirementsPath": "docs/specs/browser/requirements.v1.json",
  "requirements": [
    {
      "requirementId": "REQ-BROWSER-001",
      "ownerId": "browser.owner",
      "invariant": "The process server serves source views from explicit input.",
      "claimLevel": "blocking",
      "riskClass": "high",
      "proofBindingRefs": ["proofkit/browser.json"],
      "nonClaimRefs": ["NC-BROWSER-001"],
      "nonClaims": ["The browser process test does not prove production deployment."],
      "lifecycle": {"state": "active", "replacementRequirementIds": [], "evidenceRefs": []},
      "deferral": null,
      "updatePolicy": {
        "reviewOwnerId": "browser.owner",
        "requiresImpactDeclaration": true,
        "requiresProofBindingReview": true
      }
    }
  ],
  "nonClaims": ["Consumer repositories own requirement meaning."]
}`), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	binaryPath := buildTestBinary(t)
	command := exec.Command(
		binaryPath,
		"requirement-browser-server",
		"--input",
		inputPath,
		"--view",
		"source",
		"--serve",
		"--port",
		"0",
	)
	command.Dir = repoRoot(t)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start browser process: %v", err)
	}
	waited := false
	defer func() {
		if !waited && command.Process != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	lineChannel := make(chan string, 1)
	errorChannel := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			errorChannel <- err
			return
		}
		lineChannel <- line
	}()
	var line string
	select {
	case line = <-lineChannel:
	case err := <-errorChannel:
		t.Fatalf("read server output: %v stderr=%s", err, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatalf("server did not print URL stderr=%s", stderr.String())
	}
	url := strings.TrimSpace(strings.TrimPrefix(line, "Proofkit requirement browser: "))
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("unexpected URL line: %q", line)
	}
	client := http.Client{Timeout: 5 * time.Second}
	health, err := client.Get(url + "healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v stderr=%s", err, stderr.String())
	}
	_ = health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("unexpected health status: %d", health.StatusCode)
	}
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal interrupt: %v", err)
	}
	waitChannel := make(chan error, 1)
	go func() {
		waitChannel <- command.Wait()
	}()
	select {
	case err := <-waitChannel:
		waited = true
		if err != nil {
			t.Fatalf("browser process did not exit cleanly: %v stderr=%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("browser process did not stop after interrupt stderr=%s", stderr.String())
	}
}

func runCLI(t *testing.T, args []string, stdin string) []byte {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), args, strings.NewReader(stdin), &stdout, &stderr)
	if status != 0 {
		t.Fatalf("%s failed status=%d stdout=%s stderr=%s", strings.Join(args, " "), status, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("%s wrote stderr: %s", strings.Join(args, " "), stderr.String())
	}
	return stdout.Bytes()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := testRepoRoot()
	if err != nil {
		t.Fatalf("get repo root: %v", err)
	}
	return root
}

func testRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(wd, "../..")), nil
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected writer failure")
}

func buildTestBinary(t *testing.T) string {
	t.Helper()
	processTestBinary.once.Do(func() {
		root, err := testRepoRoot()
		if err != nil {
			processTestBinary.err = err
			return
		}
		tempDir, err := os.MkdirTemp("", "agentic-proofkit-app-test-*")
		if err != nil {
			processTestBinary.err = err
			return
		}
		processTestBinary.tempDir = tempDir
		processTestBinary.path = filepath.Join(tempDir, "agentic-proofkit")
		command := exec.CommandContext(t.Context(), "go", "build", "-o", processTestBinary.path, "./cmd/agentic-proofkit")
		command.Dir = root
		output, err := command.CombinedOutput()
		if err != nil {
			processTestBinary.err = fmt.Errorf("go build failed: %w\n%s", err, output)
		}
	})
	if processTestBinary.err != nil {
		t.Fatal(processTestBinary.err)
	}
	return processTestBinary.path
}
