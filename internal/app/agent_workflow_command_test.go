package app

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/changeworkflowplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/nativeevidenceguidance"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

const validChangeWorkflowInput = `{"checkpoint":{"state":"not_started"},"completedStageIds":[],"contextRefs":[],"governingAuthorityRefId":null,"requiredContextRefIds":[],"schemaVersion":1}`

func TestAgentWorkflowCLITruthTable(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.110027854485263740098018592752615689790850067351556445289115876582278838003288")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.008921652518915565373824823596859113418310007148763537766174180247340157842807")
	const (
		semanticOutputClasses     = 24
		envelopeTransitionClasses = 8
		frozenRejectionClasses    = 45
		extraRejectionCases       = 3
		helpClasses               = 10
		colorClasses              = 8
	)
	if got, want := semanticOutputClasses+envelopeTransitionClasses+frozenRejectionClasses+extraRejectionCases+helpClasses+colorClasses, 98; got != want {
		t.Fatalf("agent workflow CLI truth-table cardinality = %d, want %d", got, want)
	}
	t.Run("semantic output classes", testAgentWorkflowSemanticOutputClasses)
	t.Run("envelope transition classes", testAgentWorkflowEnvelopeTransitionClasses)
	t.Run("usage errors precede input", testAgentWorkflowUsageErrorsPrecedeInput)
	t.Run("exclusive help classes", testAgentWorkflowHelpClasses)
	t.Run("terminal capability product", testAgentWorkflowTerminalCapabilityProduct)
	t.Run("retired flat route", func(t *testing.T) {
		status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"change-workflow-plan", "--input", "-"}, panicReader{}, PresentationCapabilities{})
		if status != 1 || stdout != "" || !strings.Contains(stderr, "unsupported command: change-workflow-plan") {
			t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
	})
}

func testAgentWorkflowEnvelopeTransitionClasses(t *testing.T) {
	const digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	stages := []string{"architecture", "design", "implementation_plan", "implementation", "verification", "pull_request", "closeout"}
	for stageIndex := range stages {
		t.Run(stages[stageIndex], func(t *testing.T) {
			completed := make([]any, stageIndex)
			for index := 0; index < stageIndex; index++ {
				completed[index] = stages[index]
			}
			prior := map[string]any{
				"checkpoint": map[string]any{
					"assessmentSubjectDigest": digest,
					"state":                   "review_passed",
					"subjectDigest":           digest,
					"subjectRefId":            "ctx.artifact",
				},
				"completedStageIds": completed,
				"contextRefs": []any{
					map[string]any{
						"artifactPath":     "evidence/artifact.json",
						"dependencyRefIds": []any{},
						"refId":            "ctx.artifact",
						"refKind":          "artifact",
						"subjectDigest":    digest,
					},
					map[string]any{
						"artifactPath":     "evidence/authority.json",
						"dependencyRefIds": []any{},
						"refId":            "ctx.authority",
						"refKind":          "authority",
						"subjectDigest":    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
					},
				},
				"governingAuthorityRefId": "ctx.authority",
				"requiredContextRefIds":   []any{},
				"schemaVersion":           json.Number("1"),
			}
			payload, err := stablejson.MarshalLayout(prior, stablejson.LayoutCompact)
			if err != nil {
				t.Fatal(err)
			}
			status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"change", "plan", "--input", "-", "--agent-envelope"}, bytes.NewReader(payload), PresentationCapabilities{})
			if status != 0 || stderr != "" {
				t.Fatalf("status=%d stderr=%q", status, stderr)
			}
			envelope := decodeCLIJSON(t, stdout).(map[string]any)
			action := envelope["actionPlan"].([]any)[0].(map[string]any)
			delta, ok := action["successorStateDelta"].(map[string]any)
			if action["outputKind"] != "next_action" || !ok {
				t.Fatalf("transition envelope is incomplete: %v", action)
			}
			wantCompleted := make([]any, stageIndex+1)
			for index := 0; index <= stageIndex; index++ {
				wantCompleted[index] = stages[index]
			}
			if !equalCLIJSON(t, delta["completedStageIds"], wantCompleted) {
				t.Fatalf("transition completedStageIds=%v want %v", delta["completedStageIds"], wantCompleted)
			}
			if stageIndex+1 == len(stages) {
				if delta["checkpoint"] != nil {
					t.Fatalf("final transition checkpoint=%v want nil", delta["checkpoint"])
				}
			} else {
				wantCheckpoint := map[string]any{"state": "not_started", "subjectDigest": digest, "subjectRefId": "ctx.artifact"}
				if !equalCLIJSON(t, delta["checkpoint"], wantCheckpoint) {
					t.Fatalf("transition checkpoint=%v want %v", delta["checkpoint"], wantCheckpoint)
				}
			}
			merged, err := changeworkflowplan.MergeSuccessor(prior, delta)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := changeworkflowplan.Build(merged); err != nil {
				t.Fatalf("CLI-projected successor is not admitted: %v", err)
			}
		})
	}

	t.Run("terminal", func(t *testing.T) {
		terminal := map[string]any{
			"checkpoint":              nil,
			"completedStageIds":       []any{"architecture", "design", "implementation_plan", "implementation", "verification", "pull_request", "closeout"},
			"contextRefs":             []any{},
			"governingAuthorityRefId": nil,
			"requiredContextRefIds":   []any{},
			"schemaVersion":           json.Number("1"),
		}
		payload, err := stablejson.MarshalLayout(terminal, stablejson.LayoutCompact)
		if err != nil {
			t.Fatal(err)
		}
		status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"change", "plan", "--input", "-", "--agent-envelope"}, bytes.NewReader(payload), PresentationCapabilities{})
		if status != 0 || stderr != "" {
			t.Fatalf("status=%d stderr=%q", status, stderr)
		}
		action := decodeCLIJSON(t, stdout).(map[string]any)["actionPlan"].([]any)[0].(map[string]any)
		if action["outputKind"] != "workflow_complete" || action["phase"] != "terminal" {
			t.Fatalf("terminal envelope is incomplete: %v", action)
		}
	})
}

func testAgentWorkflowSemanticOutputClasses(t *testing.T) {
	workflowValue, err := admission.DecodeJSON(strings.NewReader(validChangeWorkflowInput), 1<<20)
	if err != nil {
		t.Fatalf("decode workflow fixture: %v", err)
	}
	wantPlan, err := changeworkflowplan.Build(workflowValue)
	if err != nil {
		t.Fatalf("build workflow fixture: %v", err)
	}
	wantText, err := changeworkflowplan.BuildText(workflowValue)
	if err != nil {
		t.Fatalf("build workflow text fixture: %v", err)
	}
	wantGuidanceText, err := nativeevidenceguidance.RenderPlainText()
	if err != nil {
		t.Fatalf("build guidance text fixture: %v", err)
	}

	for _, explicitFormat := range []bool{false, true} {
		for _, layout := range []string{"default", "pretty", "compact"} {
			for _, envelope := range []bool{false, true} {
				name := strings.Join([]string{"planner", formatClass(explicitFormat), layout, envelopeClass(envelope)}, "/")
				t.Run(name, func(t *testing.T) {
					args := []string{"change", "plan", "--input", "-"}
					if explicitFormat {
						args = append(args, "--format", "json")
					}
					if envelope {
						args = append(args, "--agent-envelope")
					}
					args = withWorkflowLayout(layout, args)
					status, stdout, stderr := executeAgentWorkflowCLI(t, args, strings.NewReader(validChangeWorkflowInput), PresentationCapabilities{})
					if status != 0 || stderr != "" || strings.Contains(stdout, "\x1b[") {
						t.Fatalf("status=%d stderr=%q stdout=%q", status, stderr, stdout)
					}
					value := decodeCLIJSON(t, stdout)
					if envelope {
						record := value.(map[string]any)
						if record["envelopeId"] != "proofkit.change-workflow-plan.agent-envelope" {
							t.Fatalf("unexpected envelope identity: %#v", record["envelopeId"])
						}
					} else if !equalCLIJSON(t, value, wantPlan) {
						t.Fatalf("planner JSON projection drifted")
					}
					assertJSONLayout(t, stdout, layout)
				})
			}
		}
	}

	for _, args := range [][]string{
		{"change", "plan", "--input", "-", "--format", "text"},
		{"change", "plan", "--input", "-", "--format", "text", "--color", "never"},
		{"change", "plan", "--input", "-", "--format", "text", "--color", "auto"},
	} {
		status, stdout, stderr := executeAgentWorkflowCLI(t, args, strings.NewReader(validChangeWorkflowInput), PresentationCapabilities{})
		if status != 0 || stderr != "" || stdout != wantText || strings.Contains(stdout, "\x1b[") {
			t.Fatalf("planner text status=%d stderr=%q stdout=%q want=%q", status, stderr, stdout, wantText)
		}
	}

	for _, explicitFormat := range []bool{false, true} {
		for _, layout := range []string{"default", "pretty", "compact"} {
			t.Run(strings.Join([]string{"guidance", formatClass(explicitFormat), layout}, "/"), func(t *testing.T) {
				args := []string{"native-evidence-guidance"}
				if explicitFormat {
					args = append(args, "--format", "json")
				}
				args = withWorkflowLayout(layout, args)
				status, stdout, stderr := executeAgentWorkflowCLI(t, args, strings.NewReader("unread"), PresentationCapabilities{})
				if status != 0 || stderr != "" || strings.Contains(stdout, "\x1b[") {
					t.Fatalf("status=%d stderr=%q stdout=%q", status, stderr, stdout)
				}
				record := decodeCLIJSON(t, stdout).(map[string]any)
				if record["guidanceId"] != nativeevidenceguidance.GuidanceID {
					t.Fatalf("unexpected guidance identity: %#v", record["guidanceId"])
				}
				assertJSONLayout(t, stdout, layout)
			})
		}
	}
	for _, args := range [][]string{
		{"native-evidence-guidance", "--format", "text"},
		{"native-evidence-guidance", "--format", "text", "--color", "never"},
		{"native-evidence-guidance", "--format", "text", "--color", "auto"},
	} {
		status, stdout, stderr := executeAgentWorkflowCLI(t, args, strings.NewReader("unread"), PresentationCapabilities{})
		if status != 0 || stderr != "" || stdout != wantGuidanceText || strings.Contains(stdout, "\x1b[") {
			t.Fatalf("guidance text status=%d stderr=%q stdout=%q want=%q", status, stderr, stdout, wantGuidanceText)
		}
	}
}

func testAgentWorkflowUsageErrorsPrecedeInput(t *testing.T) {
	cases := map[string][]string{
		"planner/json auto":                    {"change", "plan", "--input", "-", "--color", "auto"},
		"planner/json auto envelope":           {"change", "plan", "--input", "-", "--color", "auto", "--agent-envelope"},
		"planner/json explicit never":          {"change", "plan", "--input", "-", "--color", "never"},
		"planner/text envelope never":          {"change", "plan", "--input", "-", "--format", "text", "--color", "never", "--agent-envelope"},
		"planner/text envelope auto":           {"change", "plan", "--input", "-", "--format", "text", "--color", "auto", "--agent-envelope"},
		"planner/text layout pretty":           {"--json-layout", "pretty", "change", "plan", "--input", "-", "--format", "text"},
		"planner/text layout compact":          {"--json-layout", "compact", "change", "plan", "--input", "-", "--format", "text"},
		"planner/missing input":                {"change", "plan"},
		"planner/output":                       {"change", "plan", "--input", "-", "--output", "out.json"},
		"planner/duplicate input":              {"change", "plan", "--input", "-", "--input", "second.json"},
		"planner/duplicate pointer":            {"change", "plan", "--input", "-", "--input-pointer", "", "--input-pointer", "/other"},
		"planner/duplicate format":             {"change", "plan", "--input", "-", "--format", "json", "--format", "text"},
		"planner/duplicate color":              {"change", "plan", "--input", "-", "--color", "never", "--color", "auto"},
		"planner/unknown flag":                 {"change", "plan", "--input", "-", "--unknown"},
		"planner/missing input value":          {"change", "plan", "--input"},
		"planner/missing pointer value":        {"change", "plan", "--input", "-", "--input-pointer"},
		"planner/missing format value":         {"change", "plan", "--input", "-", "--format"},
		"planner/missing color value":          {"change", "plan", "--input", "-", "--color"},
		"planner/bad pointer":                  {"change", "plan", "--input", "-", "--input-pointer", "workflow"},
		"planner/malformed UTF-8 pointer":      {"change", "plan", "--input", "-", "--input-pointer", string([]byte{'/', 0xff})},
		"planner/bad format":                   {"change", "plan", "--input", "-", "--format", "yaml"},
		"planner/bad color":                    {"change", "plan", "--input", "-", "--format", "text", "--color", "always"},
		"planner/post-command layout":          {"change", "plan", "--json-layout", "compact", "--input", "-"},
		"planner/surplus operand":              {"change", "plan", "--input", "-", "surplus"},
		"guidance/input":                       {"native-evidence-guidance", "--input", "-"},
		"guidance/pointer":                     {"native-evidence-guidance", "--input-pointer", "/workflow"},
		"guidance/output":                      {"native-evidence-guidance", "--output", "out.json"},
		"guidance/envelope":                    {"native-evidence-guidance", "--agent-envelope"},
		"guidance/json auto":                   {"native-evidence-guidance", "--color", "auto"},
		"guidance/json explicit never":         {"native-evidence-guidance", "--color", "never"},
		"guidance/text layout pretty":          {"--json-layout", "pretty", "native-evidence-guidance", "--format", "text"},
		"guidance/text layout compact":         {"--json-layout", "compact", "native-evidence-guidance", "--format", "text"},
		"guidance/duplicate format":            {"native-evidence-guidance", "--format", "json", "--format", "text"},
		"guidance/duplicate color":             {"native-evidence-guidance", "--color", "never", "--color", "auto"},
		"guidance/unknown flag":                {"native-evidence-guidance", "--unknown"},
		"guidance/missing format value":        {"native-evidence-guidance", "--format"},
		"guidance/missing color value":         {"native-evidence-guidance", "--color"},
		"guidance/bad format":                  {"native-evidence-guidance", "--format", "yaml"},
		"guidance/bad color":                   {"native-evidence-guidance", "--format", "text", "--color", "always"},
		"guidance/post-command layout":         {"native-evidence-guidance", "--json-layout", "compact"},
		"guidance/surplus operand":             {"native-evidence-guidance", "surplus"},
		"global/missing layout value planner":  {"--json-layout", "change", "plan", "--input", "-"},
		"global/missing layout value guidance": {"--json-layout", "native-evidence-guidance"},
		"global/bad layout planner":            {"--json-layout", "dense", "change", "plan", "--input", "-"},
		"global/bad layout guidance":           {"--json-layout", "dense", "native-evidence-guidance"},
		"global/duplicate layout planner":      {"--json-layout", "pretty", "--json-layout", "compact", "change", "plan", "--input", "-"},
		"global/duplicate layout guidance":     {"--json-layout", "pretty", "--json-layout", "compact", "native-evidence-guidance"},
	}
	if got, want := len(cases)-2, 45; got != want {
		t.Fatalf("frozen rejection class count = %d, want %d", got, want)
	}
	for name, args := range cases {
		args := args
		t.Run(name, func(t *testing.T) {
			status, stdout, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
			if status != 1 || stdout != "" || stderr == "" || strings.Contains(stderr, "\x1b[") {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
		})
	}
}

func testAgentWorkflowHelpClasses(t *testing.T) {
	valid := [][]string{
		{"change", "plan", "--help"},
		{"change", "plan", "-h"},
		{"native-evidence-guidance", "--help"},
		{"native-evidence-guidance", "-h"},
	}
	for _, args := range valid {
		status, stdout, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
		if status != 0 || stdout == "" || stderr != "" || strings.Contains(stdout, "\x1b[") {
			t.Fatalf("args=%v status=%d stdout=%q stderr=%q", args, status, stdout, stderr)
		}
	}
	invalid := []struct {
		args []string
		want string
	}{
		{args: []string{"--json-layout", "compact", "change", "plan", "--help"}, want: "--json-layout is valid only for JSON command output"},
		{args: []string{"--json-layout", "compact", "native-evidence-guidance", "--help"}, want: "--json-layout is valid only for JSON command output"},
		{args: []string{"change", "plan", "--input", "-", "--help"}, want: "help accepts no additional arguments"},
		{args: []string{"change", "plan", "-h", "--input", "-"}, want: "help accepts no additional arguments"},
		{args: []string{"native-evidence-guidance", "--format", "text", "--help"}, want: "help accepts no additional arguments"},
		{args: []string{"native-evidence-guidance", "-h", "--format", "text"}, want: "help accepts no additional arguments"},
	}
	for _, item := range invalid {
		status, stdout, stderr := executeAgentWorkflowCLI(t, item.args, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
		if status != 1 || stdout != "" || !strings.Contains(stderr, item.want) || strings.Contains(stderr, "\x1b[") {
			t.Fatalf("args=%v status=%d stdout=%q stderr=%q", item.args, status, stdout, stderr)
		}
	}

	t.Run("help_like_input_paths_are_values", func(t *testing.T) {
		for _, path := range []string{"--help", "-h"} {
			status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"change", "plan", "--input", path}, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
			if status != 1 || stdout != "" || stderr == "" || strings.Contains(stderr, "help accepts no additional arguments") {
				t.Fatalf("path=%q status=%d stdout=%q stderr=%q", path, status, stdout, stderr)
			}
		}
	})
}

func testAgentWorkflowTerminalCapabilityProduct(t *testing.T) {
	workflowValue, err := admission.DecodeJSON(strings.NewReader(validChangeWorkflowInput), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	wantWorkflowText, err := changeworkflowplan.BuildText(workflowValue)
	if err != nil {
		t.Fatal(err)
	}
	wantGuidanceText, err := nativeevidenceguidance.RenderPlainText()
	if err != nil {
		t.Fatal(err)
	}
	commands := []struct {
		name  string
		args  []string
		stdin func() io.Reader
		plain string
	}{
		{name: "change plan", args: []string{"change", "plan", "--input", "-", "--format", "text", "--color", "auto"}, stdin: func() io.Reader { return strings.NewReader(validChangeWorkflowInput) }, plain: wantWorkflowText},
		{name: "native-evidence-guidance", args: []string{"native-evidence-guidance", "--format", "text", "--color", "auto"}, stdin: func() io.Reader { return strings.NewReader("unread") }, plain: wantGuidanceText},
	}
	for _, command := range commands {
		for _, tty := range []bool{false, true} {
			for _, noColorPresent := range []bool{false, true} {
				name := command.name + "/tty=" + boolName(tty) + "/no-color=" + boolName(noColorPresent)
				t.Run(name, func(t *testing.T) {
					status, stdout, stderr := executeAgentWorkflowCLI(t, command.args, command.stdin(), PresentationCapabilities{StdoutIsTTY: tty, NoColorPresent: noColorPresent})
					if status != 0 || stderr != "" {
						t.Fatalf("status=%d stderr=%q", status, stderr)
					}
					wantANSI := tty && !noColorPresent
					if gotANSI := strings.Contains(stdout, "\x1b["); gotANSI != wantANSI {
						t.Fatalf("ANSI presence=%t want=%t stdout=%q", gotANSI, wantANSI, stdout)
					}
					if plain := stripTestANSI(stdout); plain != command.plain {
						t.Fatalf("stripped output=%q want=%q", plain, command.plain)
					}
				})
			}
		}
	}
}

func executeAgentWorkflowCLI(t *testing.T, args []string, stdin io.Reader, capabilities PresentationCapabilities) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := RunWithRendererAndCapabilities(t.Context(), args, stdin, &stdout, &stderr, cliexec.PathRenderer(), capabilities)
	return status, stdout.String(), stderr.String()
}

func decodeCLIJSON(t *testing.T, output string) any {
	t.Helper()
	value, err := admission.DecodeJSON(strings.NewReader(output), 1<<20)
	if err != nil {
		t.Fatalf("decode CLI JSON: %v\n%s", err, output)
	}
	return value
}

func equalCLIJSON(t *testing.T, left any, right any) bool {
	t.Helper()
	leftBytes, err := marshalCompactForTest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightBytes, err := marshalCompactForTest(right)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(leftBytes, rightBytes)
}

func marshalCompactForTest(value any) ([]byte, error) {
	return stablejson.MarshalLayout(value, stablejson.LayoutCompact)
}

func withWorkflowLayout(layout string, args []string) []string {
	if layout == "default" {
		return args
	}
	return append([]string{"--json-layout", layout}, args...)
}

func assertJSONLayout(t *testing.T, output string, layout string) {
	t.Helper()
	if layout == "compact" && strings.Count(output, "\n") != 1 {
		t.Fatalf("compact JSON has non-terminal newlines: %q", output)
	}
	if layout != "compact" && strings.Count(output, "\n") < 2 {
		t.Fatalf("pretty JSON lacks structural newlines: %q", output)
	}
}

func formatClass(explicit bool) string {
	if explicit {
		return "explicit-json"
	}
	return "default-json"
}

func envelopeClass(value bool) string {
	if value {
		return "envelope"
	}
	return "report"
}

func boolName(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
