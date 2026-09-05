package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/projectstatus"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestStatusOutputUsesExactRootShape(t *testing.T) {
	root := t.TempDir()
	code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"status", "--repo-root", root}, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" {
		t.Fatalf("status exit=%d stderr=%q stdout=%q", code, diagnostic, output)
	}
	value, ok := decodeCLIJSON(t, output).(map[string]any)
	if !ok {
		t.Fatal("status output must be an object")
	}
	assertExactObjectKeys(t, value, []string{"issueCodes", "manifestId", "nextAction", "nonClaims", "projectId", "projectState", "reportKind", "schemaVersion", "snapshotId", "statusId"}, "status output")
}

func TestNextOutputUsesExactRootShape(t *testing.T) {
	root := t.TempDir()
	code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"next", "--repo-root", root}, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" {
		t.Fatalf("next exit=%d stderr=%q stdout=%q", code, diagnostic, output)
	}
	value, ok := decodeCLIJSON(t, output).(map[string]any)
	if !ok {
		t.Fatal("next output must be an object")
	}
	assertExactObjectKeys(t, value, []string{"action", "issueCodes", "nonClaims", "packetId", "packetKind", "projectState", "schemaVersion", "snapshotId", "statusRef"}, "next output")
}

func TestProjectStatusOutputMatrix(t *testing.T) {
	statusKeys := []string{"issueCodes", "manifestId", "nextAction", "nonClaims", "projectId", "projectState", "reportKind", "schemaVersion", "snapshotId", "statusId"}
	nextKeys := []string{"action", "issueCodes", "nonClaims", "packetId", "packetKind", "projectState", "schemaVersion", "snapshotId", "statusRef"}
	states := []projectstatus.ProjectState{
		projectstatus.StateBlocked,
		projectstatus.StateRecoveryRequired,
		projectstatus.StateStale,
		projectstatus.StateUninitialized,
		projectstatus.StateVerificationRequired,
	}
	for _, state := range states {
		status := admittedProjectStatusFixture(t, state)
		if route := status.NextAction.CommandRoute; len(route) > 0 {
			if _, ok := commandDescriptorByRoute[commandroute.Key(route)]; !ok {
				t.Fatalf("project state %s emits route %v without a public command descriptor", state, route)
			}
		}
		for _, command := range []string{"next", "status"} {
			t.Run(string(state)+"/"+command, func(t *testing.T) {
				var stdout bytes.Buffer
				var stderr bytes.Buffer
				code := projectStatusResult(command, projectStatusArgs{color: "never", format: "json", repositoryRoot: "unused"}, status, &stdout, &stderr, PresentationCapabilities{})
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("JSON exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
				}
				value, ok := decodeCLIJSON(t, stdout.String()).(map[string]any)
				if !ok {
					t.Fatal("project navigation JSON must be an object")
				}
				keys := statusKeys
				if command == "next" {
					keys = nextKeys
				}
				assertExactObjectKeys(t, value, keys, command+" output")
				if value["projectState"] != string(state) {
					t.Fatalf("projectState=%v, want %s", value["projectState"], state)
				}

				stdout.Reset()
				code = projectStatusResult(command, projectStatusArgs{color: "never", format: "text", repositoryRoot: "unused"}, status, &stdout, &stderr, PresentationCapabilities{})
				if code != 0 || stderr.Len() != 0 || stdout.Len() == 0 || strings.Contains(stdout.String(), "\x1b[") || !strings.Contains(stdout.String(), string(state)) {
					t.Fatalf("text exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
				}
			})
		}
	}
}

func TestProjectStatusCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.082990774938213415032196768034286988848197095097772338307445528941413312751637")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.016575929375243753473232212796372621717203348455914493779019079597618731316529")
	repositoryRoot := t.TempDir()

	t.Run("status and next preserve owner output", func(t *testing.T) {
		statusCode, statusOutput, statusDiagnostic := executeAgentWorkflowCLI(t, []string{"status", "--repo-root", repositoryRoot}, panicReader{}, PresentationCapabilities{})
		if statusCode != 0 || statusDiagnostic != "" {
			t.Fatalf("status exit=%d stderr=%q stdout=%q", statusCode, statusDiagnostic, statusOutput)
		}
		status, err := projectstatus.AdmitStatusOutput(decodeCLIJSON(t, statusOutput))
		if err != nil || status.ProjectState != projectstatus.StateUninitialized {
			t.Fatalf("status admission=%v state=%s", err, status.ProjectState)
		}

		nextCode, nextOutput, nextDiagnostic := executeAgentWorkflowCLI(t, []string{"next", "--repo-root", repositoryRoot}, panicReader{}, PresentationCapabilities{})
		if nextCode != 0 || nextDiagnostic != "" {
			t.Fatalf("next exit=%d stderr=%q stdout=%q", nextCode, nextDiagnostic, nextOutput)
		}
		next, err := projectstatus.AdmitNextOutput(decodeCLIJSON(t, nextOutput))
		if err != nil || next.StatusRef != status.StatusID || next.Action.ActionClass != projectstatus.ActionChooseAdoptionMode {
			t.Fatalf("next admission=%v packet=%#v", err, next)
		}
		if strings.Contains(statusOutput+nextOutput, repositoryRoot) {
			t.Fatal("project status output disclosed repository root")
		}
	})

	t.Run("compact JSON preserves value", func(t *testing.T) {
		prettyCode, pretty, prettyDiagnostic := executeAgentWorkflowCLI(t, []string{"status", "--repo-root", repositoryRoot}, panicReader{}, PresentationCapabilities{})
		compactCode, compact, compactDiagnostic := executeAgentWorkflowCLI(t, []string{"--json-layout", "compact", "status", "--repo-root", repositoryRoot}, panicReader{}, PresentationCapabilities{})
		if prettyCode != 0 || compactCode != 0 || prettyDiagnostic != "" || compactDiagnostic != "" {
			t.Fatalf("pretty=%d/%q compact=%d/%q", prettyCode, prettyDiagnostic, compactCode, compactDiagnostic)
		}
		if !equalCLIJSON(t, decodeCLIJSON(t, pretty), decodeCLIJSON(t, compact)) || strings.Contains(compact, "\n  ") {
			t.Fatal("JSON layout changed project status value or retained indentation")
		}
	})

	t.Run("materialized project and drift remain visible through the public route", func(t *testing.T) {
		materializedRoot := t.TempDir()
		payload, transactionID, desiredStateID := adoptionMaterializationPlanFixture(t, materializedRoot)
		applyArgs := []string{
			"adopt", "materialize", "apply",
			"--input", "-",
			"--repo-root", materializedRoot,
			"--expect-transaction", transactionID,
			"--expect-desired-state", desiredStateID,
		}
		if code, output, diagnostic := executeAgentWorkflowCLI(t, applyArgs, bytes.NewReader(payload), PresentationCapabilities{}); code != 0 || diagnostic != "" {
			t.Fatalf("materialize exit=%d stderr=%q stdout=%q", code, diagnostic, output)
		}

		statusCode, statusOutput, statusDiagnostic := executeAgentWorkflowCLI(t, []string{"status", "--repo-root", materializedRoot}, panicReader{}, PresentationCapabilities{})
		if statusCode != 0 || statusDiagnostic != "" {
			t.Fatalf("materialized status exit=%d stderr=%q stdout=%q", statusCode, statusDiagnostic, statusOutput)
		}
		status, err := projectstatus.AdmitStatusOutput(decodeCLIJSON(t, statusOutput))
		if err != nil || status.ProjectState != projectstatus.StateVerificationRequired {
			t.Fatalf("materialized status admission=%v state=%s", err, status.ProjectState)
		}
		nextCode, nextOutput, nextDiagnostic := executeAgentWorkflowCLI(t, []string{"next", "--repo-root", materializedRoot}, panicReader{}, PresentationCapabilities{})
		if nextCode != 0 || nextDiagnostic != "" {
			t.Fatalf("materialized next exit=%d stderr=%q stdout=%q", nextCode, nextDiagnostic, nextOutput)
		}
		next, err := projectstatus.AdmitNextOutput(decodeCLIJSON(t, nextOutput))
		if err != nil || next.StatusRef != status.StatusID || next.Action.ActionClass != projectstatus.ActionRunRepositoryVerification {
			t.Fatalf("materialized next admission=%v packet=%#v", err, next)
		}

		requirementPath := filepath.Join(materializedRoot, "docs", "specs", "pilot", "requirements.v1.json")
		content, err := os.ReadFile(requirementPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(requirementPath, append(content, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		staleCode, staleOutput, staleDiagnostic := executeAgentWorkflowCLI(t, []string{"status", "--repo-root", materializedRoot}, panicReader{}, PresentationCapabilities{})
		if staleCode != 0 || staleDiagnostic != "" {
			t.Fatalf("stale status exit=%d stderr=%q stdout=%q", staleCode, staleDiagnostic, staleOutput)
		}
		stale, err := projectstatus.AdmitStatusOutput(decodeCLIJSON(t, staleOutput))
		if err != nil || stale.ProjectState != projectstatus.StateStale || stale.NextAction.ActionClass != projectstatus.ActionRematerializeProject {
			t.Fatalf("stale status admission=%v packet=%#v", err, stale)
		}
	})

	t.Run("text and terminal color are derived", func(t *testing.T) {
		args := []string{"next", "--repo-root", repositoryRoot, "--format", "text"}
		code, plain, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
		if code != 0 || diagnostic != "" || strings.Contains(plain, "\x1b[") {
			t.Fatalf("plain exit=%d stderr=%q stdout=%q", code, diagnostic, plain)
		}
		colorArgs := append(cloneStrings(args), "--color", "auto")
		code, colored, diagnostic := executeAgentWorkflowCLI(t, colorArgs, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
		if code != 0 || diagnostic != "" || !strings.Contains(colored, "\x1b[") {
			t.Fatalf("colored exit=%d stderr=%q stdout=%q", code, diagnostic, colored)
		}
		code, noColor, diagnostic := executeAgentWorkflowCLI(t, colorArgs, panicReader{}, PresentationCapabilities{StdoutIsTTY: true, NoColorPresent: true})
		if code != 0 || diagnostic != "" || noColor != plain {
			t.Fatalf("NO_COLOR exit=%d stderr=%q stdout=%q", code, diagnostic, noColor)
		}
		code, redirected, diagnostic := executeAgentWorkflowCLI(t, colorArgs, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || redirected != plain || strings.Contains(redirected, "\x1b[") {
			t.Fatalf("non-TTY exit=%d stderr=%q stdout=%q want=%q", code, diagnostic, redirected, plain)
		}
	})

	t.Run("argument admission precedes repository reads", func(t *testing.T) {
		missingRoot := filepath.Join(t.TempDir(), "missing")
		cases := []struct {
			args []string
			want string
		}{
			{args: []string{"status", "--repo-root", missingRoot, "--format", "yaml"}, want: "--format"},
			{args: []string{"next", "--repo-root", missingRoot, "--format", "json", "--color", "auto"}, want: "--color"},
			{args: []string{"status", "--repo-root", missingRoot, "--repo-root", repositoryRoot}, want: "only once"},
			{args: []string{"next", "--repo-root"}, want: "requires a path"},
			{args: []string{"status", "--repo-root", missingRoot, "--unknown", "value"}, want: "unsupported argument"},
		}
		for _, item := range cases {
			code, output, diagnostic := executeAgentWorkflowCLI(t, item.args, panicReader{}, PresentationCapabilities{})
			if code != 1 || output != "" || !strings.Contains(diagnostic, item.want) || strings.Contains(diagnostic, missingRoot) {
				t.Fatalf("args=%v exit=%d stdout=%q stderr=%q", item.args, code, output, diagnostic)
			}
		}
		code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"status", "--repo-root", missingRoot}, panicReader{}, PresentationCapabilities{})
		if code != 1 || output != "" || diagnostic == "" || strings.Contains(diagnostic, missingRoot) {
			t.Fatalf("inspection failure exit=%d stdout=%q stderr=%q", code, output, diagnostic)
		}
		secretArgument := "--sk-proj-caller-secret-sentinel"
		code, output, diagnostic = executeAgentWorkflowCLI(t, []string{"status", "--repo-root", repositoryRoot, secretArgument}, panicReader{}, PresentationCapabilities{})
		if code != 1 || output != "" || !strings.Contains(diagnostic, "unsupported argument") || strings.Contains(diagnostic, secretArgument) {
			t.Fatalf("secret-shaped argument exit=%d stdout=%q stderr=%q", code, output, diagnostic)
		}
	})
}

func TestProjectStatusTransportFailureUsesOneBoundedWriteWithoutAtomicSinkClaim(t *testing.T) {
	status := admittedProjectStatusFixture(t, projectstatus.StateUninitialized)
	stdout := &prefixThenErrorWriter{maximum: 7}
	var stderr bytes.Buffer
	code := projectStatusResult("status", projectStatusArgs{color: "never", format: "json", repositoryRoot: "unused"}, status, stdout, &stderr, PresentationCapabilities{})
	if code != 1 || stdout.calls != 1 || stdout.Len() != stdout.maximum || !strings.Contains(stderr.String(), "write output") {
		t.Fatalf("transport failure exit=%d calls=%d stdout=%q stderr=%q", code, stdout.calls, stdout.String(), stderr.String())
	}
}

type prefixThenErrorWriter struct {
	bytes.Buffer
	calls   int
	maximum int
}

func (writer *prefixThenErrorWriter) Write(value []byte) (int, error) {
	writer.calls++
	count := min(writer.maximum, len(value))
	_, _ = writer.Buffer.Write(value[:count])
	return count, errors.New("injected transport failure")
}

func admittedProjectStatusFixture(t *testing.T, state projectstatus.ProjectState) projectstatus.Status {
	t.Helper()
	manifestID := digest.SHA256TextRef("project manifest")
	status := projectstatus.Status{
		ProjectState: state,
		SnapshotID:   digest.SHA256TextRef("project snapshot " + string(state)),
	}
	switch state {
	case projectstatus.StateBlocked:
		status.IssueCodes = []string{projectstatus.IssueManifestInvalid}
		status.NextAction.ActionClass = projectstatus.ActionRepairProjectRecords
	case projectstatus.StateRecoveryRequired:
		status.IssueCodes = []string{projectstatus.IssueTransactionRecoveryRequired}
		status.NextAction.ActionClass = projectstatus.ActionChooseRecovery
		status.NextAction.CommandRoute = []string{"adopt", "materialize", "recover"}
		status.NextAction.ContextRef = digest.SHA256TextRef("active transaction")
		status.NextAction.RequiredDecision = "resume_or_rollback"
	case projectstatus.StateStale:
		status.IssueCodes = []string{projectstatus.IssueChildMissing}
		status.ProjectID = "pilot.project"
		status.ManifestID = manifestID
		status.NextAction.ActionClass = projectstatus.ActionRematerializeProject
		status.NextAction.CommandRoute = []string{"adopt", "materialize", "plan"}
		status.NextAction.ContextRef = manifestID
	case projectstatus.StateUninitialized:
		status.IssueCodes = []string{projectstatus.IssueManifestMissing}
		status.NextAction.ActionClass = projectstatus.ActionChooseAdoptionMode
		status.NextAction.CommandRoute = []string{"adopt", "plan"}
		status.NextAction.RequiredDecision = "adoption_mode"
	case projectstatus.StateVerificationRequired:
		status.ProjectID = "pilot.project"
		status.ManifestID = manifestID
		status.NextAction.ActionClass = projectstatus.ActionRunRepositoryVerification
		status.NextAction.ContextRef = manifestID
	default:
		t.Fatalf("unsupported fixture state %s", state)
	}
	status.NextAction.CommandRoute = append([]string{}, status.NextAction.CommandRoute...)
	status.NextAction.ActionID = "proofkit.project-status.action." + status.NextAction.ActionClass
	identity := status.JSONValue()
	delete(identity, "statusId")
	statusID, err := digest.StableJSONSHA256Ref(identity)
	if err != nil {
		t.Fatal(err)
	}
	status.StatusID = statusID
	admitted, err := projectstatus.AdmitStatusOutput(status.JSONValue())
	if err != nil {
		t.Fatalf("admit fixture state %s: %v", state, err)
	}
	return admitted
}
