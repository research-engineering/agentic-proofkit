package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/projectfixture"
)

func TestProjectViewCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.108643115507842968757287693696779878324657631379944770299252611290330528256825")
	fixture := projectfixture.New(t)
	code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"view", "--repo-root", fixture.Root}, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" {
		t.Fatalf("project plan exit=%d diagnostic=%q", code, diagnostic)
	}
	plan := decodeCLIJSON(t, output).(map[string]any)
	assertExactObjectKeys(t, plan, []string{"authority", "host", "htmlByteLength", "nonClaims", "planKind", "port", "portSelection", "renderedAuthority", "renderedViewKind", "schemaVersion", "url", "view"}, "view plan")
	if plan["authority"] != "presentation_adapter_plan" || plan["planKind"] != "proofkit.requirement-browser-server-plan" || plan["view"] != "workspace" || plan["host"] != "127.0.0.1" || plan["portSelection"] != "ephemeral" || plan["url"] != nil || plan["renderedViewKind"] != "proofkit.requirement-workspace" || plan["renderedAuthority"] != "presentation_adapter" {
		t.Fatal("project view did not produce the bounded workspace plan")
	}
	if strings.Contains(output, fixture.Root) || strings.Contains(output, "\x1b[") || len(plan["nonClaims"].([]any)) == 0 {
		t.Fatal("project plan disclosed the root, styled JSON or lost limitations")
	}
	code, compact, diagnostic := executeAgentWorkflowCLI(t, []string{"--json-layout", "compact", "view", "--repo-root", fixture.Root}, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" || strings.Count(compact, "\n") != 1 {
		t.Fatal("project view compact plan failed")
	}
	var normalized bytes.Buffer
	if err := json.Compact(&normalized, []byte(output)); err != nil || normalized.String()+"\n" != compact {
		t.Fatal("project view JSON layouts describe different plans")
	}
	code, status, diagnostic := executeAgentWorkflowCLI(t, []string{"status", "--repo-root", fixture.Root}, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" || decodeCLIJSON(t, status).(map[string]any)["projectState"] != "verification_required" {
		t.Fatal("view promoted structural admission to repository verification")
	}
	for path, before := range fixture.Files {
		after, err := os.ReadFile(filepath.Join(fixture.Root, filepath.FromSlash(path)))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("view changed a captured project file")
		}
	}
	if err := os.WriteFile(filepath.Join(fixture.Root, "docs/specs/a/requirements.v1.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, output, diagnostic = executeAgentWorkflowCLI(t, []string{"view", "--repo-root", fixture.Root}, panicReader{}, PresentationCapabilities{})
	if code != 1 || output != "" || !strings.Contains(diagnostic, "complete admitted project") || !strings.Contains(diagnostic, "next") || strings.Contains(diagnostic, fixture.Root) {
		t.Fatal("view did not fail closed on a stale project")
	}
}

func TestProjectViewRejectsFlagsBeforeProjectIO(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	cases := [][]string{
		{"--input", "-"}, {"--input-pointer", "/"}, {"--output", "result.json"}, {"--format", "json"}, {"--scope", "graph"}, {"--local-environment-class", "local-go"}, {"--view", "source"},
		{"--host", "0.0.0.0"}, {"--host", "localhost"}, {"--host", ""}, {"--port", "-1"}, {"--port", "65536"}, {"--port", "1.2"}, {"--port"},
		{"--session-mode", "other"}, {"--session-mode", "browse"}, {"--open"}, {"--serve", "--session-mode", "one-shot-question"},
		{"--session-timeout-seconds", "1"}, {"--serve", "--open", "--session-mode", "one-shot-question", "--session-timeout-seconds", "0"},
		{"--serve", "--open", "--session-mode", "one-shot-question", "--session-timeout-seconds", "7201"},
	}
	for _, flag := range commandDescriptorByName["view"].singleOccurrenceFlags {
		args := []string{flag}
		if flagRequiresValue(flag) {
			value := map[string]string{"--host": "127.0.0.1", "--port": "0", "--repo-root": missing, "--session-mode": "browse", "--session-timeout-seconds": "1"}[flag]
			args = append(args, value)
		}
		cases = append(cases, append(append([]string{}, args...), args...))
	}
	for index, extra := range cases {
		args := append([]string{"view", "--repo-root", missing}, extra...)
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 1 || output != "" || diagnostic == "" || strings.Contains(diagnostic, missing) || strings.Contains(diagnostic, "could not inspect") {
			t.Fatalf("case %d did not reject before inspection: exit=%d diagnostic=%q", index, code, diagnostic)
		}
		assertProjectViewEffectCount(t, args, 1, 0)
	}
	for _, args := range [][]string{{"view"}, {"view", "--repo-root"}, {"view", "--repo-root", ""}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 1 || output != "" || !strings.Contains(diagnostic, "--repo-root") {
			t.Fatal("view accepted an absent explicit root")
		}
		assertProjectViewEffectCount(t, args, 1, 0)
	}
	fixture := projectfixture.New(t)
	assertProjectViewEffectCount(t, []string{"view", "--repo-root", fixture.Root}, 0, 1)
	assertProjectViewEffectCount(t, []string{"view", "--repo-root", fixture.Root, "--serve"}, 0, 1)
}

func assertProjectViewEffectCount(t *testing.T, args []string, expectedExit, expectedCalls int) {
	t.Helper()
	calls := 0
	observe := func(ctx context.Context, root string, options requirementbrowser.Options) (map[string]any, int, error) {
		calls++
		return requirementbrowser.BuildProjectPlan(ctx, root, options)
	}
	operations := projectViewOperations{
		plan: observe,
		serve: func(ctx context.Context, root string, options requirementbrowser.Options, _ io.Writer) error {
			_, _, err := observe(ctx, root, options)
			return err
		},
	}
	runner := func(ctx context.Context, parsed descriptorArguments, stdout, stderr io.Writer) int {
		return runProjectViewWithOperations(ctx, parsed, stdout, stderr, operations)
	}
	var stdout, stderr bytes.Buffer
	code := runWithProjectView(t.Context(), args, panicReader{}, &stdout, &stderr, cliexec.PathRenderer(), PresentationCapabilities{}, runner)
	if code != expectedExit || calls != expectedCalls {
		t.Fatalf("project effect boundary: exit=%d calls=%d, want exit=%d calls=%d", code, calls, expectedExit, expectedCalls)
	}
}

func TestProjectViewChoiceDiagnosticsAreDeterministic(t *testing.T) {
	args := []string{"view", "--repo-root", filepath.Join(t.TempDir(), "missing"), "--host", "localhost", "--session-mode", "invalid", "--serve"}
	for range 128 {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 1 || output != "" || diagnostic != "--host requires one of: 127.0.0.1, ::1\n" {
			t.Fatalf("choice diagnostics changed: exit=%d diagnostic=%q", code, diagnostic)
		}
	}
}

func TestProjectViewHelpLayoutAndFlagShapedPaths(t *testing.T) {
	for _, help := range [][]string{{"help", "view"}, {"view", "--help"}, {"view", "-h"}} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, help, panicReader{}, PresentationCapabilities{})
		if code != 0 || diagnostic != "" || !strings.Contains(output, "--repo-root") || !strings.Contains(output, "--serve") {
			t.Fatal("view contextual help is not discoverable")
		}
		code, output, diagnostic = executeAgentWorkflowCLI(t, append([]string{"--json-layout", "compact"}, help...), panicReader{}, PresentationCapabilities{})
		if code != 1 || output != "" || !strings.Contains(diagnostic, "--json-layout") {
			t.Fatal("text help accepted JSON-only layout")
		}
	}
	missing := filepath.Join(t.TempDir(), "missing")
	code, output, diagnostic := executeAgentWorkflowCLI(t, []string{"--json-layout", "compact", "view", "--repo-root", missing, "--serve"}, panicReader{}, PresentationCapabilities{})
	if code != 1 || output != "" || !strings.Contains(diagnostic, "--json-layout") {
		t.Fatal("serving accepted a JSON layout or inspected the root first")
	}
	fixture := projectfixture.New(t)
	directory := t.TempDir()
	if err := os.Rename(fixture.Root, filepath.Join(directory, "--serve")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	code, output, diagnostic = executeAgentWorkflowCLI(t, []string{"--json-layout", "compact", "view", "--repo-root", "--serve"}, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" || decodeCLIJSON(t, output).(map[string]any)["planKind"] != "proofkit.requirement-browser-server-plan" {
		t.Fatal("a flag-shaped path was reinterpreted as a server flag")
	}
}

func TestProjectViewSignalClosesNativeProcessServer(t *testing.T) {
	fixture := projectfixture.New(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProjectViewProcessHelper$")
	command.Env = append(os.Environ(), "PROOFKIT_VIEW_PROCESS_TEST_ROOT="+fixture.Root)
	command.WaitDelay = time.Second
	pipe, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	line, err := bufio.NewReader(pipe).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "Proofkit requirement browser: http://127.0.0.1:") {
		t.Fatal("view process did not publish its actual loopback URL")
	}
	browserURL := strings.TrimSpace(strings.TrimPrefix(line, "Proofkit requirement browser: "))
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(browserURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	capability := regexp.MustCompile(`name="proofkit-browser-capability" content="([A-Za-z0-9_-]{43})"`).FindSubmatch(body)
	if err != nil || response.StatusCode != http.StatusOK || len(capability) != 2 {
		t.Fatal("project CLI did not serve the existing capability-protected workspace")
	}
	request, err := http.NewRequest(http.MethodGet, browserURL+"api/v1/manifest", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Proofkit-Browser-Capability", string(capability[1]))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("project CLI manifest request failed")
	}
	manifest := decodeCLIJSON(t, string(body)).(map[string]any)
	if manifest["requirementCount"] != json.Number("3") || manifest["workspaceId"] != "shared.identity" || manifest["coverageAvailable"] != false || manifest["diffAvailable"] != false || manifest["graphAvailable"] != true {
		t.Fatal("project CLI manifest is not bound to its explicit root")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	waited = true
	if err != nil || diagnostic.Len() != 0 {
		t.Fatalf("project CLI shutdown error=%v diagnostic=%q", err, diagnostic.String())
	}
	parsed, err := url.Parse(browserURL)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp", parsed.Host, time.Second)
	if err == nil {
		_ = connection.Close()
		t.Fatal("project CLI retained its listener after termination")
	}
}

func TestProjectViewProcessHelper(t *testing.T) {
	root := os.Getenv("PROOFKIT_VIEW_PROCESS_TEST_ROOT")
	if root == "" {
		return
	}
	os.Exit(Run(context.Background(), []string{"view", "--repo-root", root, "--serve"}, panicReader{}, os.Stdout, os.Stderr))
}

func TestProjectViewOneShotCLIOutputVariants(t *testing.T) {
	fixture := projectfixture.New(t)
	launcherDir := t.TempDir()
	launcherName := "xdg-open"
	if runtime.GOOS == "darwin" {
		launcherName = "open"
	}
	launcher := "#!/bin/sh\nprintf '%s\\n' \"$1\" > \"$PROOFKIT_TEST_BROWSER_URL_FILE\"\n"
	if err := os.WriteFile(filepath.Join(launcherDir, launcherName), []byte(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	urlFile := filepath.Join(t.TempDir(), "browser-url")
	t.Setenv("PROOFKIT_TEST_BROWSER_URL_FILE", urlFile)
	t.Setenv("PATH", launcherDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	args := []string{"view", "--repo-root", fixture.Root, "--serve", "--open", "--session-mode", "one-shot-question", "--session-timeout-seconds", "10"}
	ctx, cancel := context.WithCancel(t.Context())
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		result <- Run(ctx, args, panicReader{}, &stdout, &stderr)
	}()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("project one-shot did not finish cleanup")
		}
	}()
	browserURL := waitForBrowserLauncherURL(t, urlFile, result, &stdout, &stderr)
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(browserURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	capability := regexp.MustCompile(`name="proofkit-browser-capability" content="([A-Za-z0-9_-]{43})"`).FindSubmatch(body)
	if err != nil || response.StatusCode != http.StatusOK || len(capability) != 2 {
		t.Fatal("one-shot project CLI workspace is unavailable")
	}
	handoff := `{"annotations":[{"anchorId":"requirement:REQ-WIRE-001:invariant","startCodePoint":11,"endCodePoint":12,"exactQuote":"\ud83e\udded","question":"Does this remain source-bound?"}]}`
	request, err := http.NewRequest(http.MethodPost, browserURL+"api/v1/handoff", strings.NewReader(handoff))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", strings.TrimSuffix(browserURL, "/"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Proofkit-Browser-Capability", string(capability[1]))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("project CLI handoff was not admitted")
	}
	select {
	case code := <-result:
		if code != 0 || stderr.Len() != 0 {
			t.Fatal("submitted project CLI handoff failed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("project CLI handoff did not terminate")
	}
	packet := decodeCLIJSON(t, stdout.String()).(map[string]any)
	if !equalCLIJSON(t, packet, decodeCLIJSON(t, string(body))) || packet["state"] != "submitted" || strings.Count(stdout.String(), "\n") != 1 {
		t.Fatal("project CLI did not preserve the compact native handoff packet")
	}
	assertPublicCLIRootVariant(t, "view", "output", "03-one-shot-submitted", packet)
	args[len(args)-1] = "1"
	code, terminal, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
	if code != 1 || diagnostic != "" || decodeCLIJSON(t, terminal).(map[string]any)["state"] != "expired" {
		t.Fatal("one-shot expiry did not retain the existing terminal output contract")
	}
	assertPublicCLIRootVariant(t, "view", "output", "02-one-shot-terminal", decodeCLIJSON(t, terminal))
}

func TestProjectViewDiagnosticsDoNotDiscloseCallerText(t *testing.T) {
	sentinel := "api_key=" + strings.Repeat("a", 40)
	fixture := projectfixture.New(t)
	for _, args := range [][]string{
		{"view", "--repo-root", filepath.Join(t.TempDir(), sentinel)},
		{"view", "--repo-root", fixture.Root, sentinel},
		{"view", "--repo-root", fixture.Root, "--port", sentinel},
	} {
		code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if code != 1 || output != "" || diagnostic == "" || strings.Contains(diagnostic, sentinel) {
			t.Fatal("project view leaked caller text or accepted malformed input")
		}
	}
	var stderr bytes.Buffer
	code := Run(t.Context(), []string{"view", "--repo-root", fixture.Root, "--serve"}, panicReader{}, projectViewFailureWriter{err: errors.New(sentinel)}, &stderr)
	if code != 1 || stderr.Len() == 0 || strings.Contains(stderr.String(), sentinel) {
		t.Fatal("project view leaked a terminal writer error")
	}
}

type projectViewFailureWriter struct{ err error }

func (writer projectViewFailureWriter) Write([]byte) (int, error) { return 0, writer.err }
