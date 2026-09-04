package app

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestAdoptionFrontDoorCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.090463125918686417415789408747385969243450426928488527569779502859159168077392")
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.018641750690260403629185124984627586551707121364144838147335227432629735564274")

	repositoryRoot := t.TempDir()
	writeAdoptionFixture(t, repositoryRoot, "README.md", "# Pilot\n")
	writeAdoptionFixture(t, repositoryRoot, "pyproject.toml", "[project]\nname = \"pilot\"\n")
	writeAdoptionFixture(t, repositoryRoot, "private-notes.txt", "opaque\n")
	descriptor, ok := commandDescriptorFor("adopt-plan")
	if !ok {
		t.Fatal("adopt-plan descriptor missing")
	}
	if !slices.Equal(descriptor.flagValueChoices["--mode"], adoptionplan.IntentValues()) {
		t.Fatalf("adopt-plan mode choices = %v, want owner values %v", descriptor.flagValueChoices["--mode"], adoptionplan.IntentValues())
	}

	t.Run("public route and owner-closed JSON", func(t *testing.T) {
		for _, item := range []struct {
			mode              string
			stack             string
			wantTrust         string
			wantDeclared      bool
			wantCapabilityMap any
		}{
			{mode: adoptionplan.IntentFresh, wantTrust: "owner_intent_required"},
			{mode: adoptionplan.IntentCodeBaseline, stack: "python_service", wantTrust: "caller_declared_code_baseline", wantDeclared: true, wantCapabilityMap: "code_baseline"},
			{mode: adoptionplan.IntentAuditFromCode, wantTrust: "untrusted_code_observation", wantCapabilityMap: "audit_from_code"},
		} {
			t.Run(item.mode, func(t *testing.T) {
				args := []string{"adopt", "plan", "--mode", item.mode, "--repo-root", repositoryRoot}
				if item.stack != "" {
					args = append(args, "--stack", item.stack)
				}
				status, stdout, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
				if status != 0 || stderr != "" || strings.Contains(stdout, "\x1b[") {
					t.Fatalf("status=%d stderr=%q stdout=%q", status, stderr, stdout)
				}
				raw := decodeCLIJSON(t, stdout)
				plan, err := adoptionplan.AdmitOutput(raw)
				if err != nil {
					t.Fatalf("adoptionplan.AdmitOutput() error = %v", err)
				}
				if plan.Intent != item.mode || plan.TrustDeclaration.Class != item.wantTrust {
					t.Fatalf("intent/trust = %s/%s", plan.Intent, plan.TrustDeclaration.Class)
				}
				record := raw.(map[string]any)
				summary := record["summary"].(map[string]any)
				if summary["codeBaselineDeclared"] != item.wantDeclared {
					t.Fatalf("code baseline declaration=%v want %v", summary["codeBaselineDeclared"], item.wantDeclared)
				}
				trust := record["sourceTrust"].(map[string]any)
				if trust["capabilityMapTrustMode"] != item.wantCapabilityMap {
					t.Fatalf("capabilityMapTrustMode=%v want %v", trust["capabilityMapTrustMode"], item.wantCapabilityMap)
				}
				if strings.Contains(stdout, repositoryRoot) || strings.Contains(stdout, "private-notes.txt") {
					t.Fatal("adoption plan disclosed repository root or an unknown entry name")
				}
			})
		}
	})

	t.Run("inventory route", func(t *testing.T) {
		status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"repository-inventory", "--repo-root", repositoryRoot}, panicReader{}, PresentationCapabilities{})
		if status != 0 || stderr != "" {
			t.Fatalf("status=%d stderr=%q stdout=%q", status, stderr, stdout)
		}
		inventory, err := repositoryinventory.AdmitOutput(decodeCLIJSON(t, stdout))
		if err != nil {
			t.Fatalf("repositoryinventory.AdmitOutput() error = %v", err)
		}
		if len(inventory.Entries) != 2 || inventory.Omissions.UnrecognizedCount != 1 {
			t.Fatalf("unexpected inventory: %#v", inventory)
		}
		if strings.Contains(stdout, repositoryRoot) || strings.Contains(stdout, "private-notes.txt") {
			t.Fatal("repository inventory disclosed repository root or an unknown entry name")
		}
	})

	t.Run("JSON layouts preserve value", func(t *testing.T) {
		baseArgs := []string{"adopt", "plan", "--mode", "fresh", "--repo-root", repositoryRoot}
		prettyStatus, pretty, prettyErr := executeAgentWorkflowCLI(t, baseArgs, panicReader{}, PresentationCapabilities{})
		compactStatus, compact, compactErr := executeAgentWorkflowCLI(t, append([]string{"--json-layout", "compact"}, baseArgs...), panicReader{}, PresentationCapabilities{})
		if prettyStatus != 0 || compactStatus != 0 || prettyErr != "" || compactErr != "" {
			t.Fatalf("pretty=%d/%q compact=%d/%q", prettyStatus, prettyErr, compactStatus, compactErr)
		}
		if !equalCLIJSON(t, decodeCLIJSON(t, pretty), decodeCLIJSON(t, compact)) || strings.Contains(compact, "\n  ") {
			t.Fatal("JSON layout changed adoption-plan value or retained indentation")
		}
	})

	t.Run("text and color are derived", func(t *testing.T) {
		args := []string{"adopt", "plan", "--mode", "fresh", "--repo-root", repositoryRoot, "--format", "text"}
		status, plain, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
		if status != 0 || stderr != "" || strings.Contains(plain, "\x1b[") {
			t.Fatalf("plain status=%d stderr=%q stdout=%q", status, stderr, plain)
		}
		colorArgs := append(cloneStrings(args), "--color", "auto")
		status, colored, stderr := executeAgentWorkflowCLI(t, colorArgs, panicReader{}, PresentationCapabilities{StdoutIsTTY: true})
		if status != 0 || stderr != "" || !strings.Contains(colored, "\x1b[") {
			t.Fatalf("colored status=%d stderr=%q stdout=%q", status, stderr, colored)
		}
		status, disabled, stderr := executeAgentWorkflowCLI(t, colorArgs, panicReader{}, PresentationCapabilities{StdoutIsTTY: true, NoColorPresent: true})
		if status != 0 || stderr != "" || disabled != plain {
			t.Fatalf("NO_COLOR status=%d stderr=%q stdout=%q want=%q", status, stderr, disabled, plain)
		}
		status, nonTTY, stderr := executeAgentWorkflowCLI(t, colorArgs, panicReader{}, PresentationCapabilities{})
		if status != 0 || stderr != "" || nonTTY != plain {
			t.Fatalf("non-TTY status=%d stderr=%q stdout=%q want=%q", status, stderr, nonTTY, plain)
		}
	})

	t.Run("argument admission precedes scanning", func(t *testing.T) {
		missingRoot := filepath.Join(t.TempDir(), "unavailable")
		for _, item := range []struct {
			args []string
			want string
		}{
			{args: []string{"adopt", "plan"}, want: "requires --mode"},
			{args: []string{"adopt", "plan", "--mode", "fresh"}, want: "requires --repo-root"},
			{args: []string{"adopt", "plan", "--repo-root", missingRoot}, want: "requires --mode"},
			{args: []string{"adopt", "plan", "--repo-root", missingRoot, "--mode"}, want: "--mode requires one of"},
			{args: []string{"adopt", "plan", "--mode", "fresh", "--repo-root"}, want: "--repo-root requires a path"},
			{args: []string{"adopt", "plan", "--mode", "unknown", "--repo-root", missingRoot}, want: "--mode requires one of"},
			{args: []string{"adopt", "plan", "--mode", "fresh", "--repo-root", missingRoot, "--stack", "unknown"}, want: "--stack requires one of"},
			{args: []string{"adopt", "plan", "--mode", "fresh", "--mode", "fresh", "--repo-root", missingRoot}, want: "--mode may be specified only once"},
			{args: []string{"adopt", "plan", "--mode", "fresh", "--repo-root", missingRoot, "--format", "yaml"}, want: "--format requires one of"},
			{args: []string{"adopt", "plan", "--mode", "fresh", "--repo-root", missingRoot, "--format", "text", "--color", "always"}, want: "--color requires one of"},
			{args: []string{"adopt", "plan", "--mode", "fresh", "--repo-root", missingRoot, "--unknown", "value"}, want: "unsupported argument"},
			{args: []string{"repository-inventory", "--repo-root", missingRoot, "--mode", "fresh"}, want: "unsupported argument"},
			{args: []string{"adopt", "plan", "--mode", "fresh", "--repo-root", missingRoot, "--color", "never"}, want: "adopt plan --color requires --format text"},
			{args: []string{"adopt-plan", "--mode", "fresh", "--repo-root", repositoryRoot}, want: "unsupported command: adopt-plan"},
		} {
			status, stdout, stderr := executeAgentWorkflowCLI(t, item.args, panicReader{}, PresentationCapabilities{})
			if status != 1 || stdout != "" || !strings.Contains(stderr, item.want) || strings.Contains(stderr, "repository root") {
				t.Fatalf("args=%v status=%d stdout=%q stderr=%q want=%q", item.args, status, stdout, stderr, item.want)
			}
		}
	})

	t.Run("route-aware help", func(t *testing.T) {
		for _, args := range [][]string{{"adopt", "plan", "--help"}, {"adopt", "plan", "-h"}, {"help", "adopt", "plan"}} {
			status, stdout, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
			if status != 0 || stderr != "" || !strings.Contains(stdout, "agentic-proofkit adopt plan") || !strings.Contains(stdout, "Command ID:\n  adopt-plan") {
				t.Fatalf("args=%v status=%d stderr=%q stdout=%q", args, status, stderr, stdout)
			}
		}
		status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"help", "adopt"}, panicReader{}, PresentationCapabilities{})
		if status != 1 || stdout != "" || stderr != "unsupported help target: adopt\n" {
			t.Fatalf("abbreviated help status=%d stderr=%q stdout=%q", status, stderr, stdout)
		}
	})
}

func writeAdoptionFixture(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
