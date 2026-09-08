package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestAdoptionInputGuideCLI(t *testing.T) {
	var canonical string
	for _, args := range [][]string{
		{"adopt", "materialize", "plan", "--help"},
		{"adopt", "materialize", "plan", "-h"},
		{"help", "adopt", "materialize", "plan"},
	} {
		status, help, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if status != 0 || stderr != "" || strings.Count(help, adoptionmaterialization.InputGuide(cliexec.PathRenderer())) != 1 {
			t.Fatalf("help status=%d stderr=%q", status, stderr)
		}
		if canonical != "" && canonical != help {
			t.Fatal("help aliases disagree")
		}
		canonical = help
		if len(help) > 16<<10 || strings.Contains(help, "\x1b[") {
			t.Fatal("on-demand guide is not bounded plain text")
		}
	}
	for _, args := range [][]string{{"help"}, {"help", "families"}, {"changed-path-set", "--help"}, {"adopt", "materialize", "apply", "--help"}} {
		status, help, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
		if status != 0 || stderr != "" || strings.Contains(help, "Connected request template") {
			t.Fatalf("guide must remain lazy for %v: status=%d stderr=%q", args, status, stderr)
		}
	}

	for command, pointer := range map[string]string{
		"requirement-source-admission": "/requirementSources/0",
		"requirement-bindings":         "/requirementProofBinding/record",
		"test-evidence-inventory":      "/testEvidenceInventory/record",
	} {
		t.Run(command, func(t *testing.T) {
			status, help, stderr := executeAgentWorkflowCLI(t, []string{command, "--help"}, panicReader{}, PresentationCapabilities{})
			if status != 0 || stderr != "" || !strings.Contains(help, "adopt materialize plan --help") || !strings.Contains(help, pointer) {
				t.Fatalf("missing CLI continuation: status=%d stderr=%q help=%s", status, stderr, help)
			}
			if strings.Contains(help, "Connected request template") || strings.Contains(help, "Continue with the installed README") {
				t.Fatal("child help duplicated the template or requires external documentation")
			}
		})
	}

	for _, carrier := range []struct{ profile, python string }{
		{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/example/python 3"},
	} {
		renderer, err := cliexec.AdmitLauncherProfile(carrier.profile, carrier.python)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, ok := commandDescriptorFor("requirement-source-admission")
		if !ok {
			t.Fatal("requirement source descriptor missing")
		}
		help := commandUsageWithRenderer(descriptor, renderer)
		if !strings.Contains(help, renderer.DisplayCommand("adopt", "materialize", "plan", "--help")) {
			t.Fatal("continuation lost the installed carrier")
		}
		descriptor, _ = commandDescriptorFor("adopt-materialize-plan")
		guide := commandUsageWithRenderer(descriptor, renderer)
		commands := guideCommands(t, guide, "Materialization input guide:", renderer)
		if !reflect.DeepEqual(commands, expectedMaterializationGuideCommands()) {
			t.Fatalf("published carrier command operands drifted: %v", commands)
		}
		for _, denial := range []string{"NOT an additive patch", "binding's specPath must equal its source's requirementsPath", "durability_unknown", "not an execution", "Sort unique ID/path lists and every nonClaims list lexicographically.", "Do not sort argv; its token order is meaningful."} {
			if !strings.Contains(guide, denial) {
				t.Fatalf("guide lost required boundary: %s", denial)
			}
		}
		descriptor, _ = commandDescriptorFor("requirement-authoring-plan")
		authoring := commandUsageWithRenderer(descriptor, renderer)
		commands = guideCommands(t, authoring, "Requirement authoring input guide:", renderer)
		if !reflect.DeepEqual(commands, [][]string{{"requirement-authoring-plan", "--input", "<packet>"}}) ||
			!strings.Contains(authoring, "    "+renderer.DisplayCommand("adopt", "materialize", "plan", "--help")) {
			t.Fatalf("authoring guide lost the carrier or published operands: %v", commands)
		}
	}
}

func TestAdoptionInputGuideWholeChain(t *testing.T) {
	for _, intent := range []string{"fresh", "audit-from-code", "code-baseline"} {
		t.Run(intent, func(t *testing.T) {
			root := t.TempDir()
			packet := adoptionHelpPacket(t, root, intent)
			nonClaims := []any{"Candidate meaning requires owner review.", "Witness execution is not proven."}
			packet["nonClaims"] = nonClaims
			source := packet["requirementSources"].([]any)[0].(map[string]any)
			source["nonClaims"] = nonClaims
			adoptionHelpRequirement(packet)["nonClaims"] = nonClaims
			binding := packet["requirementProofBinding"].(map[string]any)["record"].(map[string]any)
			binding["nonClaims"] = nonClaims
			binding["requirements"].([]any)[0].(map[string]any)["nonClaims"] = nonClaims
			packet["testEvidenceInventory"].(map[string]any)["record"].(map[string]any)["nonClaims"] = nonClaims
			adoptionHelpEntry(packet)["nonClaims"] = nonClaims
			payload := adoptionHelpJSON(t, packet)
			_, help, _ := executeAgentWorkflowCLI(t, []string{"adopt", "materialize", "plan", "--help"}, panicReader{}, PresentationCapabilities{})
			commands := guideCommands(t, help, "Materialization input guide:", cliexec.PathRenderer())
			if !reflect.DeepEqual(commands, expectedMaterializationGuideCommands()) {
				t.Fatalf("guide chain drifted: %v", commands)
			}
			operands := map[string]string{"<packet>": "-", "<root>": root}
			for _, command := range commands[1:4] {
				report := runAdoptionHelpCLI(t, payload, fillGuideOperands(t, command, operands)...)
				if report["state"] != "passed" {
					t.Fatalf("child %s did not admit the real template", command[0])
				}
			}
			plan := runAdoptionHelpCLI(t, payload, fillGuideOperands(t, commands[4], operands)...)
			if plan["planKind"] != "proofkit.adoption-materialization-plan" || plan["state"] != "ready" || plan["sourceIntent"] != intent {
				t.Fatalf("wrong plan identity or trust intent: %v", plan)
			}
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
				t.Fatal("help, source planning or write planning mutated the empty repository")
			}
			transaction := plan["transaction"].(map[string]any)
			operands["<transaction.transactionId>"] = transaction["transactionId"].(string)
			operands["<transaction.desiredStateId>"] = transaction["desiredStateId"].(string)
			receipt := runAdoptionHelpCLI(t, payload, fillGuideOperands(t, commands[5], operands)...)
			if receipt["receiptKind"] != "proofkit.adoption-materialization-receipt" || receipt["state"] != "passed" {
				t.Fatalf("wrong materialization receipt: %v", receipt)
			}
			for _, artifact := range []struct{ path, command string }{
				{"docs/specs/requests/requirements.v1.json", "requirement-source-admission"},
				{"proofkit/requirement-bindings.json", "requirement-bindings"},
				{"proofkit/test-evidence-inventory.json", "test-evidence-inventory"},
			} {
				report := runAdoptionHelpCLI(t, nil, artifact.command, "--input", filepath.Join(root, artifact.path))
				if report["state"] != "passed" {
					t.Fatalf("materialized %s failed re-admission", artifact.path)
				}
			}
			bindingBytes, err := os.ReadFile(filepath.Join(root, "proofkit/requirement-bindings.json"))
			if err != nil {
				t.Fatal(err)
			}
			materializedBinding := decodeCLIJSON(t, string(bindingBytes)).(map[string]any)
			if !reflect.DeepEqual(materializedBinding["requirements"].([]any)[0].(map[string]any)["nonClaims"], nonClaims) {
				t.Fatal("materialization lost ordered requirement nonClaims")
			}
			inventoryBytes, err := os.ReadFile(filepath.Join(root, "proofkit/test-evidence-inventory.json"))
			if err != nil {
				t.Fatal(err)
			}
			materializedInventory := decodeCLIJSON(t, string(inventoryBytes)).(map[string]any)
			if !reflect.DeepEqual(materializedInventory["entries"].([]any)[0].(map[string]any)["nonClaims"], nonClaims) {
				t.Fatal("materialization lost ordered inventory entry nonClaims")
			}
			route := materializedBinding["bindings"].([]any)[0].(map[string]any)
			if route["scenarioId"] != "example.requests.empty" || route["witnessId"] != "example.witness.empty" || route["requirementId"] != "REQ-EXAMPLE-001" {
				t.Fatal("materialization lost the scenario/requirement/witness edge")
			}
			for _, absent := range []string{"src/request_test.go", "docs/specs/requests/overview.md"} {
				if _, err := os.Stat(filepath.Join(root, absent)); !os.IsNotExist(err) {
					t.Fatalf("guide fabricated a native test or overview: %s", absent)
				}
			}
		})
	}
}

func TestAdoptionInputGuideNonClaimsOrdering(t *testing.T) {
	for _, scope := range []string{"packet", "source", "requirement", "inventory", "entry"} {
		for _, invalid := range []struct {
			name   string
			values []any
		}{
			{"unsorted", []any{"Witness execution is not proven.", "Candidate meaning requires owner review."}},
			{"duplicate", []any{"Witness execution is not proven.", "Witness execution is not proven."}},
		} {
			t.Run(scope+"/"+invalid.name, func(t *testing.T) {
				root := t.TempDir()
				packet := adoptionHelpPacket(t, root, "fresh")
				owners := map[string]map[string]any{
					"packet":      packet,
					"source":      packet["requirementSources"].([]any)[0].(map[string]any),
					"requirement": adoptionHelpRequirement(packet),
					"inventory":   packet["testEvidenceInventory"].(map[string]any)["record"].(map[string]any),
					"entry":       adoptionHelpEntry(packet),
				}
				owners[scope]["nonClaims"] = invalid.values
				status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"adopt", "materialize", "plan", "--input", "-", "--repo-root", root}, bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
				if status != 1 || stdout != "" || !strings.Contains(stderr, "nonClaims") || !strings.Contains(stderr, "sorted") || !strings.Contains(stderr, "unique") {
					t.Fatalf("wrong rejection: status=%d stdout=%q stderr=%q", status, stdout, stderr)
				}
				if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
					t.Fatal("noncanonical nonClaims planning mutated the repository")
				}
			})
		}
	}
}

func TestAdoptionInputGuideRejectsBrokenEdges(t *testing.T) {
	for _, mutation := range []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"missing runtime operand", func(v map[string]any) { v["sourcePlan"] = nil }, "adoption plan"},
		{"source plan ID is not a plan", func(v map[string]any) { v["sourcePlan"] = v["sourcePlan"].(map[string]any)["planId"] }, "adoption plan"},
		{"wrong identity", func(v map[string]any) { v["requestKind"] = "example.wrong" }, "identity"},
		{"owner projection", func(v map[string]any) { adoptionHelpRequirement(v)["ownerId"] = "example.other" }, "binding requirement projection"},
		{"nonclaim projection", func(v map[string]any) { adoptionHelpRequirement(v)["nonClaims"] = []any{} }, "binding requirement projection"},
		{"source binding path", func(v map[string]any) { adoptionHelpRequirement(v)["proofBindingRefs"] = []any{"proofkit/other.json"} }, "proofBindingRefs"},
		{"inventory source edge", func(v map[string]any) {
			adoptionHelpEntry(v)["sourcePath"] = "src/other_test.go"
			adoptionHelpEntry(v)["selector"] = "src/other_test.go::TestRejectEmptyInput"
		}, "not connected"},
		{"inventory command edge", func(v map[string]any) { adoptionHelpEntry(v)["commandRefs"] = []any{"example.unknown"} }, "not connected"},
		{"inventory witness edge", func(v map[string]any) { adoptionHelpEntry(v)["witnessRefs"] = []any{"example.unknown"} }, "not connected"},
		{"inventory requirement edge", func(v map[string]any) { adoptionHelpEntry(v)["requirementRefs"] = []any{"REQ-UNKNOWN-001"} }, "unknown requirement"},
		{"secret text", func(v map[string]any) { adoptionHelpRequirement(v)["invariant"] = "api_key=private-example-value" }, "secret"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			root := t.TempDir()
			packet := adoptionHelpPacket(t, root, "fresh")
			mutation.edit(packet)
			status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"adopt", "materialize", "plan", "--input", "-", "--repo-root", root}, bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
			if status != 1 || stdout != "" || !strings.Contains(stderr, mutation.want) || strings.Contains(stderr, "private-example-value") {
				t.Fatalf("wrong rejection: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
				t.Fatal("failed plan mutated the repository")
			}
		})
	}
}

func TestAdoptionInputGuideInventoryVersion(t *testing.T) {
	_, help, _ := executeAgentWorkflowCLI(t, []string{"test-evidence-inventory", "--help"}, panicReader{}, PresentationCapabilities{})
	if !strings.Contains(help, "direct inventory schemaVersion=1") || strings.Contains(help, "\n  schemaVersion=2\n") {
		t.Fatal("inventory help confuses aggregate contract version with direct input schema")
	}
	packet := adoptionHelpPacket(t, t.TempDir(), "fresh")
	inventory := packet["testEvidenceInventory"].(map[string]any)["record"].(map[string]any)
	report := runAdoptionHelpCLI(t, adoptionHelpJSON(t, inventory), "test-evidence-inventory", "--input", "-")
	if report["state"] != "passed" {
		t.Fatal("published direct inventory was rejected")
	}
	inventory["schemaVersion"] = 2
	status, stdout, stderr := executeAgentWorkflowCLI(t, []string{"test-evidence-inventory", "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, inventory)), PresentationCapabilities{})
	if status != 1 || stdout != "" || !strings.Contains(stderr, "schemaVersion must be 1") {
		t.Fatalf("direct v2 input was not rejected: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
}

func adoptionHelpPacket(t *testing.T, root, intent string) map[string]any {
	t.Helper()
	status, help, stderr := executeAgentWorkflowCLI(t, []string{"adopt", "materialize", "plan", "--help"}, panicReader{}, PresentationCapabilities{})
	if status != 0 || stderr != "" {
		t.Fatalf("guide status=%d stderr=%q", status, stderr)
	}
	sections := strings.Split(help, "```json\n")
	if len(sections) != 2 {
		t.Fatal("guide must publish exactly one connected JSON template")
	}
	input, _, closed := strings.Cut(sections[1], "\n```")
	if !closed {
		t.Fatal("guide template fence is not closed")
	}
	packet := decodeCLIJSON(t, input).(map[string]any)
	if packet["sourcePlan"] != nil {
		t.Fatal("template contains a fabricated source plan")
	}
	commands := guideCommands(t, help, "Materialization input guide:", cliexec.PathRenderer())
	if !reflect.DeepEqual(commands, expectedMaterializationGuideCommands()) {
		t.Fatalf("published source-plan or continuation operands drifted: %v", commands)
	}
	args := fillGuideOperands(t, commands[0], map[string]string{"<root>": root, "<intent>": intent})
	packet["sourcePlan"] = runAdoptionHelpCLI(t, nil, args...)
	return packet
}

func adoptionHelpJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func runAdoptionHelpCLI(t *testing.T, input []byte, args ...string) map[string]any {
	t.Helper()
	status, stdout, stderr := executeAgentWorkflowCLI(t, args, bytes.NewReader(input), PresentationCapabilities{})
	if status != 0 || stderr != "" {
		t.Fatalf("%v status=%d stderr=%q stdout=%q", args, status, stderr, stdout)
	}
	return decodeCLIJSON(t, stdout).(map[string]any)
}

func adoptionHelpRequirement(v map[string]any) map[string]any {
	return v["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)
}

func adoptionHelpEntry(v map[string]any) map[string]any {
	return v["testEvidenceInventory"].(map[string]any)["record"].(map[string]any)["entries"].([]any)[0].(map[string]any)
}

func expectedMaterializationGuideCommands() [][]string {
	return [][]string{
		{"adopt", "plan", "--repo-root", "<root>", "--mode", "<intent>", "--format", "json"},
		{"requirement-source-admission", "--input", "<packet>", "--input-pointer", "/requirementSources/0"},
		{"requirement-bindings", "--input", "<packet>", "--input-pointer", "/requirementProofBinding/record"},
		{"test-evidence-inventory", "--input", "<packet>", "--input-pointer", "/testEvidenceInventory/record"},
		{"adopt", "materialize", "plan", "--input", "<packet>", "--repo-root", "<root>"},
		{"adopt", "materialize", "apply", "--input", "<packet>", "--repo-root", "<root>", "--expect-transaction", "<transaction.transactionId>", "--expect-desired-state", "<transaction.desiredStateId>"},
	}
}

// These guides publish simple literal route operands, not arbitrary shell code.
func guideCommands(t *testing.T, help, marker string, renderer cliexec.Renderer) [][]string {
	t.Helper()
	_, guide, ok := strings.Cut(help, marker)
	if !ok {
		t.Fatal("guide marker missing")
	}
	prefix := "  " + renderer.DisplayCommand() + " "
	var commands [][]string
	for _, line := range strings.Split(guide, "\n") {
		if tail, matched := strings.CutPrefix(line, prefix); matched {
			args := strings.Fields(tail)
			if strings.Join(args, " ") != tail {
				t.Fatal("guide operands are not canonically space-delimited")
			}
			commands = append(commands, args)
		}
	}
	return commands
}

func fillGuideOperands(t *testing.T, args []string, operands map[string]string) []string {
	t.Helper()
	result := append([]string{}, args...)
	for index, value := range result {
		if replacement, ok := operands[value]; ok {
			result[index] = replacement
		} else if strings.ContainsAny(value, "<>") {
			t.Fatalf("unbound guide operand: %s", value)
		}
	}
	return result
}
