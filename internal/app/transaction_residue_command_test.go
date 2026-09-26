package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/transactionresidue"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

const residueActive = ".agentic-proofkit/transactions/active"

var residuePublicNonClaims = []any{
	"A residue observation does not authenticate its producer or establish absence of historical effects.",
	"Quarantine retains evidence; it does not roll back targets, validate their contents, or create a transaction receipt.",
	"These operations do not prove power-loss durability or protection from non-cooperative same-user writers.",
}

func TestTransactionResidueStructuralContracts(t *testing.T) {
	contract := readCLIContractRaw(t)
	definitions, _, err := indexPublicABIRecords(contract["contractDefinitions"], "definitionId")
	if err != nil {
		t.Fatal(err)
	}
	commands, _, err := indexPublicABIRecords(contract["commands"], "command")
	if err != nil {
		t.Fatal(err)
	}
	for name, schema := range map[string]map[string]any{
		"transaction-inspect-residue":    transactionresidue.InspectionOutputStructure(),
		"transaction-quarantine-residue": transactionresidue.RelocationOutputStructure(),
	} {
		definitionID := "proofkit." + name + ".output.v1.json-schema"
		definition, ok := definitions[definitionID]
		if !ok {
			t.Fatal("residue structural definition missing")
		}
		tree := definition["fieldTree"].(map[string]any)
		variants := tree["variants"].([]any)
		if tree["kind"] != "structural_json_schema" || len(variants) != 1 {
			t.Fatal("residue schema is incomplete")
		}
		variant := variants[0].(map[string]any)
		if !reflect.DeepEqual(canonicalJSONValue(t, variant["schema"]), canonicalJSONValue(t, schema)) {
			t.Fatal("public residue schema differs from native owner")
		}
		fields := []any{"kind", "nonClaims", "observationId", "schemaVersion", "state"}
		if !reflect.DeepEqual(variant["allowedFields"], fields) || !reflect.DeepEqual(variant["requiredFields"], fields) {
			t.Fatal("residue root key inventory changed")
		}
		command := commands[name]
		output := command["outputContract"].(map[string]any)
		if output["rootDefinitionRef"] != definitionID || output["rootDefinitionDigest"] != definition["canonicalDigest"] || output["contractId"] != "proofkit."+name+".output.v1" || command["input"] != "none" || command["stdin"] != false || command["inputPointer"] != false {
			t.Fatal("residue consumer contract binding changed")
		}
		if _, ok := command["inputContract"]; ok {
			t.Fatal("residue acquired an input contract")
		}
		sources := output["nativeSources"].([]any)
		paths := []any{}
		for _, raw := range sources {
			paths = append(paths, raw.(map[string]any)["path"])
		}
		if !reflect.DeepEqual(paths, []any{"internal/app", "internal/command/transactionresidue", "internal/kernel/repositorytransaction"}) {
			t.Fatal("residue native source closure changed")
		}
		if err := routeSemanticSourceProblemAtRoot(name, commandCoverageRoutes[name][0], repoRoot(t)); err != "" {
			t.Fatal(err)
		}
	}
}

func residueCLIFixture(t *testing.T, root string, content []byte) string {
	t.Helper()
	active := filepath.Join(root, residueActive)
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	if content != nil {
		if err := os.WriteFile(filepath.Join(active, "journal.tmp"), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return active
}

type residueCLIEntry struct {
	info    fs.FileInfo
	content []byte
	link    string
}

func residueCLITree(t *testing.T, root string) map[string]residueCLIEntry {
	t.Helper()
	entries := map[string]residueCLIEntry{}
	err := filepath.WalkDir(root, func(path string, item fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		entry := residueCLIEntry{info: info}
		if info.Mode().IsRegular() {
			entry.content, err = os.ReadFile(path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			entry.link, err = os.Readlink(path)
		}
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		entries[relative] = entry
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func assertResidueCLITree(t *testing.T, before, after map[string]residueCLIEntry) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatal("residue tree entry count changed")
	}
	for path, previous := range before {
		current, ok := after[path]
		if !ok || !os.SameFile(previous.info, current.info) || previous.info.Mode() != current.info.Mode() || !bytes.Equal(previous.content, current.content) || previous.link != current.link {
			t.Fatalf("residue evidence changed at %s", path)
		}
	}
}

func residueCLIArgs(root, operation string, observation ...string) []string {
	args := []string{"transaction", operation, "--repo-root", root}
	if len(observation) != 0 {
		args = append(args, "--expect-observation", observation[0])
	}
	return args
}

func residueCLIOutput(t *testing.T, args []string, state string, observation any) map[string]any {
	t.Helper()
	code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" || strings.Contains(output, "\x1b") {
		t.Fatalf("residue success streams: %d %q", code, diagnostic)
	}
	value := decodeCLIJSON(t, output).(map[string]any)
	assertExactObjectKeys(t, value, []string{"kind", "nonClaims", "observationId", "schemaVersion", "state"}, "residue output")
	kind := "proofkit.preparation-residue-inspection.v1"
	if state == "quarantined" {
		kind = "proofkit.preparation-residue-relocation.v1"
	}
	if value["kind"] != kind || value["schemaVersion"] != json.Number("1") || value["state"] != state || !reflect.DeepEqual(value["nonClaims"], residuePublicNonClaims) {
		t.Fatal("residue output contract changed")
	}
	if state == "eligible" && observation == nil {
		id, ok := value["observationId"].(string)
		if !ok || len(id) != 71 || !strings.HasPrefix(id, "sha256:") {
			t.Fatal("eligible observation is not a SHA256 ref")
		}
	} else if value["observationId"] != observation {
		t.Fatal("residue observation changed")
	}
	return value
}

func residueCLIFailure(t *testing.T, args []string, diagnosticPart string) {
	t.Helper()
	code, output, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
	if code != 1 || output != "" || diagnostic == "" || !strings.Contains(diagnostic, diagnosticPart) {
		t.Fatalf("residue failure streams: %d %q %q", code, output, diagnostic)
	}
	for _, arg := range args {
		if filepath.IsAbs(arg) && strings.Contains(diagnostic, arg) {
			t.Fatal("diagnostic disclosed repository path")
		}
	}
}

func TestTransactionInspectResidueCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.023840112833300781161777878649653566124650016931777164362071792846008234874013")
	root := t.TempDir()
	before := residueCLITree(t, root)
	residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "absent", nil)
	assertResidueCLITree(t, before, residueCLITree(t, root))
	for _, content := range [][]byte{nil, {}, []byte("{\"private\":\"unprinted"), {0, 255, 10, 13}} {
		root := t.TempDir()
		residueCLIFixture(t, root, content)
		before := residueCLITree(t, root)
		value := residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "eligible", nil)
		residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "eligible", value["observationId"])
		assertResidueCLITree(t, before, residueCLITree(t, root))
	}
	for _, wrongRoot := range []bool{false, true} {
		root := t.TempDir()
		planRoot := root
		if wrongRoot {
			planRoot = t.TempDir()
		}
		plan, err := repositorytransaction.BuildPlan(t.Context(), planRoot, []repositorytransaction.Target{{Path: "known", Content: []byte("retained"), Mode: 0o600}})
		if err != nil {
			t.Fatal(err)
		}
		journal := plan.JSONValue()
		delete(journal, "transactionKind")
		delete(journal, "nonClaims")
		journal["journalKind"] = "proofkit.repository-write-journal"
		content, err := stablejson.Marshal(journal)
		if err != nil {
			t.Fatal(err)
		}
		residueCLIFixture(t, root, content)
		before := residueCLITree(t, root)
		for _, args := range [][]string{residueCLIArgs(root, "inspect-residue"), residueCLIArgs(root, "quarantine-residue", "sha256:"+strings.Repeat("0", 64))} {
			residueCLIFailure(t, args, "unsafe, recognized or unsupported")
		}
		assertResidueCLITree(t, before, residueCLITree(t, root))
	}
}

func TestTransactionQuarantineResidueCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.108730979137923608554137281360123651427348251676143453419155635346880590692784")
	for _, content := range [][]byte{nil, []byte("{\"unprinted\":"), {0, 255, 10}} {
		root := t.TempDir()
		plan, err := repositorytransaction.BuildPlan(t.Context(), root, []repositorytransaction.Target{{Path: "old", Content: []byte("retained"), Mode: 0o640}})
		if err != nil {
			t.Fatal(err)
		}
		old, err := repositorytransaction.Apply(t.Context(), root, plan)
		if err != nil || old.State != repositorytransaction.StateApplied {
			t.Fatalf("native receipt fixture: %v", err)
		}
		prior := residueCLITree(t, root)
		active := residueCLIFixture(t, root, content)
		before := residueCLITree(t, active)
		value := residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "eligible", nil)
		id := value["observationId"].(string)
		args := residueCLIArgs(root, "quarantine-residue", id)
		residueCLIOutput(t, args, "quarantined", id)
		moved := filepath.Join(root, ".agentic-proofkit/transaction-residue/quarantined-"+strings.TrimPrefix(id, "sha256:"))
		assertResidueCLITree(t, before, residueCLITree(t, moved))
		if _, err := os.Lstat(active); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("active directory was not relocated")
		}
		current := residueCLITree(t, root)
		retained := map[string]residueCLIEntry{}
		for path := range prior {
			retained[path] = current[path]
		}
		assertResidueCLITree(t, prior, retained)
		got, err := repositorytransaction.ReadTerminalResult(t.Context(), root, old.TransactionID)
		if err != nil || got != old {
			t.Fatal("quarantine changed the retained receipt")
		}
		post := residueCLITree(t, root)
		residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "absent", nil)
		if _, err := repositorytransaction.BuildPlan(t.Context(), root, []repositorytransaction.Target{{Path: "next", Content: []byte("next"), Mode: 0o600}}); err != nil {
			t.Fatal(err)
		}
		assertResidueCLITree(t, post, residueCLITree(t, root))
		residueCLIFailure(t, args, "destination is already present")
		// Destination-first refusal must precede admission of even invalid new active state.
		residueCLIFixture(t, root, []byte("new active evidence"))
		if err := os.WriteFile(filepath.Join(active, "journal.json"), []byte("new unsupported evidence"), 0o600); err != nil {
			t.Fatal(err)
		}
		beforeRetry := residueCLITree(t, root)
		residueCLIFailure(t, args, "destination is already present")
		assertResidueCLITree(t, beforeRetry, residueCLITree(t, root))
	}
	root := t.TempDir()
	missingBefore := residueCLITree(t, root)
	residueCLIFailure(t, residueCLIArgs(root, "quarantine-residue", "sha256:"+strings.Repeat("0", 64)), "residue is absent")
	assertResidueCLITree(t, missingBefore, residueCLITree(t, root))
	active := residueCLIFixture(t, root, []byte("first"))
	id := residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "eligible", nil)["observationId"].(string)
	if err := os.WriteFile(filepath.Join(active, "journal.tmp"), []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := residueCLITree(t, root)
	residueCLIFailure(t, residueCLIArgs(root, "quarantine-residue", id), repositorytransaction.ErrControlStateChanged.Error())
	assertResidueCLITree(t, before, residueCLITree(t, root))
}

type residueRejectedOutput struct{}

func (residueRejectedOutput) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestTransactionResidueLostOutputAcknowledgment(t *testing.T) {
	root := t.TempDir()
	active := residueCLIFixture(t, root, []byte("unknown retained bytes"))
	before := residueCLITree(t, active)
	id := residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "eligible", nil)["observationId"].(string)
	args := residueCLIArgs(root, "quarantine-residue", id)
	var diagnostic bytes.Buffer
	code := Run(t.Context(), args, panicReader{}, residueRejectedOutput{}, &diagnostic)
	if code != 1 || !strings.Contains(diagnostic.String(), "write output") {
		t.Fatal("lost output acknowledgment claimed success")
	}
	moved := filepath.Join(root, ".agentic-proofkit/transaction-residue/quarantined-"+strings.TrimPrefix(id, "sha256:"))
	assertResidueCLITree(t, before, residueCLITree(t, moved))
	residueCLIFixture(t, root, []byte("new active"))
	after := residueCLITree(t, root)
	for _, format := range []string{"json", "text"} {
		residueCLIFailure(t, append(append([]string{}, args...), "--format", format), "destination is already present")
		assertResidueCLITree(t, after, residueCLITree(t, root))
	}
}

func TestTransactionResidueInvocationAndPresentation(t *testing.T) {
	for _, operation := range []string{"inspect-residue", "quarantine-residue"} {
		root := t.TempDir()
		var observation []string
		if operation == "quarantine-residue" {
			residueCLIFixture(t, root, []byte("retained"))
			observation = []string{residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "eligible", nil)["observationId"].(string)}
		}
		valid := residueCLIArgs(root, operation, observation...)
		before := residueCLITree(t, root)
		invalid := [][]string{{"transaction", operation}, {"transaction", operation, "--repo-root"}, {"transaction", operation, "--repo-root", ""}}
		for _, tail := range [][]string{
			{"--repo-root", root}, {"--format", "text", "--format", "json"}, {"--format", "text", "--color", "auto", "--color", "never"},
			{"--input", "-"}, {"--input-pointer", "/"}, {"--output", "not-created"}, {"--unknown", "value"},
			{"--format", "yaml"}, {"--format", "text", "--color", "always"}, {"--color", "auto"},
			{"--json-layout", "compact"}, {"--format", "text", "--unexpected"},
		} {
			invalid = append(invalid, append(append([]string{}, valid...), tail...))
		}
		invalid = append(invalid, append([]string{"--json-layout", "compact"}, append(append([]string{}, valid...), "--format", "text")...))
		if operation == "quarantine-residue" {
			invalid = append(invalid, residueCLIArgs(root, operation), append(append([]string{}, valid...), "--expect-observation", observation[0]))
			for _, ref := range []string{"bad", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("0", 63), "sha256:" + strings.Repeat("0", 64) + "\n"} {
				invalid = append(invalid, residueCLIArgs(root, operation, ref))
			}
		} else {
			invalid = append(invalid, residueCLIArgs(root, operation, "sha256:"+strings.Repeat("0", 64)))
		}
		for _, args := range invalid {
			residueCLIFailure(t, args, "")
			assertResidueCLITree(t, before, residueCLITree(t, root))
		}
		// Compare admission diagnostics at existing and missing roots: flags dominate repository I/O.
		for _, args := range invalid {
			_, _, existing := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
			missingArgs := append([]string{}, args...)
			for i, value := range missingArgs {
				if value == root {
					missingArgs[i] = filepath.Join(root, "missing")
				}
			}
			_, _, missing := executeAgentWorkflowCLI(t, missingArgs, panicReader{}, PresentationCapabilities{})
			if existing != missing {
				t.Fatalf("invalid flags reached repository I/O: args=%q existing=%q missing=%q", args, existing, missing)
			}
		}
		for _, help := range [][]string{{"transaction", operation, "--help"}, {"help", "transaction", operation}, {"transaction", operation, "-h"}} {
			code, output, diagnostic := executeAgentWorkflowCLI(t, help, panicReader{}, PresentationCapabilities{})
			if code != 0 || diagnostic != "" || !strings.Contains(output, "never reads stdin") || !strings.Contains(output, "error after rename") || !strings.Contains(output, "--repo-root <path>") {
				t.Fatalf("residue help contract changed: args=%q exit=%d stdout=%q stderr=%q", help, code, output, diagnostic)
			}
		}
		assertResidueCLITree(t, before, residueCLITree(t, root))
		residueCLIFailure(t, []string{"transaction-" + operation, "-h"}, "unsupported command")
	}
	for _, operation := range []string{"inspect-residue", "quarantine-residue"} {
		for _, capability := range []PresentationCapabilities{{}, {StdoutIsTTY: true}, {StdoutIsTTY: true, NoColorPresent: true}} {
			for _, color := range []string{"", "never", "auto"} {
				root := t.TempDir()
				observation := []string{}
				state := "absent"
				if operation == "quarantine-residue" {
					residueCLIFixture(t, root, nil)
					observation = append(observation, residueCLIOutput(t, residueCLIArgs(root, "inspect-residue"), "eligible", nil)["observationId"].(string))
					state = "quarantined"
				}
				args := append(residueCLIArgs(root, operation, observation...), "--format", "text")
				if color != "" {
					args = append(args, "--color", color)
				}
				code, text, diagnostic := executeAgentWorkflowCLI(t, args, panicReader{}, capability)
				colored := color == "auto" && capability.StdoutIsTTY && !capability.NoColorPresent
				if code != 0 || diagnostic != "" || strings.Contains(text, "\x1b") != colored {
					t.Fatal("residue terminal capability contract changed")
				}
				if !colored && !strings.HasPrefix(text, "State: "+state+"\n") {
					t.Fatal("residue text state changed")
				}
				for _, claim := range residuePublicNonClaims {
					if !strings.Contains(text, claim.(string)) {
						t.Fatal("text lost a non-claim")
					}
				}
			}
		}
	}
	root := t.TempDir()
	_, pretty, _ := executeAgentWorkflowCLI(t, residueCLIArgs(root, "inspect-residue"), panicReader{}, PresentationCapabilities{})
	code, compact, diagnostic := executeAgentWorkflowCLI(t, append([]string{"--json-layout", "compact"}, residueCLIArgs(root, "inspect-residue")...), panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" || strings.Count(compact, "\n") != 1 || pretty == compact || !reflect.DeepEqual(decodeCLIJSON(t, pretty), decodeCLIJSON(t, compact)) {
		t.Fatal("residue JSON layouts changed meaning")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := Run(ctx, residueCLIArgs(root, "inspect-residue"), panicReader{}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatal("cancelled residue inspection emitted success")
	}
}
