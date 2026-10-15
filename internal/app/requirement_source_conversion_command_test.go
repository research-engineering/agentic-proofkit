package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func conversionFixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "internal", "command", "requirementsourceconversion", "testdata", name)
}

func conversionFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(conversionFixturePath(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type conversionRun struct {
	exit   int
	stdout []byte
	stderr string
}

func runConversion(t *testing.T, input []byte, args ...string) conversionRun {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), args, bytes.NewReader(input), &stdout, &stderr)
	return conversionRun{exit: exit, stdout: stdout.Bytes(), stderr: stderr.String()}
}

func (run conversionRun) refused(t *testing.T, fragment string) {
	t.Helper()
	if run.exit != 1 || len(run.stdout) != 0 || !strings.Contains(run.stderr, fragment) {
		t.Fatalf("refusal exit=%d stdout=%q stderr=%q, want %q", run.exit, run.stdout, run.stderr, fragment)
	}
}

func (run conversionRun) document(t *testing.T) string {
	t.Helper()
	if run.exit != 0 || run.stderr != "" {
		t.Fatalf("conversion failed: exit=%d stderr=%s", run.exit, run.stderr)
	}
	return canonicalConversionJSON(t, run.stdout)
}

func canonicalConversionJSON(t *testing.T, data []byte) string {
	t.Helper()
	value, err := admission.DecodeJSON(bytes.NewReader(data), maxInputBytes)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := stablejson.MarshalLayout(value, stablejson.LayoutCompact)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// The whole public command exports and baseline-imports the hand-authored
// fixtures exactly and refuses every invocation and source class it cannot
// convert without loss, before any output exists.
func TestRequirementSourceConversionCLI(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.057698010316456636246617269635972158495598605803548318835904242824322932507230")
	grouped := conversionFixture(t, "source.grouped.json")
	flat := conversionFixture(t, "source.flat.json")
	baseline := conversionFixturePath(t, "source.grouped.json")
	command := []string{"requirement-source-conversion", "--input", "-"}

	if got := runConversion(t, grouped, append(command, "--to", "flat")...).document(t); got != canonicalConversionJSON(t, flat) {
		t.Fatalf("export differs from the hand-authored flat document: %s", got)
	}
	if got := runConversion(t, flat, append(command, "--to", "grouped", "--baseline", baseline)...).document(t); got != canonicalConversionJSON(t, grouped) {
		t.Fatalf("import differs from the hand-authored grouped source: %s", got)
	}
	wrapped := []byte(`{"source":` + string(grouped) + `}`)
	if got := runConversion(t, wrapped, append(command, "--input-pointer", "/source", "--to", "flat")...).document(t); got != canonicalConversionJSON(t, flat) {
		t.Fatal("selected input differs from the direct export")
	}
	compact := runConversion(t, grouped, append([]string{"--json-layout", "compact"}, append(command, "--to", "flat")...)...)
	if compact.document(t) != canonicalConversionJSON(t, flat) || string(compact.stdout) != canonicalConversionJSON(t, flat) {
		t.Fatal("compact layout is not the canonical compact document")
	}

	staleBaseline := filepath.Join(t.TempDir(), "stale.json")
	if err := os.WriteFile(staleBaseline, bytes.Replace(grouped, []byte("Deferred behavior remains owner-reviewed."), []byte("Deferred behavior remains reviewed."), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		input    []byte
		args     []string
		fragment string
	}{
		{flat, []string{"--to", "grouped"}, "requirement-source-conversion --to grouped requires --baseline"},
		{grouped, []string{"--to", "flat", "--baseline", baseline}, "requirement-source-conversion --baseline requires --to grouped"},
		{flat, []string{"--to", "grouped", "--baseline", "-"}, "--baseline requires a grouped source file path"},
		{grouped, []string{"--to", "tabular"}, "--to requires one of: flat, grouped"},
		{grouped, []string{"--to", "flat", "--to", "grouped"}, "--to may be specified only once"},
		{flat, []string{"--to", "grouped", "--baseline", staleBaseline}, "refused input: stale_baseline at /basisDigest"},
		{flat, []string{"--to", "grouped", "--baseline", filepath.Join(t.TempDir(), "absent.json")}, "could not read --baseline"},
		{flat, []string{"--to", "grouped", "--baseline", conversionFixturePath(t, "source.flat.json")}, "refused baseline: baseline_not_grouped_source at /kind"},
		{conversionFixture(t, "legacy.v1.json"), []string{"--to", "flat"}, "refused input: legacy_source_unsupported at /schemaVersion"},
		{grouped, []string{"--to", "grouped", "--baseline", baseline}, "refused input: same_format at /kind"},
		{flat, []string{"--to", "flat"}, "refused input: same_format at /kind"},
		{grouped, []string{"--to", "flat", "--output", "../escape.json"}, "must not escape the repository root"},
	} {
		runConversion(t, item.input, append(command, item.args...)...).refused(t, item.fragment)
	}

	// --output publishes only a new complete file: a fresh name receives the
	// whole document, and a name that another writer creates just before the
	// atomic link is refused and keeps that writer's bytes.
	t.Chdir(t.TempDir())
	fresh := runConversion(t, grouped, append(command, "--to", "flat", "--output", "fresh.json")...)
	if fresh.exit != 0 || len(fresh.stdout) != 0 || fresh.stderr != "" {
		t.Fatalf("publication exit=%d stdout=%q stderr=%q", fresh.exit, fresh.stdout, fresh.stderr)
	}
	if content, err := os.ReadFile("fresh.json"); err != nil || canonicalConversionJSON(t, content) != canonicalConversionJSON(t, flat) {
		t.Fatalf("published document differs: %v", err)
	}
	outputWriterBarrier = func(stage, path string) {
		if stage == "before_rename" && path == "raced.json" {
			if err := os.WriteFile(path, []byte("concurrent writer"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { outputWriterBarrier = nil })
	runConversion(t, grouped, append(command, "--to", "flat", "--output", "raced.json")...).refused(t, "output path already exists: raced.json")
	outputWriterBarrier = nil
	if content, err := os.ReadFile("raced.json"); err != nil || string(content) != "concurrent writer" {
		t.Fatalf("raced output name was replaced: %q %v", content, err)
	}
}

// --output publishes a complete new file or nothing: existing names, names
// created during publication and refused conversions leave every path as it
// was and leave no temporary file.
func TestRequirementSourceConversionOutputPublication(t *testing.T) {
	grouped := conversionFixture(t, "source.grouped.json")
	flat := conversionFixture(t, "source.flat.json")
	t.Chdir(t.TempDir())
	command := []string{"requirement-source-conversion", "--input", "-", "--to", "flat"}

	published := runConversion(t, grouped, append(command, "--output", "converted/flat.json")...)
	if published.exit != 0 || len(published.stdout) != 0 || published.stderr != "" {
		t.Fatalf("publication exit=%d stdout=%q stderr=%q", published.exit, published.stdout, published.stderr)
	}
	content, err := os.ReadFile(filepath.Join("converted", "flat.json"))
	if err != nil || canonicalConversionJSON(t, content) != canonicalConversionJSON(t, flat) {
		t.Fatalf("published document differs: %v", err)
	}
	if info, err := os.Stat(filepath.Join("converted", "flat.json")); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("published mode = %v, %v", info, err)
	}

	if err := os.WriteFile("existing.json", []byte("owner bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	runConversion(t, grouped, append(command, "--output", "existing.json")...).refused(t, "output path already exists: existing.json")

	outputWriterBarrier = func(stage, path string) {
		if stage == "before_rename" && path == "raced.json" {
			if err := os.WriteFile(path, []byte("concurrent writer"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { outputWriterBarrier = nil })
	runConversion(t, grouped, append(command, "--output", "raced.json")...).refused(t, "output path already exists: raced.json")
	outputWriterBarrier = nil

	baseline, err := filepath.Abs("stale.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baseline, bytes.Replace(grouped, []byte("accept requests."), []byte("accept every request."), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	runConversion(t, flat, "requirement-source-conversion", "--input", "-", "--to", "grouped", "--baseline", baseline, "--output", "refused.json").refused(t, "stale_baseline")

	for name, want := range map[string]string{"existing.json": "owner bytes", "raced.json": "concurrent writer"} {
		if content, err := os.ReadFile(name); err != nil || string(content) != want {
			t.Fatalf("%s changed: %q %v", name, content, err)
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if strings.Join(names, ",") != "converted,existing.json,raced.json,stale.json" {
		t.Fatalf("publication left residue or a refused output: %v", names)
	}
}

// --output admits its path through the confined writer's single predicate:
// Git metadata and Proofkit control state are refused at any depth before the
// input is read, the no-replace sink refuses them again, and nothing in the
// tree changes. Near names outside those components stay publishable.
func TestRequirementSourceConversionOutputRefusesProtectedNamespaces(t *testing.T) {
	grouped := conversionFixture(t, "source.grouped.json")
	root := t.TempDir()
	t.Chdir(root)
	writeModeFile(t, ".git/config", "[core]\n\tbare = false\n", 0o644)
	writeModeFile(t, ".agentic-proofkit/transactions/journal.json", "{}\n", 0o600)
	before := treeSnapshot(t, root)
	command := []string{"requirement-source-conversion", "--input", "-", "--to", "flat", "--output"}
	for _, output := range []string{
		".git/hooks/pre-commit",
		".git/objects/info/alternates",
		".GIT/info/attributes",
		".g\u200cit/info/exclude",
		"vendor/module/.git/hooks/post-merge",
		".agentic-proofkit/transactions/forged.json",
		".AGENTIC-PROOFKIT/flat.json",
		"docs/.agentic-proofkit/flat.json",
	} {
		refusal := "requirement-source-conversion output " + protectedOutputRefusal
		runConversion(t, grouped, append(command, output)...).refused(t, refusal)
		// Unparseable input proves the path is refused before input admission.
		runConversion(t, []byte("{"), append(command, output)...).refused(t, refusal)
		if err := writeNewRepoRelativeOutputFile(filepath.FromSlash(output), []byte("sink must refuse\n")); err == nil || !strings.Contains(err.Error(), protectedOutputRefusal) {
			t.Errorf("no-replace writer sink admitted %q: %v", output, err)
		}
	}
	runConversion(t, grouped, append(command, "out/\xff.json")...).refused(t, "requirement-source-conversion output path identity is invalid")
	assertSameTree(t, "protected conversion output", before, treeSnapshot(t, root))

	for _, output := range []string{".github/flat.json", ".githooks/flat.json", "a.git/flat.json", ".agentic-proofkit-flat/flat.json"} {
		published := runConversion(t, grouped, append(command, output)...)
		if published.exit != 0 || len(published.stdout) != 0 || published.stderr != "" {
			t.Fatalf("%q: exit=%d stdout=%q stderr=%q", output, published.exit, published.stdout, published.stderr)
		}
		if _, err := os.Stat(output); err != nil {
			t.Fatalf("%q was not published: %v", output, err)
		}
	}
}

// Expanded flat output must stay re-admissible through the CLI input bound.
// Two sources with the same model text size differ only in JSON escaping: the
// plain one is published and the quote-heavy one is refused, so byte size is
// measured on the emission rather than inferred from semantic text size.
func TestRequirementSourceConversionOutputBound(t *testing.T) {
	source := func(character string) []byte {
		text, err := json.Marshal("Bound " + strings.Repeat(character, 400<<10) + ".")
		if err != nil {
			t.Fatal(err)
		}
		rows := make([]string, 50)
		for index := range rows {
			rows[index] = `{"requirementId":"REQ-BOUND-N` + strconv.Itoa(index) + `","statementCompletion":"Bound requirement statement.","fields":{"externalNonClaimRefs":[],"proofBindingRefs":[],"ownerId":"bound.owner","claimLevel":"advisory","riskClass":"low","nonClaimRefs":[],"lifecycle":{"state":"active"},"deferral":null,"updatePolicy":{"reviewOwnerId":"bound.owner"}}}`
		}
		return []byte(`{"schemaVersion":2,"kind":"proofkit.requirement-source","sourceId":"bound.source","specPackagePath":"docs/specs/bound","sourceNonClaims":["Bound fixtures do not execute native witnesses."],"profiles":[{"profileId":"RPROF-BOUND","fields":{"nonClaims":[` + string(text) + `]}}],"groups":[{"groupId":"RGRP-BOUND","profileId":"RPROF-BOUND","statementStem":"","sharedPremises":[],"members":[` + strings.Join(rows, ",") + `]}]}`)
	}
	command := []string{"--json-layout", "compact", "requirement-source-conversion", "--input", "-", "--to", "flat"}
	plain := runConversion(t, source("a"), command...)
	if plain.exit != 0 || len(plain.stdout) > maxInputBytes || len(plain.stdout) < 50*(400<<10) {
		t.Fatalf("plain export exit=%d bytes=%d stderr=%s", plain.exit, len(plain.stdout), plain.stderr)
	}
	runConversion(t, source(`"`), command...).refused(t, "refused output: output_limit_exceeded")
}
