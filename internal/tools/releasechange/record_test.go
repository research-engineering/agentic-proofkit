package releasechange

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAdmitAndRenderVersionBoundChangeRecord(t *testing.T) {
	record, err := Admit(validRecord())
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireVersion(record, "2.0.0"); err != nil {
		t.Fatal(err)
	}
	notes := RenderMarkdown(record, "@research-engineering/agentic-proofkit", "agentic-proofkit", true)
	for _, expected := range []string{
		"## Breaking Contract Changes", "## Additions", "## Migration", "Migration is required:",
		"## Platform Requirements", "## Known Limitations", "## Install", "## Rollback",
		"npm install --save-dev --save-exact @research-engineering/agentic-proofkit@2.0.0",
		"uv tool install agentic-proofkit==2.0.0",
		"previous admitted version 1.2.2",
		"`npm install --save-dev --save-exact @research-engineering/agentic-proofkit@1.2.2`",
		"`proofkit.contract.breaking`: Remove the inert field.",
	} {
		if !strings.Contains(notes, expected) {
			t.Fatalf("rendered notes missing %q:\n%s", expected, notes)
		}
	}
}

func TestAdmitEnforcesVersionedChangeClass(t *testing.T) {
	tests := []struct {
		name          string
		previous      string
		version       string
		changeClass   string
		breaking      bool
		wantErrorText string
	}{
		{name: "breaking patch is rejected", previous: "0.1.159", version: "0.1.160", changeClass: "breaking", breaking: true, wantErrorText: "breaking change requires"},
		{name: "breaking zero-major minor is admitted", previous: "0.1.160", version: "0.2.0", changeClass: "breaking", breaking: true},
		{name: "breaking zero-major minor with patch is admitted", previous: "0.1.3", version: "0.2.1", changeClass: "breaking", breaking: true},
		{name: "breaking stable major with minor is admitted", previous: "1.2.3", version: "2.1.0", changeClass: "breaking", breaking: true},
		{name: "breaking stable patch is rejected", previous: "1.2.3", version: "1.2.4", changeClass: "breaking", breaking: true, wantErrorText: "breaking change requires"},
		{name: "compatible minor is admitted", previous: "1.2.3", version: "1.3.0", changeClass: "compatible"},
		{name: "nonmonotonic equal is rejected", previous: "1.2.3", version: "1.2.3", changeClass: "compatible", wantErrorText: "greater than previousVersion"},
		{name: "nonmonotonic lower is rejected", previous: "1.2.4", version: "1.2.3", changeClass: "compatible", wantErrorText: "greater than previousVersion"},
		{name: "breaking declaration without breaking facts is rejected", previous: "1.2.3", version: "2.0.0", changeClass: "breaking", wantErrorText: "changeClass does not match"},
		{name: "compatible declaration with migration is rejected", previous: "1.2.3", version: "1.3.0", changeClass: "compatible", breaking: true, wantErrorText: "changeClass does not match"},
		{name: "leading zero is rejected", previous: "1.2.3", version: "1.03.0", changeClass: "compatible", wantErrorText: "canonical SemVer"},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			record := validRecord()
			record["previousVersion"] = item.previous
			record["version"] = item.version
			record["changeClass"] = item.changeClass
			if !item.breaking {
				record["breakingChanges"] = []any{}
				record["migration"] = map[string]any{"required": false, "steps": []any{}}
			}
			_, err := Admit(record)
			if item.wantErrorText == "" {
				if err != nil {
					t.Fatalf("Admit() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), item.wantErrorText) {
				t.Fatalf("Admit() error = %v, want %q", err, item.wantErrorText)
			}
		})
	}
}

func TestRenderStatesPreOneExactPinPolicy(t *testing.T) {
	value := validRecord()
	value["previousVersion"] = "0.1.160"
	value["version"] = "0.2.0"
	record, err := Admit(value)
	if err != nil {
		t.Fatal(err)
	}
	notes := RenderMarkdown(record, "@research-engineering/agentic-proofkit", "agentic-proofkit", false)
	for _, expected := range []string{
		"npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.2.0",
		"Pre-1.0 npm consumers must keep this dependency exact-pinned.",
		"`npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.1.160`",
	} {
		if !strings.Contains(notes, expected) {
			t.Fatalf("rendered notes missing %q:\n%s", expected, notes)
		}
	}
}

func TestCurrentChangeRecordNamesReviewedSemanticChanges(t *testing.T) {
	record, err := Read(filepath.Join("..", "..", "..", RecordPath))
	if err != nil {
		t.Fatal(err)
	}
	notes := RenderMarkdown(record, "@research-engineering/agentic-proofkit", "agentic-proofkit", false)
	if err := validateCurrentChangeRecord(record, notes); err != nil {
		t.Fatal(err)
	}

	for index := range record.BreakingChanges {
		mutant := cloneReleaseChangeRecord(record)
		mutant.BreakingChanges = deleteReleaseChangeAt(mutant.BreakingChanges, index)
		assertCurrentChangeRecordRejected(t, "missing breaking "+record.BreakingChanges[index].ChangeID, mutant)
		mutant = cloneReleaseChangeRecord(record)
		mutant.BreakingChanges[index].ChangeID += ".drift"
		assertCurrentChangeRecordRejected(t, "substituted breaking id "+record.BreakingChanges[index].ChangeID, mutant)
		mutant = cloneReleaseChangeRecord(record)
		mutant.BreakingChanges[index].Summary += " Drift."
		assertCurrentChangeRecordRejected(t, "substituted breaking summary "+record.BreakingChanges[index].ChangeID, mutant)
	}
	for index := range record.Additions {
		mutant := cloneReleaseChangeRecord(record)
		mutant.Additions = deleteReleaseChangeAt(mutant.Additions, index)
		assertCurrentChangeRecordRejected(t, "missing addition "+record.Additions[index].ChangeID, mutant)
		mutant = cloneReleaseChangeRecord(record)
		mutant.Additions[index].ChangeID += ".drift"
		assertCurrentChangeRecordRejected(t, "substituted addition id "+record.Additions[index].ChangeID, mutant)
		mutant = cloneReleaseChangeRecord(record)
		mutant.Additions[index].Summary += " Drift."
		assertCurrentChangeRecordRejected(t, "substituted addition summary "+record.Additions[index].ChangeID, mutant)
	}
	for index := range record.Migration.Steps {
		mutant := cloneReleaseChangeRecord(record)
		mutant.Migration.Steps = deleteReleaseChangeAt(mutant.Migration.Steps, index)
		assertCurrentChangeRecordRejected(t, fmt.Sprintf("missing migration %d", index), mutant)
		mutant = cloneReleaseChangeRecord(record)
		mutant.Migration.Steps[index] += " Drift."
		assertCurrentChangeRecordRejected(t, fmt.Sprintf("substituted migration %d", index), mutant)
	}
	for index := 0; index+1 < len(record.BreakingChanges); index++ {
		mutant := cloneReleaseChangeRecord(record)
		mutant.BreakingChanges[index], mutant.BreakingChanges[index+1] = mutant.BreakingChanges[index+1], mutant.BreakingChanges[index]
		assertCurrentChangeRecordRejected(t, fmt.Sprintf("reordered breaking %d", index), mutant)
	}
	for index := 0; index+1 < len(record.Additions); index++ {
		mutant := cloneReleaseChangeRecord(record)
		mutant.Additions[index], mutant.Additions[index+1] = mutant.Additions[index+1], mutant.Additions[index]
		assertCurrentChangeRecordRejected(t, fmt.Sprintf("reordered addition %d", index), mutant)
	}
	for index := 0; index+1 < len(record.Migration.Steps); index++ {
		mutant := cloneReleaseChangeRecord(record)
		mutant.Migration.Steps[index], mutant.Migration.Steps[index+1] = mutant.Migration.Steps[index+1], mutant.Migration.Steps[index]
		assertCurrentChangeRecordRejected(t, fmt.Sprintf("reordered migration %d", index), mutant)
	}
	breakingSurplus := cloneReleaseChangeRecord(record)
	breakingSurplus.BreakingChanges = append(breakingSurplus.BreakingChanges, Change{ChangeID: "proofkit.surplus.breaking", Summary: "Surplus breaking change."})
	assertCurrentChangeRecordRejected(t, "surplus breaking", breakingSurplus)
	additionSurplus := cloneReleaseChangeRecord(record)
	additionSurplus.Additions = append(additionSurplus.Additions, Change{ChangeID: "proofkit.surplus.addition", Summary: "Surplus addition."})
	assertCurrentChangeRecordRejected(t, "surplus addition", additionSurplus)
	migrationSurplus := cloneReleaseChangeRecord(record)
	migrationSurplus.Migration.Steps = append(migrationSurplus.Migration.Steps, "Surplus migration step.")
	assertCurrentChangeRecordRejected(t, "surplus migration", migrationSurplus)

	for _, projected := range currentChangeRecordProjectionStrings() {
		mutantNotes := strings.Replace(notes, projected, "projection drift", 1)
		if err := validateCurrentChangeRecord(record, mutantNotes); err == nil {
			t.Fatalf("current release projection admitted missing %q", projected)
		}
	}
	if len(currentBreakingChanges) > 1 {
		reordered := swapAdjacentNoteItems(notes, currentChangeBullet(currentBreakingChanges[0]), currentChangeBullet(currentBreakingChanges[1]))
		assertCurrentChangeRecordNotesRejected(t, "reordered breaking note", record, reordered)
	}
	if len(currentAdditions) > 1 {
		reordered := swapAdjacentNoteItems(notes, currentChangeBullet(currentAdditions[0]), currentChangeBullet(currentAdditions[1]))
		assertCurrentChangeRecordNotesRejected(t, "reordered addition note", record, reordered)
	}
	if len(currentMigrationSteps) > 1 {
		reordered := swapAdjacentNoteItems(notes, "- "+currentMigrationSteps[0], "- "+currentMigrationSteps[1])
		assertCurrentChangeRecordNotesRejected(t, "reordered migration note", record, reordered)
	}
	if len(currentAdditions) > 0 {
		relocatedNotes := strings.Replace(notes, currentChangeBullet(currentAdditions[0])+"\n", "", 1)
		relocatedNotes = strings.Replace(relocatedNotes, "## Breaking Contract Changes\n\n", "## Breaking Contract Changes\n\n"+currentChangeBullet(currentAdditions[0])+"\n", 1)
		assertCurrentChangeRecordNotesRejected(t, "addition note relocated to breaking", record, relocatedNotes)
		assertCurrentChangeRecordNotesRejected(t, "appended duplicate change note", record, notes+currentChangeBullet(currentAdditions[0])+"\n")
	}
	surplusNotes := strings.Replace(notes, "\n\n## Additions", "\n- `proofkit.surplus.note`: Surplus note.\n\n## Additions", 1)
	assertCurrentChangeRecordNotesRejected(t, "surplus breaking note", record, surplusNotes)
	assertCurrentChangeRecordNotesRejected(t, "appended surplus change note", record, notes+"- `proofkit.surplus.appended`: Appended surplus note.\n")
	assertCurrentChangeRecordNotesRejected(t, "appended duplicate change section", record, notes+"## Breaking Contract Changes\n\n- `proofkit.surplus.section`: Surplus section.\n")
}

var currentBreakingChanges = []Change{}

var currentAdditions = []Change{
	{ChangeID: "proofkit.adoption.transactional-materialization", Summary: "Add separate read-only plan, compare-and-swap apply, and state-bound recovery routes that compile owner-admitted adoption candidates into canonical repository artifacts."},
	{ChangeID: "proofkit.repository.transaction-protocol", Summary: "Add a bounded repository-confined transaction owner with immutable journals, exact before-state checks, deterministic resume, and byte-identical rollback for cooperative writers."},
}

var currentMigrationSteps = []string{}

func validateCurrentChangeRecord(record Record, notes string) error {
	if !slices.Equal(record.BreakingChanges, currentBreakingChanges) {
		return fmt.Errorf("current release breaking inventory is not exact")
	}
	if !slices.Equal(record.Additions, currentAdditions) {
		return fmt.Errorf("current release addition inventory is not exact")
	}
	if !slices.Equal(record.Migration.Steps, currentMigrationSteps) {
		return fmt.Errorf("current release migration inventory is not exact")
	}
	if notes != currentExpectedReleaseNotes() {
		return fmt.Errorf("rendered current release notes are not the exact reviewed projection")
	}
	return nil
}

func currentExpectedReleaseNotes() string {
	lines := []string{
		"# @research-engineering/agentic-proofkit 0.8.0",
		"",
		"## Breaking Contract Changes",
		"",
	}
	for _, change := range currentBreakingChanges {
		lines = append(lines, currentChangeBullet(change))
	}
	if len(currentBreakingChanges) == 0 {
		lines = append(lines, "- None.")
	}
	lines = append(lines, "", "## Additions", "")
	for _, change := range currentAdditions {
		lines = append(lines, currentChangeBullet(change))
	}
	if len(currentAdditions) == 0 {
		lines = append(lines, "- None.")
	}
	lines = append(lines,
		"",
		"## Migration",
		"",
		"No consumer migration is required.",
		"",
	)
	lines = append(lines,
		"## Platform Requirements",
		"",
		"- Published Darwin package binaries require macOS 13.0 or later on arm64 and x86_64.",
		"",
		"## Known Limitations",
		"",
		"- Adopt plan inventories only a fixed root-file catalog; it does not infer stack identity, inspect arbitrary source semantics, generate requirements, write files, or execute native evidence.",
		"- Transactional materialization writes only owner-admitted candidate artifacts under one explicit repository root; it does not infer requirement meaning, execute native evidence, approve merge or release, provide filesystem-wide atomic visibility to concurrent readers, or protect its private namespace from a hostile same-user process.",
		"- Agent workflow plans, prompts, text, and envelopes are derived guidance and do not execute agents, repository mutations, native witnesses, CI, release, rollout, or production operations.",
		"- Brief agent-route packets cap pretty JSON at 3072 bytes and may defer oversized argv to explicit full detail; the bound does not claim tokenizer-specific token counts.",
		"- Complete nested public structural contracts remain blocked under SCHEMA-01; current CLI contracts own exact root variants only.",
		"- The selected requirement-source v2 codec remains internal; current requirement sources are not migrated and no source cutover is claimed.",
		"- TSX source parsing remains unsupported.",
		"",
		"## Install",
		"",
		"Primary npm channel:",
		"",
		"```bash",
		"npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.8.0",
		"```",
		"",
		"Pre-1.0 npm consumers must keep this dependency exact-pinned.",
		"",
		"Python wheels are candidate artifacts until a PyPI release workflow publishes them.",
		"",
		"GitHub Release assets and checksums are archive and provenance evidence, not package-manager dependency authority.",
		"",
		"## Rollback",
		"",
		"- Pin npm consumers to the previous admitted version 0.7.0 with `npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.7.0`.",
		"- Treat local package artifacts as candidates until registry identity is proven.",
	)
	return strings.Join(lines, "\n") + "\n"
}

func currentChangeBullet(change Change) string {
	return fmt.Sprintf("- `%s`: %s", change.ChangeID, change.Summary)
}

func currentChangeRecordProjectionStrings() []string {
	result := make([]string, 0, 2*(len(currentBreakingChanges)+len(currentAdditions))+len(currentMigrationSteps))
	for _, change := range currentBreakingChanges {
		result = append(result, change.ChangeID, change.Summary)
	}
	for _, change := range currentAdditions {
		result = append(result, change.ChangeID, change.Summary)
	}
	return append(result, currentMigrationSteps...)
}

func assertCurrentChangeRecordRejected(t *testing.T, name string, record Record) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		notes := RenderMarkdown(record, "@research-engineering/agentic-proofkit", "agentic-proofkit", false)
		if err := validateCurrentChangeRecord(record, notes); err == nil {
			t.Fatal("current release inventory mutant was admitted")
		}
	})
}

func assertCurrentChangeRecordNotesRejected(t *testing.T, name string, record Record, notes string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		if err := validateCurrentChangeRecord(record, notes); err == nil {
			t.Fatal("current release note projection mutant was admitted")
		}
	})
}

func swapAdjacentNoteItems(notes string, first string, second string) string {
	ordered := first + "\n" + second
	reordered := second + "\n" + first
	return strings.Replace(notes, ordered, reordered, 1)
}

func cloneReleaseChangeRecord(record Record) Record {
	record.BreakingChanges = append([]Change(nil), record.BreakingChanges...)
	record.Additions = append([]Change(nil), record.Additions...)
	record.Migration.Steps = append([]string(nil), record.Migration.Steps...)
	return record
}

func deleteReleaseChangeAt[T any](values []T, index int) []T {
	result := append([]T(nil), values[:index]...)
	return append(result, values[index+1:]...)
}

func TestAdmitRejectsAmbiguousOrIncompleteChangeRecords(t *testing.T) {
	t.Run("duplicate identity across sections", func(t *testing.T) {
		record := validRecord()
		record["additions"] = []any{map[string]any{"changeId": "proofkit.contract.breaking", "summary": "Duplicate identity."}}
		if _, err := Admit(record); err == nil || !strings.Contains(err.Error(), "must be unique") {
			t.Fatalf("Admit() error = %v, want duplicate identity rejection", err)
		}
	})
	t.Run("required migration without steps", func(t *testing.T) {
		record := validRecord()
		record["migration"] = map[string]any{"required": true, "steps": []any{}}
		if _, err := Admit(record); err == nil || !strings.Contains(err.Error(), "must be non-empty") {
			t.Fatalf("Admit() error = %v, want migration closure rejection", err)
		}
	})
	t.Run("no migration with steps", func(t *testing.T) {
		record := validRecord()
		record["migration"] = map[string]any{"required": false, "steps": []any{"Do something."}}
		if _, err := Admit(record); err == nil || !strings.Contains(err.Error(), "must be empty") {
			t.Fatalf("Admit() error = %v, want no-migration contradiction rejection", err)
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		record, err := Admit(validRecord())
		if err != nil {
			t.Fatal(err)
		}
		if err := RequireVersion(record, "2.0.1"); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("RequireVersion() error = %v, want mismatch", err)
		}
	})
	t.Run("multiline release-note field", func(t *testing.T) {
		record := validRecord()
		record["additions"] = []any{map[string]any{
			"changeId": "proofkit.release.license",
			"summary":  "Embed license evidence.\n## Forged Section",
		}}
		if _, err := Admit(record); err == nil || !strings.Contains(err.Error(), "single-line") {
			t.Fatalf("Admit() error = %v, want multiline rejection", err)
		}
	})
}

func TestReadRejectsDuplicateJSONKeys(t *testing.T) {
	content := `{"schemaVersion":1,"version":"1.2.3","version":"1.2.4"}`
	path := t.TempDir() + "/record.json"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("Read() error = %v, want duplicate-key rejection", err)
	}
}

func TestRenderRepresentsEmptyOptionalSectionsExplicitly(t *testing.T) {
	record := validRecord()
	record["knownLimitations"] = []any{}
	record["platformRequirements"] = []any{}
	admitted, err := Admit(record)
	if err != nil {
		t.Fatal(err)
	}
	notes := RenderMarkdown(admitted, "@research-engineering/agentic-proofkit", "agentic-proofkit", false)
	if strings.Count(notes, "- None.") < 2 {
		t.Fatalf("rendered notes must represent empty sections explicitly:\n%s", notes)
	}
}

func validRecord() map[string]any {
	return map[string]any{
		"schemaVersion":   json.Number("2"),
		"previousVersion": "1.2.2",
		"version":         "2.0.0",
		"changeClass":     "breaking",
		"breakingChanges": []any{
			map[string]any{"changeId": "proofkit.contract.breaking", "summary": "Remove the inert field."},
		},
		"additions":            []any{map[string]any{"changeId": "proofkit.release.license", "summary": "Embed license evidence."}},
		"migration":            map[string]any{"required": true, "steps": []any{"Delete the obsolete input field."}},
		"platformRequirements": []any{"macOS 12.0 or later is required by Darwin wheels."},
		"knownLimitations":     []any{"TSX parsing remains unsupported."},
		"rollback":             map[string]any{"strategy": "previous_admitted_version"},
	}
}
