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
	breakingReorderedNotes := swapAdjacentNoteItems(notes, currentChangeBullet(currentBreakingChanges[0]), currentChangeBullet(currentBreakingChanges[1]))
	assertCurrentChangeRecordNotesRejected(t, "reordered breaking note", record, breakingReorderedNotes)
	additionReorderedNotes := swapAdjacentNoteItems(notes, currentChangeBullet(currentAdditions[0]), currentChangeBullet(currentAdditions[1]))
	assertCurrentChangeRecordNotesRejected(t, "reordered addition note", record, additionReorderedNotes)
	migrationReorderedNotes := swapAdjacentNoteItems(notes, "- "+currentMigrationSteps[0], "- "+currentMigrationSteps[1])
	assertCurrentChangeRecordNotesRejected(t, "reordered migration note", record, migrationReorderedNotes)
	relocatedNotes := strings.Replace(notes, currentChangeBullet(currentBreakingChanges[0])+"\n", "", 1)
	relocatedNotes = strings.Replace(relocatedNotes, "## Additions\n\n", "## Additions\n\n"+currentChangeBullet(currentBreakingChanges[0])+"\n", 1)
	assertCurrentChangeRecordNotesRejected(t, "breaking note relocated to additions", record, relocatedNotes)
	surplusNotes := strings.Replace(notes, "\n\n## Additions", "\n- `proofkit.surplus.note`: Surplus note.\n\n## Additions", 1)
	assertCurrentChangeRecordNotesRejected(t, "surplus breaking note", record, surplusNotes)
	assertCurrentChangeRecordNotesRejected(t, "appended surplus change note", record, notes+"- `proofkit.surplus.appended`: Appended surplus note.\n")
	assertCurrentChangeRecordNotesRejected(t, "appended duplicate change note", record, notes+currentChangeBullet(currentBreakingChanges[0])+"\n")
	assertCurrentChangeRecordNotesRejected(t, "appended duplicate change section", record, notes+"## Breaking Contract Changes\n\n- `proofkit.surplus.section`: Surplus section.\n")
}

var currentBreakingChanges = []Change{
	{ChangeID: "proofkit.adoption-doctor.advisory-rule-status", Summary: "Non-enforced adoption-doctor advisory gap rules now report skipped instead of passed, including observe-mode rules and gaps outside an enforce-touched selection; these gaps do not change the top-level outcome."},
	{ChangeID: "proofkit.adoption-doctor.blocked-prerequisites", Summary: "Adoption doctor now reports unresolved external prerequisites as blocked with exit code 1 in every adoption mode; observe and warn no longer relax them."},
	{ChangeID: "proofkit.browser.native-list-keyboard-contract", Summary: "Requirement browser navigation now uses native list and button semantics; the removed synthetic tree no longer provides ArrowUp or ArrowDown roving focus."},
	{ChangeID: "proofkit.cli.adoption-contract-single-value-flags", Summary: "Adoption contract envelope now rejects repeated --mode or --pilot flags and an explicitly empty --pilot value instead of changing or misreporting the selected root-shape variant."},
	{ChangeID: "proofkit.cli.invalid-input-channels", Summary: "Malformed ordinary command input now uses stderr while explicit agent envelopes retain machine-readable invalid-input output."},
	{ChangeID: "proofkit.cli.pilot-admission-single-value-selector", Summary: "Pilot admission now rejects repeated or mixed --pilot and --stack-diverse selectors instead of applying last-write-wins routing; the single --stack-diverse alias remains supported with direct or contract-envelope input."},
	{ChangeID: "proofkit.context.digest-coverage-v2", Summary: "Requirement context, diff, graph, and browser workspace contracts advance to version 2 with expectedDigestCoverage vocabulary."},
	{ChangeID: "proofkit.launcher.python-executable-format-controls", Summary: "Python-module launcher admission now rejects Unicode format characters as well as control characters in the absolute executable path before rendering display commands."},
	{ChangeID: "proofkit.onboarding.generated-command-invocation", Summary: "Proofkit-owned generated display commands and structured argv now use one explicit installed launcher channel across help, preset, bootstrap, project, route, workflow, and coverage surfaces: offline npm exec for npm consumers and the active absolute Python interpreter module route for wheel consumers; direct binary consumers retain caller-owned PATH resolution."},
	{ChangeID: "proofkit.package.installed-governance-routes", Summary: "The npm artifact no longer ships AGENTS.md or CONTRIBUTING.md; governance and contribution routes remain source-checkout-only."},
	{ChangeID: "proofkit.readiness-closeout.character-reference-policy", Summary: "Readiness closeout now decodes one strict semicolon-terminated CommonMark or HTML character reference pass before policy phrase matching; text that previously hid a forbidden phrase through one such reference now fails closed."},
	{ChangeID: "proofkit.typescript.absolute-symlink", Summary: "The TypeScript public API scanner rejects absolute symlink targets and requires confined relative in-root links."},
}

var currentAdditions = []Change{
	{ChangeID: "proofkit.browser.accessibility-state-matrix", Summary: "The requirement browser adds deterministic loading and failure states, native list semantics, bounded reflow, target-size, and contrast witnesses."},
	{ChangeID: "proofkit.cli.contract-closure", Summary: "The authored CLI contract now closes input and output compatibility projections, admits canonical machine-disjoint CLI variant condition models, and generates private runtime metadata."},
	{ChangeID: "proofkit.onboarding.installed-artifact-trace", Summary: "Canonical onboarding uses exact npm pins, copyable offline npm exec routes at every displayed help transition, exact preset commands, and a displayed installed-README first-input continuation."},
	{ChangeID: "proofkit.package.public-reference-closure", Summary: "The npm package excludes contributor-only governance files and closes package-public Markdown and machine references over shipped entries or explicit source-checkout evidence fields."},
	{ChangeID: "proofkit.pilot-admission.all-envelope", Summary: "Pilot admission contract envelopes now admit the existing all mode as one strict two-input envelope and return the ordered first and stack-diverse pilot reports."},
	{ChangeID: "proofkit.requirement-bindings.witness-selectors", Summary: "Requirement binding admission and output now preserve optional witnessSelectors records with exact selector and command fields."},
	{ChangeID: "proofkit.requirement-output.confined-atomic-publication", Summary: "Requirement view output now uses repository-confined same-parent atomic replacement after final destination-parent plus temporary-object identity, mode, and content admission."},
	{ChangeID: "proofkit.security-workflows.permission-separation", Summary: "Security workflow source contracts now keep advisory CodeQL, OSV, and Scorecard analysis read-only, isolate provider publication authority, and require exact Scorecard public-output inputs."},
	{ChangeID: "proofkit.release.artifact-honest-sbom", Summary: "CycloneDX runtime edges are emitted only from content-bound per-binary build information while source module inventory is excluded."},
	{ChangeID: "proofkit.release.existing-release-immutability", Summary: "Existing release verification is read-only and fails closed instead of uploading or backfilling missing assets."},
	{ChangeID: "proofkit.release.workflow-action-pins", Summary: "Every external GitHub Actions use is guarded by a full commit-SHA source oracle."},
}

var currentMigrationSteps = []string{
	"Update adoption-doctor consumers that inspect non-enforced advisory rule results to accept skipped instead of passed in observe mode and outside an enforce-touched selection; these gaps leave the top-level outcome unchanged.",
	"Update adoption-doctor consumers to treat unresolved external prerequisites as blocked with a nonzero exit in every adoption mode; only advisory gaps remain mode-relaxable.",
	"Update requirement-browser keyboard automation to use standard Tab and Shift+Tab traversal plus Enter or Space activation instead of synthetic ArrowUp or ArrowDown tree navigation.",
	"Pass --mode and --pilot at most once to adoption-contract-envelope, provide a non-empty --pilot value, and split repeated-flag invocations into one unambiguous invocation.",
	"Pass at most one of --pilot <value> or --stack-diverse to pilot-admission; omit both to retain the default first pilot, and split repeated or mixed-selector invocations into one unambiguous invocation.",
	"Update context, semantic-diff, graph, and workspace consumers to schemaVersion 2 and replace baselineVerification with expectedDigestCoverage.",
	"Remove Unicode control or format characters from the absolute Python executable path supplied by the Python-module launcher profile.",
	"Update consumers that compare, execute, or persist Proofkit-generated display commands or structured argv to accept channel-specific installed invocation prefixes across help, preset, bootstrap, project, route, workflow, and coverage surfaces; do not rewrite caller-owned bootstrap command text.",
	"Update readiness-closeout consumers and fixtures to treat one strict semicolon-terminated CommonMark or HTML character reference pass as equivalent policy text before phrase matching.",
	"Replace absolute symlinks traversed by the TypeScript public API scanner, including package-manifest ancestors and source paths, with relative in-root symlinks.",
	"Update consumers that read AGENTS.md or CONTRIBUTING.md from the installed npm artifact to use a source checkout or their own admitted governance policy.",
	"Read ordinary malformed-input diagnostics from stderr unless an explicit agent envelope was requested.",
}

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
		"# @research-engineering/agentic-proofkit 0.2.0",
		"",
		"## Breaking Contract Changes",
		"",
	}
	for _, change := range currentBreakingChanges {
		lines = append(lines, currentChangeBullet(change))
	}
	lines = append(lines, "", "## Additions", "")
	for _, change := range currentAdditions {
		lines = append(lines, currentChangeBullet(change))
	}
	lines = append(lines, "", "## Migration", "", "Migration is required:", "")
	for _, step := range currentMigrationSteps {
		lines = append(lines, "- "+step)
	}
	lines = append(lines,
		"",
		"## Platform Requirements",
		"",
		"- Published Darwin package binaries require macOS 12.0 or later on arm64 and x86_64.",
		"",
		"## Known Limitations",
		"",
		"- TSX source parsing remains unsupported.",
		"- Static route coverage does not prove semantic execution coverage.",
		"- The immutable 0.1.160 release is not modified, republished, or backfilled.",
		"",
		"## Install",
		"",
		"Primary npm channel:",
		"",
		"```bash",
		"npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.2.0",
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
		"- Pin npm consumers to the previous admitted version 0.1.160 with `npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.1.160`.",
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
