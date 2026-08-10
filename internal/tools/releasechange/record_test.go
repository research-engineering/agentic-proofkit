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

var currentBreakingChanges = []Change{
	{ChangeID: "proofkit.authoring.lossless-reference-projection", Summary: "Requirement authoring plan output advances from schema v1 to v2, requires the complete admitted authoringRefs projection, and composes current and candidate requirement records only from canonical requirement-source owner projections."},
	{ChangeID: "proofkit.coverage.declaration-only-vocabulary", Summary: "Caller-authored test routes, falsifier, oracle-signal, and supersession metadata now use declaration-only classes and mapped states; mapping no longer emits covered, verified, semantic-execution, oracle-review, or dominance-proof vocabulary, and related classifications and coverage metric fields are renamed."},
	{ChangeID: "proofkit.coverage.output-parent-reference-closure", Summary: "Requirement coverage output advances from schema v1 to v2, retains complete test projections on requirement, owner-invariant, command, and unmapped-inventory surfaces, and re-admits the exact root and row shapes, row metadata, command-owned non-claims, canonical row order, coverage-basis owner scope and inventory commitments, inventory warnings and failures, compact scenario route unions, command state, parent references, retained unknown-reference diagnostics, and declared dead-zone diagnostics."},
	{ChangeID: "proofkit.migration.caller-declared-parity", Summary: "Migration parity input statuses, diagnostics, and summaries now identify caller-declared claims, preserve each record's admitted non-claims, and no longer imply that Proofkit computed native parity."},
	{ChangeID: "proofkit.proof.requirement-state-vocabulary-closure", Summary: "Requirement proof states now use one closed vocabulary across structured bindings, compact contracts, and re-admitted coverage output; arbitrary rule IDs and assurance-sounding states are rejected."},
}

var currentAdditions = []Change{
	{ChangeID: "proofkit.coverage.classification-contract-closure", Summary: "The requirement coverage output contract now declares every reachable diagnostic classification, including proof_route_candidate_only and the fail-closed unclassified_gap fallback."},
	{ChangeID: "proofkit.release.coverage-metric-reachability", Summary: "Release closeout now uses overflow-safe exact coverage-producer relations for inventory entries, route classes, proof-route candidates, the complete command inventory, and commands missing declaration-only routes, and binds both command projections to the actual CLI contract inventory from the same source snapshot."},
}

var currentMigrationSteps = []string{
	"Replace test inventory evidenceClass values semantic_falsifier, contract_admission, and property_or_fuzz with declared_semantic_falsifier_route, declared_contract_admission_route, and declared_property_or_fuzz_route.",
	"Replace test inventory summary fields semanticFalsifierCount and weakOracleFailureCount with declaredSemanticFalsifierRouteCount and incompleteDeclaredOracleMetadataFailureCount; replace diagnostics missing_semantic_anchor and weak_or_empty_oracle with missing_declared_route_anchor and incomplete_declared_oracle_metadata; and replace rule IDs test_inventory.semantic_entries_have_anchors and test_inventory.strong_oracles with test_inventory.declared_routes_have_anchors and test_inventory.declared_oracle_metadata.",
	"Within test-evidence-inventory-discovery-draft output, replace summary field weakOracleWarningCount with missingDeclaredAssertionSignalWarningCount, warning and action type weak_or_empty_oracle with missing_declared_assertion_signal, candidate quality finding suffix weak-oracle with missing-declared-assertion-signal, class empty_oracle with missing_edge, and suffix missing-semantic-anchor with missing-declared-route-anchor.",
	"Within agent-route inspect_coverage stopConditions, replace weak-oracle language with missing declared assertion-signal language; treat the condition as routing guidance rather than an oracle-quality classification.",
	"Replace falsifier field supersessionProofRef with supersessionDeclarationRef, diagnostic reasons missing_dominance_proof and unowned_dominance_proof with missing_supersession_declaration and unowned_supersession_declaration, and rule ID test_inventory.no_duplicate_falsifiers with test_inventory.declared_falsifier_supersession_consistency.",
	"Replace requirement coverage states covered_by_semantic_falsifier, covered_by_property_or_fuzz, covered_by_contract_admission, covered_by_governance_invariant_nonproduct, command_semantic_falsifier_present, and missing_command_semantic_falsifier with mapped_to_declared_semantic_falsifier_route, mapped_to_declared_property_or_fuzz_route, mapped_to_declared_contract_admission_route, mapped_to_declared_governance_or_release_route_nonproduct, command_declared_semantic_falsifier_route_present, and missing_command_declared_semantic_falsifier_route; replace classification missing_semantic_test with missing_declared_test_route.",
	"Consume proofkit.requirement-coverage-view.output.v2 with schemaVersion 2; preserve every admitted test-entry field, retain entries without selected parents in the required unmappedTests root array, consume the required coverageBasis owner scope, full-repository out-of-scope source identities, and retained-inventory digest, and consume compact scenarios with required verifyCommands and witnessSelectors arrays. Output re-admission now requires exact root and row shapes, exact row metadata, command-owned non-claims, canonical row order, owner-scoped compact scenario identities, exact missing-inventory warnings, and rejects owner-scope, inventory-failure, proof-route union, parent-reference, repeated-test, command-state, retained unknown-reference, mutable-fragment, dead-zone, and row-derived or scope-derived diagnostic drift; coverageBasis does not authenticate source inputs or producer identity.",
	"Use only explicitly_deferred, not_bound, or witness_backed for requirement proofState values; compact binding rows contain positive and falsification witnesses and therefore require witness_backed proof_contract_state. Arbitrary rule IDs and assurance-sounding states are no longer admitted.",
	"Replace coverage metric fields commandWithoutSemanticFalsifierRouteCount, commandsWithoutSemanticFalsifierRoute, semanticInventoryEntryCount, unknownSemanticCommandRefCount, and unknownSemanticCommandRefs with commandWithoutDeclaredSemanticFalsifierRouteCount, commandsWithoutDeclaredSemanticFalsifierRoute, declaredSemanticFalsifierRouteEntryCount, unknownDeclaredSemanticRouteCommandRefCount, and unknownDeclaredSemanticRouteCommandRefs; stop consuming removed semanticRouteCount, consume commandRoutes.commands and cliContract.commands, and require both inventories to equal the actual CLI contract command inventory from the same source snapshot.",
	"Replace migration parity statuses matched, mismatched, not_comparable, and not_run with caller_declared_match, caller_declared_mismatch, caller_declared_not_comparable, and caller_declared_not_run.",
	"Replace migration parity output fields admittedParityEvidenceCount, matchedCount, mismatchedCount, notComparableCount, notRunCount, and admittedParityEvidenceRefs with admittedParityClaimCount, callerDeclaredMatchCount, callerDeclaredMismatchCount, callerDeclaredNotComparableCount, callerDeclaredNotRunCount, and admittedParityClaimRefs; consume each migrationParity record's required nonClaims projection.",
	"Consume proofkit.requirement-authoring-plan.output.v2 with schemaVersion 2, preserve its required authoringRefs array, treat nonAuthoritativeAdmissionPreview.requirementSourcePreview as a canonical requirement-source projection in which absent optional fields are omitted, and handle candidateRequirement owner-admission failures as input errors before composition.",
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
		"# @research-engineering/agentic-proofkit 0.3.0",
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
	lines = append(lines,
		"",
		"## Migration",
		"",
		"Migration is required:",
		"",
	)
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
		"- Execution-backed semantic command evidence remains open under COVERAGE-01; declared routes prove mapping only.",
		"- Requirement-source v2 representation and any textual DSL remain unselected until the typed-model and codec replacement gates pass.",
		"- TSX source parsing remains unsupported.",
		"",
		"## Install",
		"",
		"Primary npm channel:",
		"",
		"```bash",
		"npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.3.0",
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
		"- Pin npm consumers to the previous admitted version 0.2.1 with `npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.2.1`.",
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
