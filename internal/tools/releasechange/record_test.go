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

func TestCurrentMigrationSeparatesBootstrapDigestFromIdentityCutover(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	record, err := Read(filepath.Join(root, RecordPath))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, "proofkit", "cli-contract.v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Commands []struct {
			Command       string
			InputContract struct {
				ContractID           string
				RootDefinitionDigest string
			}
			OutputContract struct{ ContractID string }
		}
	}
	if err := json.Unmarshal(content, &contract); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range contract.Commands {
		if command.Command != "gradual-adoption-bootstrap" {
			continue
		}
		found = true
		// Independent facts from the published previous release, not this generator.
		if command.InputContract.ContractID != "proofkit.gradual-adoption-bootstrap.input.v2" || command.OutputContract.ContractID != "proofkit.gradual-adoption-bootstrap.output.v2" {
			t.Fatal("current migration premise changed; re-adjudicate the identity transition")
		}
		if command.InputContract.RootDefinitionDigest == "sha256:74d153954dbd80780ded085db0bd25c13498291f7c2c8a000a43edae9d14ecac" {
			t.Fatal("claimed bootstrap input digest change is not present")
		}
	}
	if !found || !strings.Contains(strings.Join(record.Migration.Steps, " "), "Refresh the pinned bootstrap input digest; its semantic v2 identity and wire header are unchanged.") {
		t.Fatal("migration does not distinguish changed digest from unchanged input identity")
	}
}

var currentBreakingChanges = []Change{
	{ChangeID: "proofkit.workflow.input-alternatives", Summary: "Workflow plan blockers replace requiredInputKinds with inputAlternatives: an OR of complete AND bundles of still-missing input kinds. Empty alternatives mean scalar preset choice. New repository repairs preserve bootstrap_witness_plan OR (requirement_bindings AND witness_plan); release repairs preserve external_consumer OR registry_consumer. The same semantics apply to embedded scaffold and aggregate workflow plans."},
	{ChangeID: "proofkit.workflow.materialized-inputs", Summary: "Workflow, scaffold and bootstrap prepared child-input paths refuse the CLI stdin sentinel -. Direct, contract-wrapped and selected aggregate inputs require materialized repository-relative file paths. Top-level --input - and ordinary output filenames remain supported. Bootstrap input semantic ID is v2, scaffold input is v3 and aggregate input is v4. Their wire headers stay unchanged. Bootstrap also rejects equal or file/descendant conflicts among its six planned file paths, including its four payload files, while preserving collected failure reporting. Scaffold retains exact child paths and owner-assigned file roles; prepared commands require the expected materialization source, JSON content and available payload."},
	{ChangeID: "proofkit.workflow.typed-repair-linkage", Summary: "adoption-workflow-plan and the workflow mode of adoption-contract-envelope request preset_choice when a required presetId is missing, instead of missing_context_ref. The question lists supported preset IDs. Those output contracts and scaffold-project-structure output advance to semantic v2 while wire schemaVersion remains 1. Action and what-changed evidence references name the same local context IDs as contextRefs, including caller IDs that resemble generated IDs."},
	{ChangeID: "proofkit.guidance.portable-prepared-commands", Summary: "Generated agentGuidance now stores optional proofkitCommands, a closed map from gradual-adoption, gradual-adoption-guidance or witness-plan to its materialized input path. commands contains caller-authored text only. Public guidance renders generated displays and argv with the actual invocation launcher, including Python interpreters with benign task-like path components. Guidance input/output and bootstrap output use semantic v2; aggregate input uses v4. Wire headers do not change. Derived displays retain the command union, but native-witness actions contain only independently declared caller commands; prepared operations remain planning or inspection routes."},
	{ChangeID: "proofkit.agent-envelope.reference-catalogs", Summary: "Agent-route output semantic v4 preserves structural paths and selectors for observed-report blockers as local contexts. Adoption-doctor output semantic v2 replaces duplicated path selectors with source-role-aware context IDs and top-level action evidenceRefs. Guidance action and ownership references resolve through source-role contexts. Doctor local command and context IDs reserve external source-report identities. Scalar diagnostic text still follows its existing redaction and length policy; bounded omissions never authorize argv with lost context."},
	{ChangeID: "proofkit.selective-evidence.reference-model", Summary: "Selective-gate-evidence output uses semantic contract v2 with unchanged wire headers. The envelope-only reference-model correction preserves report observations; the separate receipt-path admission correction can change joined-input decisions. Envelope command identities are local ranks of complete planned tuples, not caller command IDs. Artifact receipt refs name local path-context IDs containing exact locators; unplanned receipt observations cannot become planned retry commands. Commands and receipts account for their losses separately before filtering and retain those separate counts after downstream bounds."},
	{ChangeID: "proofkit.guidance.unattributed-failure", Summary: "Guidance preserves actual failed and warning rule partitions without inventing a failed rule from reportId. A failed source without rule attribution remains a report-level failure; enforce-touched now fails closed because that failure cannot be proven outside the checked scope. Attributed failures outside touched scope remain nonblocking."},
	{ChangeID: "proofkit.receipt.structural-path-admission", Summary: "Receipt producer, selective evidence and obligation decision adapters preserve exact canonical path references under path-specific privacy, including benign task-like names and significant whitespace. Previously trimmed locator pairs may now fail producer/selective/trust linkage: a padded producer evidenceRef or provenanceRef no longer equals an unpadded peer. Corresponding fields must name the intended filename byte-for-byte. Prose privacy, list ordering and uniqueness, null handling and evidence-class policies remain separate. These reports classify caller facts; they do not prove file existence or native execution."},
	{ChangeID: "proofkit.launcher.single-line-path-admission", Summary: "Python module launcher executable paths reject Unicode line and paragraph separators and malformed UTF-8 at launcher-profile admission, before command parsing. Even --help and --version refuse an invalid profile. Ordinary Unicode, literal path bytes and supported launcher profiles remain unchanged. This changes environment admission, not JSON wire versions."},
}

var currentAdditions = []Change{
	{ChangeID: "proofkit.build.go-security-toolchain", Summary: "Builds use Go 1.27.4, including the net/http security correction for GO-2026-6859. Source toolchain selection and the checksum-bound Linux ARM64 contributor environment select the same patch release. This does not prove exploitability of an earlier product or change the declared platform support."},
	{ChangeID: "proofkit.release.metadata-output-confinement", Summary: "Release manifest, SBOM and PyPI evidence tools use repository-owned atomic file publication for generated metadata. They refuse symlink or special-file destinations, preserve hard-linked peer contents and publish regular files with private mode. This is per-file single-writer protection, not a multi-file crash transaction or protection against hostile concurrent namespace mutation."},
	{ChangeID: "proofkit.agent-envelope.structural-operands", Summary: "Agent envelopes preserve safe structural context references without diagnostic truncation. Workflow and route owners bind prepared paths to exact argv positions; all argv-producing envelope owners preserve their admitted Python launcher. Equal text elsewhere gains no structural role. Unsafe references or argv cause explicit target omission and dependent-reference pruning, not an executable redaction marker. Missing bounded contexts remove dependent argv. If an independently admitted caller command has the same display, its local ID and action references remain as scalar diagnostic text without argv; otherwise the command is omitted. Scalar fallback changes only display and argv on the current admitted command, without restoring pruned sibling references. Secret signatures remain refused inside paths, and scalar text retains its existing protection."},
}

var currentMigrationSteps = []string{
	"Refresh receipt-admission contract digests and reconcile corresponding producer, selective and trust locators byte-for-byte. Leading or trailing whitespace names a literal filename: producer evidenceRef or provenanceRef with a trailing space no longer matches an unpadded peer. Preserve identical significant spaces when they name the intended file; do not blindly trim paths or treat a digest refresh alone as an input repair.",
	"Read inputAlternatives as alternative complete bundles, not a flattened all-required list; an empty alternatives array requests a scalar preset choice. Existing workflow acceptance policy is unchanged.",
	"Materialize workflow, scaffold and bootstrap child inputs and replace any prepared input path equal to - with its repository-relative file path; top-level commands may still read JSON from stdin.",
	"Refresh pinned machine-contract digests and semantic v2 output validators for adoption-workflow-plan, adoption-contract-envelope and scaffold-project-structure without changing wire headers. Handle preset_choice with a supported presetId; handle missing_context_ref with one complete inputAlternatives bundle per input blocker.",
	"Resolve action and what-changed evidenceRefs against contextRefs by exact refId instead of treating them as raw plan inputRefIds. Planned commands remain non-executing caller-owned routes.",
	"Regenerate bootstrap guidance payloads from the authoritative original bootstrap input, preserving exact ownerRoute.specPaths, proofBindingPaths and evidencePaths. Do not migrate from lossy saved guidance alone or only replace its generated commands suffix: older payloads may have stripped significant path whitespace. If the original owner-reviewed paths are unavailable, obtain owner reconciliation before admitting guidance. Generated operations belong in proofkitCommands; keep only caller-authored strings in commands. Do not persist a launcher: saved guidance is rendered under its actual later invocation profile. Refresh guidance input/output, bootstrap output, scaffold input, aggregate input, doctor output and route output validators to their new semantic identities while preserving wire versions. Refresh the pinned bootstrap input digest; its semantic v2 identity and wire header are unchanged.",
	"Refresh the selective-gate-evidence output validator to semantic v2 while keeping its wire header. Resolve receipt_artifact.ref through contextRefs by exact refId; that path context contains the artifact locator. Join command, receipt and action references by local commandId, not by the caller command ID alone. Required receipt classes retain their separate meaning.",
	"Do not interpret reportId as a failed rule when a source report has no failed ruleResults. Supply truthful rule attribution or resolve the report-level failure before enforce-touched can proceed; adding a fabricated touched RuleID is not a repair.",
	"For python_module launchers, configure AGENTIC_PROOFKIT_PYTHON_EXECUTABLE to the intended absolute single-line path with valid UTF-8, no control or format characters, and no Unicode line or paragraph separators. An invalid value refuses before help, version or command parsing. Do not silently rewrite a filesystem name; use a valid executable path or another supported launcher profile.",
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
		"# @research-engineering/agentic-proofkit 0.19.0",
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
		"Migration is required:",
		"",
	)
	for _, step := range currentMigrationSteps {
		lines = append(lines, "- "+step)
	}
	lines = append(lines, "")
	lines = append(lines,
		"## Platform Requirements",
		"",
		"- Published Darwin arm64 binaries are verified on macOS 15 or later by the required macos-15 CI job. Darwin x86_64 binaries are cross-built and packaged without native Intel macOS CI qualification. Both targets declare a macOS 13.0 minimum in Mach-O build metadata; macOS 13 and 14 are not executed or verified.",
		"- Published Linux package binaries and wheels target manylinux 2.17 or later on arm64 and x86_64; Linux wheel installation requires pip 20.3 or later.",
		"- Python wheels require Python 3.11 or later.",
		"- Windows is unsupported.",
		"",
		"## Known Limitations",
		"",
		"- macOS 13 and 14 are binary-compatible by Mach-O metadata only; they are not executed or verified, because no hosted macOS 13 image exists and GitHub retires macos-14 on 2026-11-02.",
		"- Branch authority admits caller-owned branch facts but does not query Git refs or repository protection settings.",
		"- Deployment evidence admission checks declared endpoint facts but does not connect to endpoints, authenticate evidence, or prove rollout readiness.",
		"- The UTC leap-second validator admits IERS-announced positive leap dates through 2016 and fails closed on unannounced future insertions until its source is updated.",
		"- The TypeScript public API scanner supports only the declared non-JSX export subset in .ts, .mts, and .cts files; it is a bounded lexical inventory for compiler-valid sources, not a compiler or type checker, and it does not prove built-module runtime exports.",
		"- Structural schemas describe every public direction, but native admission remains authoritative and may refuse values a schema admits, and no test excludes a published schema constraint that is stricter than native admission. The source-checkout completeness manifest records native-owned constraints as a verified lower bound, and an input constraint class recorded as absent means only that no indicator of that class is reachable from the command route.",
		"- Output schemas may admit values their producers never emit: for example, some publish integer ranges, enumerations, booleans or plain strings where a producer emits a fixed literal, a narrower vocabulary or a narrower grammar, and some admit an optional member, or an absent, null or alternative form of a member, that the producer never emits, notably where an output embeds an input structure; adoption-contract-envelope output variants that admit the same documents are selected by their CLI flags, not by oneOf.",
		"- requirement-source-conversion does not make a flat document a source of record, synchronize representations, migrate proof bindings or references, preserve input formatting or bytes, import flat v1 sources or authenticate a baseline beyond its admitted model digest. --output needs hard-link support and fails closed without it, does not protect publication from adversarial concurrent namespace mutation by the same operating-system user, does not guarantee crash or fsync durability, and may leave parent directories it created after a later failure.",
		"- Protected --output paths cover Git metadata and Proofkit control state only; non-Git version-control metadata, hook files outside .git beyond execute-bit removal, and a working directory inside Git metadata are not covered.",
		"- Proof node digests bind command execution decisions, not native test truth; Proofkit does not execute native tests or compute witness digests for the consumer.",
		"- Remote publication, hosting, authentication, access control, TLS, revocation and freshness of hosted specification views are consumer responsibilities and are not claimed.",
		"",
		"## Install",
		"",
		"Primary npm channel:",
		"",
		"```bash",
		"npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.19.0",
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
		"- First follow the migration and persistent-state compatibility restrictions above; changing a package pin does not roll back repository state.",
		"- Pin npm consumers to the previous admitted version 0.18.0 with `npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.18.0`.",
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
