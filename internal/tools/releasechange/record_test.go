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
	{ChangeID: "proofkit.python-wheel.minimum-python", Summary: "Python wheels declare Requires-Python >=3.11 instead of >=3.9, so installers on Python 3.9 and 3.10 no longer select them. The required installed-wheel minimum smoke runs CPython 3.11.0 with a checksum-pinned pip 26.2.1. CLI contract identities are unchanged."},
	{ChangeID: "proofkit.platform.darwin-verified-support", Summary: "The supported Darwin claim narrows from macOS 13 or later, the 0.16.0 support claim, to verified macOS 15 or later on arm64 and x86_64, which required CI executes on the macos-15 and macos-15-intel runners. macOS 13 and 14 are no longer supported targets: Darwin binaries still declare a macOS 13.0 minimum in their Mach-O build metadata, so they remain binary-compatible by that metadata only and are not executed or verified. CLI contract identities are unchanged."},
	{ChangeID: "proofkit.path-pattern.utf8-literals", Summary: "Repository-relative wildcard path patterns compare UTF-8 literal spans instead of single bytes, so a wildcard pattern whose literal part contains non-ASCII characters now matches the paths it names, which 0.16.0 did not match. Selections and verdicts that use such patterns change, including impact, requirement-impact-input-compose, selective-gate-plan, workspace-changed-package-plan, repo-profile-admission and the pilot-admission impact demonstrations. Contract identities are unchanged."},
	{ChangeID: "proofkit.json-admission.promoted-field-keys", Summary: "Commands that decode their JSON input into typed records refuse an object key that equals a promoted embedded field only after case folding, as they already did for other declared fields, instead of binding the key to that field. This change keeps every contractId."},
	{ChangeID: "proofkit.typescript-public-api.token-boundaries", Summary: "typescript-public-api-surfaces finds export boundaries with a bounded Go token and expression recognizer instead of newline heuristics, so semicolonless compiler-valid sources in the declared lexical profile are inventoried by tokens. Secret-shaped report-visible text is refused, and direct exported generator declarations are stated as excluded. Manifests derived from the previous classification must be regenerated. Contract identities are unchanged."},
	{ChangeID: "proofkit.conformance-profile.surface-environments", Summary: "conformance-profile fails a selected profile when one of its selected surfaces requires an environment class outside the profile's allowed classes, or a non-local class in a local_only profile. Profiles that passed only because surface environments were not checked now fail. Manifest and expected nonClaims are compared element by element instead of as newline-joined text, so arrays that matched only after joining are refused. Contract identities are unchanged."},
	{ChangeID: "proofkit.custom-rule-boundary.catch-all-globs", Summary: "custom-rule-boundary fails a rule whose affected globs include a wildcard-only pattern that matches every repository root name, such as `**/**`, as a repository-wide catch-all; 0.16.0 recognized only `*`, `**` and `**/*`. Contract identities are unchanged."},
	{ChangeID: "proofkit.release-authority.tarball-identity", Summary: "release-authority refuses an input that omits the registryAuthority member, and it fails a tarball_pilot release whose rollback versionPin does not name the package tarball file exactly, either as file: followed by the tarball file name or as a path whose last segment is that file name; 0.16.0 accepted any pin ending in the tarball file name. external-consumer reports both conditions as failures of its embedded release-authority input. This change keeps every contractId; the external-consumer input v2 identity comes from the integrity-encoding change."},
	{ChangeID: "proofkit.consumer-evidence.integrity-encoding", Summary: "external-consumer, registry-consumer and registry-consumer-proof-input-compose admit an integrity value only as canonical standard base64 of exactly 64 SHA-512 bytes, keeping their existing admission-versus-failed-report behavior for that field. Contract identities: proofkit.external-consumer.input.v2, proofkit.registry-consumer.input.v2 and proofkit.registry-consumer-proof-input-compose.input.v2, each with wire schemaVersion 1; output identities are unchanged."},
	{ChangeID: "proofkit.repository-transaction.canonical-path-v3", Summary: "Fresh repository-transaction plans and journals use transaction schema v3 with Unicode 17 canonical caseless path identity, NFD(Fold(NFD(path))), so target paths that collide only under that identity are refused as aliases. Retained v1 and v2 plans and journals keep their historical path rules, identities and recovery; a 0.16.0 binary rejects v3 plans and journals. Recoverable directory ownership is preserved after ambiguous publication failures, and directory admission cleanup failures are reported. Contract identities: proofkit.adopt-materialize-plan.input.v3 and proofkit.adopt-materialize-apply.input.v3 with wire schemaVersion 2, and proofkit.adopt-materialize-plan.output.v2, proofkit.adopt-materialize-apply.output.v2, proofkit.adopt-materialize-recover.output.v2, proofkit.integration-plan.output.v2, proofkit.integration-apply.output.v2 and proofkit.integration-recover.output.v2 with wire schemaVersion 1."},
	{ChangeID: "proofkit.selective-gate-evidence.nul-command-keys", Summary: "selective-gate-evidence reconstructs command keys whose command text contains NUL exactly, so for such commands the reported duplicate keys, the failure and route diagnostic text and the two content-derived envelope hashes change; admission, grouping, states and counts are unchanged. Contract identities are unchanged."},
	{ChangeID: "proofkit.workspace-shard-partition.resource-budgets", Summary: "workspace-shard-partition bounds the shard count before nested node admission and the aggregate expanded work and normalized UTF-8 text before materialization, refusing inputs above those budgets. Contract identities: proofkit.workspace-shard-partition.input.v2 and proofkit.workspace-shard-partition.output.v2, both with wire schemaVersion 1."},
	{ChangeID: "proofkit.test-evidence-inventory.report-text-admission", Summary: "test-evidence-inventory refuses an emitted report whose report-visible text is secret-shaped, admits the derived normalizedInventoryId through the normalized identifier grammar before emission, rejects cross-fragment falsifier identifier collisions and closes discovery action types. Every emitted diagnostic maps to a published classification ID, including incomplete_declared_oracle_metadata and the unclassified_test_inventory_gap fallback. Contract identities are unchanged."},
	{ChangeID: "proofkit.producer-policy-self-proof.exact-tuple-keys", Summary: "producer-policy-self-proof keys producer trust tuples by their exact coordinates instead of a |-joined string, so valid provenance or retention paths containing | no longer cause false self-proof failures or merge distinct tuples in counts. Contract identities are unchanged."},
	{ChangeID: "proofkit.release-classification.derived-text-admission", Summary: "release-authority and readiness-closeout admit recognized row identifiers and statuses taken from Markdown-derived text before insertion, duplicate formatting or report and error interpolation. Inadmissible text is refused with a bounded value-free error and no report; analysis-only body, owner and completion text and ignored rows keep their previous behavior. Contract identities are unchanged."},
	{ChangeID: "proofkit.bootstrap.detached-payload-admission", Summary: "gradual-adoption-bootstrap and its public wrappers adoption-contract-envelope and scaffold-project-structure admit the detached bootstrap payload before it reaches reports or materialization manifests: secret-shaped scalar values, structured credential pairs and malformed object keys are refused, planned profile paths come from the admitted child result instead of a reread of caller input, and optional rollback text is redacted in passed and failed reports. Contract identities: proofkit.gradual-adoption-bootstrap.input.v2 with wire schemaVersion 1, proofkit.adoption-contract-envelope.input.v3 with wire schemaVersion 2 and proofkit.scaffold-project-structure.input.v2 with wire schemaVersion 1; output identities and wire versions are unchanged."},
	{ChangeID: "proofkit.gradual-adoption.rollback-text-redaction", Summary: "gradual-adoption, directly and with --contract-envelope, and adoption-contract-envelope --mode adoption report a rollback owner or versionPin that is secret-shaped, is not a valid Unicode scalar string or contains unsafe scalars as <redacted-diagnostic-value> in passed and failed reports instead of echoing it; states and exit codes are unchanged. Contract identities are unchanged."},
	{ChangeID: "proofkit.bootstrap.witness-plan-routing", Summary: "gradual-adoption-bootstrap, and the bootstrap routes of scaffold-project-structure and adoption-contract-envelope, route the commands and vocabulary payload to witness-plan instead of witness-scheduler-plan, keep caller command prefixes and append only the generated commands the caller did not already list. Generated guidance commands and materialization-manifest content hashes change, and a bootstrap whose caller commands include a generated command now passes instead of failing. This change keeps every contractId; the input identities named by the detached-payload change come from that change."},
	{ChangeID: "proofkit.cli-contract.structural-publication", Summary: "The CLI contract describes every public command direction, 172 directions in 168 definitions, with structural JSON Schema, and all root-shape-only definitions are retired, so rootDefinitionRef values and definition digests change for most directions. Each variant schema references root $defs entries named shared- plus 16 hexadecimal digits: compile each variant as its own document; inlining the shared- entries alone does not make every variant embeddable, because some variants also reference owner-named root $defs, and expect Ajv schemaPath values to differ from the inline form. The shipped contract grows from 985,545 bytes to about 3.5 MB and the installed contract read bound rises from 1 MiB to 8 MiB; readers with a smaller limit must raise it. Native admission remains the semantic authority. The publication itself changes no contractId or schemaVersion; the identities that change in this release are named by their entries."},
	{ChangeID: "proofkit.workspace-registry.root-script-allowlist", Summary: "workspace-registry treats an absent or null admittedRootScriptNames as no allowlist, so root scripts are unrestricted; an explicit [] remains an empty allowlist. In 0.16.0 absent and null were admitted as [], which refused every root script. The other optional script lists keep absent equal to []. Contract identities are unchanged."},
	{ChangeID: "proofkit.migration-plan.blocker-slug", Summary: "migration-plan splits camelCase before lowercasing in blockerReasonSlug, so the retained-owner blockerId suffix changes from -retained-wners to -listed-in-retained-owners. Contract identities are unchanged."},
	{ChangeID: "proofkit.pilot-admission.echoed-text-admission", Summary: "pilot-admission checks the caller text that its report echoes, namely blocking status, stack dimension, cache expectedOutcome and invalidatedInputClass, and the compact serialization of pilotMode, before projection. Secret-shaped text, including credential pairs split across JSON structure in pilotMode, refuses the input with no report and no echo, while ordinary unknown values remain collected failures. Contract identities are unchanged."},
	{ChangeID: "proofkit.scaffold-profile-plan.environment-provenance", Summary: "scaffold-profile-plan records environment-class provenance from the operand that supplied the classes, so classes supplied by the caller are recorded with provenance caller_input instead of stack_preset, in its own output and in the plan that scaffold-project-structure embeds. Contract identities are unchanged."},
	{ChangeID: "proofkit.requirement-spec-tree-view.protected-output", Summary: "requirement-spec-tree-view --output refuses, at argument admission before stdin is read and again at the writer sink, a path with any component equivalent to .git or .agentic-proofkit under canonical caseless matching after removal of HFS+-ignorable code points, a path outside the path-identity domain (invalid UTF-8, more than 1024 bytes or more than 64 components), and a path with a component that becomes . or .. once HFS+-ignorable code points are removed. Replacing an existing file keeps its read and write bits but drops every execute bit; new files stay 0644. Flags, contract shapes and contract identities are unchanged."},
	{ChangeID: "proofkit.requirement-source.transition-and-diff-outputs", Summary: "requirement-source-transition output lists addedRequirementIds, lifecycleChangedRequirementIds and missingRequirementIds beside their counts. requirement-semantic-diff output adds scenario entries (entityKind scenario) under /requirementSources/{sourceId}/scenarios/{scenarioId} with their value shapes, and its non-claim text changes; its input stays schema v3 and output admission accepts only v4. Scenario entries count toward query.maxChanges (default 8192) together with requirement entries, so requirement-semantic-diff, and requirement-browser-server --view workspace with a diffInput, now exit 1 where they previously succeeded when scenario edits push the count past maxChanges. Closed-schema validators of the previous outputs reject the new reports. Contract identities: proofkit.requirement-source-transition.output.v3 with schemaVersion 3 and proofkit.requirement-semantic-diff.output.v4 with schemaVersion 4."},
	{ChangeID: "proofkit.workspace-shard-partition.root-dependencies", Summary: "workspace-shard-partition fails a shard whose root's workspaceDependencies contradict that package's record, where 0.16.0 succeeded. This change keeps every contractId; the v2 shard identities come from the resource-budget change."},
	{ChangeID: "proofkit.pilot-admission.duplicate-custom-rule-ids", Summary: "pilot-admission fails an input with duplicate custom rule IDs wherever they occur, not only when adjacent, so a list such as [a, b, a] that passed now fails. Contract identities are unchanged."},
	{ChangeID: "proofkit.external-consumer.packed-files", Summary: "external-consumer no longer requires AGENTS.md and CONTRIBUTING.md in the npm pack metadata, so a report that failed only for those files now passes. This change keeps every contractId; the external-consumer input v2 identity comes from the integrity-encoding change."},
	{ChangeID: "proofkit.adoption-doctor.exact-envelope-identity", Summary: "adoption-doctor --agent-envelope actions take route and candidate data only from the record their gap names by exact ID: a route or candidate whose ID is another record's ID plus a dot-separated suffix no longer receives that record's commands, selectors, owner questions or facts, and no action carries both route and candidate selectors. Contract identities are unchanged."},
	{ChangeID: "proofkit.proof-linkage.node-digest", Summary: "witness-scheduler-plan output adds a required proofNodeDigests diagnostic: per command, the SHA-256 of that node's execution decision. proof-receipt-admission input requires receipts[].proofNodeDigest and refuses v1 receipts with a migration message. spec-proof-bundle-admission child receipts carry proofNodeDigest, and a receipt links only when both the scheduler plan ID and the node digest of its receipt kind match, so a receipt recorded under one command definition no longer links under another plan that reuses the plan ID; edits to other nodes, nonClaims prose or spelling do not unlink it. Closed-schema validators of the previous versions reject the new records. Contract identities: proofkit.witness-scheduler-plan.output.v2 with schemaVersion 2, proofkit.proof-receipt-admission.input.v2 with schemaVersion 2 and proofkit.spec-proof-bundle-admission.input.v2 with wire schemaVersion 1."},
	{ChangeID: "proofkit.requirement-source-admission.source-paths", Summary: "requirement-source-admission sourcePaths no longer lists overview.md, which stays a reserved owner-written path. Closed-schema validators of the previous version reject the new reports. Contract identity: proofkit.requirement-source-admission.output.v3 with schemaVersion 3."},
	{ChangeID: "proofkit.adopt-materialize.current-source-plan", Summary: "adopt materialize plan and apply accept a sourcePlan only when it is the plan recorded in proofkit/project.v1.json or an observation of the current repository root, and refuse a stale sourcePlan before any write. This change keeps every contractId; the input identities proofkit.adopt-materialize-plan.input.v3 and proofkit.adopt-materialize-apply.input.v3 come from the canonical-path change."},
	{ChangeID: "proofkit.project-navigation.verification-route", Summary: "status and next name native-evidence-guidance as the route for verification_required instead of an empty route, so statusId and packetId values change and records with an empty verification route are refused. Contract identities are unchanged: proofkit.status.output.v1 and proofkit.next.output.v1 with wire schemaVersion 1."},
}

var currentAdditions = []Change{
	{ChangeID: "proofkit.requirement-views.shared-design-and-matrices", Summary: "Static source, specification-tree, proof and coverage HTML views and the local browser workspace share one offline light/dark design-token owner, textual state badges, bounded card/table layouts and keyboard-visible focus. Mobile product identities scroll instead of covering workspace controls; desktop sticky navigation is retained. Separate checkout-only static/workspace accessibility matrices bind exact per-engine cells, controls and reader tasks, including content checks in every narrow dialog state, multiline text-owner contrast, canonical graph-field alternates and complete content-bound input acquisition. Visual references and the README image are refreshed in the admitted reference environment. Static filters preserve every declared role, source kind and overlay value instead of only the first, using one value-set protocol across all four view producers. Rendering-command JSON/Markdown semantics and exit codes stay unchanged; contract nativeSource metadata is refreshed for changed implementations. Passing browser checks do not claim WCAG certification, a human usability study, branded Safari compatibility, arbitrary CSS compositing or hostile-runner authentication."},
	{ChangeID: "proofkit.cli-contract.identity-rule", Summary: "docs/proofkit-contract-map.md states when a direction's contractId changes: when its wire shape changes (the outer schemaVersion, a newly emitted record shape or a newly required input shape), or when the CLI contract or a bound requirement statement gives a record that both releases admit or emit a different meaning. Defect corrections, narrower or wider admission, changed values of behavior the previous text did not specify, human diagnostics and renderings keep the contractId, and the release change record declares them and states whether they are breaking; correcting published text that the previous release's behavior already contradicted is a defect correction. The rule applies from this release: it governs the changes made after its adoption, and contract identities set before it, in earlier releases and by the changes of this release that were merged before its adoption, are retained as set. For example, typescript-public-api-surfaces keeps proofkit.typescript-public-api-surfaces.output.v1 although a change merged before the rule altered the bound REQ-PROOFKIT-PACKAGE-002 statement. Under the rule, the structural schemas of eight inputs describe as optional the members that their previous root shapes listed as required although native admission did not require them: adoption-doctor, adoption-workflow-plan, capability-map-admission, deployment-evidence-admission, pilot-admission, requirement-browser-server, scaffold-profile-plan and workspace-registry. That correction of published text is a defect correction: it keeps their contractIds, changes no command behavior and is not breaking. Likewise, three directions that 0.16.0 already published with structural schemas now state constraints their native owners already enforced or emitted: the agent-envelope variant of proofkit.requirement-coverage-view.output.v4 constrains actionPlan, bounds, costContract, sourceReport, contextRefs, routeQuestions and commands to the producer's bounded structure instead of any array or object, and the query members of proofkit.requirement-context-slice.input.v2 and proofkit.requirement-semantic-diff.input.v3 state the native bounds and defaults maxNodes 1 to 4096 (default 256), maxRequirements 1 to 16384 (default 2048), integer maxDepth 0 to 512 and maxChanges 1 to 8192 (default 8192). These corrections keep their contractIds, change no command behavior and are not breaking. In the same way, proofkit.requirement-context-compose.output.v4, which 0.16.0 also published with a structural schema, now requires changedPaths, ownerIds and requirementIds, members its producer always emits, in a non-null projections.proofBinding.selection; this correction keeps its contractId, changes no command behavior and is not breaking. The first structural schemas of proofkit.registry-consumer-proof-input-compose.output.v1 and proofkit.requirement-coverage-input-compose.output.v3 likewise describe members their producers always emit: a materialized registryConsumerInput requires input.releaseAuthorityInput, described by the release-authority input structure of schemaVersion 3 with channel registry_release, rolloutClaim false, a non-null registryAuthority and a present non-null package publishConfigRegistry, and a non-null requirementProofBinding.selection requires changedPaths, ownerIds and requirementIds."},
	{ChangeID: "proofkit.requirement-source.conversion", Summary: "Add requirement-source-conversion, with contracts proofkit.requirement-source-conversion.input.v1 and proofkit.requirement-source-conversion.output.v1. --to flat exports an admitted grouped v2 source as a complete derived flat document (kind proofkit.requirement-source-flat, schemaVersion 1) with profile and group ownership coordinates and a basisDigest; --to grouped requires --baseline and imports value edits only when the baseline's canonical digest equals basisDigest and identities, membership, profile assignment, field ownership and statement stems are unchanged. The retired flat v1 source is refused with legacy_source_unsupported. A refused decoded input or baseline document carries one closed code and a JSON pointer or structural path into the caller's document and no caller value, while argument, path, file-system and JSON decoding refusals use the shared CLI diagnostics. --output publishes a new file only, never replacing an existing name, and refuses the same paths as requirement-spec-tree-view --output."},
	{ChangeID: "proofkit.transaction.residue-maintenance", Summary: "Add read-only transaction inspect-residue and observation-bound transaction quarantine-residue, with contracts proofkit.transaction-inspect-residue.output.v1 and proofkit.transaction-quarantine-residue.output.v1, for unidentified repository-transaction preparation residue: unknown bytes and historical receipts are preserved, known journals and ambiguous filesystem state are refused, and quarantine publishes with one same-filesystem directory rename. Fresh transaction preparation is read back in a private sibling directory and published atomically, and SIGINT or SIGTERM during transaction plan, apply, recover and residue routes cancels through the existing transaction cancellation path."},
	{ChangeID: "proofkit.diagnostics.positions-and-fault-lists", Summary: "JSON syntax rejections of --input, and of requirement-source-conversion --baseline, end with the line, column and byte offset of the rejected byte, and a nesting-depth rejection points at the first value past the limit, except for self-check, external-consumer, registry-consumer, registry-consumer-proof-input-compose, producer-policy-self-proof, migration-parity-admission, spec-overview-claims, release-authority and readiness-closeout, whose frozen stderr is preserved. Requirement source admission reports up to eight independent faults of a rejected source on one line and counts the rest as N more; a line longer than 512 Unicode scalar values keeps its first 512 and ends with `...<truncated-diagnostic>`, so later descriptions and the N more count can be cut off. A single fault keeps its previous error identity and text, except that duplicate-identity paths now name the repeated entry. Unsupported-field diagnostics report the command-owned context and a count instead of unknown caller key names. Exit codes are unchanged. Positions, nesting-depth pointers and fault lists appear only on stderr, but the unsupported-field count also replaces caller key names where a command carries that diagnostic in stdout: the actionPlan rationale and blocked-precondition description of --agent-envelope refusal envelopes, and the ruleResults messages of failed reports that collect unknown nested members, such as a gradual-adoption rollback record."},
	{ChangeID: "proofkit.requirement-views.scenario-nesting-and-rendering", Summary: "Source views nest a scenario under its requirement when it links to exactly one requirement and otherwise render it once in a Shared Scenarios section that every linked requirement lists by ID, as an in-page link in HTML; the workspace shows owner-declared deferral records and a deferred count, and static HTML views hide a card group whose cards a search has hidden. Compact requirement-coverage-view Markdown and HTML show declared witness routes, and Markdown code spans follow CommonMark padding while payloads containing <, > or & render as escaped text. Browser views route graph edges around unrelated cards in separated corridors, preserve search text and disclosure state, answer a terminal handoff with HTTP 410 and a stale one with 409, respect font preferences, provide skip navigation and admit only the embedded script hash in the static-page CSP. Static HTML views name section anchors by the base64url encoding of the section key instead of a lower-cased slug with a hash suffix, and search attributes keep the original case, so fragment links into earlier exports or hosted copies must be regenerated. requirement-browser-server JSON reports replace the non-claim that browser servers do not scan repository state with one stating that explicit project preparation inspects repository state and serving the admitted snapshot does not rescan it."},
	{ChangeID: "proofkit.agent-guidance.cli-continuations", Summary: "CLI help adds input guides for witness-scheduler-plan, requirement-context-slice and requirement-semantic-diff, a total next-action continuation in status and next help, the scenario body shape in requirement-source-admission help, the agent bootstrap route in root help, adoption modes in adopt plan help, enumerations and identifier grammars derived from native constants, and a witness-migration recipe that never relabels receipts. A missing context catalog file is named by kind and path with the step that creates it, native-evidence-guidance help routes materialized projects to semantic diff, slice and currentness, and first adoption instructions name the carrier-correct guidance. The public-contract stanza of command help pages names structural JSON Schemas instead of root JSON shapes among the surfaces that proofkit/cli-contract.v2.json owns."},
	{ChangeID: "proofkit.native-admission.correctness-fixes", Summary: "Static non-directory roots and FIFO candidates are refused instead of blocking, including requirement-context-compose and repository-inventory roots and requirement-context catalog sources; repository planning runs under cooperative shared read leases; on Darwin, when the kernel no longer reports a child process after a foreign reap, process cleanup reports lost ownership with child cleanup unverified and sends no signal, instead of signalling a process group whose ID may have been reused."},
	{ChangeID: "proofkit.workflow.agent-trajectory-witness", Summary: "REQ-PROOFKIT-WORKFLOW-020 adds a whole agent trajectory witness that drives a fixture repository through the public CLI only, from install bootstrap to current proof, with a route ledger, negative controls and an edge-local invalidation matrix; the installed npm carrier and the host wheel's module and console-script carriers execute it, while the CPython 3.11.0 floor smoke keeps its finite carrier cases. It proves CLI admission, linkage, currentness and route closure, not native test truth."},
	{ChangeID: "proofkit.release-evidence.hardening", Summary: "Release tooling admits npm absence only from bounded strict E404 JSON, rejects failed or incomplete Go build-info metadata instead of emitting an empty SBOM dependency inventory, bounds the root-package verifier to 128 MiB compressed, 512 MiB expanded and 4096 entries, rejects duplicate wheel filenames in PyPI registry evidence, reads each wheel once in the Python package verifier and installs a private copy of the admitted bytes in its local consumer check, requires installed-CLI help on stdout with empty stderr, and passes the workflow credential to curl on stdin instead of argv. The release guide defines the provider-bound default signing policy; independently signed annotated tags remain optional. Source-checkout coverage tooling rejects partial, aborted, expired or failed native test observations."},
	{ChangeID: "proofkit.browser.consumer-hosting-boundary", Summary: "Remote reading of specification views is documented as a consumer hosting concern: publish the existing --format html exports from a consumer-owned static host behind a consumer-owned access gateway, use rendered-artifact-freshness for hosted copies and secret-scan as an advisory byte check. requirement-browser-server and view keep serving only literal loopback hosts."},
	{ChangeID: "proofkit.browser.spec-tree-node-navigation", Summary: "Static specification-tree hierarchy links target the named node's own escaped card anchor rather than its kind group. Navigation reveals that node through the existing Cards and hidden-target filter reset, while Node kinds links retain their group targets. Other renderers without an explicit internal card anchor keep their prior markup; JSON, Markdown, caller node IDs and CLI contract identities are unchanged."},
	{ChangeID: "proofkit.toolchain.runtime-and-build-updates", Summary: "Release binaries are built with Go 1.27.3 instead of 1.27.1, whose crypto/x509 fix removes the reachable standard-library vulnerability GO-2026-6809 that govulncheck reports for 1.27.2, and bundle golang.org/x/mod 0.42.0, golang.org/x/net 0.61.0, golang.org/x/sys 0.49.0, golang.org/x/text 0.43.0 and github.com/mattn/go-isatty 0.0.24; no runtime module was added or removed. LICENSE now also names the Go standard library among the bundled BSD-3-Clause components; its reproduced Go Authors notice already covered it. The development and CI toolchain moves to npm 12.2.0, Node 26.11.1, CPython 3.15.0, Playwright 1.63.0 and axe-core 4.14.0 with pinned GitHub Actions, and the Python launcher's POSIX path imports neither subprocess nor typing."},
}

var currentMigrationSteps = []string{
	"Run the Python wheel on Python 3.11 or later; Python 3.9 and 3.10 environments must keep 0.16.0 or upgrade the interpreter.",
	"Refresh every copy of proofkit/cli-contract.v2.json and every pinned contractId that this record names, compile each variant schema as its own document; before embedding a variant elsewhere, inline its shared- $defs and also carry its remaining root $defs, which the pilot-admission, adoption-contract-envelope pilot and deployment-evidence-admission variants reference, and raise contract read limits to at least 8 MiB.",
	"Record proofNodeDigest from the witness-scheduler-plan v2 report in every proof receipt and re-admit receipts; v1 receipts are refused.",
	"Rerun adopt plan after any repository root change so adopt materialize plan and apply receive a current sourcePlan. Do not downgrade to 0.16.0 while a v3 transaction plan or journal is in flight; retained v1 and v2 transactions remain recoverable.",
	"Replace inputs that the narrowed admissions refuse: non-canonical SHA-512 integrity values, workspace shard inputs above the budgets, secret-shaped bootstrap, pilot or report-visible text, JSON keys that match a promoted typed field only after case folding, release-authority inputs without a registryAuthority member, and requirement-spec-tree-view --output paths that the protected-output rule refuses.",
	"Correct inputs whose reports now fail: conformance profiles that select surfaces requiring unallowed environments, custom-rule-boundary rules with a wildcard-only catch-all glob such as `**/**`, tarball_pilot rollback pins that do not name the package tarball file exactly, workspace shard roots whose dependencies contradict their package records, and pilot inputs with duplicate custom rule IDs.",
	"Set an explicit admittedRootScriptNames list in workspace-registry inputs that relied on an absent or null value to refuse root scripts.",
	"Update consumers keyed on changed values: the migration-plan retained-owner blockerId suffix, status and next statusId or packetId values, overview.md in requirement-source-admission sourcePaths, scaffold-profile-plan environment-class provenance, adoption-doctor envelope actions, bootstrap guidance commands and materialization content hashes, selective-gate-evidence envelope hashes for NUL-bearing command keys, selections by wildcard path patterns with non-ASCII literals, external-consumer, producer-policy-self-proof and bootstrap reports that now pass, unsupported-field diagnostic text in agent envelopes and failed-report messages, which now counts unknown keys instead of naming them, gradual-adoption and adoption-contract-envelope adoption-mode rollback owner and versionPin values that are now redacted, fragment links into exported or hosted HTML views, whose anchor IDs changed, and the previous transition and semantic-diff output versions.",
	"Raise query.maxChanges, up to 8192, or narrow requirementIds when scenario entries push a requirement-semantic-diff, or the diffInput of requirement-browser-server --view workspace, past its bound.",
	"Rerun the repository-owned native evidence and installed CLI smoke after updating the package pin; derived reports do not themselves prove native witness quality.",
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
		"# @research-engineering/agentic-proofkit 0.17.0",
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
		"- Published Darwin package binaries support macOS 15 or later on arm64 and x86_64, verified by the required macos-15 (arm64) and macos-15-intel (x86_64) CI jobs; they declare a macOS 13.0 minimum in their Mach-O build metadata, but macOS 13 and 14 are not supported targets.",
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
		"npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.17.0",
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
		"- Pin npm consumers to the previous admitted version 0.16.0 with `npm install --save-dev --save-exact @research-engineering/agentic-proofkit@0.16.0`.",
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
