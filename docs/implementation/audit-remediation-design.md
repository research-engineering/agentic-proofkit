# Audit Remediation Design

Status: C-124 implementation candidate; C-01 through C-124
corrections are present; provider validation is invalidated by the C-124
semantic delta; unaffected prior validations remain historical evidence.

Owner: `proofkit`.

Target baseline: `3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64`.

Review history:

- cycle 1: `REVISE` by proof/security, contract/release, and UX/accessibility
  reviewers; resolved by explicit `0.2.0` migration, versioned downstream
  envelopes, deterministic race barriers, single-owner generated CLI
  projections, strict entity grammar, exact proof routing, read-only release
  allowlists, and state-specific browser oracles;
- cycle 2: `REVISE`; resolved by executable selector alignment, symmetric
  closed input/output ABI trees, an explicit change-record v2 path, split proof
  ownership, exact generator checks, relative/absolute symlink compatibility,
  a legacy-term boundary, and a canonical whole existing-release block;
- cycle 3: two `APPROVE`, one `REVISE`; resolved by aligning the output-writer
  selector and making generated CLI-contract freshness a mandatory
  `npm run check` step;
- cycle 4: unanimous `APPROVE`; no P0-P2 design contradiction remains.
- cycle 5: unanimous `APPROVE` after correcting the generated stack-preset
  topology; the single authored owner remains unchanged.
- implementation cycle 1: three independent `APPROVE` verdicts after
  corrections C-01 through C-20, exact proof-selector closure, dead-helper
  cleanup, and a green full worktree gate; no confirmed P0-P2 finding remains.
- committed-candidate cycle 1: two `REVISE` verdicts found a job-level
  `continue-on-error` expression bypass and three untested per-view loading
  states; C-21 and C-22 plus primary-owner projections closed both findings,
  and the focused correction review returned three `APPROVE` verdicts.
- committed-candidate cycle 2: two `APPROVE` verdicts and one `REVISE` exposed
  ignored inherited and step-level execution controls plus partial
  `continue-on-error` evaluation in the generic workflow oracle; C-23 closed
  workflow/job/step inheritance, exact environment entries, nullable scalar
  key presence, required leaf jobs, and the aggregate, after which the focused
  correction review returned three `APPROVE` verdicts.
- exact-commit cycle 1: proof/security and UX/architecture returned `APPROVE`;
  contract/release returned `REVISE` because the `0.2.0` machine change record
  omitted the intentional `adoption-doctor` blocked-state and exit-code
  migration; C-24 closed the machine record, migration, rendered-note
  falsifier, and proof binding, after which focused correction review returned
  three `APPROVE` verdicts.
- exact-commit cycle 2: proof/security and UX/architecture returned `APPROVE`;
  contract/release returned `REVISE` because the record and top-level-only
  semantic test omitted the intentional non-enforced advisory rule transition
  from `passed` to `skipped`; the first focused review exposed the same
  undeclared transition outside the touched selection in `enforce-touched`.
  C-25 declares the complete migration, strengthens both adjacent-rule oracles,
  and binds them; the second focused correction review returned three
  `APPROVE` verdicts.
- provider cycle 1: the exact candidate passed locally but two provider browser
  attempts failed at the same 30-second Firefox cap on different tests while
  Chromium and WebKit passed; the run lifecycle then deleted the promised
  retained traces and the success-only upload skipped them. C-26 preserves
  attempt-scoped failure diagnostics without creating or admitting passed
  proof so the moving Firefox stall can be diagnosed rather than guessed; the
  focused correction review returned three `APPROVE` verdicts after routing
  both selectors exclusively to QUALITY-022.
- provider cycle 2: the first post-C-26 exact local gate reproduced the moving
  Firefox timeout in two different state-matrix rows; both retained traces end
  at the first `AxeBuilder.analyze()` evaluate of the 1,287,127-character
  default axe source. A first minified-source candidate passed two full runs
  but was falsified by a controlled repeated-audit run: minified and default
  sources both stall under continuous trace screenshots, while the default
  source completes 13 two-audit cycles without tracing and with action, DOM,
  network, and source tracing when screenshots are disabled. A third full run
  then falsified screenshot removal alone by stalling at the same large
  builder evaluate. C-27 combines both necessary controls: pinned axe
  initialization through the browser-context script channel, constant builder
  loaders, and screenshot-free traces with one bounded best-effort post-failure
  screenshot; the combination completed 30 consecutive two-audit Firefox
  cycles.
- provider correction review: proof and UX returned `APPROVE`; contract
  returned `CONDITIONAL APPROVE` after C-27 also closed the exact development
  dependency allowlist, owner-to-binding non-claims, and constant-loader
  reachability mutant. Two consecutive frozen-byte 72-test browser proofs and
  direct proof verification passed without an intervening browser-input edit,
  discharging the sole condition before final committed-object revalidation.
- final committed-object review: proof/security found that C-13's pinned-parent
  publication could still follow a parent moved outside the repository after
  the last route check. C-28 keeps temporary-file creation and cleanup on the
  pinned parent but binds the irreversible publication to full source and
  destination routes through the repository root; the exact pre-publication
  falsifier covers outside-root and in-root replacements.
- final correction review: all three reviewers rejected C-28 because
  `os.Root.Rename` resolves its source and destination routes separately and a
  replacement can substitute the discoverable temporary basename. C-29 moves
  the temporary object to the repository root, admits its identity and the
  destination parent after the exact barrier, publishes through the repository
  root, and narrows the owner contract to the strongest cross-platform claim
  the implementation can prove. Adversarial same-user namespace mutation after
  final identity admission is explicit rather than hidden behind another
  check-then-use implication.
- C-29 correction review: the root-level candidate was rejected because it
  regressed writable-child and nested-filesystem outputs, object identity did
  not admit content, its compatible public contract was missing from the
  release record, and final PR-body validation did not machine-check all
  mandatory closeout facts. C-30 restores same-parent staging/publication under
  the explicit concurrency boundary and admits identity, exact mode, and
  digest; C-31
  projects the compatible addition into release notes; C-32 adds a canonical
  closeout record validated in both reviewed and server-side body bytes.
- C-30 through C-32 correction review found that permission-only mode
  comparison discarded setuid, setgid, and sticky bits, while C-32 validated
  mutable artifact paths and later reread them for projection. C-30 now admits
  the complete file mode exactly; C-33 copies each local evidence object once
  into a private snapshot and validates and projects those same bytes.
- C-33 correction review found that snapshot byte identity does not admit
  fields absent from its predicate. C-34 removes unvalidated artifact digests
  from closeout so every projected local value is explicitly admitted.
- C-34 self-review found that streaming `jq -e` accepts a forged first JSON
  document when a valid second document determines the final exit status. C-35
  slurps each snapshot, requires exactly one document, and admits the exact
  browser-project inventory.
- The independent maximum-reasoning audit reproduced dynamically false
  conditions on a required CI test step and the release candidate job that the
  literal `false`/`0` deny-list admitted. C-36 closes both workflow inventories
  with exact absent-or-owner condition projections.
- The C-36 correction review replaced the macOS smoke with an Ubuntu no-op
  while retaining a successful job ID and reproduced vacuous bound negative
  selectors on an invalid owner workflow. C-37 binds exact CI check names,
  runners, and the platform-smoke command, rejects reusable-job substitution,
  and requires positive owner admission inside the bound selectors.
- The C-37 correction review inserted a semantic shadow step before the exact
  platform command, passed a mixed-type runner list through lossy
  normalization, demonstrated that QUALITY-013 still omitted its positive CI
  and release package-gate owners, and found a malformed closeout `jq` filter.
  C-38 closes the ordered platform step inventory and package-script owner,
  requires exact scalar runners, binds both positive package-gate owners, and
  restores the executable singleton filter.
- The C-38 correction review moved the semantic shadow into the repository-local
  setup action and added an otherwise-empty `run` key beside `uses`; both
  survived path/value-only comparison. C-39 admits the exact local-action bytes
  and makes `run`, `uses`, and `with` key presence part of the ordered step
  inventory.
- The C-39 correction review returned three independent `APPROVE` verdicts
  after reproducing the nested local-action shadow and null, empty, whitespace,
  and dual execution-key mutants; no P0-P2 finding remains.
- A subsequent independent maximum-reasoning audit approved the exact C-39
  commit at 97/100 with no P0-P2 finding, but confirmed two P3 hardening gaps:
  the closed selector inventory omitted the QUALITY-011 and QUALITY-013
  anti-vacuity scenarios, and README command extraction used whitespace
  splitting that changed safe quoted Bash words. C-40 reopens exact-object
  validation for both findings.
- C-40 focused review reproduced an owner-transfer mutant: changing only a
  critical scenario's `requirementId` preserved its exact selectors and passed
  the scenario-keyed inventory. C-41 keys every protected inventory by the
  exact requirement/scenario pair and independently falsifies owner transfer.
- The same focused cycle reproduced complete selector deletion through the
  generic empty-selector early return and NUL admission through the bounded
  lexer, then found a plan threshold weaker than the final completion
  criterion. C-42 moves exact-set admission before the empty path, rejects NUL,
  and requires every final reviewer to report no unresolved confirmed finding.
- Continued boundary review found Unicode trimming changed literal Bash argv
  and could erase invalid JSON NBSP bytes, escaped NUL bypassed the top-level
  lexer check, and interactive Bash history expansion changed an admitted
  double-quoted `!`. C-43 preserves exact non-IFS and JSON fence bytes, closes
  escaped NUL, and rejects unescaped double-quoted history expansion.
- C-43 focused review then showed that symmetric space/tab trimming consumed
  a valid trailing escaped delimiter before lexing. C-44 trims only leading
  unescaped Bash delimiters and preserves trailing escaped space and tab.
- The first complete package-level run after C-44 showed that the pre-existing
  missing-function mutant now stopped earlier at the new exact-set boundary.
  C-45 moves that mutant to an unprotected binding so exact-set and generic
  function-existence failures remain independently reachable.
- Continued review reproduced quoted and unquoted even-backslash history
  literals rejected after pair collapse, one remaining P0-P2-only preparation
  threshold, and repeated generic I/O during pure inventory mutants. C-46
  consumes complete backslash runs before `!` with Bash-equivalent quoted and
  unquoted projection; C-47 aligns the last threshold; C-48 separates pure
  inventory admission from generic AST and `go list` validation.
- Adversarial complexity review then showed that the first C-46 helper rescanned
  a non-history backslash suffix after every collapsed pair, producing
  quadratic work on a package-bounded README line. C-49 consumes every
  backslash run once and dispatches its terminal byte under the same bounded
  quoted or unquoted rules.
- The next complete package-level run showed that isolated generic
  executability fixtures now stopped at the intentionally earlier global
  inventory phase. C-50 exposes the two existing validation phases as separate
  local functions: production composes both, while each fixture calls the
  owner of the error it falsifies.
- Frozen C50 proof-routing review found that the generic missing-function and
  invalid-signature falsifiers were not selectors of the QUALITY-010
  executability scenario. C-51 binds both and protects that complete
  four-selector scenario with the same exact owner/set inventory.
- Frozen C51 review reproduced the same selective-route gap for the
  QUALITY-013 permission-floor falsifier. A closed-world pass over the typed
  package-gate oracle found ten owner-relevant tests outside its seven-selector
  binding. C-52 binds the complete seventeen-test owner surface and protects it
  with exact set equality.
- The frozen C52 correction review returned three independent `APPROVE`
  verdicts with no confirmed P0-P3 finding. The reviewers independently
  checked exact QUALITY-010, QUALITY-011, and QUALITY-013 inventories, bounded
  README lexer semantics and linearity, JSON byte preservation, owner
  separation, documentation parity, and absence of business-logic drift.
- The next exact-commit review confirmed two omitted boundary cases. The
  intentional readiness-closeout character-reference verdict change was absent
  from the closed release record, and the selector validator rejected an
  executable Go test with an unnamed `*testing.T` parameter. C-53 closes the
  release declaration, migration, rendered-note witness, selector grammar, and
  exact QUALITY-010 and QUALITY-024 inventories.
- The repeated exact-commit review confirmed five further P2 gaps: entity
  decoding preceded Markdown pipe parsing, the reachable specifications
  no-match state was absent from the browser matrix, the removed synthetic
  Arrow-key contract lacked migration disclosure, and the compatible pilot-all
  envelope plus optional witness-selector I/O were absent from the release
  record. C-54 closes all five at their existing owners.
- The next exact-commit UX review reproduced a discontinuous npm onboarding
  route: root help displayed a bare executable while the installed consumer
  admitted only local offline npm resolution, and the witness ignored the
  displayed command. C-55 projects the copyable npm route and executes argv
  parsed from that exact stdout while rejecting the bare-route mutant.
- C-55 correction review then reproduced Unicode-whitespace normalization:
  leading or trailing NBSP around the displayed route passed the witness even
  though Bash does not treat that byte as an IFS delimiter. C-56 removes only
  the authored leading space/tab indentation and preserves both NBSP mutants.
- The next exact-commit review proved that the installed trace still
  hard-coded every transition after root help, that the release record
  omitted the onboarding addition and misclassified removed installed
  governance paths, that absolute-symlink migration omitted manifest
  ancestors, and that merge-critical workflow jobs admitted semantic shadow
  steps. C-57 through C-59 close the displayed onboarding chain, exact release
  declarations, migration scope, and complete ordered step inventories.
- The same review falsified A-04: the 3,025-line workflow oracle mixed five
  independent requirement owners and the concentration had already hidden a
  shadow-step gap. C-60 records a closed size ledger, splits peripheral owners
  and neutral support, preserves the inseparable QUALITY-011/013 selector
  cluster, and protects every moved binding by exact selector inventories and
  stale-path mutants.
- The C-60 correction review confirmed six residual proof gaps: the closed
  step projection omitted `id` and `timeout-minutes`; exact selectors did not
  preserve their witness path; candidate staging could omit the five new
  untracked owners; one ledger byte count was stale; the extracted scanner
  selectors were not requirement-bound; and exact-tarball onboarding still
  admitted bare invocation copy for ordinary leaves. C-61 through C-66 close
  these gaps with presence-aware step fields, exact witness paths, closed
  staging and size inventories, scanner owner bindings, and execution of every
  displayed leaf-help route and installed invocation.
- Candidate-command rehearsal then showed that cleanup-bearing temporary-file
  staging was not executable under the repository's destructive-action guard.
  C-67 replaces temporary files and cleanup with in-memory exact inventories
  and stdin pathspec admission while preserving every equality predicate.
- The next focused proof review removed the workflow permission floor and
  added a surplus provider write scope without tripping the scanner selector;
  its contract review also placed the installed block before Usage and used a
  command-token prefix collision without tripping the onboarding verifier.
  C-68 and C-69 close exact permission sets plus explicit inheritance and exact
  Usage order, token boundary, and installed-byte equality.
- The C-69 review then deleted its new falsifier while all bound QUALITY-019
  selectors remained green. C-70 adds the selector to the owner requirement,
  exact selector set, exact witness path, and deletion/surplus/owner/relocation
  mutation inventory.
- The final C-61 through C-70 focused correction review returned three
  independent `APPROVE` verdicts with no confirmed P0-P3 finding on one
  unchanged frozen snapshot. Exact committed-object validation remains the
  final publication precondition.
- Final provider-closeout rehearsal then proved that its browser snapshot
  predicate still required the superseded 24-tests-per-project matrix while
  the exact committed gate produced 25 per project. C-71 aligns the executable
  closeout predicate with the current 75-test owner result before repeating
  committed-object validation.
- The repeated exact-commit architecture review then reproduced overlapping
  adoption output conditions: `--mode bootstrap` also described the agent and
  materialization routes while the generator compared only condition text.
  C-72 introduces one optional bounded machine condition model, closes its
  finite normalized option space, binds concrete argv to exact conditions and
  variants, and rejects repeated single-value selectors instead of retaining
  last-write-wins ambiguity.
- C-72 decomposition then falsified the candidate-staging closure: moving the
  pure condition algorithm out of the generator I/O owner created a sixth
  decomposition-owner file, while P12.2 still admitted only the five earlier
  workflow owners. C-73 closes that six-file owner subset and keeps exact
  staged-path equality plus empty unstaged and untracked remainders.
- Direct argv falsification then showed that `--pilot ""` set the raw flag but
  normalized to the same empty native value as omission, so the ABI condition
  incorrectly reported `--pilot=absent` and selected the default first pilot.
  C-74 rejects the empty valued selector, binds its exact diagnostic, and
  includes the intentional rejection in requirements and migration guidance.
- Staging rehearsal then proved that a baseline-relative added-path inventory
  is not the current untracked inventory after an earlier candidate commit:
  five workflow files already exist in `HEAD`, while only the condition-model
  owner remains untracked in the C-72 through C-74 amend. C-75 proves the
  one-file current set separately and requires the six-file decomposition
  subset to survive staging.
- Condition-closure review then showed that the 80-state test duplicated the
  native mode and pilot literals. C-76 derives immutable test domains from the
  same internal native lists that build `ValidateOptions` admission maps, while
  retaining the exact current 80-combination and twelve-valid-state predicates.
- Claim review then showed that generic condition syntax does not imply generic
  native-option closure: only the adoption output owner has the required
  finite-domain and argv witnesses. C-77 admits that exact definition as the
  only current condition-model owner and requires any later owner to add its
  own native-closure proof before generator admission.
- Baseline-diff rehearsal then showed that the six decomposition owners are
  only a subset of all added files: the candidate already contains seventeen
  added files relative to the reviewed baseline and the condition owner makes
  eighteen. C-78 closes the complete baseline-relative added-path inventory
  independently from the current untracked set and owner subset.
- Independent C-78 review then found two proof escapes and one stale
  architecture fact: the guidance mode/scope failure emitted JSON without an
  exact output condition and variant assertion; an alias command or direction
  could reuse the admitted definition; and the C-73 prose retained superseded
  exact line counts. C-79 through C-81 bind the JSON error route, close the
  command/direction/definition triple, and remove volatile inline measurements.
- C-79 correction review then removed both route coordinates from only the
  guidance failure while the shared guidance condition kept the global count
  green. C-82 makes JSON assertion and both route coordinates a biconditional
  per case, eliminating that false-green path.
- C-82 review then removed the JSON assertion together with both coordinates;
  the fixture biconditional remained true while runtime still emitted unchecked
  JSON. C-83 binds the expectation to observed non-empty JSON stdout and closes
  the exact fourteen-case JSON inventory.
- Final committed-object decomposition review then found that
  `condition_model.go` duplicated the generator package's existing generic
  sorted-map-key helper. C-84 reuses the same-package owner and removes the
  redundant algorithm and import.
- Final committed-object proof review then found that the critical Mach-O
  byte-compatibility scenario selected only a README projection test. C-85
  binds the exact negative, boundary-positive, truncated-parser, and legacy
  parser witnesses and protects their selector/path inventory against
  deletion, surplus, transfer, and relocation.
- The repeated exact-object review then found the same semantic-reachability
  escape in the Python wheel-platform and one-shot browser cleanup scenarios:
  both selected tests passed while their named operations had zero coverage.
  C-86 binds the wheel owner/projection/verifier tests and the three cleanup
  concurrency tests, then closes both selector and path inventories.
- Exhaustive review of all 105 candidate-added selector rows then found one
  remaining semantic false route: the mutable-release-facts scenario selected
  only package reference closure. C-87 binds the existing ten-case stale-fact
  falsifier and closes its exact selector/path inventory.
- The independent Sol/max audit then found that exact permission maps on named
  scanner jobs did not close the workflow job inventory: an unclassified job
  with write authority remained admissible. C-88 requires each scanner
  workflow's jobs to equal the advisory/provider union and preserves a surplus
  write-job falsifier.
- Terminal UX review then executed the exact first command emitted by a stack
  preset in the installed npm consumer and received `command not found`.
  Initial C-89 review rejected a global npm renderer because the same binary is
  shipped in the Python wheel. C-89 therefore admits one explicit immutable
  invocation profile at the launcher boundary, renders npm, Python-module, and
  direct-path continuations separately, and proves both installed channels.
- Terminal contract review then replaced the pilot aggregate output with an
  object while its declared output witness still passed, and observed that
  self-check's output witness asserted empty stdout on an input error. Review
  also identified the root-distinct adoption aggregate and the app-owned pilot
  union constructor. C-90 closes all three selector tuples, native-source
  ownership, requirement bindings, and substitution falsifiers.
- Frozen implementation review then found that the Python executable could
  carry report-visible secret-like or control content, and that help,
  structured agent-route/workflow/coverage argv, project workflow identity, and
  the installed wheel route chain remained outside the C-89 closed inventory.
  C-91 closes launcher value admission; C-92 closes every owned display/argv
  route while proving caller-owned argv preservation and direct-argv execution.
- Provider exact-object review then exposed two test-oracle portability gaps.
  Linux could immediately reuse the inode of a removed temporary file, so the
  writer correctly rejected the substitution as a mode change while the
  identity mutant demanded a platform-dependent diagnostic. Separately, the
  retained Firefox trace proved a fully rendered graph before one page-realm
  bulk evaluation consumed the remaining 29 seconds without returning. C-93
  substitutes a pre-existing live file whose identity must differ while both
  files coexist; C-94 replaces the bulk evaluation with retryable count plus
  indexed-attribute assertions that are logically equivalent to exact ordered
  array equality, without retries, timeout expansion, test splitting, or
  assertion weakening. Independent architecture and UX review approved both
  repair classes.
- Final measurement review found that the last static-analysis cleanup changed
  `agentroute.go` after the threshold ledger was frozen. C-95 refreshes the
  complete final ledger after every correction instead of treating a prior
  exact snapshot as current evidence.
- The first exact-object Sol/max audit then falsified input-grammar closure:
  typed workflow decoding silently discarded job-level execution controls, and
  source hygiene omitted the shipped tracked CSS language. C-96 admits every
  tracked workflow through closed raw workflow/job/step mappings with two
  exact release-environment exceptions before typed semantics. C-97 derives
  browser-asset extension mutants from the tracked owner inventory and adds
  CSS without changing identifier-boundary matching.
- Dependency pre-merge validation then reproduced the Firefox 30-second stall
  twice on the same immutable branch while the failing test moved between the
  two selection scenarios. C-98 removes their repeated page-realm range
  synthesis: collapse uses Playwright `selectText` and click actions, while the
  Unicode case performs one locator-scoped exact-range operation with
  independently computed strict bounds, without retries, a larger timeout, or
  production hooks.
- The next exact-object Sol/max audit returned `REVISE` with four P2 findings
  and no P0, P1, or P3 finding. It proved that publication commands conflated
  the historical audit baseline with the current integration base, the
  closeout predicate retained a stale scenario count, launcher admission
  accepted bidi format controls, and `pilot-admission` exposed one undeclared
  alias route plus last-write-wins selectors. C-99 through C-102 separate Git
  identities, bind the exact final coverage count, close Unicode `Cc` and `Cf`
  admission, and make every accepted pilot route declared and unambiguous.
- C-99 through C-102 review cycle 1 returned one `APPROVE` and two `REVISE`
  verdicts; it required an exhaustive `Cc`/`Cf` oracle, two-phase Git/PR
  identity, applicable closeout completion criteria, singleton-parent proof,
  durable QUALITY-004 ownership, and compatibility declarations. Cycle 2
  returned one `APPROVE` and two `REVISE` verdicts because the migration text
  incorrectly required exactly one pilot selector and hid the valid omitted
  default-first route. Cycle 3 returned three independent `APPROVE` verdicts
  on one frozen diff with no confirmed P1-P3 finding.
- The mandatory final exact-object Sol/max audit of
  `e55bfc6e5641aed906d9a3c02e56a431bc0ca4b5` returned `REVISE` with one P2
  and no P0, P1, or P3 finding. The current release-record witness admitted
  only a manually selected subset of the machine record, so semantic deletion
  or a structurally valid surplus could remain green after regeneration.
  C-103 closes the complete breaking, addition, migration, and rendered-note
  inventories under the existing QUALITY-024 owner.
- C-103 review cycle 1 returned one `APPROVE` and two `REVISE` verdicts;
  exact machine ID/order mutants and note-projection closure were added.
  Cycle 2 returned two `APPROVE` verdicts and one `REVISE` because
  section-local equality still admitted appended surplus, duplicate, or second
  owned sections. Cycle 3 returned three independent `APPROVE` verdicts on one
  frozen diff after complete ordered machine equality and one independently
  authored byte-exact full-note projection closed every confirmed escape; no
  confirmed P1-P3 finding remains.
- Publication rehearsal after the first C-103 terminal approval reproduced a
  zsh refspec-expansion failure in the plan itself: `"$final_sha:refs/..."`
  treats `:r` as a parameter modifier instead of a literal separator. C-104
  braces the variable before the adjacent colon and rejects every remaining
  unbraced variable-colon occurrence in the tracked plan.
- C-104 focused review returned two `APPROVE` verdicts and one `REVISE`: the
  exact braced refspec was correct, but the plan retained the lease preceding
  the already successful first publication. C-105 preserves that value as
  history and binds the next correction publication to the exact current
  remote head.
- The mandatory new post-C-105 exact-object Sol/max audit returned `REVISE`
  with one P2 and no other confirmed P0-P3 finding. The baseline-relative
  added-file inventory still contained 18 paths even though three later
  owner-test files increased the final set to 21. C-106 refreshed the 21-path
  set at the C-106 freeze and made that epoch's two-file amend staging
  sequence executable.
- The mandatory new post-C-106 exact-object Sol/max audit of
  `4a828d1be9e3f9cab0e93d4ef5991fef0d2cd475` returned `REVISE` with two P2,
  one P3, and no other confirmed P0-P3 finding. C-107 closes the public
  Scorecard action's exact output-input set and adds the surviving surplus
  mutant. C-108 restores the exact 30-requirement P10 invariant delta. C-109
  completes C-81 by removing all four volatile line-count qualifiers from the
  reverse-decomposition rationale.
- C-107 through C-109 focused review returned one `APPROVE` and two `REVISE`
  verdicts. C-110 rejects a string that the generic expression normalizer
  previously converted into boolean truth and binds that exact substitution
  mutant. C-111 time-indexes the two-file staging predicate to the C-106 epoch
  so it cannot contradict the then-current C-107 through C-109 three-file
  correction set.
- C-110 through C-111 focused review returned two `APPROVE` and one `REVISE`
  verdict. The remaining design-history sentence still described C-106 as the
  active freeze without a historical qualifier. C-111 now time-indexes that
  sentence to the same C-106 freeze without changing either inventory.
- C-111 focused review cycle 3 returned two `APPROVE` and one `REVISE`.
  C-112 closes the full Scorecard-action subset after a second differently
  named action with surplus authority-bearing input survived the named-step
  selector.
- C-112 focused review cycle 4 returned three `REVISE` verdicts. C-113 aligns
  Scorecard repository identity with GitHub's case-insensitive owner/repository
  semantics after a mixed-case second action survived the lowercase-prefix
  classifier.
- C-113 focused review cycle 5 returned three `REVISE` verdicts. C-114 makes
  repository admission explicitly ASCII before case folding after Unicode
  simple-fold long-s aliases exceeded the provider identity domain.
- The first exact-provider attempt for
  `81e2c7d570e1982ffe4a9f1e5a43150438017b41` passed source and macOS quality
  but failed `quality / browser runtime` with 74 of 75 tests passing, which
  caused `quality / required aggregate` to fail. The retained Firefox trace
  proves that the rendered state and heading assertions completed before an
  auxiliary `page.evaluate` version probe remained outstanding until the
  unchanged 30-second test deadline; axe analysis had not started. Earlier
  retained attempts timed out at distinct page-realm and locator operations,
  evidence consistent with but not proof of one moving engine-level stall.
  The exact Firefox/Juggler cause remains unverified. C-115 therefore treats
  the provider failure as a falsification of C-27's bounded first-attempt
  claim and makes removal of source-proven avoidable wrapper exposure the first
  controlled correction hypothesis.
- C-115 design review cycles 1 through 5 returned `REVISE` while narrowing
  causal claims, closing the combined default-rule and target-size falsifier,
  naming every owner, preserving exact branding, adding frame/version/result
  and operation-topology mutants, defining the empirical overturn condition,
  and closing run-options plus test-engine identity. Cycle 6 returned three
  independent `APPROVE` verdicts with no confirmed design gap.
- C-115 implementation review separated attempted from completed context and
  page states, closed pending, failed, concurrent, and zero-retry mutants,
  replaced an unsound source scanner with one fresh-page fixture, and removed
  one redundant state assertion. Three independent reviewers approved exact
  diff SHA-256 `4bf170fc8f5ea50619bc414badd88cd0997198e0419e2739357760c0e577d33f`
  with no P0-P3 finding.
- The first immutable C-115 falsifier epoch used input digest
  `sha256:8099d7060ba9033c1e8317b6032a8776ef21c879b371edda9a460732f66281f4`.
  Firefox iterations 1 through 14 each passed 25 of 25 tests. Iteration 15
  passed 24 of 25 and stopped at the unchanged 30-second deadline in
  `Locator.boundingBox()` after the locator had resolved a visible graph.
  C-116 preserves the graph contract while removing that raw geometry call,
  which had no narrower per-call bound and consumed the remaining test budget,
  and two later raw operations that the failed attempt did not reach.
- C-116 design review cycle 1 returned three `REVISE` verdicts. The correction
  narrows the theorem from effective raster usability to the local SVG and
  owned-viewport contract, derives expected identities from the admitted HTTP
  response rather than circular DOM metadata, closes descendant visibility,
  alpha, and degenerate-edge mutants, removes a redundant production CSS
  floor, defines exact CSS properties, separates review-byte freshness from
  runtime-input freshness, and makes toolchain A/B explicitly conditional.
- C-116 design review cycle 2 returned one `APPROVE` and two `REVISE`
  verdicts. The correction arms exact request/response observers before UI
  activation and proves the single rendered response, names the complete data
  and geometry owner chain, closes hidden rectangle/text paint, and excludes
  cross-engine-incompatible line visibility assertions.
- C-116 design review cycle 3 returned two `REVISE` verdicts while the third
  review was invalidated by a concurrent correction. Effective-alpha mutants
  preserved opaque computed colors while setting node fill or stroke opacity
  to zero, and an overlapping-node mutant preserved every identity, label,
  paint, and edge predicate. The node contract now admits each opacity factor,
  exact geometry, direct-child order, and local transform independently.
- C-116 design review cycle 4 returned three `REVISE` verdicts. CSS geometry,
  individual-transform, motion-path, text-offset, and empty-label mutants
  preserved exact SVG attributes or the singular `transform` property. The
  contract now closes used rectangle geometry, the complete current transform
  family, absent text-offset attributes, exact visible-label projection, and
  positive font size.
- C-116 design review cycle 5 returned one `APPROVE` and two `REVISE`
  verdicts. Hidden-overflow, individual zoom, content-visibility, and zero-dash
  mutants survived the otherwise closed local predicates. The owned viewport
  now preserves exact scrolling, and every admitted local graph element closes
  zoom, content visibility, local effects, and edge dash paint.
- C-116 design review cycle 6 returned `REVISE` after text-anchor, baseline,
  and font-adjustment mutants changed or erased visible glyph layout while
  retaining content, coordinates, font size, and paint. Generic visibility
  and viewport-intersection alternatives were independently falsified across
  all pinned engines. The bounded text contract now admits the exact current
  layout serializations directly.
- C-116 design review cycle 7 returned three `REVISE` verdicts. Alignment
  baseline and hidden-`tspan` mutants survived; several retained text
  conjunctions lacked independent falsifiers; `text-indent` was empirically
  inert; and the generic-matcher counterexample used an overbroad quantifier.
  The correction closes each effective text property independently, removes
  the inert property, requires direct text-only labels, and states the exact
  existential cross-engine failure.
- C-116 design review cycle 8 returned one `APPROVE` and two `REVISE`
  verdicts. Text-security substitution and SMIL animation preserved base
  content or geometry while changing glyphs or animated SVG values. The
  correction closes text security, root and leaf element topology, and
  animated-geometry surplus with isolated mutants.
- C-116 design review cycle 9 returned three `REVISE` verdicts. Fixture-equal
  cached rendering survived response/DOM equality; independent retrying CSS
  assertions admitted a phase-split animation with no jointly valid state;
  and three new childlessness predicates lacked independent falsifiers. The
  correction adds a response intervention sentinel, closes local CSS animation
  and transition activity, names the temporal non-claim, and gives every leaf
  topology predicate its own mutant.
- C-116 design review cycle 10 returned three `REVISE` verdicts. A positive
  zero-duration transition delay, an animation on an ancestor that changed
  inherited graph paint, and an external SMIL target all survived local
  element checks; the exact group and root ordering predicates also lacked
  independent reorder falsifiers. The correction closes the complete owned
  ancestor chain, both transition dimensions, local SVG addressability, and
  both order predicates with isolated mutants.
- C-116 design review cycle 11 returned one `APPROVE` and two `REVISE`
  verdicts. Hidden graph tables preserved response/text equality while
  removing the only visible authority, currentness, verification, and state
  fields. Conversely, `xml:id` did not create an addressable SVG target in any
  pinned engine and had no independent counterexample. The correction adds a
  bounded local visibility and temporal contract for both graph tables and
  removes that unjustified conjunct while retaining the reproduced plain-ID
  external-SMIL falsifier.
- C-116 design review cycle 12 returned three `REVISE` verdicts. Transparent
  text color, local filter/clip/mask effects, and Firefox external SMIL through
  a table-cell ID preserved the first table contract while erasing trust-state
  glyphs; static captions and headers and both transition dimensions also
  lacked independent falsifiers. The correction closes local table paint and
  addressability, exact static semantics, and every retained table conjunct
  with separate mutants.
- C-116 design review cycle 13 returned two `REVISE` verdicts while the third
  review was invalidated by the correction. Table font adjustment, zoom,
  content visibility, and several order/count predicates lacked independent
  mutants. More importantly, Firefox SMIL could target the existing
  `#workspace-content` ancestor, proving that local ID bans were the wrong
  boundary. The correction removes those bans, excludes declarative SVG
  animation at the document boundary, and makes local topology falsifiers
  inert and independent.
- C-116 design review cycle 14 returned three independent `APPROVE` verdicts
  on git blob `598dfb89b7567df269b41491b15c7fe527248b3d` with no confirmed
  P0-P3 finding. C-116 is approved for planning; no runtime success follows
  until implementation and the fresh immutable 30-process epoch pass.
- The C-116 implementation candidate at
  `0c67de58b0b9837d714e417f64758a76368f3efa` passed the complete immutable
  replacement epoch. All 30 separate Firefox processes passed exactly 25 of
  25 tests with one worker, zero retries, zero skipped, unexpected, or flaky
  tests, and `exited` watchdog status. Every record used input digest
  `sha256:ec3d79218e20831e726bf45e171b1d0276fdf22a04790a13f1e72e6df8dbee0d`
  and historical test-ID digest
  `sha256:f7b80cd6ea950cad6693a7b11020f746581d6eba4f2b7314700e4161448a554c`;
  the 30-record JSONL SHA-256 is
  `e38754615878a012358d2fe75fd4af031107450a7ec2bc6d70db6bc89c543051`.
  Both subsequent full browser proofs passed 75 of 75, the composite browser
  gate passed 21 static tests and 75 runtime tests, and the final full
  `npm run check` passed. All five outer watchdog records were `exited` with
  leader exit code zero and empty signal and group-probe error sets.
- Provider run `30297044766`, attempt 1, reported pull-request head
  `26e44b79a90b41494f9971b84f66e4b737bc9baa` and checked out synthetic merge
  commit `da27a7a1b3e17a901a47621a31ca8ae3432f9901`. Both objects have tree
  `ae3b0b16efc3d185425a91488b1f902eee630c2f`, so the executed bytes equal the
  head bytes even though the commit identities differ. That run falsified the
  implication from the local epoch to provider liveness. Firefox timed out
  after entering Playwright 1.61.1 `evalOnSelectorAll` for the focus negative
  control. Retained artifact `8665124396` has GitHub digest
  `sha256:db3179664637de3b053bde5efce6b0e2e8b44e3d96c5b7bf07032a270b2b46b5`;
  its report SHA-256 is
  `3498361d22679cc87c6560c055750bb3c782bb1d8761b28e5287499e0486a4d2`,
  its trace ZIP SHA-256 is
  `b4f5560b9e0e240dab35e631d9b848a6f18817b02ca6c03c2254a32ba989328d`,
  and the inner `0-trace.trace` SHA-256 is
  `86a30f0e21dc41a9961d26506f262e18a1cfd8832cca24d9c70a1504864dc0a4`.
  The trace contains the call's `before` record and no `after` record.
  Chromium and WebKit passed, as did source, macOS smoke, CodeQL, OSV, and
  semantic diff. This is not evidence of a product or focus-contract failure.
  It activates the already approved isolated Playwright 1.61.1-versus-1.62
  A/B overturn condition. Bot PR 80 run `30250528617`, against base
  `3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64`, checked out merge
  `3367101eaf48fd664f1c1975181c15d047d7fac2`; browser artifact `8646807702`
  has GitHub digest
  `sha256:57de6b30f9a3a82ca33b4ad18f9f36c2b47dbc55dac301c4f11669040b7a4ae1`.
  Its 1.62 provider browser job passed only the older six tests per engine and
  therefore did not exercise the current focus negative control; its source
  job failed package verification because it changed only the manifest and
  lock. The admitted A/B therefore changes exactly the manifest, lock,
  package-verifier pin, and verifier fixture together; it does not change
  runtime tests, retries, timeouts, production code, or business logic.
- The first Playwright 1.62 post-epoch full gate exposed C-117 under a retained
  `TMPDIR` whose group was `wheel`, outside the caller's supplementary groups.
  The `mode-setgid` test mutation treated successful `chmod` return as proof
  that the bit materialized. Darwin instead returned success while clearing
  setgid, so the writer correctly observed unchanged mode `0644` and published.
  The same subtest passed 100 of 100 under the default `staff`-group temp root
  and failed 100 of 100 under the retained `wheel`-group root. This confirms a
  test-oracle precondition defect, not a production-writer defect.
- Final exact-object review found that C-119 introduced terminal HTTP-response
  and exact accessible-name guards without guard-specific falsifiers. Removing
  either guard left the 81-test matrix green. C-120 adds owner-local open and
  reload 503 counterexamples plus a substring-preserving heading-name drift;
  all three engines must reject those mutants before provider validation
  repeats.
- Provider attempt 1 for exact source commit
  `dcc824b31f858ab8fea5be683e5d81f12f039279` falsified C-119's remaining
  `page.goto(..., {waitUntil: "commit"})` dependency. Firefox received the
  main document with status 200, loaded every local asset and API response, and
  rendered the initialized workspace, but the runner never resolved the
  navigation call. C-121 replaces provider-falsified lifecycle waiting with a
  pre-armed exact-URL navigation-response observation, exact trigger token,
  successful-response admission, and the existing exact semantic heading
  assertion. A same-URL non-navigation 503 decoy makes the navigation
  classifier executable rather than structural.
- Final Sol/max review of exact candidate
  `c2315fdf28be95eab08089008773d7dd234d9c96` found two false-green
  candidates. C-122 reconciles P12.2's correction inventory so its
  declaration and executable post-`c2315fd` three-path set have one value;
  the preceding four-path staging set is historical. C-123 adds a
  negative truth table for every raw base-URL admission clause; source presence
  alone did not prove that the runtime witness depended on those clauses.
- The same review then reproduced C-124: deleting exact trigger-token
  admission and pending-waiter abort/consumption left static 22/22 and runtime
  93/93 green. One deterministic injected pending waiter now distinguishes the
  exact token, signal abort, and explicit rejection-consumption paths without
  adding a browser lifecycle or production seam.

## Purpose

This document defines the smallest owner-valid repair for every finding that
survived independent reproduction and adjudication of the July 2026
architecture, proof, security, release, and usability audits.

It is temporary change authority, not a new product specification. Existing
requirements, machine contracts, code owners, and executable falsifiers remain
the durable owners.

## Scope

In scope:

- false-positive proof states and false-green local oracles;
- filesystem confinement and immutable-read boundaries;
- public CLI input, output, exit, diagnostic, and discovery contracts;
- release SBOM semantics and pre-1.0 consumer compatibility;
- package and self-hosting negative-test closure;
- install-to-first-success onboarding;
- browser error handling, accessibility, responsive layout, and contrast;
- package-public documentation closure;
- exact requirement, binding, witness, and non-claim updates needed by these
  repairs.

Out of scope:

- provider-side publication, branch protection, Trusted Publisher, registry
  identity, or production rollout;
- new commands, remote services, SDKs, retry systems, or policy engines;
- general rewrites of command packages;
- decomposition based only on line count;
- full GitHub Actions interpretation;
- full CommonMark parsing;
- a claim of complete WCAG 2.2 AA conformance.

## Authority

The repair is bounded by:

1. `AGENTS.md`, especially evidence-class separation, immutable admission,
   package boundaries, and closeout;
2. `BACKLOG.md` for active, blocked, and deferred claims;
3. `NON_CLAIMS.md` and `ADOPTION.md`;
4. `docs/release-process.md` and `docs/proofkit-contract-map.md`;
5. the five `docs/specs/*/requirements.v1.json` sources;
6. `proofkit/cli-contract.v2.json`,
   `proofkit/command-families.v1.json`,
   `proofkit/requirement-bindings.json`, and `proofkit/witness-plan.json`;
7. command-local admission code and native tests for their exact behavior.

When these surfaces conflict, the repair fails closed and updates the durable
owner rather than preserving a convenient implementation.

## Retirement

This document retires only after all accepted rows below are represented by
durable requirements or contracts plus executable falsifiers, the final
committed implementation passes `npm run check` and exact-object review, the
validated branch and an open, unmerged pull request identify that same object
against the same reviewed base commit, and the following closed source-owned
provider-check inventory is present for that head/base pair in the workflow
run for pull request `#78`, provider attempt `1`, with `success` conclusions:

- `ci` / `quality / source`;
- `ci` / `quality / platform smoke / macos-15`;
- `ci` / `quality / browser runtime`;
- `ci` / `quality / required aggregate`.

Every other check run and legacy status context observed for the object in two
consecutive final provider passes must have an accurately reported terminal
disposition. Retrospective routing must then be complete, and the final
pull-request body must record those facts and residual non-claims. A final
bounded readback must verify the remote head and base SHAs and pull-request
identity before, between, and after two reads of provider conclusions from
literal-SHA workflow-run, job, check-run, and commit-status endpoints, and must
compare the two canonical provider projections byte for byte. The reviewed
body must contain exactly one record of that projection's SHA-256 and exactly
one sentinel-delimited canonical JSON projection equal to the observed bytes;
any prose is non-authoritative. The server-side body must equal the reviewed
local body byte for byte. The inventory is owned by the exact required job set
in
`.github/workflows/ci.yml` and its typed workflow oracle; it is a closeout
requirement, not a claim about provider-side branch-protection settings,
an atomic provider snapshot across endpoints, concurrent PR-identity history
between bounded observations, or provider immutability after the final
response. Until every condition holds, this document remains temporary
closeout authority. After retirement it must not be cited as runtime, release,
or merge authority.

## Formal quality model

Let:

- `A(x)` mean caller input `x` was structurally admitted;
- `S(x)` mean a semantic report was produced from admitted input;
- `B(x)` mean an unresolved blocked precondition is present;
- `C(p, h)` mean path `p` was opened through confined root handle `h`;
- `I(f0, f1)` mean two observations refer to the same opened file identity;
- `G(e)` mean a workflow guard is one exact owner-admitted expression;
- `R(j)` mean required leaf job `j` completed with `success`;
- `Reach(s0, sn, w)` mean witness trace `w` executes every transition from
  installed state `s0` to first-success state `sn` with the same artifact;
- `X(v)` mean UI state `v` has an executable accessibility and reflow oracle.

The repaired system must satisfy:

```text
I-01  B(x) -> report.state = blocked and exit != 0
I-02a not A(x) and not envelope_mode -> exit = 1 and stdout = empty and stderr != empty
I-02b not A(x) and envelope_mode -> exit = 1 and stdout = one invalid-input envelope and stderr = empty
I-03  A(x) and S(x) -> stdout = one admitted JSON value and stderr = empty
I-04  read(p) -> exists h,f: C(p,h) and bytes = read(f) and I(f_pre,f_post)
I-05  publish(p) -> every parent, temporary file, and rename is rooted at one h
I-06  workflow_guard_accepted(e) <-> G(e)
I-07  aggregate_success <-> for all required jobs j: R(j)
I-08  one_commonmark_entity_decode(a) = b -> phrase_class(a) = phrase_class(b)
I-09  exists w: Reach(local_install, first_valid_input, w)
I-10  stable_browser_state(v) -> X(v)
I-11  release_dependency_edge(a,d) -> d is required by artifact a
I-12  breaking_pre_1_0_release -> exact_pin_policy and non-patch version change
I-13  blocking_conjunction(f1..fn) -> every fi has an independent falsifier
I-14  public_contract_change -> canonical compatibility projection changes
```

No row is complete merely because a positive test passes. Each row requires a
negative case that accepts the current wrong implementation and rejects the
repair's forbidden alternative.

## Adjudicated finding ledger

### Accepted findings

| ID | Severity | Finding | Durable owner | Required outcome |
|---|---:|---|---|---|
| R-01 | P1 | `adoption-doctor` reports blocked prerequisites as passed outside enforcing modes | `REQ-PROOFKIT-RETIRE-008` | Blocked evidence is always blocked; ordinary advisory gaps retain non-enforcing behavior |
| R-02 | P1 | CycloneDX root dependency edges include tool/build modules not required by shipped artifacts | `REQ-PROOFKIT-QUALITY-002` | Artifact dependency edges contain only evidenced runtime requirements; retained inventory is explicitly excluded; digest and build information come from one immutable byte snapshot read through an identity-checked pinned descriptor |
| R-03 | P1 | TypeScript public API scanner validates a pathname and later reopens it | `REQ-PROOFKIT-PACKAGE-002` | A confined repository root opens a pinned package-root handle before its manifest and sources; pinned file handles own identity, bytes, and cache keys |
| R-04 | P1 | Repository-relative output checks parents by pathname before independent create and rename operations | `REQ-PROOFKIT-SPEC-009` | Parent creation remains repository-root-confined; temporary write, cleanup, and atomic publication use one pinned destination parent after final parent-route plus temporary-object identity, exact mode, and content admission |
| R-05 | P1 | Workflow guard oracles accept expected substrings inside semantically false expressions or drop execution-control fields that alter an exact command | `REQ-PROOFKIT-QUALITY-013` | Trust-significant expressions use exact whole-expression allowlists and merge-critical jobs and steps admit only the modeled safe execution controls |
| R-06 | P1 | CI aggregate oracle accepts expected shell tests inside dead or neutralized code or under an inherited/local execution override | `REQ-PROOFKIT-QUALITY-011` | The exact required job set, execution controls, and canonical aggregate script are admitted |
| R-07 | P1 | Nine commands encode structural admission failure as report JSON and leave `stderr` empty | `REQ-PROOFKIT-QUALITY-004` and CLI process contract | Ordinary malformed input is an error; admitted semantic failures remain reports |
| R-08 | P2 | Readiness phrase scanning misses single-decoded HTML character references | `REQ-PROOFKIT-PACKAGE-002` | Phrase comparison uses one semantic-text decode after structural row parsing |
| R-09 | P2 | The CLI compatibility hash omits input and output contract semantics | `REQ-PROOFKIT-QUALITY-004` | Every required-input command has a bounded contract projection included in ABI compatibility |
| R-10 | P2 | A breaking pre-1.0 patch remains range-compatible for caret consumers | release change record and `REQ-PROOFKIT-QUALITY-024` | Consumer docs require exact pins and release validation rejects an incompatible patch policy |
| R-11a | P2 | Self-hosting report verdict lacks isolated falsifiers | `REQ-PROOFKIT-PACKAGE-004` | A pure verdict boundary rejects nonzero, invalid JSON, and non-passed reports |
| R-11b | P2 | Wheel version, identity, and SHA checks lack isolated falsifiers | `REQ-PROOFKIT-PACKAGE-006`, `REQ-PROOFKIT-QUALITY-023` | Each wheel integrity predicate has its own negative case |
| R-11c | P2 | Root tarball deny-list decisions lack operation-boundary falsifiers | `REQ-PROOFKIT-PACKAGE-001` | A complete tarball plus one forbidden entry fails for every denied class |
| R-11d | P2 | Local and CI receipt identity lacks an isolated falsifier | `REQ-PROOFKIT-PACKAGE-004` | Local and CI identities cannot collapse into the same receipt |
| R-12 | P2 | Four command-route closure conjuncts lack isolated falsifiers | `REQ-PROOFKIT-QUALITY-010` | Each closure field has its own negative case |
| R-13 | P2 | External action SHA pinning is correct but unguarded | `REQ-PROOFKIT-QUALITY-025` | Every non-local `uses` value is exactly a 40-lowercase-hex commit |
| R-14 | P2 | Installed README commands assume a globally resolvable executable | `REQ-PROOFKIT-PACKAGE-003`, `REQ-PROOFKIT-QUALITY-019` | Canonical npm onboarding uses offline local package resolution |
| R-15 | P2 | Stack preset IDs are not projected into direct help or the machine contract | `REQ-PROOFKIT-SPEC-018` | Runtime, help, diagnostics, and contract share one preset inventory owner |
| R-16 | P2 | No copyable first valid requirement input is routed from Start Here | `REQ-PROOFKIT-SPEC-001` | A marker-bounded shipped example is executed by a test |
| R-17 | P3 | Raw pipe characters break the first contract-map decision row | contract map | Every decision row renders as exactly three GFM cells |
| R-18 | P2 | Axe runs in only one terminal workspace state and does not execute `target-size` | `REQ-PROOFKIT-QUALITY-022` | A stable-state matrix runs default axe plus explicit target-size |
| R-19 | P2 | Initial workspace markup uses invalid or unjustified ARIA roles | `REQ-PROOFKIT-SPEC-021` | Native list/article semantics replace the synthetic tree; handoff output has a labelled region |
| R-20 | P2 | Workspace produces document-level overflow at 320 CSS pixels | `REQ-PROOFKIT-QUALITY-022` | The document reflows; only graph/table viewports scroll internally |
| R-21 | P2 | Native control colors do not prove text, boundary, and focus contrast | `REQ-PROOFKIT-QUALITY-022` | Explicit light/dark tokens and computed contrast oracles cover pinned engines |
| R-22 | P3 | Root help does not reveal command-family discovery | `REQ-PROOFKIT-SPEC-018` | Root help contains the one opt-in `help families` route |
| R-23 | P2 | Workspace has no bounded visible bootstrap failure state | `REQ-PROOFKIT-SPEC-021` | Loading and sanitized terminal failure states exist before and after manifest admission |
| R-24 | P2 | `baselineVerification` overstates caller-expected digest coverage | `REQ-PROOFKIT-SPEC-019`, `021`, `022`, and `023` | Schema v2 calls the field `expectedDigestCoverage`; every context consumer owns its v2 projection, and v1 is admitted only through an explicit adapter |
| R-25 | P2 | Python and supported-platform onboarding is incomplete | `REQ-PROOFKIT-PACKAGE-006`, `REQ-PROOFKIT-QUALITY-016`, `REQ-PROOFKIT-QUALITY-023` | Docs project package metadata without claiming registry availability |
| R-26 | P2 | Package-public docs reference `BACKLOG.md`, but the npm artifact omits it | `REQ-PROOFKIT-PACKAGE-001` | Contributor-only files and backlog routes are removed from the npm artifact |
| R-27 | P3 | The browser render diagnostic omits the supported `workspace` view | `REQ-PROOFKIT-SPEC-009` and `021` | Runtime and app diagnostics enumerate the same admitted view vocabulary |
| R-28 | P1 | Existing GitHub Releases can receive missing assets through a backfill branch | `REQ-PROOFKIT-QUALITY-025` | Existing release topology is validated without provider mutation |
| R-29 | P2 | `SPEC-021` says no command execution while `--open` invokes a fixed OS browser launcher | `REQ-PROOFKIT-SPEC-021` | The owner distinguishes fixed loopback launch from caller-supplied or witness execution |

### Reclassified or rejected hypotheses

| ID | Disposition | Reason |
|---|---|---|
| A-01 | Rejected as a global defect | Duplicate canonicalization and strict sorted-unique admission are different contracts. Replacing every local helper would change valid set semantics without a field-level owner proof. |
| A-02 | Reclassified from P1 security to R-24 P2 naming | Caller-authored expected/current digest equality proves self-consistency only. Existing owners already deny freshness and provenance; the term, not an authentication boundary, is wrong. |
| A-03 | Rejected | No `jsonNumber` exploit or divergent admitted value was reproduced. |
| A-04 | Confirmed and remediated | `scripts/workflow_package_gate_oracle_test.go` was 3,025 LOC / 94,323 bytes and mixed five independent requirement owners; the missed semantic-shadow step proves material review harm. C-60 separates browser, runtime-precondition, workflow-source, security-scanner, and neutral-support surfaces while retaining the logically inseparable QUALITY-011/013 cluster. |
| A-05 | Rejected | No prematurely decomposed package was proven. Kernel dependency direction is acyclic and command packages own distinct public routes. |
| A-06 | Rejected | Current action references are already exact commit SHAs. Only the missing falsifier remains as R-13. |
| A-07 | Rejected | A producer marker embedded in a caller-computable snapshot ID cannot create provenance and would add false authority. |
| A-08 | Rejected | Current-build self-consistency cannot alone become merge-critical proof; no repair may introduce this implication. |

## Design decisions

### D-01: Evidence state classification

Problem:

`adoption-doctor` derives both record state and rule state from policy-enforced
gaps, erasing the epistemic fact that a prerequisite is blocked.

Chosen owner boundary:

Keep gap discovery in `adoptiondoctor`; add a classification function that
separates unconditional blocked gaps from policy-enforced advisory gaps.

Design:

```text
blocked = gaps where kind is blocked_precondition or child_report_blocked
enforced = policy-selected non-blocked gaps

if blocked is non-empty: state=blocked, exit=1
else if enforced is non-empty: state=failed, exit=1
else: state=passed, exit=0
```

Blocked rule rows are always `blocked`. Other non-enforced rows use
`adoptionmode.NonEnforcingStatus`. Promotion readiness consumes both sets.

Rejected lower-cost alternative:

Changing only the rule status leaves the top-level machine state false.

Proof invariant:

`blocked gap -> blocked report`, while an observe-mode advisory candidate
remains `passed` with a `skipped` rule.

Non-claims:

The report does not authenticate the prerequisite, execute evidence, or approve
enforcement.

Rollback or overturn condition:

Only a durable owner explicitly redefining blocked as a policy warning may
overturn this decision.

Why this avoids accidental complexity:

It adds one classification boundary and reuses the existing mode vocabulary.

Why this avoids premature over-decomposition:

The logic remains in the command owner.

### D-02: Artifact-honest SBOM

Problem:

`go list -m all` is a source/build inventory, not proof that each module is a
runtime dependency of every package, wheel, and binary.

Chosen owner boundary:

`internal/tools/releasesbom` continues to own deterministic release SBOM
generation. Release files remain subject components. Go module inventory is
retained only as explicitly excluded build inventory unless an individual
release binary provides a runtime dependency edge.

Design:

- add CycloneDX `scope`;
- mark `go list` module inventory as `excluded`;
- add `proofkit:evidence-class=source_build_inventory`;
- do not include excluded modules in the root `dependsOn`;
- retain release-file components as release subjects/representations, not
  runtime dependencies, and keep them out of root `dependsOn`;
- emit artifact-specific edges from each binary BOM reference to only the
  runtime modules recovered from that binary's build information;
- when a runtime module also exists in source inventory, deterministically
  deduplicate by package URL and promote the component to `required`; source
  evidence remains a property rather than a second conflicting BOM reference;
- package and wheel components receive no runtime edge without their own
  artifact-derived evidence;
- if `debug.BuildInfo` or `go version -m` exposes runtime dependencies for a
  future non-stripped artifact, emit those through a separately tested runtime
  inventory function rather than inferring them from the module graph;
- test that tool-only modules can never become root runtime edges.

Rejected lower-cost alternative:

Deleting all Go module records hides useful supply-chain inventory. Keeping
them unscoped preserves the false dependency claim.

Proof invariant:

Every binary dependency edge has evidence from that binary; source/tool
inventory and distribution representations have no runtime dependency edge.

Non-claims:

The SBOM does not prove vulnerability absence, license approval, reachability,
or provider attestation ingestion.

Rollback or overturn condition:

A reviewed release owner may replace excluded inventory with artifact-derived
runtime edges after adding cross-platform falsifiers.

Why this avoids accidental complexity:

It corrects the evidence class without introducing a linker graph framework.

Why this avoids premature over-decomposition:

All logic stays in the current SBOM tool.

### D-03: Handle-anchored filesystem operations

Problem:

Containment checks and later pathname operations do not imply object identity.

Chosen owner boundary:

Use Go's `os.Root` independently in the public API scanner and the output
writer. Do not create a generic filesystem abstraction because the read and
publication contracts differ.

Scanner design:

- admit lexical repository-relative paths;
- open the repository once with `os.OpenRoot`;
- open each referenced package as a confined pinned sub-root before reading
  its package manifest, then read every source for that package through the
  same sub-root;
- open each admitted lexical path through its owning root and pin its file
  handle;
- resolve its canonical in-root path, open that path through the same root, and
  require `os.SameFile` between the two pinned handles before accepting the
  canonical extension; this preserves safe in-root symlinks without a
  check-then-reopen implication;
- relative symlinks whose targets remain inside the root are preserved;
  absolute symlink targets are rejected by `os.Root` even when they point back
  inside the repository. This is an intentional `0.2.0` security-hardening
  change recorded in the CLI contract, release change record, migration text,
  and positive relative-link/negative absolute-link tests;
- bind pre/open/post identity and size around the bounded read, cache each
  lexical admission immutably, and bind every alias of one canonical source
  route to the identity and digest of its first admission; reject any later
  alias whose identity or digest differs;
- derive extension and package directory from the admitted object and pinned
  sub-root, never by a second unconfined open.

The scanner implementation exposes a private operation seam used only by
same-package tests. A staged barrier deterministically pauses after the legacy
path check but before the legacy reopen, proving the current redirect
counterexample without time-based race loops. The repaired path is then tested
with the same barrier and pinned handles.

Writer design:

- open the current repository root once;
- create/check parents with root-relative operations;
- pin the admitted destination parent;
- create a random temporary file through that pinned parent using
  `O_CREATE|O_EXCL`;
- write and chmod to `0644` through the open temporary file handle, close it,
  and retain its admitted file identity;
- immediately before publication, expose a deterministic test-only object
  barrier, re-admit the non-symlink temporary entry's identity, exact mode, and
  content digest, expose a second test-only barrier, then re-admit the current
  destination-parent route at the irreversible rename boundary;
- rename the temporary source to the destination through the same pinned
  parent, preserving baseline writable-child and cross-filesystem behavior;
- clean up the temporary route through the same pinned parent;
- reject symlink or directory destinations without relying on the check for
  confinement.

The writer receives the same style of same-package operation seam: a test
barrier performs the parent substitution before temporary-file creation,
before object admission, and after object admission at the irreversible rename
boundary, while a sibling case replaces the temporary route, rewrites its
content, or changes its permission or special mode bits before final object
admission. External and in-root replacement sentinels, stable-path bytes/mode,
temporary identity, exact-mode, and content rejection, absence of published
output, and absence of temporary residue are asserted. Polling races and
probabilistic swap loops are forbidden as proof.

Rejected lower-cost alternative:

Additional `Lstat`, `EvalSymlinks`, or string-prefix checks leave a race window.

Proof invariant:

Concurrent parent or source replacement cannot read or mutate an external
sentinel.

Non-claims:

The writer does not promise protection from adversarial concurrent content or
namespace mutation by the same operating-system user during the operation,
fsync durability, or a repository-wide transaction.
The scanner does not prove checkout freshness.

Rollback or overturn condition:

Unsupported `os.Root` platform behavior or an owner-required symlink workflow
must be resolved with an equally strong descriptor-based implementation, never
with pathname rechecks.

Why this avoids accidental complexity:

It uses the standard confined-root API and command-local helpers.

Why this avoids premature over-decomposition:

No new shared package is admitted.

### D-04: Exact workflow source oracles

Problem:

Substring recognition is not semantic implication for either expressions or
shell programs.

Chosen owner boundary:

The fixed repository workflows are checked by exact, owner-reviewed source
forms. `actionlint` retains syntax/expression validation.

Design:

- normalize only layout whitespace outside quoted expression literals;
- compare every trust-significant `if` against a complete allowed-expression
  set for its specific job or step;
- require exact required-job `needs`;
- require the aggregate workflow to retain exact `bash` run defaults without
  an inherited working-directory override or environment entries;
- require every required leaf job and the aggregate job to omit job defaults
  plus job-level `continue-on-error` and have no job environment entries;
- require every step in those jobs to omit shell, working-directory, and
  `continue-on-error` and have no step environment entries;
- require the aggregate job to have exact `always()` admission and one run step
  with no step-level `if` or `uses`;
- for generic package-gate workflows, admit only absent or exact safe workflow
  run defaults, exact owner-reviewed workflow and step environments, no
  gate-job defaults or environment, and no execution override on any step in
  the gate job;
- compare the whole aggregate shell program to a canonical constant;
- require every external `uses` reference to match a 40-lowercase-hex SHA,
  exempting repository-local `./` actions;
- give this supply-chain property a dedicated requirement rather than
  overloading the actionlint requirement, which owns syntax and expression
  validity but does not claim external action safety.

Rejected lower-cost alternative:

Growing deny-lists cannot close expression or shell grammar.

Proof invariant:

`|| true`, dead branches, quoted predicate text, early success, background
tests, inherited or local environment, shell, and working-directory overrides,
unexpected environment entries, and any schema value including explicit YAML
`null` presence for the forbidden scalar job/step controls all fail the oracle.

Non-claims:

The local source oracle is not a GitHub Actions interpreter and does not prove
provider execution or branch-protection configuration.

Rollback or overturn condition:

Any workflow expression change requires an explicit owner review and an
allowlist update with a new negative case.

Why this avoids accidental complexity:

Exact forms are stronger and smaller than a partial evaluator.

Why this avoids premature over-decomposition:

The existing workflow test remains the owner.

### D-05: Structural admission versus semantic failure

Problem:

Some builders translate structural errors into ordinary report records,
contradicting the CLI process contract.

Chosen owner boundary:

Command packages return admission errors. The app layer owns channel routing.
Only explicitly requested agent-envelope modes convert an admission error to a
JSON invalid-input envelope.

Design:

```text
ordinary structural error:
  exit 1; stdout empty; sanitized stderr diagnostic

admitted semantic failed or blocked report:
  nonzero exit; stdout one JSON report; stderr empty

explicit agent-envelope invalid input:
  exit 1; stdout one invalid-input envelope; stderr empty
```

The nine reproduced commands receive a table-driven ABI falsifier. Builder
signatures are changed only where needed to preserve this split.

Rejected lower-cost alternative:

Duplicating the same diagnostic in both channels makes machine composition
ambiguous. Detecting synthetic `invalid-input` report IDs in the app preserves
the wrong owner direction.

Proof invariant:

Every required-input command satisfies the same channel algebra for `{}` and
for one admitted semantic failure.

Non-claims:

Human diagnostic bytes are stable only where explicitly included in the ABI
corpus.

Rollback or overturn condition:

A versioned CLI process contract may add another explicit projection; command
packages may not silently invent one.

Why this avoids accidental complexity:

It removes a translation layer instead of adding one.

Why this avoids premature over-decomposition:

Channel behavior stays centralized in `internal/app`.

### D-06: Machine-readable CLI compatibility

Problem:

The public contract claims input ownership but 59 required-input commands have
no input contract, and the ABI projection ignores both input and output
contracts.

Chosen owner boundary:

`proofkit/cli-contract.v2.json` is the single authored machine owner. A
deterministic checked generator projects contract metadata into private Go
tables used by descriptors and help. Command admission code remains the
implementation and must be linked to named native admission witnesses.

The generator is `internal/tools/commandcontractgen`; it writes two
owner-derived private projections:

- `internal/app/command_contract_generated.go` for app descriptors/help;
- `internal/command/stackpreset/preset_ids_generated.go` for the lower-level
  preset package.

The second output prevents `stackpreset` from importing `internal/app` and
therefore prevents an import cycle. Both files are generated from the same
authored CLI contract in one invocation and have no independently editable
vocabulary. Freshness is checked by:

```bash
npm run command-contract:check
go test ./internal/tools/commandcontractgen ./internal/app -run CLIContract
```

`package.json` defines `command-contract:check` as
`go run ./internal/tools/commandcontractgen --check` and includes it in the
mandatory `npm run check` chain before Go/package closeout.

Design:

- use a deliberately bounded `root_shape_only` definition grammar: each
  direction declares sorted, condition-complete variants with a root kind
  (`object`, `array`, or explicitly unconstrained `json_value`), exact
  top-level allowed/required fields for object roots, and exact CLI flag/mode
  conditions; a direction with multiple bounded root kinds declares
  `rootType=union`, while `json_value` is forbidden as a union escape hatch;
- the adoption output definition may opt into
  `cli_flag_conjunction_v1`; every condition then uses one canonical
  ASCII-space-separated conjunction over the same sorted flag dimensions,
  every dimension has either exact absent/present states or exact literal
  values, every dimension is an allowed command flag, and assignments owned by
  different variants are pairwise disjoint; a second definition is rejected
  until its own native-domain and argv-closure witness is admitted;
- `internal/tools/commandcontractgen/condition_model.go` owns that pure grammar
  and disjointness algorithm; generator I/O and projection remain in `main.go`;
- every required-input command receives an `inputContract` containing:
  `schemaVersion`, the bounded root-shape definition and canonical digest,
  owner refs, exact native admission witness selector, and an explicit
  non-claim for nested fields, scalar types, collection cardinality,
  nullability, and cross-field semantics;
- every JSON output command receives an `outputContract` whose variants cover
  every supported JSON-producing flag/mode route, including object/array
  unions and agent-envelope projections;
- the generated private Go projection supplies the bounded direct-help summary
  and flag choices; these values are not manually repeated in descriptors;
- the canonical ABI projection includes each bounded input/output definition,
  canonical digest, scope, flags, flag choices, and output modes;
- generator checks require complete required-input and JSON-output coverage,
  generated-file freshness, sorted and unique root variants, non-empty exact
  conditions, valid root-kind/field combinations, and an executable native
  witness selector;
- native source digests remain conservative freshness sentinels only: they
  deliberately force review after owner-package code changes but are not
  semantic-equivalence proof;
- direct public-CLI tests exercise every high-risk multi-mode route and assert
  its root kind and exact root keys; command-local witnesses remain the
  evidence for individual native admission and output behavior;
- the adoption output condition oracle enumerates the finite
  `5 modes x 2 agent states x 2 materialization states x 4 pilot states`
  domain derived from immutable copies of the same internal native value lists
  that build option-admission maps, requires native option admission to accept
  exactly the same twelve assignments declared by the condition model, derives
  each exercised condition from parsed argv, and rejects repeated `--mode` or
  `--pilot` selectors before they can change the selected assignment;
- contract mutation tests cover root kind, allowed/required fields, variant
  conditions, schema versions, deleted definitions, digests, selectors, and
  either generated output becoming stale;
- the contract does not become a second runtime validator: owner-native
  positive/negative admission tests remain required evidence, and the public
  contract explicitly denies nested, typed, cardinality, nullability, and
  cross-field semantic parity.

Rejected lower-cost alternative:

A source-file hash alone detects irrelevant refactors and still does not state
the contract. The first implementation's inferred nested record graph is also
rejected: it attached records by field-name heuristics and produced
demonstrably false scalar-to-record associations. A generic owner string does
not expose compatibility. Merely adding `without` prose to overlapping
conditions is also rejected because free text cannot prove dimension closure,
canonicality, or pairwise disjointness. A general SAT or CLI grammar is
unnecessary: the optional four-dimension conjunction model closes the only
confirmed machine-selection boundary.

Proof invariant:

Changing a declared root kind, top-level field, requiredness rule, schema
version, or JSON-producing flag/mode variant changes the public ABI projection
and fails the golden until reviewed. Changing native owner-package source also
forces review without being mislabeled as semantic proof.

Non-claims:

The summary is not JSON Schema. It does not describe nested fields, scalar
types, array item types or cardinality, nullability, or cross-field semantics,
and it does not replace command admission tests.

Rollback or overturn condition:

A future versioned JSON Schema surface may supersede these closed machine
projections after demonstrating lower duplication and exact parity.

Why this avoids accidental complexity:

It uses one bounded root-shape registry and deterministic projection generator
instead of a false full-schema model, two manually authored public/private
schema copies, or a schema service.

Why this avoids premature over-decomposition:

The public contract is authored once; generated Go metadata is derived and
freshness-checked.

### D-07: Pre-1.0 compatibility

Problem:

A breaking `0.1.x` patch is selected by a common caret range.

Chosen owner boundary:

Release change admission and package-public install documentation jointly own
the policy.

Design:

- canonical npm installation uses `--save-exact`;
- README and generated release notes state that pre-1.0 consumers must
  exact-pin; generated npm install and rollback commands include
  `--save-exact` and the rollback route names the literal admitted previous
  version;
- replace `release/change-record.v1.json` with
  `release/change-record.v2.json`; update `releasechange.RecordPath`, release
  input composers, manifests, closeout, workflow paths, bindings, package
  checks, and documentation in the same slice;
- change-record schema v2 gains exact `previousVersion` and closed
  `changeClass=compatible|breaking`;
- admission derives that non-empty `breakingChanges` or required migration
  requires `changeClass=breaking`;
- release validation rejects non-empty breaking changes or required migration
  when the new version is only a patch over the previous pre-1.0 version;
- a future breaking pre-1.0 release must increment the minor version;
- no v1 adapter is added because no durable consumer requires one; the
  version-bound record is a repository release input, and retaining two active
  paths would create ambiguous authority;
- this change advances all synchronized package, Python, release record,
  manifest, notes, and contract metadata from `0.1.160` to `0.2.0` with
  `previousVersion=0.1.160`;
- the already published `v0.1.160` is not changed, republished, or backfilled.

Rejected lower-cost alternative:

Documentation alone does not prevent a future incompatible patch. A validator
alone does not protect existing range consumers.

Proof invariant:

For `0.m.p -> 0.m.(p+1)`, breaking changes or required migration fail release
admission; `0.1.160 -> 0.2.0` is admitted as breaking; install and rollback
release-note projections both preserve exact npm dependency pins.

Non-claims:

This does not prove registry publication, downstream lockfile use, or adoption.

Rollback or overturn condition:

Only a versioned release policy with an equally strong consumer-compatibility
proof may replace exact pins and minor bumps.

Why this avoids accidental complexity:

It adds two version facts and one semver comparison to the existing owner.

Why this avoids premature over-decomposition:

No new versioning package is needed unless another owner reuses the algorithm.

### D-08: Independent blocking falsifiers

Problem:

Aggregate positive fixtures allow individual blocking conjuncts to become
inert without failing tests.

Chosen owner boundary:

Existing self-hosting, coverage, package verification, and release tests.

Design:

- extract pure verdict functions only where subprocess coupling currently
  prevents testing;
- mutate one predicate per table row;
- cover self-hosting report state, wheel SHA, version match, local/CI receipt
  identity, tarball root deny-list, command-route closure, and linkage
  dead-zone fields;
- retain route-only metrics as non-claims where the owner explicitly makes
  them non-blocking;
- do not convert line coverage into semantic proof.

Rejected lower-cost alternative:

One fixture with every field wrong cannot prove that every conjunct matters.

Proof invariant:

Removing or inverting any single blocking predicate fails at least its named
negative case, while the neighboring positive fixture remains green.

Non-claims:

These tests do not prove exhaustive input coverage or provider state.

Rollback or overturn condition:

A predicate may lose its falsifier only if the durable requirement removes it
from the blocking conjunction.

Why this avoids accidental complexity:

Pure helpers are admitted only at existing side-effect boundaries.

Why this avoids premature over-decomposition:

No test utility package is added for one-use helpers.

### D-09: Continuous onboarding

Problem:

The shipped path breaks between local install, executable resolution, family
discovery, preset vocabulary, and first valid input.

Chosen owner boundary:

README, direct/root help, descriptors, stack preset inventory, package smoke,
and one marker-bounded example.

Design:

- npm install uses `--save-exact`;
- commands use `npm exec --offline -- agentic-proofkit`;
- Bun is not presented as a verified canonical onboarding route in this
  change; adding it later requires an exact-pin artifact smoke equivalent to
  the npm witness;
- root help projects the `help families` route;
- the projected route is the copyable
  `npm exec --offline -- agentic-proofkit help families` command used by the
  installed consumer, and its witness executes argv parsed from those exact
  displayed bytes;
- the authored CLI contract is the sole editable preset-ID owner;
  `stackpreset.IDs()` returns a defensive copy of its generated lower-package
  projection, while direct help and diagnostics use that API and app metadata
  uses the sibling generated projection;
- README includes one minimal valid requirement source and a tested command;
- package verification installs the exact tarball and executes one continuous
  offline witness trace through the installed artifact: root help, family
  discovery, every stack preset ID, extraction of the marker-bounded example
  from the installed README, and successful admission of that example;
- one immutable `cliexec` renderer owns shell quoting and a previously admitted
  invocation prefix; it has exactly three profiles:
  `npm_offline` renders `npm exec --offline -- agentic-proofkit`,
  `python_module` renders the absolute admitted interpreter followed by
  `-m agentic_proofkit`, and `path` renders `agentic-proofkit`;
- the npm shell wrapper and Python wrapper overwrite private launcher
  environment fields `AGENTIC_PROOFKIT_LAUNCHER_PROFILE` and
  `AGENTIC_PROOFKIT_PYTHON_EXECUTABLE` before `exec`; the closed admission
  matrix is `("", "")` or `("path", "")` to `path`,
  `("npm_offline", "")` to `npm_offline`, and
  `("python_module", <non-empty absolute path without report-visible
  secret-like, Unicode control, or Unicode format content>)` to
  `python_module`; every unknown profile, relative or empty Python executable,
  secret-like, control-bearing, or format-bearing executable, or executable
  field supplied with another profile is rejected without disclosing the
  rejected value; the Go process boundary admits those
  fields once and passes the renderer explicitly through app and command
  builders, with no package-manager, executable, `PATH`, or repository-state
  autodetection;
- the exact current Proofkit-owned generated-command field inventory is closed
  over:
  `$.diagnostics[?key=preset].value.suggestedCommands[*]` for stack-preset;
  `$.nextCommands[*]`,
  `$.agentActionPlan[?phase=verify].commands[*]`,
  `$.payloads.adoptionGuidance.agentGuidance.commands[callerCommandCount:]`,
  `$.report.diagnostics[?key=agentActionPlan].value[?phase=verify].commands[*]`,
  and `$.report.diagnostics[?key=nextCommands].value[*]` for bootstrap JSON;
  `$.commands[*].command` for its agent envelope;
  `$.nextCommands[*]` plus decoded
  `$.files[?payloadKey=adoptionGuidance].content::$.agentGuidance.commands[callerCommandCount:]`
  for its materialization manifest;
  the same bootstrap display-command locations below `$.bootstrapReport`, plus
  `$.materializationManifest.nextCommands[*]` and decoded
  `$.materializationManifest.files[?purpose=caller-owned gradual adoption
  guidance input].content::$.agentGuidance.commands[callerCommandCount:]`
  for project-structure JSON; and `$.commands[*].command` for the
  project-structure agent envelope; adding, removing, or relocating a producer
  or field requires the same inventory, requirement, and witness update;
- the structured-argv inventory is separately closed over
  `$.nextCommands[*].argv`, agent-envelope `$.commands[*].argv`, and exact
  agent-envelope `$.commands[*].display == cliexec.DisplayArgv(argv)` for
  agent-route; release-phase `$.phases[?phase=release].commands[*].argv` for a
  direct and aggregate adoption workflow; `$.commands[*].argv` plus exact
  `command == cliexec.DisplayArgv(argv)` for their agent envelopes;
  failure-rerun `$.commands[*].argv` for requirement coverage; and project
  `$.adoptionWorkflowPlan.phases[?phase=profile].commands[*].argv`,
  `$.adoptionWorkflowPlan.phases[?phase=bootstrap].commands[*].argv`, and
  `$.adoptionWorkflowPlan.phases[?phase=bind].commands[*].argv` with exact
  counts `2`, `2`, and `3`; project source-report identity is derived from the
  same renderer-owned workflow record;
- the textual help inventory is closed over the root family-discovery route,
  every family route, every family-to-leaf route, every descriptor's installed
  invocation, the help descriptor's exact authored help forms, and every
  stack-preset copyable route; path, npm-offline, and Python-module profiles
  must render every slot exactly once;
- caller-owned bootstrap `commands` bytes remain unchanged and are proved by
  `TestBootstrapPreservesCallerDisplayCommandInGuidancePayload`; specifically,
  the prefix
  `$.payloads.adoptionGuidance.agentGuidance.commands[0:callerCommandCount]`
  and its decoded materialization copies remain caller-owned while only the
  suffix is renderer-owned;
- caller-owned native-witness argv below the project bootstrap report remains
  byte-for-byte equal to the admitted bootstrap input and is excluded from the
  Proofkit-owned structured-argv inventory;
- the installed npm trace parses every preset's exact generated command
  strings through the bounded literal-word boundary, requires the exact npm
  prefix on every string, and re-executes a self-continuation from those exact
  JSON bytes;
- the installed wheel trace invokes a preset through the installed Python
  module, requires every emitted command to use its exact venv interpreter and
  `-m agentic_proofkit`, directly re-executes a self-continuation, traverses
  root help through every family and leaf help route, emits an agent-route argv
  with the same immutable prefix, and directly executes that argv with npm
  absent from `PATH`; route extraction admits only exact authored four-space
  indentation and one canonical lower-case command operand, rejects whitespace
  and shell-expansion mutants, and never turns generated stdout into shell
  authority;
- Python docs state `python -m agentic_proofkit` and `uv run
  agentic-proofkit`, supported targets, Python minimum, wrapper-not-SDK, and
  explicit registry-availability non-claims;
- a marker-bounded platform block is projected exactly from
  `releaseplatform.Targets()`, macOS minimum 12, manylinux 2.17 arm64/x64,
  Python `>=3.9`, and explicit Windows non-support; a docs test compares every
  row with the private owners;
- Python examples include the complete conditional install-to-invoke chain:
  `python -m pip install agentic-proofkit==<version>` then
  `python -m agentic_proofkit`, and
  `uv add --dev agentic-proofkit==<version>` then
  `uv run agentic-proofkit`, without implying that a current registry version
  exists;
- remove contributor-only `AGENTS.md` and `CONTRIBUTING.md` from the npm
  package, remove the active-backlog route from package-public README, and add
  a field-aware package-reference-closure falsifier;
- update or exclude package projections such as
  `receipt-producer-policy.local.developer` that cite contributor-only files,
  and classify self-hosting witness selectors that name `AGENTS.md`,
  `BACKLOG.md`, or `CONTRIBUTING.md` as source-checkout-only rather than
  package-consumer routes;
- `BACKLOG.md` remains a source-checkout owner and is not shipped as
  version-specific consumer documentation.

Exact C-89 proof routes:

| Requirement | Scenario | Witness path | Selector | Executable command |
| --- | --- | --- | --- | --- |
| `REQ-PROOFKIT-PACKAGE-002` | `proofkit.package-boundary.launcher-profile-admission` | `internal/kernel/cliexec/cliexec_test.go` | `TestLauncherProfileAdmissionMatrix` | `go test ./internal/kernel/cliexec -run '^TestLauncherProfileAdmissionMatrix$'` |
| `REQ-PROOFKIT-PACKAGE-002` | `proofkit.package-boundary.generated-command-field-inventory` | `internal/app/invocation_profile_test.go` | `TestGeneratedCommandInvocationProfileFieldInventory` | `go test ./internal/app -run '^TestGeneratedCommandInvocationProfileFieldInventory$'` |
| `REQ-PROOFKIT-PACKAGE-002` | `proofkit.package-boundary.generated-command-field-inventory` | `internal/app/invocation_profile_test.go` | `TestGeneratedCommandInvocationProfileRouteClosure` | `go test ./internal/app -run '^TestGeneratedCommandInvocationProfileRouteClosure$'` |
| `REQ-PROOFKIT-PACKAGE-002` | `proofkit.package-boundary.generated-command-caller-preservation` | `internal/command/gradualadoption/gradualadoption_test.go` | `TestBootstrapPreservesCallerDisplayCommandInGuidancePayload` | `go test ./internal/command/gradualadoption -run '^TestBootstrapPreservesCallerDisplayCommandInGuidancePayload$'` |
| `REQ-PROOFKIT-PACKAGE-003` | `proofkit.package-boundary.outside-consumer-artifact` | `internal/tools/packageverify/main_test.go` | `TestExactTarballOnboardingTrace` | `go test ./internal/tools/packageverify -run '^TestExactTarballOnboardingTrace$'` |
| `REQ-PROOFKIT-PACKAGE-006` | `proofkit.package-boundary.python-wheel-generated-continuation` | `internal/tools/pythonpackage/continuation_test.go` | `TestInstalledWheelContinuationUsesExactPythonModuleProfileWithoutNPM` | `go test ./internal/tools/pythonpackage -run '^TestInstalledWheelContinuationUsesExactPythonModuleProfileWithoutNPM$'` |
| `REQ-PROOFKIT-PACKAGE-006` | `proofkit.package-boundary.python-wheel-generated-continuation` | `internal/tools/pythonpackage/continuation_test.go` | `TestExactDisplayedRouteOperandsRejectsWhitespaceAndExpansionMutants` | `go test ./internal/tools/pythonpackage -run '^TestExactDisplayedRouteOperandsRejectsWhitespaceAndExpansionMutants$'` |
| `REQ-PROOFKIT-QUALITY-019` | `proofkit.supply-chain-quality.installed-package-json-abi-smoke` | `internal/tools/packageverify/main_test.go` | `TestExactTarballOnboardingTrace` | `go test ./internal/tools/packageverify -run '^TestExactTarballOnboardingTrace$'` |
| `REQ-PROOFKIT-QUALITY-024` | `proofkit.supply-chain-quality.release-change-record-projection` | `internal/tools/releasechange/record_test.go` | `TestCurrentChangeRecordNamesReviewedSemanticChanges` | `go test ./internal/tools/releasechange -run '^TestCurrentChangeRecordNamesReviewedSemanticChanges$'` |

The coverage owner admits these rows as an exact critical inventory and rejects
empty, missing, surplus, selector substitution, witness relocation, executable
command drift, requirement transfer, and scenario transfer.

Rejected lower-cost alternative:

Global installation, bare `npx`, or network fallback changes package identity.
Printing all allowed keys on every malformed input is noisy and does not create
a successful first route.

Proof invariant:

For the installed `npm_offline` and `python_module` channels and every field in
the closed generated-command inventory, the emitted command resolves the same
candidate artifact without network fallback; both temporary consumers can
execute an exact emitted self-continuation. The `path` profile preserves only
the canonical bare executable token and caller-owned resolution, without an
artifact-identity claim. Caller-owned display bytes are preserved in every
profile.

Non-claims:

The docs do not prove npm or PyPI publication, Bun support execution, shell
portability outside supported package targets, or consumer adoption. A direct
binary uses the `path` profile and therefore still requires the caller to make
`agentic-proofkit` resolvable.

Rollback or overturn condition:

If a documented package channel is removed from durable release owners, its
route and test must be removed together.

Why this avoids accidental complexity:

It projects existing owners and adds no command.

Why this avoids premature over-decomposition:

The only shared field is descriptor flag-value choices.

### D-10: Browser state and narrow accessibility proof

Problem:

Initial markup, terminal failures, 320-pixel layout, controls, and axe coverage
do not satisfy a coherent stable-state contract.

Chosen owner boundary:

Existing workspace HTML/assets and Playwright witness.

Design:

- server HTML contains an initial loading status;
- initialization catches manifest failure and renders a sanitized alert;
- request failures use the same terminal state vocabulary;
- native list and article semantics replace the unjustified ARIA tree;
- handoff output uses a visible heading and labelled region;
- active view controls expose `aria-current`;
- grid children use `min-width: 0`, text can wrap, navigation wraps, and
  graph/table overflow is confined to labelled internal viewports;
- explicit light/dark control tokens preserve forced-colors adaptation;
- axe runs on bootstrap loading, bootstrap failure, specifications loading,
  specifications, specifications no-match, diff loading, diff, graph loading,
  graph, unavailable, failed, and handoff-result states;
- the Playwright matrix declares for each state its deterministic route
  interception or deferred-response barrier, exact body and content
  `data-state` where applicable, heading, and applicable axe/reflow checks; the
  observed state identity is asserted before every oracle;
- bootstrap loading is held by a deferred manifest response, and each
  specifications, diff, and graph loading state is independently held by its
  own deferred view response; every barrier is released only after its complete
  row oracle, and bootstrap, view, and handoff failures are separate rows;
- `target-size` is explicitly enabled, applies to representative controls,
  has zero violations, and an undersized-control negative fixture proves that
  the rule would fail;
- a 320 by 800 viewport asserts no document-level horizontal overflow after
  each view transition;
- computed contrast checks read actual rendered controls, adjacent
  backgrounds, border colors, opacity, and focused outline styles in pinned
  engines and light/dark schemes rather than merely checking token values;
- replacing the synthetic tree intentionally removes its ArrowUp/ArrowDown
  roving-focus contract; tests preserve standard Tab/Shift+Tab traversal,
  Enter/Space activation, selection, and handoff semantics.

Rejected lower-cost alternative:

`overflow-x: hidden` hides data. Keeping a synthetic tree adds an unsupported
keyboard contract. A single final-state axe run does not prove initial or
failure states.

Proof invariant:

Every stable state is non-empty, has no default axe violation, executes the
target-size rule with no violation, and reflows without document overflow
where applicable.

Non-claims:

The witness does not establish complete WCAG conformance, branded Safari
behavior, screen-reader interoperability, all OS themes, or 400-percent zoom.

Rollback or overturn condition:

New stable UI states must enter the state matrix or be explicitly classified
as transient and inaccessible to users.

Why this avoids accidental complexity:

It removes an ARIA widget and centralizes one test helper.

Why this avoids premature over-decomposition:

CSS and rendering remain in the existing asset owner.

### D-11: Honest digest-coverage naming

Problem:

`baselineVerification=verified` sounds like provenance even though it means
only that all caller-provided expected digests match current bytes.

Chosen owner boundary:

Versioned requirement-context snapshots and downstream diff/browser
projections.

Design:

- snapshot schema v2 emits `expectedDigestCoverage: none|partial|all`;
- v1 input is first fully admitted under the complete v1 contract, then
  normalized by an explicit legacy adapter:
  `unverified -> none`, `partially_verified -> partial`, `verified -> all`;
- all producers emit v2;
- semantic-diff input/output, workspace manifest, and affected HTTP
  projections advance to their own schema v2 envelopes and use the new name;
- each affected v1 envelope has a strict v1 adapter, mixed v1/v2 keys are
  rejected, and migration tests cover v1 admission, normalized v2 equality,
  v2 production, and stable rejection of malformed legacy data;
- UI says `Expected-digest coverage`, never `Baseline verified`;
- requirements and non-claims state that coverage does not authenticate a
  producer, baseline, checkout, or freshness.

Rejected lower-cost alternative:

A producer marker inside caller-computable data creates no provenance.
Changing UI text alone leaves the wire contract misleading.

Proof invariant:

Self-consistent caller data remains admissible. The legacy verification term
may appear only inside the strict v1 adapter, migration fixtures, and
compatibility diagnostics; no v2 output, current contract, direct help, or UI
calls digest coverage verified.

Non-claims:

No signatures, trusted producer, repository freshness, or merge authority are
added.

Rollback or overturn condition:

A future authenticated snapshot format may introduce a separate provenance
field with its own trust root; it must not reuse digest coverage.

Why this avoids accidental complexity:

One versioned rename removes a false semantic implication.

Why this avoids premature over-decomposition:

The legacy adapter stays in the snapshot model owner.

### D-12: Semantic Markdown phrase equivalence

Problem:

Readiness overclaim scanning compares source bytes that can contain one
semicolon-terminated CommonMark character reference equivalent to a direct
policy phrase.

Chosen owner boundary:

The readiness command keeps structural table parsing and phrase policy local.

Design:

- parse rows and cells from original Markdown bytes;
- decode exactly one strict semicolon-terminated named, decimal, or hexadecimal
  CommonMark character reference only in extracted textual segments before
  phrase normalization;
- use a bounded recognizer around the standard entity table rather than
  applying permissive HTML decoding to arbitrary ampersand text;
- normalize policy phrases through the same helper;
- do not decode before pipe parsing;
- do not recursively decode double-encoded values.

Rejected lower-cost alternative:

Rejecting every ampersand breaks legitimate Markdown and still does not state
visible-text semantics.

Proof invariant:

Semicolon-terminated named, decimal, and hexadecimal references classify
identically to direct text; missing-semicolon and double-encoded references
remain literal after one pass.

Non-claims:

This is not a full Markdown parser or extraction-completeness proof.

Rollback or overturn condition:

A full admitted Markdown AST may supersede the helper only with equivalence
falsifiers.

Why this avoids accidental complexity:

One standard-library decode at the semantic boundary is sufficient.

Why this avoids premature over-decomposition:

The helper remains command-local until reused by another policy owner.

## Documentation topology

The closed size audit uses a deterministic suspicion threshold:
`LOC >= 1000 or bytes >= 65536`. Crossing the threshold is necessary only for
this ledger, not sufficient for a god-file verdict. A proven god file also
requires at least two independent semantic owners and observed or reproducible
material harm from their concentration.

Candidate snapshot ledger:

| Path | LOC | Bytes | Disposition | Owner proof |
|---|---:|---:|---|---|
| `proofkit/cli-contract.v2.json` | 14,983 | 537,788 | Suspicious size; not god | One generated public CLI-contract projection with freshness and ABI oracles |
| `docs/implementation/audit-remediation-plan.md` | 4,077 | 187,518 | Temporary oversized execution document | One reviewed implementation graph; retirement is required by the closeout predicate |
| `proofkit/requirement-bindings.json` | 3,507 | 142,191 | Suspicious size; not god | One canonical binding registry whose global order and linkage closure require one record |
| `scripts/workflow_package_gate_oracle_test.go` | 2,606 | 80,168 | Remediated god-file; residual suspicious cluster | Five-owner form was split; remaining QUALITY-011/013 scenarios share an exact selector and single-path binding contract |
| `internal/tools/packageverify/main.go` | 2,590 | 92,501 | Suspicious size; not proven god | One npm artifact admission boundary; helper extraction requires a second durable consumer or independent change reason |
| `docs/implementation/audit-remediation-design.md` | 3,182 | 248,568 | Temporary oversized design document | One adjudicated correction ledger; retirement is required after durable-owner closeout |
| `internal/app/cli_abi_test.go` | 2,316 | 112,885 | Suspicious size; not god | One public CLI ABI corpus and golden identity |
| `internal/app/cli_contract_test.go` | 2,096 | 87,274 | Suspicious size; not god | One CLI contract-admission and native-source parity corpus |
| `internal/tools/releasecloseoutinput/main_test.go` | 1,757 | 72,617 | Suspicious size; not god | One release-closeout input anti-corruption boundary |
| `internal/tools/packageverify/main_test.go` | 1,752 | 64,724 | Suspicious size; not god | One npm artifact verifier corpus |
| `internal/command/agentroute/agentroute_test.go` | 1,683 | 55,743 | Suspicious size; not god | One command owner and its complete behavioral corpus |
| `internal/tools/releasecloseoutinput/main.go` | 1,674 | 63,256 | Suspicious size; not god | One closeout projection owner |
| `proofkit/witness-plan.json` | 1,440 | 37,233 | Suspicious size; not god | One generated global witness plan |
| `internal/command/testevidenceinventory/testevidenceinventory_test.go` | 1,310 | 52,773 | Suspicious size; not god | One test-evidence inventory command corpus |
| `internal/command/repoprofileadmission/repo_profile_admission.go` | 1,280 | 42,499 | Suspicious size; not god | One repository-profile admission state machine |
| `internal/command/requirementcoverageview/requirementcoverageview_test.go` | 1,276 | 54,939 | Suspicious size; not god | One requirement-coverage view corpus |
| `internal/app/app_test.go` | 1,266 | 50,345 | Suspicious size; not god | One top-level command dispatcher and process-channel corpus |
| `internal/command/requirementbinding/requirementbinding.go` | 1,155 | 37,562 | Suspicious size; not god | One requirement-binding admission owner |
| `internal/command/pilotadmission/pilotadmission.go` | 1,154 | 43,660 | Suspicious size; not god | One pilot-admission command owner |
| `internal/command/agentroute/agentroute.go` | 1,121 | 51,789 | Suspicious size; not god | One agent-route command owner |
| `tests/browser/workspace.spec.mjs` | 1,416 | 60,370 | Suspicious size; not proven god | One end-to-end browser contract corpus; helper extraction would split shared state and add a one-consumer abstraction |
| `internal/command/workspaceregistry/workspaceregistry.go` | 1,096 | 34,838 | Suspicious size; not god | One workspace-registry command owner |
| `internal/command/bindingpartition/bindingpartition.go` | 1,086 | 39,825 | Suspicious size; not god | One binding-partition command owner |
| `internal/command/releaseauthority/releaseauthority.go` | 1,083 | 39,167 | Suspicious size; not god | One release-authority command owner |
| `.github/workflows/release.yml` | 1,069 | 49,849 | Suspicious size; not god | One event/needs release state machine; splitting jobs into reusable workflows would change trust and permission semantics |
| `internal/command/testevidenceinventory/testevidenceinventory.go` | 1,033 | 35,981 | Suspicious size; not god | One test-evidence inventory command owner |
| `internal/command/capabilitymapadmission/capability_map_admission.go` | 1,015 | 34,953 | Suspicious size; not god | One capability-map admission command owner |
| `internal/command/readinesscloseout/readinesscloseout.go` | 1,014 | 33,435 | Suspicious size; not god | One readiness-closeout command owner |
| `internal/command/jsonreportcliadaptersource/json_report_cli_adapter_source.go` | 1,008 | 34,655 | Suspicious size; not god | One JSON-report CLI-adapter source owner |
| `internal/tools/releasemanifest/main.go` | 1,006 | 36,543 | Suspicious size; not god | One release-manifest construction boundary |
| `internal/command/conformanceprofile/conformanceprofile.go` | 1,000 | 35,766 | Suspicious size; not god | One conformance-profile command owner |

C-60 decomposes the confirmed concentration as follows:

- `workflow_package_gate_oracle_test.go` retains the inseparable
  QUALITY-011/013 merge/package-gate proof cluster;
- `workflow_oracle_support_test.go` contains shared typed YAML and neutral
  helpers and contains no `Test*` selector;
- browser runtime, runtime preconditions, workflow source policy, and security
  scanner policy each have their own test file;
- PACKAGE-005, QUALITY-022, and QUALITY-025 bindings point to the new semantic
  owners and exact selector inventories reject deletion, surplus,
  owner-transfer, or stale-path substitution.
- QUALITY-005, QUALITY-006, and QUALITY-007 bind the scanner-policy selectors
  to their extracted owner, and the same exact selector-and-path inventory
  rejects deletion, surplus, owner transfer, or relocation.

The reverse decomposition audit found no proven merge. It inspected every Go
file at or below 40 LOC and every package with at least eight Go files.
The strongest candidates were rejected for explicit boundaries:

- `requirementbrowser/v1_adapter.go` owns a retireable wire-version adapter;
- generated preset IDs are generator-owned output in a different Go package;
- `cmd/agentic-proofkit/main.go` is the executable boundary;
- browser `assets.go` is the embed boundary;
- small app command wrappers preserve command-route and native-source review
  identities, while merging them would not remove a dependency or duplicate
  algorithm.

Reopen a split or merge only when owner evidence proves an independent change
reason, duplicated algorithm, dependency-cycle reduction, or measurable review
harm. File count, line count, and aesthetic preference alone are insufficient.
New helpers remain admissible only when they isolate a pure predicate, project
one private owner, bind a confined handle, or serve the shared workflow
anti-corruption boundary demonstrated above.

Implementation-only documents stay outside `package.json.files`. Contributor
governance and `BACKLOG.md` also remain source-checkout surfaces: an installed
runtime dependency must not expose incomplete repository-governance routes or
version-specific work rows.

### D-13: Immutable release topology and exact browser side effects

Problem:

The release workflow can add missing assets to an existing GitHub Release even
though the release owner calls historical release evidence immutable. The
browser owner separately uses an over-broad prohibition that appears to ban its
own fixed `--open` launcher, and one renderer diagnostic omits `workspace`.

Chosen owner boundary:

The release workflow may validate but never mutate an existing release. The
browser server may invoke only a fixed platform launcher with its own admitted
loopback URL. View vocabulary remains local to the browser command and app
parity tests.

Design:

- remove the existing-release missing-asset upload branch;
- existing releases must have the exact expected asset names and bytes or fail
  with a terminal nonzero result before any provider mutation;
- admit a closed read-only provider command set for the existing-release path
  (`gh release view` and `gh release download` in exact owner-approved forms);
- compare the entire existing-release shell block to one canonical
  owner-reviewed source form, including every local and provider operation;
  any `curl`, alternate network client, shell indirection, additional command,
  or other source change fails the oracle until a new owner-reviewed form and
  negative case are admitted;
- historical exceptions may be recorded outside successful release evidence
  but never authorize upload or a passing release result;
- refine `SPEC-021` to prohibit caller-supplied and native-witness command
  execution while permitting the fixed browser launcher;
- inject the launcher operation for tests and require fixed executable/argv
  forms plus an admitted loopback URL;
- update the renderer diagnostic to include `workspace` and add app/runtime
  vocabulary parity.

Rejected lower-cost alternative:

Add-only backfill still mutates historical evidence topology. Removing
`--open` breaks the admitted one-shot workflow. A new shared enum package for
two local projections is premature.

Proof invariant:

An incomplete existing release terminates nonzero before any provider
mutation, and no caller value can select the browser executable or add launcher
arguments.

Non-claims:

Source tests do not prove provider immutability, actual release assets, OS
browser profile identity, or that the browser rendered successfully.

Rollback or overturn condition:

Only a versioned release owner may define a mutable evidence class. A future
launcher expansion requires a new trust-boundary contract.

Why this avoids accidental complexity:

It deletes a mutation path and adds narrow injected-operation tests.

Why this avoids premature over-decomposition:

Release and browser vocabularies remain with their current owners.

## Compatibility and business-logic proof

Expected intentional public changes:

- blocked prerequisites can no longer return a successful adoption report;
- readiness closeout decodes one strict semicolon-terminated CommonMark or HTML
  character reference pass before policy phrase matching, so a forbidden
  phrase hidden by one such reference now fails closed;
- malformed input for the nine affected commands moves from JSON `stdout` to
  diagnostic `stderr`;
- CLI contract compatibility projection expands;
- `pilot-admission --pilot all` contract envelopes admit one strict first and
  stack-diverse input pair and return those ordered pilot reports;
- requirement binding admission and output preserve optional
  `witnessSelectors` selector-and-command records;
- requirement-context, semantic-diff, workspace manifest, and affected HTTP
  projection outputs advance to v2 with strict v1 input adapters;
- package/release metadata advances from `0.1.160` to `0.2.0`;
- future breaking pre-1.0 patch releases are rejected;
- absolute TypeScript source/package symlink targets are rejected; relative
  in-root symlinks remain supported;
- help and docs expose existing routes and preset values;
- synthetic ArrowUp/ArrowDown tree focus behavior is removed with the
  unjustified ARIA tree; standard Tab/Shift+Tab and Enter/Space behavior is
  preserved.

Preserved behavior:

- valid admitted inputs retain the same semantic decisions except for the
  explicitly declared readiness-closeout normalization and migrations above;
- semantic failed reports remain JSON reports;
- observe/warn modes remain advisory for non-blocked gaps;
- stack preset IDs and profiles do not change;
- output bytes and mode on a stable safe path remain deterministic;
- scanner export grammar and comparison do not expand;
- browser projections remain presentation-only;
- package artifacts remain candidate evidence until provider and registry proof
  exists.

For every intentional public change, the change record, contract projection,
requirements, bindings, and migration text must agree before closeout.

## Durable proof routing

Every row below is an implementation obligation. Proposed new scenario and
witness IDs become exact binding identities in
`proofkit/requirement-bindings.json`; existing identities are retained where
they already own the boundary. Test selectors are fixed before production
edits.

| Finding | Exact requirements | Binding scenario and witness | Exact path, selector, and command | Required non-claim delta |
|---|---|---|---|---|
| R-01 | `REQ-PROOFKIT-RETIRE-008`, `REQ-PROOFKIT-QUALITY-024` | extend `proofkit.consumer-infra-retirement.adoption-doctor-enforcement` / `proofkit.adoption-doctor.enforcement-and-envelope` and `proofkit.supply-chain-quality.release-change-record-projection` / `proofkit.release-change.versioned-projection-falsifier` | `internal/command/adoptiondoctor/adoptiondoctor_test.go`, `TestBuildReportsObserveAndWarnWithoutBlockingAdvisoryGaps`, `TestBuildEnforceTouchedSkipsGapsOutsideTouchedSelection`, `TestBuildBlocksEveryModeForExternalPreconditions`; `internal/tools/releasechange/record_test.go`, `TestCurrentChangeRecordNamesReviewedSemanticChanges`; `go test ./internal/command/adoptiondoctor ./internal/tools/releasechange` | Advisory mode does not authenticate or satisfy blocked evidence; a local record does not prove consumer migration |
| R-02 | `REQ-PROOFKIT-QUALITY-002` | extend `proofkit.supply-chain-quality.release-sbom` / `proofkit.release-sbom.deterministic-inventory` | `internal/tools/releasesbom/main_test.go`, `TestArtifactSpecificRuntimeEdgesAndExcludedInventory`, `TestReleaseFileEvidenceRejectsDeterministicIdentitySwap`, `TestReleaseFileEvidenceRejectsDeterministicInPlaceMutation`, `go test ./internal/tools/releasesbom` | Required scope and edges do not prove reachability, vulnerability absence, or license approval |
| R-03 | `REQ-PROOFKIT-PACKAGE-002` | extend `proofkit.package-boundary.typescript-explicit-scan-topology` / `proofkit.typescript-public-api.explicit-scan-topology` | `internal/command/publicapi/public_api_test.go`, `TestScanCacheBindsBytesToFirstCanonicalIdentityAcrossSymlinkRetarget`, `TestCanonicalSourceSnapshotRejectsChangedCrossAliasAdmission`, `TestVerifyRejectsDeterministicSymlinkSwap`, `TestVerifyPinsPackageRootAcrossInRootSiblingSwap`, `go test ./internal/command/publicapi` | Confined read does not prove checkout freshness or compiler provenance |
| R-04 | `REQ-PROOFKIT-SPEC-009` | extend `proofkit.spec-proof-core.requirement-spec-tree-view-cli-output` / `proofkit.requirement-spec-tree-view.cli-output-path-falsifier` | `internal/app/cli_abi_test.go`, `TestOutputWriterRejectsDeterministicParentSwap`, `go test ./internal/app -run OutputWriter` | Confined atomic rename does not prove protection from same-user content or namespace mutation during the operation or fsync durability |
| R-05 | `REQ-PROOFKIT-QUALITY-013` | extend `proofkit.supply-chain-quality.workflow-package-gate-oracle` / `proofkit.workflow-package-gate.typed-oracle` | `scripts/workflow_package_gate_oracle_test.go`, `TestCIWorkflowDeclaresFailClosedRequiredAggregate`, `TestPackageGateWorkflowOracleAcceptsOwnerCIAndReleaseWorkflows`, `TestWorkflowGuardExpressionsRejectNeutralization`, `TestPackageGateWorkflowOracleRejectsDisabledAndShadowedEvidence`, `TestPackageGateWorkflowOracleRejectsExecutionOverrides`, `TestPackageGateWorkflowOracleRejectsRequiredPriorExecutionOverride`, `TestPackageGateWorkflowOracleRejectsUnusedAllowedStepEnvironment`, `go test ./scripts -run 'CIWorkflowDeclaresFailClosedRequiredAggregate|WorkflowGuard|PackageGateWorkflowOracle'` | Exact source forms do not prove provider execution |
| R-06 | `REQ-PROOFKIT-QUALITY-011` | extend `proofkit.supply-chain-quality.ci-required-aggregate-exactness` / `proofkit.ci.required-aggregate-neutralization-falsifier` | `scripts/workflow_package_gate_oracle_test.go`, `TestCIWorkflowDeclaresFailClosedRequiredAggregate`, `TestCIRequiredAggregateRejectsNeutralizedScript`, `TestCIRequiredAggregateRejectsExecutionOverrides`, `TestCIRequiredAggregateRejectsPlatformSmokeSubstitution`, `go test ./scripts -run 'CIWorkflowDeclaresFailClosedRequiredAggregate|CIRequiredAggregate'` | Local source admission does not prove branch protection |
| R-07 | `REQ-PROOFKIT-QUALITY-004` | extend `proofkit.supply-chain-quality.cli-abi-golden` / `proofkit.cli-abi.golden-corpus` | `internal/app/cli_abi_test.go`, `TestRequiredInputCommandsRouteStructuralErrorsByMode`, `go test ./internal/app -run RequiredInputCommandsRoute` | Diagnostics outside the declared corpus are not byte-stable |
| R-08 | `REQ-PROOFKIT-PACKAGE-002`, `REQ-PROOFKIT-QUALITY-024` | extend `proofkit.package-boundary.readiness-closeout-overclaim-grammar` / `proofkit.readiness-closeout.overclaim-grammar` and `proofkit.supply-chain-quality.release-change-record-projection` / `proofkit.release-change.versioned-projection-falsifier` | `internal/command/readinesscloseout/readinesscloseout_test.go`, `TestPhraseScanDecodesOneStrictCharacterReference`; `internal/tools/releasechange/record_test.go`, `TestCurrentChangeRecordNamesReviewedSemanticChanges`; `go test ./internal/command/readinesscloseout ./internal/tools/releasechange` | The bounded decoder is not a complete Markdown AST; a local change record does not prove consumer migration |
| R-09 | `REQ-PROOFKIT-QUALITY-004`, `REQ-PROOFKIT-PACKAGE-002` | extend `proofkit.supply-chain-quality.cli-contract-topology` / `proofkit.cli-contract.descriptor-parity` | `internal/app/cli_contract_test.go`, `TestCommandDescriptorContractParityRejectsMutations`; `internal/tools/commandcontractgen/main_test.go`, `TestRenderRejectsIncompleteAndStaleCommandContracts`; `npm run command-contract:check`; `go test ./internal/tools/commandcontractgen ./internal/app -run 'CommandDescriptorContractParity|RenderRejectsIncomplete'` | Machine declaration plus native witnesses does not prove every cross-field semantic constraint |
| R-10 | `REQ-PROOFKIT-QUALITY-024` | extend `proofkit.supply-chain-quality.release-change-record-projection` / `proofkit.release-change.versioned-projection-falsifier` | `internal/tools/releasechange/record_test.go`, `TestAdmitEnforcesVersionedChangeClass`, `go test ./internal/tools/releasechange` | Version admission does not prove registry history |
| R-11a | `REQ-PROOFKIT-PACKAGE-004` | add `proofkit.package-boundary.self-hosting-report-verdict` / `proofkit.self-hosting.report-verdict-falsifier` | `scripts/validate-self-hosting-receipts_test.go`, `TestRunProofkitVerdictCases`, `go test ./scripts -run RunProofkit` | Injected operation tests do not prove provider producer identity |
| R-11b | `REQ-PROOFKIT-PACKAGE-006`, `REQ-PROOFKIT-QUALITY-023` | extend `proofkit.package-boundary.python-wheel-candidate` / `proofkit.python-package.boundary` | `scripts/validate-self-hosting-receipts_test.go`, `TestPythonArtifactRefsRejectEachWheelIdentityDefect`, `go test ./scripts -run PythonArtifactRefs` | Local wheel bytes do not prove PyPI bytes |
| R-11c | `REQ-PROOFKIT-PACKAGE-001` | extend `proofkit.package-boundary.root-export-and-deep-import-denial` / `proofkit.package-artifact.boundary` | `internal/tools/packageverify/main_test.go`, `TestVerifyRootPackageRejectsEachForbiddenRootEntry`, `go test ./internal/tools/packageverify` | Local tarball proof does not prove registry tarball identity |
| R-11d | `REQ-PROOFKIT-PACKAGE-004` | extend `proofkit.package-boundary.ci-receipt-anchor` / `proofkit.ci.receipt-anchor` | `scripts/validate-self-hosting-receipts_test.go`, `TestReceiptIDKeepsLocalAndCIIdentitiesDistinct`, `go test ./scripts -run ReceiptID` | Receipt naming does not authenticate a producer |
| R-12 | `REQ-PROOFKIT-QUALITY-010` | extend `proofkit.supply-chain-quality.coverage-metrics` / `proofkit.coverage-metrics.linkage-report` | `internal/tools/coveragemetrics/main_test.go`, `TestEachCommandRouteClosureConjunctHasIndependentFalsifier`, `TestEachLinkageDeadZoneConjunctHasIndependentFalsifier`, `go test ./internal/tools/coveragemetrics` | Static route closure does not satisfy semantic falsifier coverage |
| R-13 | `REQ-PROOFKIT-QUALITY-025` | extend `proofkit.supply-chain-quality.workflow-source-oracles` / `proofkit.workflow.exact-source-oracle-falsifiers` | `scripts/workflow_source_oracles_test.go`, `TestWorkflowExternalActionsUseFullCommitSHAs`, `go test ./scripts -run ExternalActions` | A commit pin does not prove action safety or tag equivalence |
| R-14 | `REQ-PROOFKIT-PACKAGE-003`, `REQ-PROOFKIT-QUALITY-019` | extend `proofkit.package-boundary.outside-consumer-artifact` / `proofkit.package-artifact.outside-consumer` | `internal/tools/packageverify/main_test.go`, `TestExactTarballOnboardingTrace`, `go test ./internal/tools/packageverify -run OnboardingTrace` | Local artifact execution does not prove registry publication |
| R-15 | `REQ-PROOFKIT-SPEC-018` | extend `proofkit.spec-proof-core.command-family-help-compatibility` / `proofkit.command-family-navigation.help-compatibility-falsifier` | `internal/app/command_family_catalog_test.go`, `TestStackPresetVocabularyProjectsFromOneOwner`, `go test ./internal/app -run StackPresetVocabulary` | Presets remain suggestions, not consumer policy |
| R-16 | `REQ-PROOFKIT-SPEC-001`, `REQ-PROOFKIT-QUALITY-019` | add `proofkit.spec-proof-core.installed-readme-first-input` / `proofkit.packageverify.installed-readme-input-falsifier` | `internal/tools/packageverify/main_test.go`, `TestExactTarballOnboardingTrace`, `go test ./internal/tools/packageverify -run OnboardingTrace` | Example validity does not prove requirement meaning |
| R-17 | `REQ-PROOFKIT-PACKAGE-001` | add `proofkit.package-boundary.contract-map-table-shape` / `proofkit.contract-map.table-shape-falsifier` | `internal/app/cli_contract_test.go`, `TestContractMapDecisionTreeHasThreeCells`, `go test ./internal/app -run ContractMap` | Cell-count proof is not full GFM rendering |
| R-18 | `REQ-PROOFKIT-QUALITY-022`, `REQ-PROOFKIT-SPEC-021` | extend `proofkit.supply-chain-quality.browser-static-and-runtime-proof` / `proofkit.requirement-browser.static-runtime-proof-falsifier` | `tests/browser/workspace.spec.mjs`, `workspace state matrix passes axe and target-size`, `npm run browser:check` | Narrow automated rules do not establish full WCAG conformance |
| R-19 | `REQ-PROOFKIT-SPEC-021` | extend `proofkit.spec-proof-core.requirement-browser-rendered-runtime` / `proofkit.requirement-browser.rendered-runtime-falsifier` | `tests/browser/workspace.spec.mjs`, `specifications use native semantics and keyboard activation`, `npm run browser:check` | The flat list does not claim hierarchical tree navigation |
| R-20 | `REQ-PROOFKIT-QUALITY-022` | extend `proofkit.supply-chain-quality.browser-static-and-runtime-proof` / `proofkit.requirement-browser.static-runtime-proof-falsifier` | `tests/browser/workspace.spec.mjs`, `workspace states reflow at 320 CSS pixels`, `npm run browser:check` | The test is not a complete zoom/device audit |
| R-21 | `REQ-PROOFKIT-QUALITY-022` | extend `proofkit.supply-chain-quality.browser-static-and-runtime-proof` / `proofkit.requirement-browser.static-runtime-proof-falsifier` | `tests/browser/workspace.spec.mjs`, `rendered controls meet narrow contrast thresholds`, `npm run browser:check` | Pinned engine/scheme checks do not cover every OS theme |
| R-22 | `REQ-PROOFKIT-SPEC-018` | extend `proofkit.spec-proof-core.command-family-help-compatibility` / `proofkit.command-family-navigation.help-compatibility-falsifier` | `internal/app/command_family_catalog_test.go`, `TestRootHelpDiscoversFamiliesWithoutExpandingThem`, `go test ./internal/app -run CommandFamily` | Root help does not recommend a product decision |
| R-23 | `REQ-PROOFKIT-SPEC-021`, `REQ-PROOFKIT-QUALITY-022` | extend workspace rendered-runtime and static-runtime witnesses | `tests/browser/workspace.spec.mjs`, `bootstrap and request failures are visible and sanitized`, `npm run browser:check` | No retry, telemetry, or offline policy is added |
| R-24 | `REQ-PROOFKIT-SPEC-019`, `REQ-PROOFKIT-SPEC-021`, `REQ-PROOFKIT-SPEC-022`, `REQ-PROOFKIT-SPEC-023`, `REQ-PROOFKIT-QUALITY-004` | extend context compose, semantic diff, graph consumer, browser workspace, and CLI schema-evolution scenarios | context, diff, graph, browser, and app test files; selectors `TestV1DigestCoverageAdapters`, `TestDigestCoverageAdaptersPreserveSemanticDiffV2`, `TestBuildConsumesNormalizedV1AndV2ContextSnapshots`, `TestV2DigestCoverageProjections`, and `TestLegacyDigestVocabularyConfinedToV1AdaptersAndFixtures`; `go test ./internal/command/requirementcontext ./internal/command/requirementdiff ./internal/command/requirementgraph ./internal/command/requirementbrowser ./internal/app` | Digest coverage does not authenticate producer, baseline, or freshness |
| R-25 | `REQ-PROOFKIT-PACKAGE-006`, `REQ-PROOFKIT-QUALITY-016`, `REQ-PROOFKIT-QUALITY-023` | extend Python wheel and platform scenarios / platform-doc and release-platform-parity falsifiers | `internal/tools/pythonpackage/metadata_test.go`, `TestREADMEPlatformAndPythonProjection`, `TestReleaseTargetsProjectExactPythonWheelMetadata`, `TestVerifyWheelContentsRequiresExactWheelMetadata`, `go test ./internal/tools/pythonpackage ./internal/kernel/releaseplatform` | Docs do not claim a current PyPI version or Windows support |
| R-26 | `REQ-PROOFKIT-PACKAGE-001`, `REQ-PROOFKIT-PACKAGE-007` | extend package reference closure and mutable-release-fact scenarios / their separate falsifiers | `internal/tools/packageverify/main_test.go`, `TestPackagePublicReferenceClosure`, `TestVerifyNoStalePackageDocsRejectsMutableReleaseFactsInMarkdown`, `go test ./internal/tools/packageverify` | The bounded destination and exact code-span classifications are not a complete Markdown parser; the npm artifact is not a source checkout |
| R-27 | `REQ-PROOFKIT-SPEC-009`, `REQ-PROOFKIT-SPEC-021`, `REQ-PROOFKIT-QUALITY-004` | extend browser route and CLI ABI scenarios | `internal/command/requirementbrowser/requirementbrowser_test.go`, `TestInvalidViewListsEverySupportedView`, `go test ./internal/command/requirementbrowser ./internal/app` | Diagnostic parity does not prove browser runtime |
| R-28 | `REQ-PROOFKIT-QUALITY-025` | extend `proofkit.supply-chain-quality.workflow-source-oracles` / `proofkit.workflow.exact-source-oracle-falsifiers` | `scripts/workflow_source_oracles_test.go`, `TestExistingReleasePathIsReadOnlyAndFailsOnDrift`, `go test ./scripts -run ExistingRelease` | Source allowlist does not prove provider asset state |
| R-29 | `REQ-PROOFKIT-SPEC-021`, `REQ-PROOFKIT-PACKAGE-002` | extend fixed-launcher and one-shot-cleanup scenarios / their separate falsifiers | `internal/command/requirementbrowser/server_test.go`, `TestOpenBrowserUsesFixedLauncherAndLoopbackURL` plus the three `TestServeOneShot*` cleanup selectors, `go test ./internal/command/requirementbrowser` | Launcher success does not prove cleanup or browser rendering; cleanup does not prove browser profile identity |

This change makes no selective-gate sufficiency claim. The repository has no
current aggregate producer that can derive a complete
`selective_gate_plan_input` from Git plus the binding graph, and inventing one
inside an audit-remediation PR would be a new feature. The exact closeout gate
is therefore always:

```bash
git diff --check
npm run check
```

If an optional caller-owned selective input is materialized during
implementation, it is admitted with:

```bash
go run ./cmd/agentic-proofkit selective-gate-plan --input <artifact-root>/selective-gate-plan-input.json > <artifact-root>/selective-gate-plan.json
jq -e '.unknownEdges == [] and .failures == []' <artifact-root>/selective-gate-plan.json
```

Any non-empty `unknownEdges` or `failures` blocks closeout until the binding or
owner route is corrected. Running the full gate does not convert an unresolved
edge into success. Absence of an optional selective input remains an explicit
non-claim, not a skipped success.

## Proof matrix

| Repair | Current wrong implementation accepted by falsifier | Required narrow gate |
|---|---|---|
| R-01 | Observe-mode blocked prerequisite returns `passed/0` | `go test ./internal/command/adoptiondoctor ./internal/kernel/adoptionmode` |
| R-02 | Tool-only module appears as required root dependency | `go test ./internal/tools/releasesbom` |
| R-03 | Source, ancestor, or manifest-owning package swap can redirect the post-check open | `go test ./internal/command/publicapi` |
| R-04 | Output parent swap can redirect create or rename | `go test ./internal/app -run OutputWriter` |
| R-05 | Expected expression plus `|| true`, a shell override, a working-directory override, or any merge-critical `continue-on-error` field is admitted | `go test ./scripts -run 'WorkflowGuard|PackageGateWorkflowOracle'` |
| R-06 | Expected tests inside `if false` or under inherited/job/step execution overrides are admitted | `go test ./scripts -run RequiredAggregate` |
| R-07 | `{}` yields JSON stdout and empty stderr | `go test ./internal/app -run RequiredInputCommandsRoute` |
| R-08 | Entity-obfuscated visible overclaim passes | `go test ./internal/command/readinesscloseout` |
| R-09 | Input or output schema change leaves ABI hash unchanged | `npm run command-contract:check` and `go test ./internal/tools/commandcontractgen ./internal/app -run CLIContract` |
| R-10 | Breaking pre-1.0 patch is admitted | `go test ./internal/tools/releasechange ./internal/tools/releasepreflight` |
| R-11 | One self-hosting or package predicate can be inverted | Exact R-11a through R-11d gates in durable proof routing |
| R-12 | One closure field can be cleared without failure | `go test ./internal/tools/coveragemetrics` |
| R-13 | Floating external action ref is accepted | `go test ./scripts -run ExternalActions` |
| R-14 | Local install requires ambient PATH | `go test ./internal/tools/packageverify -run OnboardingTrace` |
| R-15 | Preset owner and help/contract diverge | `go test ./internal/command/stackpreset ./internal/app` |
| R-16 | Installed README example becomes invalid | `go test ./internal/tools/packageverify -run OnboardingTrace` |
| R-17 | Decision row has more than three cells | `go test ./internal/app -run ContractMap` |
| R-18..R-23 | Initial, failure, narrow, or alternate state escapes browser oracle | `npm run browser:check` with the named state-matrix rows |
| R-24 | Caller consistency is still called verified | `go test ./internal/command/requirementcontext ./internal/command/requirementdiff ./internal/command/requirementbrowser ./internal/app` |
| R-25 | Docs drift from Python/platform owners | `go test ./internal/tools/pythonpackage ./internal/kernel/releaseplatform` |
| R-26 | Installed artifact exposes a dangling source-checkout route | `go test ./internal/tools/packageverify -run PackagePublicReferenceClosure` and `npm run package:artifact` |
| R-27 | Renderer and app disagree on admitted views | `go test ./internal/command/requirementbrowser ./internal/app -run InvalidView` |
| R-28 | Existing release can enter `gh release upload` | `go test ./scripts -run ExistingRelease` |
| R-29 | Launcher can receive caller executable, arguments, or non-loopback URL | `go test ./internal/command/requirementbrowser -run OpenBrowser` |

Final proof:

```bash
git diff --check
npm run check
```

The final committed object must pass the full gate. Provider publication and
registry checks remain separately unverified unless external evidence is
available.

## Implementation correction epoch

Independent implementation review may falsify a design assumption without
expanding product scope. The following corrections are admitted because each
strengthens an existing invariant at its existing owner:

| Correction | Falsified implication | Required correction |
|---|---|---|
| C-01 | `hash(path) = h` and `buildInfo(path) = b` do not imply that `h` and `b` describe the same bytes under a pathname swap or same-inode rewrite | Derive hash and build information from one immutable byte snapshot read through a pinned release-file descriptor, then prove same-handle content, pre/post descriptor, and current-path identity |
| C-02 | Cached bytes from read `A` plus identity from later stat `B`, or a parsed-export cache keyed only by canonical route, do not imply one immutable source admission across lexical aliases | Build each TypeScript lexical admission's bytes, digest, and identity from one pinned descriptor, bind every canonical source route to its first admitted identity/digest/parsed exports, and reject deterministic same-lexical or cross-alias drift |
| C-03 | A command-level native-source digest does not expose the required input/output compatibility surface | Initially require a recursively resolved field tree, then treat that attempted correction as falsified and superseded by C-09 after field-name inference produced false nested associations |
| C-04 | An AST function declaration with a matching name does not imply that `go test -run` can discover or execute it | Admit only Go test names and signatures using `*testing.T`, including valid import aliases, and require the witness to be an active `_test.go` file in the current `go list` projection |
| C-05 | A breaking version increment does not imply a `.0` target | Admit every major increase and every pre-1.0 minor increase while rejecting only breaking patch-class changes |
| C-06 | Updating the context producer alone does not own the wire contract of semantic diff and graph consumers | Include `SPEC-022` and `SPEC-023` as direct R-24 owners and proof routes |
| C-07 | A prohibited identifier appearing as an arbitrary substring of a content digest does not imply organization-policy leakage | Match prohibited identifiers at identifier boundaries and retain staged-blob plus worktree falsifiers |
| C-08 | A hard-coded receipt-kind mismatch does not remain a negative case after proof bindings legitimately gain that command | Derive the mismatch fixture from the current complement of the selected requirement's command set and require the complement to be non-empty |
| C-09 | Internally consistent inferred record graphs and executable test names do not imply semantic CLI-contract parity | Replace the false nested graph with an honest `root_shape_only` variant grammar, enumerate every supported JSON root/mode, use exact `union` roots instead of an unconstrained scalar-capable aggregate, cover omitted flag defaults as first-class conditions, add direct high-risk CLI root oracles, and deny nested/type/cardinality/nullability parity |
| C-10 | A repository-root-confined reopen does not preserve the package directory admitted with its manifest when an in-root sibling is substituted | Open the package boundary as a confined pinned sub-root before reading its manifest, then admit all package sources through that same handle |
| C-11 | A versioned breaking-release policy does not imply exact consumer pinning when generated release notes omit npm's exact-save flag | Render install and rollback commands with `--save-exact`, include the literal previous version, and falsify both generated routes |
| C-12 | A design table naming a selector or witness does not imply that the durable proof graph contains it | Bind every exact design selector and witness identity, then run binding admission and selector-executability closure |
| C-13 | A repository-root-confined output route does not preserve the admitted parent when that parent is replaced by an in-root sibling symlink | Open and pin the admitted parent as a confined sub-root, bind the route and handle with `SameFile`, keep temporary creation and cleanup on that handle, and recheck the current route; C-28 supersedes descriptor-relative publication |
| C-14 | Counting one externally blocked gap as also enforced does not imply disjoint adoption-doctor disposition classes | Derive blocked and enforceable gap sets independently, exclude blocked gaps from enforcement counts in every mode, and let unresolved blocked evidence determine top-level blocked state |
| C-15 | One native-source digest does not imply complete ownership when an output is assembled by two command packages | Admit exactly one of `nativeSource` or a sorted, non-empty, unique `nativeSources` list and require every declared source digest to be fresh |
| C-16 | A scanner parse failure represented as a synthetic semantic report does not imply structural-error channel parity | Return scanner admission errors structurally so malformed deployment input exits non-zero with empty `stdout` and a bounded `stderr` diagnostic |
| C-17 | Server cleanup and one-shot lifecycle tests do not imply that every terminal one-shot output has a declared public root shape | Declare distinct submitted and terminal variants and execute both through package and public-CLI oracles |
| C-18 | Variant-local root checks do not imply globally unambiguous conditions, default-flag coverage, or a reachable aggregate mode | Reject duplicate conditions across variants, exercise explicit and omitted defaults directly, and admit the two-input pilot aggregate through one strict envelope |
| C-19 | A worktree snapshot derived from tracked and untracked paths does not imply that an unstaged tracked deletion affects artifact identity | Subtract `git ls-files --deleted` from the snapshot and prove staging the same deletion cannot change the candidate snapshot |
| C-20 | Rejecting forbidden root entries does not imply that the canonical root package is retained by the test fixture | Include the valid root package entry in the positive artifact fixture, then mutate each forbidden root entry independently |
| C-21 | Recognizing literal `true` does not imply that a dynamic or constant GitHub expression cannot enable job-level `continue-on-error` | Require the fail-closed aggregate job to omit `continue-on-error` entirely and falsify literal, expression, and explicitly false field presence |
| C-22 | Bootstrap and terminal-state coverage does not imply coverage of per-view loading states that remain visible under a delayed request | Hold each specifications, diff, and graph request behind a deterministic barrier and run the complete accessibility, target-size, reflow, contrast, packet, and tab-order oracle before release |
| C-23 | Exact run text and actionlint success do not imply the same execution semantics when a typed oracle drops inherited or step-level environment, shell, and working-directory controls, partial truth evaluation does not prove `continue-on-error` absence, and ordinary nullable decoding does not preserve forbidden-key presence | Model workflow, job, and step run controls with presence-aware scalar admission; require exact safe workflow defaults and exact owner-reviewed environment entries where present plus exact bash defaults for the CI aggregate; forbid job defaults, unexpected environment entries, shell, working-directory, or any `continue-on-error` presence on all required leaf and aggregate jobs and on every step in each merge-critical job; falsify each inheritance level and explicit YAML `null` for forbidden scalar controls independently |
| C-24 | A release change record that correctly declares some breaking changes does not imply that it declares every intentional public state/exit change approved by the design | Declare the `adoption-doctor` blocked-prerequisite state and nonzero-exit change plus its consumer migration step in the versioned record, and bind a direct record-to-rendered-notes falsifier |
| C-25 | A declared top-level state/exit migration does not imply declaration of nested public rule-status changes, and an observe-only test does not prove every non-enforced rule path | Declare the non-enforced advisory rule transition from `passed` to `skipped` plus its consumer migration, require exact `observe=skipped` and `warn=warning` rule statuses, prove gaps outside an `enforce-touched` selection remain top-level `passed/0` with `skipped` rules, and prove the declaration reaches rendered notes |
| C-26 | `trace: retain-on-failure` and an error naming a run directory do not imply that diagnostics survive process cleanup or reach provider review | Under the QUALITY-022 browser artifact-confinement and failure-diagnostics-retention witnesses, clean successful browser runs, retain failed attempt directories, upload only the attempt-scoped report and test-results paths under an exact failure condition, and keep authoritative proof upload success-only |
| C-27 | `retain-on-failure` plus a pinned axe package does not imply bounded Firefox execution: neither removing continuous screenshots alone nor shrinking the repeated megabyte-scale builder source alone prevents the stall | Initialize the pinned version-identical minified axe distribution through the browser-context script channel, let every builder evaluate only a constant no-op loader, retain action, DOM, network, and source trace data with continuous screenshots disabled, request one bounded best-effort screenshot after failure, preserve all default and target-size rule semantics, and require clean first-attempt execution in every pinned engine without retries or a larger timeout |
| C-28 | A pinned parent handle plus current-route checks does not imply that descriptor-relative publication stays repository-confined when the admitted parent moves after the last check | Keep temporary-file creation and cleanup through the pinned parent, publish through the repository root with full temporary-source and destination routes, and use an exact `before_publish` barrier to prove outside-root and in-root replacement sentinels remain unchanged with no temporary residue |
| C-29 | Two root-confined pathname operands do not imply that `os.Root.Rename` publishes the admitted temporary object into the admitted parent: the source and destination routes are resolved separately, and no additional pre/post pathname check closes the remaining same-user namespace race | Stage the temporary object directly under the repository root, retain its identity, re-admit both temporary identity and destination-parent route after the exact barrier, publish through the repository root, and replace the unprovable stable-parent concurrency promise with an explicit same-user post-admission namespace-mutation non-claim; this narrows only an unmerged audit hardening claim absent from the baseline contract |
| C-30 | Root-level staging does not preserve baseline writable-child or nested-filesystem behavior; `SameFile` does not imply immutable temporary content or mode, that a followed symlink is the directory entry being renamed, or that a parent admitted before hashing remains current at publication; and `FileMode.Perm() == 0644` does not exclude setuid, setgid, or sticky bits | Under the explicit same-user concurrency non-claim, stage, validate, publish, and clean through the pinned destination parent; after the exact barrier re-admit the non-symlink temporary entry identity, complete mode exactly equal to `0644`, and content digest, then re-admit the parent route at the irreversible rename boundary, and falsify object replacement, permission and every special-mode-bit change, in-place rewrite, symlink aliasing, and parent replacement before publication |
| C-31 | A compatible public requirement addition does not reach consumers merely because its source, overview, binding, and tests agree | Add the repository-confined same-parent atomic output guarantee to the versioned machine release record and require its exact summary in rendered notes |
| C-32 | Byte equality and a valid provider projection do not imply that the final PR body includes the promised final tree, diff counts, local gates, residual non-claims, and retrospective | Build one canonical closeout record from exact repository and admitted local-evidence facts, embed it with a digest and unique sentinels, and validate it independently in both the reviewed snapshot and final server body |
| C-33 | Validating a mutable local artifact path and later rereading that path for projection does not imply that the projected bytes were admitted; permission-only file-mode equality also does not imply exact mode equality | Copy each local evidence object once into a private snapshot, validate and project only those same bytes, recheck final `HEAD` and tracked-tree cleanliness after record construction, compare the complete temporary-file mode to exactly `0644`, and falsify each special mode bit independently |
| C-34 | Snapshot byte identity does not admit a field that its validation predicate ignores | Project only exact validated local fields into closeout; omit the browser input digest and package/coverage snapshot digests because this closeout has no owner-valid predicate for their semantics |
| C-35 | For a multi-document JSON stream, `jq -e predicate` returns the truth status of the last output and therefore does not imply that the first document later selected by `--slurpfile` passed | Slurp each local snapshot during validation, require exactly one document, apply the predicate to that document, and admit the exact sorted Chromium/Firefox/WebKit project inventory |
| C-36 | Rejecting only literal `false` or `0` does not imply that a trust-significant workflow job or step is reachable; a dynamically false CI step can leave its containing job successful and satisfy the aggregate, while nullable decoding can confuse explicit `if: null` with absence | Require an exact closed job inventory, presence-aware condition decoding, and exact absent-or-owner condition for every job and step in required CI and release workflows; retain exact named conditional exceptions only; and falsify dynamic false plus explicit-null conditions on required CI and release routes |
| C-37 | A successful job whose identifier is `platform-smoke` does not imply macOS platform execution, and rejection-only binding selectors can pass vacuously when their owner workflow is already invalid | Bind each required CI job to its exact provider-check name and runner, require the exact fail-closed platform-smoke command, reject reusable-job and no-op substitution, assert positive owner admission before every bound mutation table, and route the positive inventory oracle directly through QUALITY-011 and QUALITY-013 |
| C-38 | An exact final platform command does not imply that an earlier step did not rewrite its package-script owner; lossy runner-label normalization does not prove an exact scalar; negative package-gate selectors do not imply that the real CI and release owners pass; and an unparsed closeout snippet can regress its singleton predicate | Close the ordered five-step macOS inventory and exact package-script owner command, compare each runner as an exact string scalar, bind a positive oracle that admits both real package-gate workflows, restore `length == 1`, and execute the affected selectors and closeout filter |
| C-39 | An exact local-action path does not imply exact repository-controlled action semantics, and zero-value decoding does not distinguish an absent step key from `null`, empty, or whitespace-bearing dual execution syntax | Admit the exact setup-action bytes by digest, reject a nested semantic-shadow mutation, track `run`, `uses`, and `with` key presence, compare the exact YAML block value including its terminal newline, and reject dual or explicit-empty execution keys |
| C-40 | Valid selector functions and commands do not imply that the complete anti-vacuity proof set remains bound when a critical selector is removed; whitespace field splitting does not imply Bash-to-direct-exec argv equivalence for quoted literal words | Extend the existing exact selector inventory to the QUALITY-011 and QUALITY-013 scenarios and independently falsify missing and surplus selectors; replace whitespace splitting only at the README boundary with a bounded expansion-free literal shell-word lexer that preserves safe quotes, escapes, and concatenation while rejecting operators, expansion, globbing, line continuation, and malformed quotes |
| C-41 | An exact selector inventory keyed only by scenario identity does not imply that the scenario remains bound to its owning requirement | Key every protected selector inventory by the exact `(requirementId, scenarioId)` pair and falsify owner-only transfer independently for each newly protected anti-vacuity scenario |
| C-42 | Marking a required scenario seen before an empty-selector early return does not imply exact-set admission; a lexer accepting NUL cannot preserve direct-exec argv; and a P0-P2-only review threshold does not imply the plan's stronger no-unresolved-finding completion criterion | Compare every required selector set before the generic empty path and falsify complete deletion for each critical scenario; reject NUL in every lexer state and preserve the mutant; align all final review thresholds to no unresolved confirmed finding |
| C-43 | Unicode whitespace trimming does not preserve Bash IFS or JSON whitespace semantics; a top-level NUL check does not inspect a byte consumed as an escape lookahead; and double quotes do not suppress interactive Bash history expansion | Trim only Bash space/tab delimiters around the command, preserve all other literal command bytes and exact JSON fence bytes, reject escaped NUL, reject unescaped `!` inside double quotes, and preserve Bash-equivalent `\\!` as a literal backslash-plus-exclamation argument |
| C-44 | Symmetric trimming of Bash delimiters does not distinguish an unescaped trailing separator from a trailing separator escaped into the final argv word | Trim only leading space/tab before the fixed command prefix, let the lexer discard unescaped trailing delimiters, and preserve escaped trailing space and tab with direct Bash-equivalent argv mutants |
| C-45 | A missing-function mutant on a newly exact-set-protected scenario does not imply that generic function-existence validation remains independently exercised because exact-set admission now rejects it first | Route the existing missing-function mutant through an unprotected selector-bearing binding while retaining the separate exact-set missing, empty, surplus, and owner-transfer mutants |
| C-46 | Consuming one escaped `!` does not preserve Bash semantics for two or more preceding backslashes because history suppression precedes quoted or unquoted backslash collapse | Consume the complete backslash run before `!`, project `ceil(n/2)` backslashes when double quoted and `floor(n/2)` when unquoted, retain a literal `!`, and preserve mutants for both states at run lengths one through four |
| C-47 | Aligning final committed-object review thresholds does not prevent an earlier candidate-preparation P0-P2 cutoff from dropping a confirmed P3 before those reviews | Require exact evidence for every remaining confirmed objection and finding at candidate preparation |
| C-48 | A correct pure inventory mutant does not justify repeating generic AST parsing and `go list` discovery before reaching that mutant, and repeated I/O obscures the boundary being tested | Run exact requirement/scenario/selector inventory admission as a complete pure first phase, then run the existing generic selector-function and active-file validation once for the positive object |
| C-49 | Scanning the whole remaining backslash run only when looking for a history marker, then advancing by one pair when no marker exists, yields `n + (n-2) + ... = O(n^2)` work on a package-bounded command line | Consume each complete backslash run exactly once, dispatch its terminal byte with the C-46 quoted/unquoted semantics, and preserve a 128-KiB non-history run regression |
| C-50 | Moving global inventory admission before generic executability does not imply that partial generic fixtures contain the repository-global inventory, and forcing them to do so would couple local error tests to unrelated owners | Keep one production composition function, expose one pure exact-inventory phase and one generic executability phase locally, and route partial fixtures only to the phase whose error they falsify |
| C-51 | Source presence and full-package execution of generic missing-function and invalid-signature tests do not imply that selective QUALITY-010 proof routing invokes those two executability conjuncts | Bind both selectors to the QUALITY-010 executability scenario, close its exact four-selector inventory, and run empty, missing, surplus, and owner-transfer mutants against that scenario too |
| C-52 | Binding a representative subset of typed workflow-oracle tests does not imply selective proof for permission floors, prior-step order and command identity, duplicate names, need-success bypasses, admitted optional paths, or typed needs normalization | Classify every owner-relevant test in `workflow_package_gate_oracle_test.go`, bind the complete seventeen-selector QUALITY-013 surface, and make that exact set part of the protected requirement/scenario inventory |
| C-53 | A source-level intentional semantic change does not imply inclusion in the closed release record, and requiring one named Go-test parameter rejects the toolchain-valid unnamed form | Declare the readiness-closeout character-reference behavior as a breaking change with migration guidance and an exact rendered-note witness; admit zero or one Go-test parameter name, bind the unnamed-parameter regression, expand QUALITY-010 executability to five exact selectors, and protect the three-selector QUALITY-024 release-record inventory |
| C-54 | Decoding before structural Markdown parsing can create a false cell boundary; a body-level UI state does not imply coverage of a distinct stable content substate; and generic release prose does not declare specific runtime additions or a removed keyboard contract | Split original Markdown bytes before one-pass text decoding and falsify an encoded pipe; add specifications no-match to the full browser matrix with exact content-state identity; declare Arrow-key removal with migration guidance plus pilot-all and witness-selector additions, project every exact record entry into rendered notes, and refresh the readiness native-source, generated CLI-contract, and public ABI golden projections |
| C-55 | Showing a bare family-discovery executable in root help does not imply that an exact-tarball npm consumer can execute it, and searching stdout before running a separately hard-coded argv is a false-green continuity witness | Project the copyable offline npm exec route, parse and execute the displayed route through the installed consumer, reject the bare-route mutant before family discovery, and refresh the app native-source, generated CLI-contract, and public ABI golden projections |
| C-56 | Unicode whitespace normalization before parsing a displayed shell command does not preserve copied Bash argv because NBSP is not an IFS delimiter | Remove only authored leading ASCII space/tab indentation, preserve all trailing bytes, and reject leading and trailing NBSP mutants |
| C-57 | Executing one displayed root-help command does not imply a continuous installed-user route when family, leaf, preset, and README transitions are rediscovered or hard-coded by the witness | Display a copyable offline npm command at every help transition, parse and execute those exact bytes, execute every contract-owned preset route, discover the installed README path from help, and reject bare or missing intermediate routes |
| C-58 | Source implementation and generic release prose do not imply a closed, correctly classified consumer change record | Protect the exact onboarding addition, classify removal of installed `AGENTS.md` and `CONTRIBUTING.md` as breaking with migration guidance, and extend absolute-symlink migration to manifest ancestors plus source paths |
| C-59 | Exact required step identities do not imply that an earlier unreviewed step cannot rewrite their npm-script owners | Hash the complete ordered semantic step inventory for CI `source-quality`, CI `browser-runtime`, and release `candidate`, including execution-key presence and values, and reject inserted script-shadow steps in all three jobs |
| C-60 | File size alone does not prove a god file, but five independent owners plus a demonstrated missed invariant do; conversely, one physical witness path shared by exact QUALITY-011 and QUALITY-013 selector inventories prevents a sound one-owner-per-file split | Inventory every tracked file at or above 1,000 LOC or 65,536 bytes; separate browser, runtime-precondition, source-policy, scanner-policy, and neutral support files; retain the QUALITY-011/013 cluster; update exact binding paths and protect moved selectors against deletion, owner transfer, surplus, and stale-path substitution |
| C-61 | A hash over selected step fields does not imply exact semantic step identity when valid GitHub step fields are omitted | Include `id` and `timeout-minutes` values and key presence in every closed step projection, and reject each independently in CI source quality, CI browser runtime, and the release candidate |
| C-62 | Exact requirement, scenario, and selector equality does not imply that selectors remain in the file reviewed as their owner | Add one exact `witnessPath` inventory for every protected selector set and reject relocation independently from missing, surplus, and owner-transfer mutations |
| C-63 | A reviewed dirty diff does not imply that candidate staging contains new untracked owner files | Close the untracked candidate inventory to the five extracted workflow files, stage the complete reviewed path union, and require staged-path equality plus an empty unstaged and untracked remainder |
| C-64 | A threshold-complete path set does not imply that recorded file measurements are exact after surrounding edits | Recompute LOC and bytes from the final candidate snapshot, correct the stale `internal/app/app_test.go` byte count, and require exact final ledger equality before review |
| C-65 | Extracting scanner tests into a cohesive file does not imply selective proof ownership when no requirement binding names the new selectors | Bind CodeQL, OSV, and Scorecard permission/publication invariants to the extracted scanner owner, admit their exact selectors and path, and falsify deletion, surplus, owner transfer, and relocation |
| C-66 | Adding an installed invocation to generated help does not imply that every shipped leaf exposes valid copyable bytes in the exact tarball | Traverse every displayed family and leaf route from the installed artifact, execute each exact help route, compare each installed invocation to its exact bare usage, and retain preset and README transitions as additional end-to-end witnesses |
| C-67 | A logically correct staging predicate is not an executable plan when its temporary-file cleanup is rejected by the active destructive-action guard | Hold the reviewed, expected-untracked, actual-untracked, and staged path inventories in memory; pass the exact untracked inventory to `git add` through stdin; preserve equality and empty-remainder checks without temporary paths or cleanup |
| C-68 | Absence of an observed literal write scope does not imply an explicitly declared read-only scanner floor, and one required provider write scope does not exclude surplus write authority | Require exact workflow, advisory-job, and provider-job permission maps for CodeQL, OSV, advisory Scorecard, and public Scorecard; preserve intentional inheritance explicitly; reject a missing workflow floor, advisory write authority, and surplus provider write authority independently |
| C-69 | Comparing Installed invocation while scanning lines does not imply comparison with the final unique Usage line, and raw string prefix does not preserve the command-token boundary | Collect the unique Usage and Installed invocation before comparison, require their exact authored order, admit only exact command token or token-plus-space, compare full installed bytes afterward, and reject installed-before-Usage plus prefix-collision mutants |
| C-70 | A full package test containing C-69 does not imply that selective QUALITY-019 proof preserves or executes that falsifier | Add C-69 to the exact installed-package selector set and witness path, strengthen the owner requirement to name every leaf and exact ordered command-token binding, and reject selector deletion, surplus, owner transfer, and path relocation |
| C-71 | A passing current browser matrix does not imply that the final provider-closeout predicate admits that matrix when its per-project count is stale | Bind the executable closeout snapshot predicate to the current owner count of 31 passed tests for each of Chromium, Firefox, and WebKit before publishing or reporting provider closure |
| C-72 | Unique condition strings do not imply mutually exclusive machine-selectable CLI variants, and raw argv does not imply one selector state while repeated single-value flags use last-write-wins | Admit an optional canonical complete CLI-flag conjunction model; require equal allowed dimensions and disjoint assignments; close all twelve valid adoption output states against native option admission; derive every ABI condition from parsed argv; reject repeated `--mode` and `--pilot`; and project the intentional behavior change through the release record |
| C-73 | An exact decomposition-owner inventory remains exact only for the snapshot from which it was derived; a later owner-aligned split can add a required file without changing the earlier five-file predicate | Extend the decomposition-owner subset to the six files including `internal/tools/commandcontractgen/condition_model.go`, and retain exact staged-path equality plus empty unstaged and untracked remainders |
| C-74 | A valued flag being present in raw argv does not imply a literal condition state when its parser admits the empty string and native normalization uses empty as the omission sentinel | Reject an explicitly empty `--pilot` value before option construction, bind the exact CLI diagnostic and condition non-projection, and disclose the intentional rejection with migration guidance |
| C-75 | The decomposition-owner subset does not imply the set currently untracked after an earlier candidate commit has already admitted five members of that subset | In the correction amend, require the current untracked set to contain only `condition_model.go`, stage the exact reviewed correction-path union, and independently require all six decomposition owners to be present in the baseline-relative additions |
| C-76 | Enumerating hard-coded native mode and pilot literals in a test does not imply future closure against the native admission domain when that owner changes and its source digest is refreshed | Build native admission maps and immutable test projections from one internal mode list and one pilot list; derive the closure loops from those projections and retain exact 80-combination and twelve-valid-state assertions |
| C-77 | A generic canonical/disjoint condition grammar does not imply generic finite native-option or argv closure when only one current definition owns those executable witnesses | Admit `cli_flag_conjunction_v1` only on the adoption output definition, reject an unowned second opt-in, and require a future owner to extend generator admission together with its own native-domain and argv proof |
| C-78 | A complete owner-specific subset of added files does not imply the complete candidate added-file inventory relative to the reviewed baseline | Require exact equality with the complete baseline-relative added-path inventory after final correction freeze and separately prove that the six decomposition owners are a subset |
| C-79 | Covering all twelve valid normalized assignments does not imply that every exercised argv which emits JSON is bound to its exact condition and root variant | Bind the reachable guidance mode/scope failure argv to the guidance-report condition and `06-guidance-report` root before asserting its failure body |
| C-80 | Restricting a condition model by definition ID does not imply that another command or direction cannot reference that admitted definition | Require the exact `(adoption-contract-envelope, output, adoption-output-definition)` triple and reject command, direction, and definition aliases independently |
| C-81 | Exact source sizes recorded in explanatory prose do not remain exact after later corrections, even when the threshold ledger is refreshed | Remove volatile inline line counts from the decomposition rationale and keep snapshot-specific measurements only in the deterministically validated ledger |
| C-82 | Adding condition and variant coordinates to one JSON test case does not imply their retention when conditional assertions let both coordinates be deleted and a duplicate condition preserves the global count | Require `assertJSON` if and only if both route coordinates are non-empty for each case, then run argv-condition and variant-root assertions unconditionally on every JSON case |
| C-83 | A biconditional among mutable fixture fields does not imply that the fixture matches actual runtime emission, and deleting the whole case evades per-case checks | Require observed non-empty stdout exactly when a JSON assertion is declared, parse every observed stdout, and preserve the exact sorted fourteen-case JSON inventory |
| C-84 | A cohesive file boundary does not justify duplicating an identical generic algorithm already owned by the same Go package | Replace all condition-model calls with the existing `sortedKeys` helper and delete the duplicate helper plus unused import |
| C-85 | A critical binding whose selector exists and executes does not imply that the selected test reaches the claimed byte-admission invariant | Replace the README-only selector on the Mach-O compatibility scenario with the exact four-test negative/positive/parser inventory, bind its exact witness path in the coverage owner, and apply the existing empty, missing, surplus, owner-transfer, and relocation mutations |
| C-86 | Closing one semantic false route does not imply that other exact selectors reach the operation named by their scenario | For Python wheel-platform parity, bind README ownership, exact all-target wheel metadata/filename projection, and verifier rejection; for browser one-shot cleanup, replace the fixed-launcher selector with the exact three cleanup/concurrency tests while retaining the launcher in its separate package-boundary scenario; protect both exact selector/path inventories with the existing five mutation classes |
| C-87 | A package-reference closure test can pass while every mutable-release-fact detector remains unreachable | Replace the PACKAGE-007 selector with the existing ten-class stale-fact falsifier, retain reference closure only in its PACKAGE-001 scenario, and protect the exact requirement/scenario/selector/path tuple with empty, missing, surplus, owner-transfer, and relocation mutations |
| C-88 | Exact permissions for every expected scanner job do not imply that no unclassified write-capable job exists | Require the workflow job count to equal the disjoint advisory/provider expectation count before validating each expected job, and reject an added unclassified `contents: write` job for CodeQL, OSV, and Scorecard |
| C-89 | A canonical installed help route does not imply that generated continuations resolve the artifact in every supported launcher channel | Admit one immutable `npm_offline`, `python_module`, or `path` invocation profile at the launcher boundary; thread one renderer through the exact generated-field inventory; preserve caller-owned strings; execute exact npm and wheel continuations; reject wrong-profile, bare, missing, surplus, and caller-rewrite mutants; bind `PACKAGE-002`, `PACKAGE-003`, `PACKAGE-006`, `QUALITY-019`, and the public-string migration under `QUALITY-024` |
| C-90 | An executable native-output selector does not imply that the selected test observes the declared output root or its complete native owner | Close the root-distinct output inventory over adoption-contract-envelope, pilot-admission, and self-check; bind them respectively to `internal/app/cli_abi_test.go` selectors `TestAdoptionContractEnvelopeCLIABI`, `TestStandaloneMultiVariantCommandsUseExactRootShapes`, and `TestSelfCheckOutputUsesExactRootShape`; require exact native source sets adoption=`{internal/command/adoptioncontract}`, pilot=`{internal/app, internal/command/pilotadmission}`, self-check=`{internal/app}`; protect source sets and exact command/direction/path/test/executable-command/requirement/scenario tuples with empty, missing, surplus, substitution, relocation, direction-transfer, scenario-transfer, command-drift, and owner-transfer mutants under `PACKAGE-002`, `QUALITY-004`, and `SPEC-011` |
| C-91 | An absolute launcher path does not imply that the value is safe to project into generated commands or diagnostics | Reject report-visible secret-like and Unicode control content at Python launcher admission, use field-only errors that never disclose the value, and exercise the shared redaction corpus plus control mutants |
| C-92 | Closing continuation string fields does not imply closure of help display routes, structured argv, project workflow identity, or the installed wheel's complete next-step chain | Bind every owned help/display/argv sink to one immutable renderer, preserve caller-owned native-witness argv, build project workflow plans and source-report hashes with that renderer, bind `TestGeneratedCommandInvocationProfileRouteClosure`, traverse every installed wheel family/leaf route, execute exact emitted agent-route argv directly, and reject indentation, Unicode-whitespace, expansion, missing, surplus, relocation, and wrong-profile mutants |
| C-93 | Removing a temporary file and immediately recreating its pathname does not imply a different `os.SameFile` identity because Linux may reuse the released inode | Pre-create a replacement with the exact expected bytes and mode while the writer's temporary object is still live, assert that the two coexisting objects have distinct identities, then remove the temporary entry and rename that replacement into its pathname at the deterministic barrier; identity is the only changed dimension and the exact diagnostic becomes platform-independent |
| C-94 | A fully rendered DOM and prior successful locator reads do not imply that a Firefox page-realm `evaluateAll` returns within the bounded test budget | Express ordered graph/table equality as retryable row-count equality plus an indexed `data-identity` equality for every expected element; reject missing, surplus, reordered, duplicated, substituted, and absent identities while retaining one worker, zero retries, and the 30-second timeout |
| C-95 | An exact size ledger for one frozen snapshot does not remain exact after a later static-analysis or provider correction | Recompute the complete `LOC >= 1000 or bytes >= 65536` ledger only after final source and document bytes freeze, then require exact path, LOC, and byte equality before committed-object review |
| C-96 | Typed YAML decoding does not imply that execution-affecting or unknown workflow keys were absent, because unmodeled keys can be discarded before semantic validation | Admit every tracked workflow through a raw `yaml.Node` closed-key oracle at workflow, job, and step scope; permit only the two exact owner-reviewed release environments; reject unknown, duplicate, merge, container, strategy, service, output, job-concurrency, reusable-job, and step-execution-control mutants before typed decoding |
| C-97 | A source-hygiene scanner that covers several text extensions does not imply closure over the authored text languages actually shipped as embedded browser assets | Add CSS to the admitted text extension set and derive staged-blob and worktree mutants from every unique extension in the exact tracked browser-asset inventory, while leaving identifier boundaries and digest-substring admission unchanged |
| C-98 | Removing one bulk Firefox page-realm evaluation does not imply that repeated manual `waitForFunction` plus `evaluate` range synthesis in adjacent selection scenarios is bounded; two immutable provider attempts stalled on different selection tests | Create and collapse ordinary native selection through Playwright `selectText` and click actions; for the nonzero Unicode range, compute strict UTF-16 and code-point bounds independently in the test runner and perform one locator-scoped exact-range operation without query scanning, clamping, or manual event dispatch; delete the shared helper without changing production code, test identities, retries, worker count, or timeout |
| C-99 | The historical audit baseline does not imply the current Git parent, remote `main`, pull-request base, provider base, or feature lease after independently reviewed dependency merges and correction publications | Preserve `3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64` only as `audit_baseline_sha`; require the singleton parent and remote `main` to equal integration base `0df4c28bac9737f476f7dc66030363b8b40d5417`; bind each publication to its exact observed feature lease, beginning with `1a681c47911680d101d36b48ce818ea1905a7148` for the first publication; after every push and before PR-body or provider mutation require exact PR author, head, base, open state, and non-merge state; use the integration base for PR diff, closeout, and provider projections |
| C-100 | A previously valid coverage count does not imply the final regenerated artifact retains that count after new bound scenarios | Require the final coverage snapshot to contain exactly 69 requirements, 69 bound requirements, 173 scenarios, and 78 commands; reject the stale value 167 and adjacent 172/174 counterexamples |
| C-101 | `unicode.IsControl` rejection does not imply rejection of report-visible Unicode format controls because bidi controls are category `Cf`, not `Cc` | Reject both Unicode `Cc` and `Cf` at the existing Python launcher boundary, retain field-only diagnostics, and exhaustively equate the admitted category predicate and rejection/non-disclosure oracle with every Unicode scalar in `Cc or Cf`, including non-bidi `Cf` values |
| C-102 | Listing a public alias in `allowedFlags` does not imply that every accepted alias composition has an exact input/output condition, and sequential parsing does not make repeated selectors unambiguous | Retain the compatible `--stack-diverse` alias, declare `--contract-envelope --stack-diverse` in the exact pilot input/output variants, execute that route through the public CLI oracle, reject repeated or mixed `--pilot`/`--stack-diverse` selectors in either order before reading input, and project the newly rejected formerly accepted argv through QUALITY-004 plus the breaking change record and migration |
| C-103 | A bound test that checks selected release-record entries does not imply that the complete reviewed machine declaration is closed; structural admission and regenerated notes can remain consistent after semantic deletion or surplus | Require ordered equality for every current breaking change ID/summary, addition ID/summary, and migration step plus byte-for-byte equality with one independently authored complete current release-note projection; reject per-entry deletion plus ID/summary substitution, every adjacent reorder, one valid machine surplus per inventory, reordered or relocated bullets, in-block surplus, and appended surplus, duplicate, or second owned sections through the existing QUALITY-024 selector |
| C-104 | Quoting a shell variable does not imply that an immediately adjacent colon is literal in zsh; `"$final_sha:refs/..."` expands a modified parameter and makes the reviewed publication step non-executable | Use `"${final_sha}:refs/..."`, scan the complete tracked plan for unbraced variable-colon forms, and bind publication to the corrected literal refspec plus the existing exact remote lease; add no repository-wide shell abstraction or permanent product gate |
| C-105 | A feature lease admitted before one successful force-with-lease publication does not remain current after that publication or a later amend | Preserve `1a681c47911680d101d36b48ce818ea1905a7148` as the historical first-publication lease, require the next correction publication lease to equal current remote head `90090a5c712efa70b900fed0e115274cfa4773f0`, and reject any mismatch before mutation; retain one literal final SHA as the new publication result |
| C-106 | An exact baseline-relative added-file inventory does not remain complete when later correction epochs add owner tests after the inventory snapshot, and a historical untracked-file predicate does not describe the current amend | Recompute the final inventory as 21 exact paths, add the CLI output-witness, invocation-profile, and Python continuation tests, require the C-106 correction path set to equal only the two reviewed design/plan files with no untracked remainder, and retain the six-file decomposition subset proof |
| C-107 | Checking each required Scorecard output input value does not imply that the complete `with` input set is exact; an added authority-bearing input can preserve every positive assertion | Require the exact three-key input set and values for `publish_results`, `results_file`, and `results_format`, and make the same selector reject a surplus `repo_token` mutant |
| C-108 | A manually listed requirement-delta claim does not imply parity with the actual base-to-candidate invariant map | Recompute the exact changed invariant IDs, restore `SPEC-011` and `QUALITY-005`, `QUALITY-006`, and `QUALITY-007`, and require the P10 declaration to contain all 30 changed IDs with no surplus |
| C-109 | Declaring that volatile inline measurements were removed does not imply that the decomposition rationale contains no stale numeric qualifiers | Remove the numeric qualifiers from all four small-file rationale bullets and retain snapshot-specific sizes only in the threshold ledger |
| C-110 | A generic truth-expression normalizer does not prove exact YAML boolean identity; the string `true }}` can normalize to truth while changing the owned action input | Require `publish_results` to decode as the literal boolean `true`, remove the unused generic helper, and make the same selector reject the string-substitution mutant |
| C-111 | A correction set described as current or latest without an epoch qualifier does not remain current after a later correction changes another owner file | Time-index every historical two-file and 21-path statement to the C-106 freeze and reserve that epoch's correction authority for P12.2's then-current exact three-file C-107 through C-114 set |
| C-112 | Exact inputs on one named Scorecard step do not imply that no second Scorecard action carries parallel publication authority | Require the selected named step to be the sole `ossf/scorecard-action` step and make the same boundary predicate reject a differently named second-action mutant with surplus `repo_token` input |
| C-113 | A lowercase literal prefix does not classify the complete Scorecard-action subset because GitHub owner/repository identity is case-insensitive | Split one action reference at its single `@`, compare only the owner/repository portion with ASCII case-insensitive equality, preserve the ref bytes, and reject a mixed-case second-action mutant while excluding distinct repositories, subpaths, and malformed references |
| C-114 | Unicode simple case folding is strictly broader than ASCII provider repository identity | Reject any non-ASCII repository byte before case-insensitive comparison and make a long-s repository mutant fail while retaining valid ASCII case variants |
| C-115 | Context initialization plus a constant wrapper loader does not imply bounded execution when source inspection proves that the wrapper still performs avoidable page-realm evaluations, creates a temporary page, and re-executes the context init script for each audit; deleting only the auxiliary version probe would preserve that higher-exposure topology | Remove `@axe-core/playwright`; initialize the exact pinned `axe-core` source once per test context; fail closed unless `page.frames()` is exactly the singleton `[page.mainFrame()]`; in one direct evaluation preserve the wrapper's same-origin and `playwright` branding configuration, require the pinned pre-run version, and run default rules plus explicitly enabled `target-size` through an exact closed options object; require returned `testEngine` name `axe-core` and the pinned version; preserve rule applicability and add one combined negative fixture that requires both a `target-size` violation on an undersized named control and a default `button-name` violation on a normal-sized unnamed control; isolate zero-frame, child-frame, absent/wrong pre-run version with no run, exact configure and run-options closure, absent/wrong result name or version, one-evaluation, and no-temporary-page mutants; preserve one worker, zero retries, the 30-second timeout, and the existing diagnostic policy |
| C-116 | Fourteen preceding passes do not imply bounded first-attempt graph proof: on immutable iteration 15 the visible SVG locator resolved but `boundingBox()` never returned before the 30-second deadline; moreover, DOM-derived expected identities, viewBox, visibility, minimum width, non-`none` first-edge stroke, and a PNG byte threshold do not imply the admitted local SVG contract because fixture-equal cache, omission, opacity-zero, hidden-descendant, hidden-overflow, hidden trust-state tables, one-pixel-height, geometry-override, individual-transform, phase-split animation, delayed transition, external SMIL, zoom, content-visibility, text-security, empty-label, text-layout, zero-dash, and degenerate-edge mutants survive weaker or circular oracles | Remove pass-path `boundingBox`, raw computed-style evaluation, and element screenshot calls; intercept the exact one app-issued same-origin graph POST, inject a safe response sentinel absent upstream, observe that response, and require its frozen ordered node and edge records plus sentinel to equal graph metadata, exact leaf topology, SVG children, and visible opaque graph tables; independently compute the viewBox, node geometry, labels, and non-degenerate edge coordinates from response primitives and the restated layout formula; require visible owned viewport and SVG, exact viewport scrolling, explicit local display, visibility, opacity, complete transform-family, no CSS animation or transition time on the owned ancestor chain, no declarative SVG animation in the document, zoom, content visibility, filter, clip-path, and mask values, `800px` minimum width, computed height of at least `180px`, exact visible and opaque node shape/label attributes, computed geometry, direct text, text security, and bounded text-layout serializations, and positive visible opaque non-dashed `1.5px` stroke on every childless edge without applying a bounding-box visibility matcher to zero-thickness SVG lines; retain failure-only diagnostics, one worker, zero retries, and 30 seconds; restart the complete immutable 30-process Firefox epoch from iteration 1 |
| C-117 | A successful `chmod` call does not imply that a setgid mutant materialized when Darwin clears the bit for a file whose group is outside the caller's groups | Normalize only the setgid test root to the effective group before temp creation, require exact post-`chmod` mode materialization for every mode mutant, and leave the correctly fail-closed writer unchanged |
| C-118 | A handoff submitted from one rendered view does not imply that its later response still owns the workspace view-state projection after the user opens a newer view | Capture the active view request identity at submission; always render the admitted handoff result in its independent packet region, but update the global view-state projection only when that view identity is still current; preserve server submission and do not pretend client abort can revoke an already committed handoff |
| C-119 | A fully rendered document with complete successful local resources does not imply that Playwright Firefox will report either `load` or `domcontentloaded` before the unchanged test deadline | Route every workspace open and reload through one web-first readiness policy that waits only for navigation commit, requires a successful main-resource response and the exact visible server-owned workspace heading, and leaves the existing state, accessibility, and API assertions as the behavior oracles; retain the raw `about:blank` negative-control navigation and add no retry or timeout increase |
| C-120 | A guard present in a browser helper does not imply that the executable proof depends on it: deleting C-119's HTTP-response guard or weakening its exact heading matcher leaves an all-success navigation matrix green | Add independent main-document 503 falsifiers for both open and reload plus a substring-preserving accessible-name drift falsifier; require every pinned engine to reject each mutant while leaving production code, retry policy, and timeouts unchanged |
| C-121 | A main document received with status 200 and a fully initialized visible workspace does not imply that Playwright resolves even its `commit` lifecycle wait | Arm one exact-URL navigation-response waiter before scheduling location assignment or reload; admit an exact trigger token, successful response, and exact visible heading; exclude same-URL non-navigation responses with an executable 503 decoy; statically exclude provider-falsified direct lifecycle waits from the workspace corpus |
| C-122 | One current correction inventory stated in prose does not equal a later executable inventory merely because both appear in P12.2, and an inventory does not remain current across an amend | Time-index the four-path C-121 staging set to its `c2315fd` epoch and make both current P12.2 owner surfaces name the same exact three post-`c2315fd` correction paths before staging |
| C-123 | Rejecting raw base-URL drift in source does not imply that browser proof depends on every local-origin clause | In the existing navigation test, admit the configured URL and reject non-string input, HTTPS, hostname drift, missing port, username, password, path, query, and fragment independently before any navigation |
| C-124 | Exact trigger-token admission and pending-waiter cleanup present in source do not imply executable dependence when every trigger succeeds and every failure follows a settled response | Inject one deterministic pending response into the existing navigation test; return a wrong token; require the exact token error, observed abort signal, and observed consumption of the waiter rejection; make the fallback response fail distinctly if token admission is deleted |

Exact C-90 binding mappings use
`proofkit.package-boundary.cli-output-root-witnesses` for all three selectors,
`proofkit.supply-chain-quality.cli-abi-golden` for all three selectors, and
`proofkit.spec-proof-core.adoption-contract-envelope-cli-abi` for the adoption
selector. The independent tuple-closure oracle is owned by
`proofkit.supply-chain-quality.cli-output-witness-contract` at
`internal/app/cli_output_witness_contract_test.go`, selector
`TestRootDistinctOutputWitnessBindingsAreExact`; it is intentionally separate
from the general CLI topology corpus. Every row has direction `output`. The
selector/source oracle rejects
missing, surplus, or substituted native source paths independently of generic
digest freshness, including conversion between incomplete `nativeSource` and
`nativeSources` forms.

These corrections do not add commands, evidence classes, provider claims, or
general-purpose abstractions. They are overturned only by an owner-approved
contract that removes the corresponding identity, ABI, executability, SemVer,
or wire-consumer invariant.

### C-40 decision record

```text
problem:
  Exact proof bindings could silently lose a critical anti-vacuity selector,
  and safe quoted README words could be executed as different argv.
chosen owner boundary:
  REQ-PROOFKIT-QUALITY-010 owns selector-inventory admission;
  REQ-PROOFKIT-SPEC-001 and REQ-PROOFKIT-QUALITY-019 own the installed README
  command-to-current-product trace.
rejected lower-cost alternative:
  Documentation-only quoting restrictions leave an executable false reject;
  checking only selector existence leaves removal of a valid critical
  selector invisible.
proof invariant:
  Both critical scenarios equal their closed selector sets, and every admitted
  README literal word maps to the same byte argument under bounded Bash
  quoting and direct execution.
non-claims:
  This is not a complete shell or Markdown parser and admits no expansion,
  substitution, control operator, glob, multiline command, or arbitrary npm
  command.
rollback or overturn condition:
  An owner-approved structured argv field supersedes the README command line,
  or the owning quality requirements remove the exact anti-vacuity scenarios.
why this avoids accidental complexity:
  It extends one existing map and adds one boundary-local lexer with no
  dependency, process invocation, expansion, or reusable parsing layer.
why this avoids premature over-decomposition:
  The lexer has one consumer and remains adjacent to that trust boundary;
  extraction into a package would invent ownership without a second consumer.
```

C-41 retains the C-40 owner boundary, non-claims, rollback condition, and
complexity analysis. Its proof invariant strengthens set equality to exact
triple equality: requirement owner, scenario identity, and selector set.
C-42 retains those boundaries and makes the planned closeout threshold equal
to the design's actual retirement predicate.
C-43 remains inside the same README extraction anti-corruption boundary and
adds no general shell, JSON, or Markdown parsing claim.
C-44 narrows preprocessing further; it adds no parser state or abstraction.
C-45 changes only oracle routing and no production behavior.
C-46 remains inside the bounded lexer and does not add general history
expansion. C-47 changes only closeout policy. C-48 removes repeated work without
weakening the positive integration proof.
C-49 makes the lexer linear in command bytes and adds no new accepted syntax.
C-50 names two already distinct invariants and creates no reusable package or
public abstraction.
C-51 changes only durable proof routing and its anti-deletion oracle.
C-52 leaves tests owned by QUALITY-022, QUALITY-025, and unrelated workflow
requirements in their existing scenarios; it does not claim every test in the
shared file belongs to QUALITY-013.
C-53 changes no readiness runtime behavior: it makes the existing intentional
change discoverable to consumers and aligns selector admission with the Go
toolchain. The release record remains the existing closed owner, and the
unnamed-parameter regression remains inside the existing coverage validator.
C-54 changes no public runtime semantics beyond fixing the confirmed
readiness false green. It adds proof for an already reachable browser state and
documentation for already implemented public changes; it creates no new
parser, UI state, command, or release evidence class.
C-55 changes only the copyable presentation of an existing help route and
binds the installed witness to those displayed bytes. C-56 narrows
preprocessing to Bash-compatible indentation and adds no accepted syntax,
command, resolver, or shell abstraction.
C-57 extends that same route-byte invariant through already existing commands
and the already shipped first-input example; it adds no command or product
policy. C-58 changes only consumer disclosure and migration accuracy.
C-59 closes existing workflow source owners rather than inventing another
evidence class. C-60 follows executable owner boundaries: the two scenarios
that share one exact selector and one single-path binding remain together,
while independently changing peripheral owners move without selector renames.
C-61 extends the existing closed step record without adding a workflow model.
C-62 strengthens the existing selector inventory with its already authoritative
path. C-63 changes only candidate admission, and C-64 changes only exact
measurement evidence. C-65 restores selective routing for existing scanner
requirements without creating a new requirement class. C-66 applies the
existing installed-route invariant uniformly to every leaf; it adds no command,
resolution mechanism, or public input behavior.
C-67 changes no candidate membership or repository bytes; it removes an
execution-environment contradiction from the existing candidate-admission
proof and adds no script or reusable abstraction.
C-68 narrows existing source permission claims to exact checked maps and adds
no provider authority. C-69 changes only installed-help admission and no
command dispatch, JSON shape, exit code, or runtime input semantics.
C-70 changes only durable proof routing and requirement precision.
C-71 changes only the executable final-closeout predicate and adds no provider
claim.
C-72 changes only the public root-variant selection contract and two formerly
ambiguous repeated-flag inputs; it adds no runtime schema validator, general
condition language, command, evidence class, or provider authority.
C-73 changes no runtime or public contract. It repairs only candidate
admission after the C-72 owner split. Keeping the cohesive pure condition
algorithm separate is lower-cost than returning its grammar and disjointness
logic to the generator I/O owner, while splitting that algorithm further would
be premature over-decomposition.
C-74 changes only one formerly ambiguous empty-valued invocation. Reusing the
existing parser error path and ABI corpus is lower-cost than adding a second
normalization layer or another condition state.
C-75 changes no repository contract. It keeps current worktree state and
baseline-relative candidate identity as distinct evidence classes instead of
adding a stateful staging abstraction.
C-76 changes no accepted option or public package surface. Two clone-returning
accessors in an `internal` package remove duplicated test authority and remain
cohesive with the native option owner.
C-77 removes an unproven extension point rather than adding a framework. A
future second owner can overturn the one-definition admission only with the
proof whose absence currently justifies rejection.
C-78 changes no code or contract. It separates whole-candidate identity from
one semantic owner subset using the existing in-memory staging predicates.
C-79 and C-80 add no product behavior: they close existing ABI and generator
proof paths. C-81 removes redundant volatile evidence instead of adding
another measurement owner.
C-82 strengthens only test anti-vacuity and introduces no new abstraction or
runtime branch.
C-83 adds only observed-output and exact-inventory conjuncts to the same ABI
oracle; it changes no command behavior.
C-84 reduces the implementation by one identical helper and does not change
condition ordering or package ownership.
C-85 changes only selective proof routing and its anti-deletion oracle; it
adds no package behavior, platform claim, test implementation, or evidence
class.
C-86 adds one boundary-local projection test and otherwise reuses existing
tests and validator machinery. It separates launcher and cleanup semantics,
changes no runtime behavior, and avoids a generic coverage-threshold framework
whose line coverage would not prove semantic adequacy.
C-87 changes only proof routing and reuses an existing semantic test; it adds
no runtime branch, file, abstraction, or release evidence class.
C-88 strengthens the existing scanner source oracle with one set-cardinality
conjunct and one mutation case; it adds no workflow model, runtime dependency,
provider claim, or production behavior.
C-89 adds one value renderer because three existing generated-command producers
and two installed channels need the same quoting invariant. It preserves
caller-owned display text, admits launcher identity once, adds no ambient
resolver or runner autodetection, and records the supported-channel public
string change plus migration. The wrapper fields are an anti-corruption
boundary, not a public command or package-manager framework.
C-90 changes source-checkout proof routing, pilot native-source closure, and
anti-substitution oracles only. Its focused self-check witness reuses the
existing contract-derived root assertion. It adds no public runtime schema
field, output-root change, consumer migration, parser, or general source-level
test analyzer.
C-91 adds one bounded value-admission conjunct at the existing launcher
boundary and reuses the shared redaction corpus; it adds no credential model or
secret scanner.
C-92 extends the existing renderer and exact inventory instead of introducing
a second route model. It executes admitted argv directly, retains caller-owned
argv, changes no public JSON field, and records the already-breaking display
and argv prefix migration without adding a shell parser or ambient resolver.
C-93 changes only a negative-test fixture: one pre-existing regular file with
the same content and exact mode provides a cross-platform distinct identity
without adding production synchronization or weakening the writer's mode and
content checks.
C-94 re-expresses the same equality theorem through Playwright's retryable web
assertions. It removes both page-realm callbacks, adds no retry or timeout
policy, does not split the end-to-end flow, and preserves every negative case
implied by exact ordered equality.
C-95 changes only snapshot evidence and prevents explanatory measurements from
outliving the bytes they describe.
C-96 closes an existing source grammar before lossy decoding. It adds no
GitHub Actions schema framework, recursively models no dynamic `on`, `env`,
`with`, or permission vocabulary, and changes no workflow bytes.
C-97 changes only language reachability in the existing source scanner. It
adds no MIME inference or binary classifier and leaves the token predicate
byte-for-byte unchanged.
C-98 changes only how the browser test performs selection. The exact emoji
range retains a nonzero expected start, a two-code-unit DOM span, and a
one-code-point output span, while click collapse preserves the same visible
authority transitions. No test-only production surface or browser-specific
branch is admitted.
C-99 changes temporary closeout authority only. It keeps the original audit
baseline as historical evidence while preventing it from impersonating the
current PR base. The two phases reflect observable state: the old PR base is
not required to equal the new integration base until the new head is pushed;
no repository product behavior or provider result is changed.
C-100 changes one exact artifact predicate after regeneration and introduces
no inferred coverage implication.
C-101 adds one Unicode general-category conjunct at the existing launcher
admission boundary. It adds no normalization, credential model, shell parser,
or alternate display renderer. Python-module paths containing `Cf` change from
accepted to rejected and are therefore declared in the breaking change record.
C-102 preserves all previously valid single-selector pilot routes and the
documented alias. It removes only ambiguous argv sequences, extends the
existing root-shape condition owner, and adds no new command, mode, or output
shape. The repeated-selector rejection is declared as a breaking compatibility
change with an exact migration step.
C-103 strengthens only the existing source-checkout release-declaration
witness and its durable owner projection. It adds no runtime branch, release
record field, second registry, or inferred source-diff completeness claim.
C-104 corrects one temporary execution-owner command and adds no runtime,
public-contract, package, workflow, or business-logic behavior. Its proof is
the exact absence of unbraced variable-colon forms plus successful publication
under the pre-existing remote lease.
C-105 corrects only the temporary publication epoch identity. It adds no
product, provider, branch-protection, or merge authority and does not weaken
the existing exact lease.
C-106 updates only candidate-staging and inventory evidence after owner files
already admitted by earlier corrections. It adds no source file, runtime
behavior, package contract, or new decomposition boundary.
C-107 strengthens one existing QUALITY-007 test predicate without changing
workflow bytes, permissions, or publication behavior.
C-108 corrects temporary plan parity evidence and changes no requirement,
binding, or product behavior.
C-109 removes stale explanatory measurements and changes no decomposition
boundary or source behavior.
C-110 narrows only the QUALITY-007 test oracle to the exact decoded type and
changes no workflow input or runtime behavior.
C-111 corrects temporal language in both review history and temporary closeout
authority and changes no staging operation beyond the already reviewed
three-file set.
C-112 closes the Scorecard-action subset inside the existing QUALITY-007 test
owner and adds no full step inventory, workflow byte, or publication behavior.
C-113 aligns the same bounded classifier with provider repository identity and
adds no general action parser, network dependency, or ref normalization.
C-114 narrows that classifier to its declared ASCII domain and adds no
normalization, Unicode mapping, or provider lookup.
C-115 removes a source-only wrapper dependency and replaces two wrapper audits
per state with one direct call to the already pinned `axe-core` distribution.
Let `D` be the default-enabled axe rules and `t` be default-disabled
`target-size`. Let exact options `O` omit `runOnly`, omit overrides for every
`r in D`, and contain only `rules.target-size.enabled = true`. Axe's selected
rule set under `O` is then `D union {t}` while the check options for each
`r in D` remain unchanged. The old admitted predicate was
`Violations(D) = empty and Violations({t}) = empty and Applicable(t) and
Incomplete(t) = empty`. The new admitted predicate over the one combined
result `R = axe.run(document, O)` is
`R.violations = empty and Applicable(R, t) and Incomplete(R, t) = empty`.
These predicates are equivalent at the per-rule outcome projection because
only `t` changes from unselected to selected; no equality of complete result
objects is claimed. A combined negative fixture must defeat a
`runOnly: target-size` mutant by requiring both a `target-size` violation on an
undersized named control and the default `button-name` violation on a
normal-sized unnamed button in the same result.

The topology oracle must admit `O` by exact closed equality: the top level has
only `rules`; `rules` has only `target-size`; and that record has only the
literal boolean `enabled: true`. Missing, wrong, or surplus keys or values,
including `runOnly: ["target-size", "button-name"]` and any default-rule
override, must fail even though the two-defect fixture could still observe both
named violations.

Inside the direct evaluation, capture `axe`, require the exact pre-run version
and callable `configure` and `run`, apply the wrapper-equivalent closed
configuration `allowedOrigins = ["<same_origin>"]` and
`branding.application = "playwright"`, and only then run. Full result-byte,
timestamp, array-order, tool-option, help-URL, and two-run-to-one-run equality
remain explicit non-claims; QUALITY-022 admits only the pinned engine identity
and accessibility verdict projections named above. Isolated falsifiers must
prove: zero frames and any child frame reject before evaluation;
`page.frames()` equals exactly `[page.mainFrame()]` on admission; an absent or
wrong pre-run version invokes neither `configure` nor `run`; missing
`configure` or `run` fails closed; missing, wrong, or surplus configuration
keys fail the closed topology oracle; an absent or wrong returned
`testEngine.name` or `testEngine.version` rejects unless the pair is exactly
`("axe-core", axeDistributionVersion)`; and each audit performs exactly one
page evaluation and never creates or accesses a temporary page.

The matrix and combined negative control use one dedicated Playwright fixture
that owns a fresh `Page` and its `BrowserContext` for one test state. The
fixture initializes exactly once before the test body and its teardown admits
the test only if that page completed exactly one audit. The harness rejects a
second initialization before another registration and a second audit before
another evaluation, including concurrent attempts; a failed init registration
releases ownership for one retry, while an audit attempt is fail-closed under
the existing zero-retry policy. Reusing one `Page` lifetime for multiple
audited states is not admitted by C-115 and requires a separately owned fixture
topology rather than a caller-invented state token.

The exact QUALITY-022 runtime and topology owners are
`tests/browser/axe-harness.mjs`, `tests/browser/workspace.spec.mjs`, and
`scripts/browser-proof-inputs.test.mjs`. The exact source-only dependency
inventory owners are `package.json`, `package-lock.json`,
`internal/tools/packageverify/main.go`, and
`internal/tools/packageverify/main_test.go`. The durable statement is updated
only in `docs/specs/proofkit-supply-chain-quality/requirements.v1.json` and its
human projection
`docs/specs/proofkit-supply-chain-quality/overview.md`. Existing Proofkit
binding paths and witness identities remain unchanged; no new proof-like owner
is introduced.

The single-main-frame precondition makes removal of the wrapper's recursive
frame topology explicit and fail-closed. A future child frame overturns this
design and requires a separately owned iframe-aware witness. Increasing the
timeout, adding retries, skipping Firefox, or upgrading the browser toolchain
without a causal falsifier are rejected because none proves bounded
first-attempt execution. Removing only the observed version probe is the
lower-byte alternative, but it is rejected because prior exact traces moved
the stall to other operations and the wrapper would retain all other avoidable
page-realm calls and temporary pages.

C-115 is a controlled topology hypothesis, not a proven Firefox root-cause
repair. If a bounded repeated full Firefox project or the exact-head provider
attempt 1 again times out on any Playwright page, locator, or evaluation call,
the hypothesis is falsified and closeout remains blocked. Re-adjudicate the
retained trace before choosing another repair. Only if the new evidence again
localizes the failure to cross-operation engine-level liveness should a pinned
Playwright 1.62 toolchain and browser-lifetime isolation be tested as separate
candidate A/B epochs. Do not combine those changes with C-115 before this
falsifier, because that would erase causal attribution. No C-115 evidence
claims a product or UX defect, a specific browser crash, or the exact
Playwright/Firefox mechanism.

C-116 is the required adjudication of that overturn condition. Let `F(i)` mean
that every test in independent Firefox process `i` terminates successfully
within the unchanged per-test bound. The first epoch observed
`F(1) through F(14)` and `not F(15)`. Therefore the universal claim
`for every i in 1..30, F(i)` is false; the fourteen passes remain diagnostic
evidence but cannot admit the candidate. The retained trace narrows the failed
boundary: `Locator.boundingBox()` began about 1.5 seconds into the test, its
internal locator resolved the visible SVG in about 3.5 milliseconds, and no
successful return was recorded before the deadline. The trace does not
distinguish the later Firefox content-quad response from handle disposal, so
the exact Firefox or Juggler cause remains a non-claim. The preserved page and
failure screenshot show a rendered graph, so no product or UX failure follows
from this tooling-liveness counterexample. The retained trace SHA-256 is
`a08498b0ce74c39a714856c855d7757f0907a8a67df3d06b1cdab3b652904fc7`;
the machine report SHA-256 is
`2e5475d20b3161d6d0128b9097288302ad70a94de57b90c6e569533c114383a9`.

The old graph smoke test also lacked a useful raster theorem. A transparent
SVG can be Playwright-visible and produce a PNG larger than 1,000 bytes, while
an explicit one-pixel height can preserve its viewBox, computed minimum width,
and non-`none` stroke. Thus PNG size does not imply meaningful visible pixels,
and viewBox plus visibility does not imply the prior physical-height floor.
C-116 does not infer a broader raster theorem. It admits one bounded local SVG
structure and computed-style contract under the current owned viewport.

Before activating Traceability, the witness arms an exact same-origin POST
route and request/response observers for `/api/v1/graph`; it does not issue an
independent API request. The route fetches the real upstream response, requires
at least one node, replaces only the first node label with one safe
deterministic sentinel proven absent from the upstream projection, and fulfills
that one app-issued request. The witness then activates the view, admits the
successful response linked to that request, deep-copies and freezes its
projection records, waits for the stable graph, and requires exactly one
matching request, route interception, and response over that window. The
expected node/edge order, count, labels, and endpoint relations come from that
single observed response, never from DOM datasets. The witness separately
equates those records with the graph dataset, the ordered SVG groups and lines,
and both ordered tables, and requires the sentinel in both the first node's
full title and truncated visible text. This rejects a renderer that
consistently omits a record from every derived DOM surface, compares against a
different response, or renders an unchanged fixture-equal cache. The one-field
intervention proves dependency on this response channel; it does not prove
independent causal consumption of every response field.

The retryable style contract requires both `.graph-viewport` and its direct
SVG child to be visible with their exact current `display`, `visibility`,
`opacity`, transform-family, `filter`, `clip-path`, and `mask-image` values. The
closed transform family is `transform`, `translate`, `rotate`, `scale`, and
`offset-path`, each with its exact current `none` value. The viewport must
retain exact computed `overflow-x: auto` and `overflow-y: auto`; an isolated
`hidden` or `clip` mutant must fail. Every element on the exact owned chain
`html > body > main > #workspace-content > .graph-viewport`, the direct SVG,
and every admitted node group, rectangle, text, and edge must have computed
`animation-name: none`, `transition-duration: 0s`, and
`transition-delay: 0s`. The viewport, SVG, and admitted graph elements also
have computed `zoom: 1` and `content-visibility: visible`; every graph element
retains exact `filter: none`, `clip-path: none`, and `mask-image: none`.
Isolated zoom, content-visibility, positive-duration, zero-duration
positive-delay, local phase-split animation, and ancestor inherited-paint
phase-split animation mutants must fail. Closing CSS animation and both
transition time dimensions on the owned ancestor chain prevents retrying
property assertions from admitting either confirmed alternating CSS mutant;
simultaneous stability under script-driven mutation or the Web Animations API
remains an explicit non-claim. The SVG requires its `800px` computed minimum
width and a computed height matched
by the explicit numeric CSS serialization for values at least 180 pixels. It
requires every node group, rectangle, and text label to have non-`none` local
display, visible visibility, opacity equal to one, and the owned positive
opaque fill/stroke where applicable. Rectangle and text fill opacity and
rectangle stroke opacity must each equal one; isolated zero-value mutants for
all three properties must fail. Each node also has exactly one accessible
title with the response-derived label. For response-order index `i`, the
independent formula computes `x = 28 + (i mod 2) * 390` and
`y = 28 + floor(i / 2) * 76`; the direct children must be exactly
`title, rect, text`, the rectangle must have exact
`x, y, width = 350, height = 48, rx = 4`, the text must have exact
`x + 10, y + 29`, and the group, rectangle, and text must satisfy the complete
closed transform family above. An isolated swap of rectangle and text must
fail while preserving their membership, attributes, and content. Computed
rectangle `x`, `y`, `width`, `height`, `rx`, and `ry` must equal the current
exact pixel serializations, with `ry = auto`, so CSS geometry cannot override
exact attributes. Text must omit
`dx`, `dy`, `textLength`, `lengthAdjust`, and attribute-level `rotate`. Its
visible content is exactly `evidencePlane + ": " + label`, truncated only
when longer than 48 Unicode code points to the first 47 code points plus
`"..."`. Its computed text contract is exactly `font-size: 13px`,
`font-size-adjust: none`, `text-anchor: start`, `direction: ltr`,
`writing-mode: horizontal-tb`, `dominant-baseline: auto`,
`alignment-baseline` in the complete pinned set `auto` or `baseline`,
`letter-spacing: normal`, `word-spacing: 0px`, `text-transform: none`, and
`baseline-shift` in the complete pinned
serialization set `0px` or `baseline`. Independent zero-size,
geometry-override, individual-translate, motion-path, text-offset, empty-label,
zero-font-size, zero-font-adjustment, end-anchor, right-to-left direction,
vertical-writing, hanging dominant baseline, shifted alignment baseline, large
baseline shift, extreme-letter-spacing, extreme-word-spacing, and uppercase
transformation mutants must fail. Computed `-webkit-text-security` must equal
`none`, and an isolated `disc` mutant must fail. The text and title elements
must have no direct element children. Separate hidden-`tspan` mutants under
text and title must each fail while preserving the exact direct text bytes.
Generic
`toBeVisible()` and `toBeInViewport()` are rejected as replacement oracles:
for each matcher at least one harmful mutant/engine pair survives, while the
viewport matcher also rejects unscrolled baseline rows and would add a new
scroll operation. Neither is therefore one uniform cross-engine oracle. The
positive display predicate admits the pinned engines' `inline` or `block`
serialization but rejects `none`. Every edge is bound to independently
computed, response-derived non-degenerate endpoint coordinates and must have
non-`none` local display, visible visibility, opacity and stroke opacity equal
to one, a positive opaque computed stroke, `1.5px` stroke width,
`stroke-dasharray: none`, and the same closed transform family. Every line and
rectangle must have zero direct element children. The SVG root's direct element
children must equal exactly all response-derived lines in edge order followed
by all response-derived groups in node order, with no surplus. Separate inert
line-child, inert rectangle-child, and root-surplus element mutants plus a
zero-dash mutant must fail while preserving geometry and paint. A separate
root-order mutant moves the
first group before the last line while preserving both subsets' relative
order, identities, and counts. The complete document must contain zero SVG
declarative animation elements from the exact set `animate`, `animateColor`,
`animateMotion`, `animateTransform`, `discard`, and `set`. Separate hidden
external-SVG mutants must target a graph line coordinate and the existing
`#workspace-content` ancestor color; both must fail at this document boundary.
This direct source exclusion replaces local `id` and `xml:id` bans: the former
did not close ancestor targets and the latter did not create an addressable
target in any pinned engine. It intentionally does not use `toBeVisible()` on
an SVG line: horizontal or vertical zero-thickness line boxes are reported
differently by the pinned engines. The property `clip-path: none` is exact;
normal SVG viewport overflow clipping is neither rejected nor generalized into
a no-clipping claim. No production CSS floor is added: the used-height
assertion directly rejects the one-pixel mutant at the lower owner cost.

The two graph table viewports, their tables, captions, section groups, rows,
headers, and response-derived cells form the visible trust-state projection.
Their captions are exactly `Admitted traceability nodes` and
`Admitted traceability edges`. Their ordered headers are exactly the two
inventories constructed by `workspace.js`; their exact ordered body-cell text
comes from the same frozen response records, not from the DOM. Exact visible
header, row, and cell counts close omission and surplus. Independent caption
substitution or emptying, header substitution or surplus, body-row reorder,
omission or surplus, and body-cell substitution mutants must fail.

Each local table element must satisfy the retryable visible predicate,
computed opacity `1`, `filter: none`, `clip-path: none`, `mask-image: none`,
`content-visibility: visible`, `zoom: 1`, `animation-name: none`,
`transition-duration: 0s`, and `transition-delay: 0s`. Each text-bearing
caption, header, and body cell also requires the current exact positive opaque
computed color `rgb(23, 32, 51)`, positive `16px` font size,
`font-size-adjust: none`, `-webkit-text-security: none`, and
`text-transform: none`. Each table's exact response-derived row and cell
counts must equal the count of matching visible locators. This closes hidden
ancestors, hidden individual rows or cells, local alpha and glyph loss, local
effects, and phase-split table animation without adding raw page evaluation.
Separate
hidden-viewport, hidden-row, opacity-zero-cell, transparent header and data
cell color, filter-opacity, complete-clip, transparent-mask, zero-font-size,
zero-font-adjustment, text-security, text-transform, zero-zoom,
hidden-content-visibility, phase-split-cell animation, positive-duration, and
zero-duration positive-delay mutants must fail. Separate header reorder and
body-cell reorder, body-cell-only omission, and body-cell-only surplus mutants
must preserve every unrelated count and order dimension and fail their sole
predicate. Exact initial page-viewport intersection, pixel layout, ancestor
effective compositing outside the owned table viewport, font rasterization,
and raster equality remain non-claims.

`internal/testsupport/browserfixture/fixture.go` owns the raw graph fixture;
`internal/command/requirementgraph/requirementgraph.go` constructs normalized
records and identities; `internal/command/requirementgraph/output_admission.go`
admits them; `internal/command/requirementbrowser/workspace.go` owns
snapshot/session closure; and
`internal/command/requirementbrowser/http_handler.go` owns windowing and the
HTTP envelope. `internal/command/requirementbrowser/assets/workspace.js` owns
SVG construction and the geometry formula. The witness independently restates
that formula and computes viewBox height plus edge coordinates from the
response order and endpoint relations; it never reads expected geometry from
the DOM or calls production code. The unchanged
`internal/command/requirementbrowser/assets/workspace.css` owns style, and
`tests/browser/workspace.spec.mjs` is the runtime witness. Existing
`REQ-PROOFKIT-SPEC-021` and
`REQ-PROOFKIT-QUALITY-022` bindings already own visible traceability UX and
the same non-empty passed browser identities, so C-116 changes no requirement,
public API, packet, route, or business rule. Pixel-perfect raster equality,
anti-aliasing, effective compositing, ancestor occlusion, useful pixels,
exact screenshots, simultaneous stability under script-driven mutation or the
Web Animations API, a general ban on necessary page evaluation, independent
causal consumption of every response field, and the exact engine defect remain
non-claims. Increasing timeout or retries, retaining any of the three raw
pass-path operations, accepting 14 of 15, or merging a toolchain upgrade into
the same repair are rejected because they either preserve the counterexample
or destroy causal attribution. Any change in the resolved browser-runtime
input set creates a new input digest and restarts the full 30-process epoch; a
design-only byte change restarts design review but does not imply a new runtime
digest. The failed epoch cannot be resumed.

A pinned Playwright 1.61.1 versus 1.62 or browser-lifetime A/B is diagnostic
and nonblocking if the fresh C-116 epoch passes all 30 processes. It becomes
blocking only if the replacement web-first path times out again or if an exact
engine or browser-lifetime cause is claimed. Running it before the lower-cost
raw pass-path operation-removal/replacement falsifier would mix variables
without closing the independent oracle defects.

### Playwright 1.62 A/B decision record

Problem: the immutable Playwright 1.61.1 C-116 epoch passed locally, but the
first provider execution later stalled inside a different raw Playwright page
operation. Therefore local bounded reliability does not imply provider
liveness: `L and not P` falsifies `L -> P`.

Chosen owner boundary: update exactly the root manifest pin, lock resolution,
package-verifier exact dev-dependency admission, and its fixture from 1.61.1 to
1.62.0. These are the four existing owners of the same source-only browser
proof toolchain version. The root dev-dependency pin is an intentional,
nonbreaking public package-metadata change, while the lock records the
toolchain dependency's Node `>=20` engine floor. That floor governs source-only
development proof execution, not the shipped package runtime. The admission
oracle changes only to preserve exact metadata parity. No shipped CLI
JSON/exit-code behavior, product runtime, business rule, browser test, retry,
timeout, worker, or report-semantics byte changes.

Rejected lower-cost alternatives: rerunning or republishing the failed 1.61.1
object cannot distinguish an intermittent provider stall from a version
effect; increasing timeout or retries weakens the falsifier; deleting the
negative control removes coverage; and changing browser lifetime or another
raw operation in the same epoch mixes causal variables. The already completed
raw graph pass-path removal was the lower-cost prior intervention and did not
establish provider liveness.

Proof invariant: the version change creates a new resolved browser-runtime
input digest. The candidate is admissible only after a new immutable
30-process Firefox epoch passes from iteration 1, two subsequent full browser
proofs pass, the composite and full gates pass, committed-object reviewers
approve, and the first fresh provider attempt passes every required check.
All Firefox projections must retain the historical 25-test identity digest,
one worker, zero retries, and 30-second per-test timeout.

Non-claims: a successful 1.62 epoch does not prove the exact 1.61.1 engine
defect, universal browser liveness, registry publication, provider attestation,
production readiness, or a general absence of browser-runner defects. The A/B
does not preserve byte-identical package metadata, change the consuming
runtime Node floor, or claim compatibility for unsupported contributor
environments below the development toolchain's Node floor.

Rollback or overturn condition: revert all four version-owner changes together
if 1.62 changes a verdict or test identity, fails package admission, fails any
immutable local gate, or introduces a security or platform incompatibility.
If the exact 1.62 provider attempt stalls again while other required jobs pass,
retain diagnostics and reject a version-only causal conclusion; the next
admissible intervention is a separately reviewed browser-lifetime or remaining
raw-operation experiment with a fresh input digest and complete epoch. A green
provider attempt admits the 1.62 candidate but does not establish that the
upgrade alone caused the difference.

Accidental-complexity and decomposition argument: synchronizing four existing
owners is the minimum change that preserves exact package admission. A new
adapter, retry layer, test file, configuration surface, or version registry
would add an owner without a second independent consumer. Keeping the decision
in this temporary remediation authority avoids both a permanent one-off
abstraction and premature file decomposition.

### C-117 setgid-mutant decision record

Problem: the test assumed `chmod returned nil -> requested setgid mode exists`.
Darwin provides a counterexample when the file group is outside the caller's
groups: `chmod` returns nil but clears setgid. The writer then sees its expected
`0644` mode, so publication is correct and an expected writer error is a false
oracle conclusion.

Chosen owner boundary: change only `internal/app/cli_abi_test.go`. Before the
setgid temporary object is created, normalize the test root to the caller's
effective group. After every mode mutation, require an immediate `Lstat` mode
equality before the barrier returns. This preserves independent permission,
setuid, setgid, and sticky-bit falsifiers.

Rejected lower-cost alternative: rerunning under the default temp root hides
the environmental counterexample; skipping or deleting setgid removes an
independent security falsifier; accepting nil without a materialization
postcondition preserves the false implication; and changing the writer would
reject a state that did not actually change.

Proof invariant: both default-group and foreign-group `TMPDIR` executions must
materialize the requested setgid mode and make the unchanged writer reject it
100 of 100 times. The complete full gate must then pass. Because this test file
is outside the resolved browser input set, its correction must leave the
Playwright 1.62 epoch digest unchanged.

Non-claims: this correction does not assert Windows or Plan 9 support, change
output semantics, strengthen a caller privilege boundary, or prove arbitrary
filesystem special-mode behavior.

Rollback or overturn condition: revert the test-only correction if group
normalization changes production bytes, fails on a supported Darwin or Linux
platform, or the explicit postcondition cannot materialize the mutant. Such a
counterexample requires a platform-specific test-fixture design, not a weaker
writer assertion.

Accidental-complexity and decomposition argument: two local setup and
postcondition checks repair the existing oracle. A platform adapter, new test
file, production hook, or reusable abstraction has no second consumer and
would add unjustified ownership.

### C-118 browser-state decision record

Problem: the handoff panel and the active workspace view are independent
presentation regions, but a late handoff response writes the same global state
projection used by a newer view.

Chosen owner boundary: change only
`internal/command/requirementbrowser/assets/workspace.js` and its existing
browser owner test. Capture the active view request identity when a handoff is
submitted and condition only the global state write on that identity.

Rejected lower-cost alternatives: aborting a handoff on view navigation cannot
revoke a server-side terminal commit and could hide a valid submitted packet;
discarding the late packet conflates view navigation with handoff cancellation.

Proof invariant: after a handoff begins, a newer Diff or Graph view remains the
global workspace state when the handoff succeeds or fails, while the handoff
region still reports its own terminal result.

Non-claims: view navigation does not cancel or roll back a submitted handoff;
the packet region is not hidden; no new persistence behavior or
provider-liveness claim is introduced.

Rollback or overturn condition: revert C-118 if the handoff packet is no longer
observable after a valid submission or if one-shot terminal semantics change.

Accidental-complexity and decomposition argument: one captured scalar and one
conditional state write separate two existing lifecycles without a controller,
queue, or new state machine. The correction stays in the existing browser owner
and existing test file.

### C-119 browser-navigation decision record

Problem: provider attempt 1 for the C-118 candidate timed out twice in Firefox
while `page.goto("/")` waited for `load`. Both retained traces show every local
HTML, CSS, JavaScript, manifest, and requirements response completed
successfully in milliseconds, and both failure snapshots show the initialized
workspace. The failures occurred before test-specific behavior. Evidence is CI
run `30334467601`, job `90196309721`, artifact `8678666391`, report SHA-256
`50e45237d4d41ad221cd9320a37ed3a96ca413af2caa4db790309976e38a533d`,
and trace SHA-256 values
`66cf9aef659dc4bf93ba97c192e9fb6d5cd63fa67e012df1acf862fa848bddd7`
and `8f817656fe74b2920c559014216a598a7d4409571a775b8a01c0f4ad5340bf6f`.
The first C-119 candidate replaced `load` with `domcontentloaded`; provider
attempt 1 then reproduced two fully rendered Firefox timeouts at that earlier
lifecycle event. That evidence is CI run `30335313301`, job `90198820640`,
artifact `8678963003`, report SHA-256
`e1c495fd99d35a972ae9301b5c4799369409186a4c7445d1f720e9a9f0ba1c61`,
and trace SHA-256 values
`f03f9fbf5b5e15f1d5bf3b54a5c7543f04a3c8c64fdae834164571f76d74a853`
and `302cc38a72aa7b8399e5fa36f0de31e6f19900c4c412ebef2f41e047581451d4`.

Chosen owner boundary: change only the existing browser witness. Route all
then-current workspace opens and reloads through owner-local helpers that wait
only for navigation commit, reject a missing or unsuccessful main-resource
response, and require the visible server-owned workspace heading through
Playwright's exact accessible-name matcher before returning. Keep the
`about:blank` axe negative control unchanged. C-121 supersedes the lifecycle
mechanism while preserving these response and semantic admission obligations.

Rejected lower-cost alternatives: a rerun would not satisfy attempt-1 proof;
waiting for `domcontentloaded` was empirically falsified by the next provider
attempt; raising the 30-second timeout would hide rather than remove the
irrelevant lifecycle dependency; `networkidle` would add a discouraged
ambient-network heuristic; production changes cannot repair a test-runner
lifecycle signal after the application is already rendered.

Proof invariant: browser tests admit the new main document through its
successful navigation response and exact visible server-owned heading, while
each existing state, accessibility, and API assertion still proves the
behavior it owns. Navigation HTTP failure remains terminal.

Non-claims: navigation commit and the heading did not themselves prove module
completion, application behavior, visual correctness, API completion,
provider reliability, or a generally flake-free browser engine. No retry,
timeout increase, server change, or product behavior change is introduced.

Rollback or overturn condition: replace this policy only if the application
requires a resource whose correctness is not covered by the existing semantic
assertions and whose completion needs a separately owned readiness signal.

Accidental-complexity and decomposition argument: two small owner-local helpers
centralized one repeated navigation policy without a new module, fixture,
retry controller, production hook, or general navigation abstraction.

### C-120 navigation-guard falsifier decision record

Problem: C-119's ordinary success paths exercise navigation through the new
helpers but do not distinguish an implementation with the response or exact
accessible-name guard removed. Therefore `allSuccess -> guardRequired` is
false for the 81-test matrix, even though both guards own admission decisions.

Chosen owner boundary: add three cases to the existing browser contract corpus.
Intercept the main document, preserve its original body, and return status 503
for open and reload independently. In a third case, preserve successful
navigation and change only the server heading to
`browser.fixture.workspace drift`, which retains the weaker substring. Admit
the original 200 response, byte-changing substitution, and completed route
fulfillment out of band before accepting the helper rejection.

Rejected lower-cost alternative: source inspection proves guard presence but
not executable dependence. One 503 case cannot prove both duplicated operation
paths. A heading-absence mutant would not distinguish exact from substring
matching. A new fixture, module, production hook, retry, or timeout increase
adds no proof.

Proof invariant: for every pinned engine, deleting the shared HTTP-response
guard or weakening the accessible-name matcher makes its owning negative
control fail; both open and reload operation paths reject their independently
injected 503 response; a route-handler or fixture-precondition failure cannot
satisfy the heading oracle; the unchanged C-121 implementation passes 31 tests
per engine. Controlled Chromium rehearsal deletes the shared response guard
and changes the exact matcher to substring matching; the owning falsifiers
must fail because the helper resolves instead of rejecting.

Non-claims: these falsifiers do not prove arbitrary navigation failures,
browser-engine liveness, remote networking, or document integrity beyond the
admitted response and exact heading.

Rollback or overturn condition: consolidate the two operation cases only if a
single counterexample still proves both open and reload routing through the
shared response-admission owner.

Accidental-complexity and decomposition argument: three declarative tests reuse
the existing helpers and route API. No production state, abstraction, fixture,
or file is introduced.

### C-121 provider-falsified navigation-lifecycle decision record

Problem: provider attempt 1 for exact source
`dcc824b31f858ab8fea5be683e5d81f12f039279` timed out in Firefox while
`page.goto(..., {waitUntil: "commit"})` remained pending. The retained trace
records the main document status 200, complete local asset and API responses,
and a fully initialized workspace screenshot. Thus
`response200 and renderedWorkspace -> gotoCommitResolved` is false. The exact
evidence is run `30337477288`, job `90205431977`, diagnostic artifact
`8679825289`, GitHub artifact digest
`sha256:274cb4bbe4ef2bcbb55f476ed21414287f5d1d80632f051304ea07d0c7e94cba`,
report SHA-256
`da78d940df3e969252c612bd89e90818b4ee5154dd81d05d74761d928164f953`,
and trace SHA-256
`3e75d3fffd297652d30cc3c7f17b1252f92214e43990f4830e6350291e145cb4`.
The provider checked out synthetic merge
`30e9f1892d95b5aa886a360f5b14f28372c15862`; the exact source revision and
tree identity remain the source-owned comparison surface.

Chosen owner boundary: change only the existing browser witness. Admit the
configured local base URL before use. Capture its current main frame, arm one
exact-URL main-frame navigation-response waiter, then schedule location
assignment or reload from the page and require the exact trigger token. Admit
only a successful response and the exact visible server-owned heading. Abort
and consume the waiter if the trigger or later admission fails. The current
inventory is 27 open-helper calls, two reload-helper calls, and one
classifier-only reload trigger.

Rejected lower-cost alternatives: rerun-only acceptance violates attempt-1
proof; another lifecycle event preserves the falsified dependency; a longer
timeout or retry hides it; `networkidle` adds ambient-network authority;
unawaited navigation creates an unowned rejection; fetch plus `setContent`
does not execute browser navigation semantics; production readiness hooks or
dependency churn change a non-owner surface.

Proof invariant: the response waiter exists before the timer-backed trigger;
the trigger synchronously returns one exact scheduling token; only an
exact-URL main-frame navigation response can satisfy the waiter; status 503 is
terminal; and the exact visible heading remains the semantic readiness oracle.
A pure classifier truth table admits the main-frame navigation and rejects a
same-URL main-frame fetch, same-URL child-frame navigation, and foreign URL.
The live same-URL 503 fetch decoy proves operation-level classifier wiring.
Open and reload 503 cases prove shared response admission, heading drift proves
exact semantic admission, and a static source oracle excludes every direct
workspace lifecycle wait except the isolated `about:blank` axe control. The
unchanged corpus must pass 31 tests in each pinned engine with zero retries.
Controlled Chromium rehearsals removed the URL, navigation, and frame clauses
independently; each corresponding truth-table row failed. Deleting the shared
response guard failed both 503 cases, and weakening exact heading admission
failed the substring-preserving drift case.

Non-claims: the classifier does not prove child-frame readiness, arbitrary
navigation behavior, remote-network reliability, browser-engine liveness, or
product behavior beyond the downstream assertions. A response and heading do
not replace the existing state, accessibility, API, or mutation oracles.

Rollback or overturn condition: replace the response-event policy only if
provider evidence falsifies it or a separately owned application readiness
contract offers a lower-cost deterministic signal. Any new direct lifecycle
wait must first falsify the static source oracle and receive an owner-specific
counterexample.

Accidental-complexity and decomposition argument: one pure three-clause
classifier and one shared observer serve both existing open and reload helpers.
The truth table closes the only added classification branch. A new module,
fixture, retry state machine, production hook, or generic navigation framework
would add ownership without another consumer.

### C-122 correction-inventory parity decision record

Problem: before `c2315fd`, P12.2 first declared the current correction
inventory as design, plan, and workspace test, but its executable equality
predicate also required `scripts/browser-proof-inputs.test.mjs`. After that
four-path correction was amended, the next correction epoch changed only
design, plan, and workspace test. Thus both the pre-amend three-vs-four
contradiction and the post-amend claim that four remained current were false.

Chosen owner boundary: time-index the four-path set to the `c2315fd` staging
epoch and make both current P12.2 surfaces consume the exact same three sorted
post-`c2315fd` paths.

Rejected lower-cost alternative: retaining the static owner would make the
current executable predicate fail because that file is unchanged from HEAD.
Deleting it from the historical `c2315fd` account would omit a real C-121
correction.

Proof invariant: for the current epoch, P12.2 has one exact three-path
correction set, the worktree inventory equals it before staging, and the staged
inventory equals it after staging. Earlier sets are explicitly epoch-bound.

Non-claims: this parity does not prove the separate baseline-relative
150-file diff or 21-file addition inventory; their existing predicates remain
independent.

Rollback or overturn condition: change the list whenever a later correction
epoch changes an owner file or an amend absorbs one, and update the epoch
statement, declaration, and predicate in the same reviewed edit.

Accidental-complexity and decomposition argument: one added list row removes
contradictory authority. A generator or second inventory file would increase
cost without a durable consumer.

### C-123 base-URL admission falsifier decision record

Problem: C-121 added raw base-URL rejection clauses, but all passing browser
calls supplied the configured valid URL. Therefore
`allBrowserTestsPass -> everyBaseURLClauseRequired` was false.

Chosen owner boundary: extend the existing navigation-classifier test with one
positive configured-URL row and independent negative rows for non-string
input, protocol, hostname, port, username, password, path, query, and fragment.
Run this table before navigation so an admission failure cannot be hidden by a
later response or heading failure.

Rejected lower-cost alternative: source inspection proves clause presence but
not behavioral dependence. A single malformed URL cannot distinguish the
clauses. A new test file, exported production helper, or general URL policy
adds no owner.

Proof invariant: the exact configured `http://127.0.0.1:<port>/` bytes
normalize to their own canonical URL; changing any admitted authority
dimension makes its corresponding row reject with the owner error. Username
and password have separate counterexamples, including an empty-username,
non-empty-password URL. Controlled Chromium rehearsal removed the root-path
clause and the path-drift row failed because the helper admitted its mutant.

Non-claims: the table does not claim DNS confinement, remote URL admission,
network isolation outside the test server, or general URL validation.

Rollback or overturn condition: broaden the URL domain only when the browser
server contract admits another origin and adds an owner-specific positive and
negative proof.

Accidental-complexity and decomposition argument: one data table exercises the
existing pure helper in its sole runtime owner. It adds no abstraction,
fixture, browser count, production hook, or retry path.

### C-124 trigger-and-cleanup falsifier decision record

Problem: every real trigger returned the expected token, and the 503 and
heading failures occurred after the response waiter settled. Deleting token
admission and `controller.abort()` therefore left static 22/22 and runtime
93/93 green. The source guards did not imply behavioral dependence.

Chosen owner boundary: in the existing navigation test, inject one page-shaped
object whose response waiter remains pending, rejects when its supplied abort
signal fires, and otherwise resolves shortly to a distinct unsuccessful
response. Return a wrong trigger token and require the exact token error,
observed signal abort, and observed invocation of the waiter's rejection
consumer.

Rejected lower-cost alternative: source inspection is the false-green being
repaired. A real network stall adds timing and browser authority. Removing the
guards would allow the trigger/observer handshake to drift and leave a pending
waiter rejection unowned.

Proof invariant: wrong token is terminal before response admission; every
failure aborts a still-pending response observation; and its rejection is
explicitly consumed before the original error escapes. If token admission is
deleted, the distinct fallback response error appears. If abort or consumption
is deleted, its exact observation remains false. The injected operation
requires the exact event order `waiter-armed`, `trigger-called`,
`waiter-aborted`, `waiter-consumed`, which also makes pre-arm ordering
executable.

Non-claims: the injected object is not a general Playwright mock, does not
prove every AbortController behavior, and does not replace real-browser
response, heading, or decoy cases.

Rollback or overturn condition: remove the seam only if the observer API no
longer creates a pending rejection or another owner provides equally
deterministic token and cleanup falsifiers.

Accidental-complexity and decomposition argument: one local object exercises
the two failure-only branches of the existing helper. It adds no exported
helper, fixture, file, retry, production state, or test identity.

The C-27/C-115 axe harness remains an anti-corruption boundary, not a product
layer. C-115 removes the wrapper, not the boundary: exact source initialization,
runtime version admission, rule selection, frame scope, and returned-result
identity stay centralized. Remove the harness only after those obligations
move to a lower-cost owner with equivalent mutation and browser-runtime proof.

## Review acceptance criteria

The design is ready for implementation only when independent reviewers agree:

1. every accepted row has one owner, counterexample, repair invariant, and
   non-claim;
2. every rejected row states why its conclusion does not follow;
3. no repair changes valid-input business semantics without an explicit
   compatibility record;
4. no new shared abstraction lacks two real consumers;
5. no documentation-only repair substitutes for a runtime or proof defect;
6. every stable browser state enters the executable state matrix;
7. the implementation plan orders owner and contract changes before dependent
   projections and full closeout.
