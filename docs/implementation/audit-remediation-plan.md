# Audit Remediation Implementation Plan

Status: C-124 implementation candidate; C-01 through C-124
corrections are present; provider validation is invalidated by the C-124
semantic delta; unaffected prior validations remain historical evidence.

Owner: `proofkit`.

Design input:
`docs/implementation/audit-remediation-design.md`.

Target baseline: `3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64`.

Branch: `fix/audit-remediation`.

Review history:

- cycle 1: three `REVISE` verdicts; corrections applied for owner-first
  sequencing, the omitted SBOM tranche, artifact dependencies, committed-object
  closeout, exact selector/workflow inventories, race falsifiers, onboarding
  continuity, and accessibility oracles;
- cycle 2: three `REVISE` verdicts; corrections applied for exact requirement
  ownership, artifact-derived SBOM edges, generated preset topology,
  source-only witness classification, branch/PR commands, help continuity,
  and route-bearing README code spans;
- cycle 3: three `REVISE` verdicts; corrections applied for the exact two-file
  generated-artifact exception and mutation-free branch preflight;
- cycle 4: two `APPROVE`, one `REVISE`; corrections applied for pre-switch
  target-ref identity and immutable validated-SHA publication binding;
- cycle 5: unanimous `APPROVE`; no P0-P2 plan contradiction remains.
- implementation cycle 1: proof/security, contract/release, and
  UX/accessibility reviewers returned `APPROVE` after C-01 through C-20 and
  static-analysis cleanup; the complete worktree `npm run check` passed.
- committed-candidate cycle 1: two `REVISE` findings added C-21 and C-22 for
  aggregate job bypass-field absence and the three held per-view loading
  states; focused correction review returned three `APPROVE` verdicts.
- committed-candidate cycle 2: two `APPROVE` verdicts and one `REVISE` added
  C-23 for ignored workflow/job/step execution controls and partial
  `continue-on-error` evaluation; exact environment entries, nullable scalar
  key presence, required leaf jobs, and the aggregate were closed, and focused
  correction review returned three `APPROVE` verdicts.
- exact-commit cycle 1: proof/security and UX/architecture returned `APPROVE`;
  contract/release returned `REVISE` because the `0.2.0` machine change record
  omitted the intentional `adoption-doctor` blocked-state and exit-code
  migration; C-24 closed the machine record, migration, rendered-note
  falsifier, and proof binding, and focused correction review returned three
  `APPROVE` verdicts.
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
- provider cycle 2: C-26 retained the next locally reproduced Firefox traces;
  both failures terminate at the first default axe-source evaluate rather than
  an application action or assertion. A minified-source candidate passed two
  full runs but a controlled falsifier made both minified and default sources
  stall under continuous trace screenshots; the default source completed 13
  two-audit cycles without tracing and with screenshot-free action, DOM,
  network, and source tracing. A third full run falsified screenshot removal
  alone at the same large builder evaluate. C-27 therefore combines
  browser-context axe initialization, constant builder loaders, screenshot-free
  traces, one bounded best-effort post-failure screenshot, zero retries, and
  the existing timeout; the combination passed 30 consecutive two-audit
  Firefox cycles and still requires repeated clean first-attempt runtime proof
  before exact-object closeout.
- provider correction review: proof and UX returned `APPROVE`; contract
  returned `CONDITIONAL APPROVE` after the exact package allowlist,
  owner-to-binding non-claims, and deterministic constant-loader reachability
  oracle were aligned. Two consecutive frozen-byte 72-test browser proofs and
  direct proof verification passed without an intervening browser-input edit,
  discharging the only remaining review condition before final
  committed-object revalidation.
- final committed-object review: proof/security found that a descriptor-relative
  rename could follow the admitted output parent after it moved outside the
  repository between the last route check and publication. C-28 binds the
  irreversible rename to full routes through the repository root while keeping
  temporary-file cleanup on the pinned parent, and adds exact outside-root and
  in-root pre-publication falsifiers.
- final correction review: all three reviewers rejected C-28 because
  `os.Root.Rename` resolves mutable source and destination routes separately and
  a replacement can substitute the visible temporary basename. C-29 stages
  temporary bytes at the repository root, re-admits their identity and the
  destination-parent route after the exact barrier, keeps publication and
  cleanup root-confined, and records adversarial same-user namespace mutation
  after final admission as the unavoidable cross-platform non-claim.
- C-29 correction review: the root-level candidate was rejected for
  writable-child and nested-filesystem regressions, missing content admission,
  an omitted compatible release-record entry, and PR-body checks that did not
  machine-validate every promised closeout fact. C-30 restores pinned
  same-parent staging and publication with identity-plus-mode-plus-content
  admission;
  C-31 closes the release projection; C-32 adds a canonical closeout-body
  record. The next correction review found that permission-only mode checks
  omitted special bits and that local artifacts were reread from mutable paths;
  C-33 requires complete-mode equality and one private byte snapshot per local
  evidence object. C-34 removes artifact fields not admitted by the exact local
  predicates. C-35 rejects multi-document JSON substitution and admits the
  exact browser-project inventory. The independent maximum-reasoning audit then
  reproduced dynamically false CI-step and release-candidate conditions; C-36
  closes both workflow condition inventories. Its correction review then
  replaced the macOS smoke with an Ubuntu no-op while preserving aggregate
  success and reproduced vacuous negative selectors; C-37 binds exact CI check
  names, runners, and platform-smoke execution and requires positive owner
  admission inside bound falsifiers. The next review inserted a semantic shadow
  step, passed a mixed-type runner list, reproduced missing positive
  package-gate owners, and found a malformed closeout filter; C-38 closes the
  ordered platform topology and package-script owner, exact scalar runners,
  positive CI/release package-gate admission, and executable singleton filter.
  The next review moved the shadow into the repository-local setup action and
  added an empty `run` key beside `uses`; C-39 binds exact local-action bytes
  and makes execution-key presence part of the exact step inventory.
- The C-39 correction review returned three independent `APPROVE` verdicts
  after reproducing the nested local-action shadow and null, empty, whitespace,
  and dual execution-key mutants; no P0-P2 finding remains.
- The next independent maximum-reasoning audit approved the exact C-39 commit
  at 97/100 with no P0-P2 finding and confirmed two P3 hardening gaps. C-40
  closes exact QUALITY-011/013 selector-set immutability and bounded
  expansion-free README shell-word parsing; all exact-object gates and reviews
  must therefore be repeated.
- C-40 focused review reproduced owner-only transfer of a protected scenario
  while its exact selector set remained unchanged. C-41 binds every protected
  inventory to the exact requirement/scenario pair and adds the missing
  owner-transfer falsifier.
- The same cycle reproduced all-selector deletion through an empty-selector
  early return, NUL admission that direct execution cannot preserve, and a
  stale P0-P2-only final-review threshold. C-42 closes all three contradictions.
- Continued focused review reproduced Unicode-trim drift in both command and
  JSON fence bytes, escaped-NUL lookahead bypass, and double-quoted interactive
  Bash history expansion. C-43 preserves exact boundary bytes and closes each
  lexer mutant without widening the grammar.
- C-43 review then reproduced a trailing escaped-space/tab false reject caused
  by symmetric delimiter trimming. C-44 restricts preprocessing to leading
  delimiters and preserves both mutants.
- The first complete package-level run then exposed that the generic
  missing-function mutant was shadowed by the new exact-set check. C-45 routes
  it through an unprotected binding and keeps both failure classes reachable.
- Continued review reproduced even-backslash history-literal false rejects,
  one remaining P0-P2-only preparation threshold, and repeated generic I/O in
  every pure inventory mutant. C-46 through C-48 close all three without
  widening product scope.
- Complexity review then found quadratic rescanning of long non-history
  backslash runs in the first C-46 helper. C-49 consumes each run once and
  retains a large-run regression.
- The next complete package-level run showed partial generic fixtures stopping
  at the earlier global inventory phase. C-50 keeps production composition but
  routes isolated fixtures directly to the validation phase they own.
- Frozen C50 review then found two generic executability falsifiers absent from
  selective QUALITY-010 routing. C-51 binds both and closes the scenario's
  exact four-selector inventory.
- Frozen C51 review reproduced the same gap for QUALITY-013's permission-floor
  falsifier. A closed-world owner pass found ten omitted typed-oracle tests;
  C-52 binds and protects the complete seventeen-selector owner surface.
- The frozen C52 correction review returned three independent `APPROVE`
  verdicts with no confirmed P0-P3 finding after exact inventory, README
  lexer, JSON byte, owner-separation, documentation-parity, and business-logic
  checks. The implementation is therefore ready for final committed-object
  validation.
- The next exact-commit review confirmed that readiness-closeout's intentional
  character-reference verdict change was absent from the closed release record
  and that selector admission rejected a toolchain-valid unnamed
  `*testing.T` parameter. C-53 adds the release declaration, migration,
  rendered-note witness, Go grammar regression, and exact QUALITY-010 and
  QUALITY-024 selector inventories before committed-object validation repeats.
- The repeated exact-commit review confirmed five P2 gaps: decoding before
  Markdown pipe parsing, an untested stable specifications no-match state,
  undisclosed removal of synthetic Arrow-key navigation, and undisclosed
  compatible pilot-all envelope plus witness-selector I/O additions. C-54
  repairs the parser order, adds the complete browser row, and projects all
  three public changes through the closed release record and rendered notes.
- The next exact-commit UX review confirmed that root help displayed a bare
  executable unavailable to a normal npm consumer while the installed witness
  executed separately hard-coded argv. C-55 makes the displayed route the
  copyable offline npm exec command, parses and executes those exact bytes, and
  rejects the bare-route mutant.
- C-55 correction review confirmed that Unicode `TrimSpace` admitted leading
  or trailing NBSP around the displayed command even though Bash does not
  treat NBSP as an IFS delimiter. C-56 removes only the authored leading
  ASCII space/tab indentation and keeps both NBSP falsifiers.
- The next exact-commit review confirmed a discontinuous onboarding witness,
  incomplete and misclassified release declarations, under-scoped symlink
  migration, merge/release semantic shadow steps, and a five-owner workflow
  oracle concentration. C-57 through C-60 close the full displayed route,
  release classification and migration, complete step inventories, exact
  large-file ledger, owner-aligned split, and moved-selector anti-deletion
  proof.
- The C-60 decomposition review approved one minimal owner-cluster split and
  rejected one-requirement-per-file decomposition because QUALITY-011 and
  QUALITY-013 share an exact selector while each binding admits one
  `witnessPath`. The implementation preserves that cluster and separates only
  independently changing owners plus neutral support.
- The C-60 correction review confirmed six residual gaps in step-field
  closure, witness-path ownership, untracked-file staging, exact size evidence,
  scanner selective routing, and ordinary leaf invocation UX. C-61 through
  C-66 add independent mutants and owner-bound repairs before candidate
  creation.
- Candidate-command rehearsal rejected temporary-file cleanup under the active
  destructive-action guard. C-67 keeps the exact staging predicates but uses
  in-memory inventories and stdin pathspec admission, so the documented
  sequence is executable without cleanup authority.
- The next focused review admitted a missing scanner permission floor, a
  surplus provider write scope, an installed block before Usage, and a
  command-token prefix collision. C-68 and C-69 add exact permission-map and
  post-parse invocation predicates with independent mutants.
- C-69 proof review then deleted the new test while every bound QUALITY-019
  selector remained green. C-70 adds the falsifier to the exact owner selector
  and path inventory.
- The final C-61 through C-70 focused correction review returned three
  independent `APPROVE` verdicts with no confirmed P0-P3 finding on one
  unchanged frozen snapshot. Candidate staging and exact committed-object
  validation may proceed.
- Final provider-closeout rehearsal then rejected the current 75-test browser
  matrix because its executable predicate still required 24 rather than 25
  tests per project. C-71 aligns that predicate with the immutable gate output
  before repeating the entire committed-object epoch.
- The repeated exact-commit architecture review then reproduced overlapping
  adoption output conditions and showed that last-write-wins repeated
  `--mode`/`--pilot` argv prevented a unique raw-argv selector projection.
  C-72 adds the bounded condition model, finite native-option closure,
  argv-derived ABI binding, duplicate-selector rejection, and release migration
  before the committed-object epoch repeats again.
- Splitting the C-72 pure condition algorithm from generator I/O then created
  a sixth decomposition owner while P12.2 still required the earlier exact
  five-file workflow inventory. C-73 extends that owner subset to six without
  weakening staged-path equality or the empty-remainder predicates.
- Raw-argv falsification then admitted `--pilot ""`: the parser marked the flag
  present but native normalization and the ABI condition both treated its empty
  value as omission. C-74 rejects the empty valued selector and projects that
  intentional behavior through the exact ABI, requirements, release record,
  and migration.
- Staging rehearsal then rejected comparison of that six-file
  decomposition subset with the current untracked set: the earlier candidate
  already owns the five workflow files, so the correction amend has exactly one
  untracked condition-model owner. C-75 proves the current set independently
  and retains the owner subset after staging.
- Condition-closure review then found that the 80-state test duplicated native
  mode and pilot literals. C-76 derives immutable domains from the same
  internal lists that build native admission maps and preserves the exact
  80-combination and twelve-valid-state assertions.
- Claim review then found that the generic condition grammar did not prove
  native-domain or argv closure for an arbitrary future definition. C-77
  admits only the current adoption output owner and makes a second opt-in fail
  until its own executable closure witness is added.
- Baseline-diff rehearsal then found seventeen pre-existing added paths, so the
  six decomposition owners were not the complete baseline-relative inventory.
  C-78 requires all eighteen final added paths exactly and proves the six-owner
  set only as a subset.
- Independent C-78 review then found that one guidance failure emitted JSON
  without exact condition/variant binding, the admitted definition could be
  rebound through another command or direction, and explanatory prose retained
  stale line counts. C-79 through C-81 close the JSON route, exact owner triple,
  and snapshot-measurement ownership.
- C-79 correction review then deleted both guidance-failure route coordinates
  while the duplicate successful guidance condition preserved the global count.
  C-82 requires JSON assertion and both route coordinates together per case.
- C-82 review then deleted the JSON assertion with both coordinates while
  runtime still emitted unchecked JSON. C-83 equates fixture expectation with
  observed stdout and protects the exact fourteen-case JSON inventory.
- Final committed-object decomposition review then found an identical generic
  sorted-key helper duplicated inside the same Go package. C-84 reuses the
  existing owner and deletes the redundant helper and import.
- Final committed-object proof review then found that the critical Mach-O
  byte-compatibility scenario selected only a README projection test. C-85
  binds the exact four byte-admission/parser witnesses and protects their
  selector and path inventory.
- Repeated exact-object review then found two analogous semantic false routes:
  Python wheel-platform parity did not reach wheel projection or verification,
  and browser one-shot cleanup selected only the fixed launcher. C-86 binds
  the named operations directly and closes both exact inventories.
- Exhaustive review of all candidate-added selector rows then found one final
  analogous route: mutable-release-fact policy selected only reference closure.
  C-87 binds its existing ten-case stale-fact test and exact inventory.
- The independent Sol/max audit then found a scanner authority escape outside
  selector routing: exact permissions on named jobs did not reject an
  unclassified write-capable job. C-88 closes the exact advisory/provider job
  union and adds the surplus-job falsifier.
- Terminal UX review then executed a preset's exact generated continuation in
  the installed npm consumer and reproduced a bare-binary `command not found`.
  Initial review rejected a global npm renderer because it broke the Python
  wheel. C-89 now uses an explicit immutable launcher profile and proves exact
  continuations in both installed channels.
- Terminal contract review then proved that adoption, pilot, and self-check
  output selectors could pass without observing their declared output roots,
  and that pilot output omitted its app-layer union constructor from native
  ownership. C-90 closes all three exact selector/binding/source tuples.
- Frozen implementation review then found secret/control launcher values and
  unbound help, structured argv, project workflow identity, and installed-wheel
  route sinks. C-91 hardens admission; C-92 closes and binds those sinks while
  preserving caller-owned argv.
- Provider exact-object review then reproduced Linux inode reuse inside the
  output-writer identity mutant and retained a Firefox trace that stalled only
  in the graph table's page-realm `evaluateAll` after the page was fully
  rendered. C-93 makes the identity substitution deterministic with a
  pre-existing live replacement; C-94 proves the same exact ordered table
  equality through retryable count and indexed-attribute assertions, retaining
  zero retries and the 30-second timeout. Independent focused architecture and
  UX reviews approved both repair classes.
- Final ledger review found the `agentroute.go` measurement stale after the
  last static-analysis cleanup. C-95 requires one more complete threshold
  measurement after all correction bytes freeze.
- The first exact-object Sol/max audit then reproduced two input-closure gaps:
  typed workflow decoding ignored valid execution controls, and CSS was absent
  from source hygiene. C-96 adds a raw closed-key oracle over the exact tracked
  workflow inventory with only exact release-environment exceptions. C-97 adds
  CSS and derives both staged and worktree language mutants from tracked
  browser-asset extensions without changing the token matcher.
- Dependency pre-merge validation then produced two current-base Firefox
  failures on one immutable dependency branch; the timeout moved between the
  collapsed and Unicode selection scenarios. C-98 replaces their repeated
  manual page-realm range synthesis with Playwright `selectText` and click for
  collapse plus one locator-scoped exact-range operation for the nonzero
  Unicode selection while preserving one worker, zero retries, 30 seconds, the
  exact test identities, and Unicode code-point proof.
- The next exact-object Sol/max audit returned four P2 findings and no P0, P1,
  or P3 finding. C-99 separates the historical audit baseline from the current
  integration, PR, and provider base; C-100 admits the final 173-scenario
  coverage artifact; C-101 closes launcher admission over Unicode `Cc` and
  `Cf`; and C-102 declares the accepted contract-envelope stack alias while
  rejecting repeated or mixed pilot selectors.
- C-99 through C-102 review cycle 1 returned one `APPROVE` and two `REVISE`
  verdicts and closed exhaustive Unicode classification, two-phase identity,
  singleton-parent, temporary-closeout, durable-owner, and compatibility
  omissions. Cycle 2 returned one `APPROVE` and two `REVISE` verdicts because
  its migration wording excluded the valid omitted default-first pilot route.
  Cycle 3 returned three independent `APPROVE` verdicts on the same frozen diff
  with no confirmed P1-P3 finding.
- The mandatory final Sol/max audit of exact commit
  `e55bfc6e5641aed906d9a3c02e56a431bc0ca4b5` returned one P2 and no P0, P1,
  or P3 finding: the current release-record witness checked only 10 of 12
  breaking changes and 7 of 11 additions and admitted semantic deletion or
  surplus after regeneration. C-103 closes the entire record and rendered-note
  inventories at the existing QUALITY-024 selector.
- C-103 review cycle 1 returned one `APPROVE` and two `REVISE` verdicts and
  added exact machine ID/order mutants plus note-projection closure. Cycle 2
  returned two `APPROVE` verdicts and one `REVISE` because section-local
  equality still admitted appended surplus, duplicate, or second owned
  sections. Cycle 3 returned three independent `APPROVE` verdicts on one
  frozen diff after complete ordered machine equality and one independently
  authored byte-exact full-note projection closed every confirmed escape; no
  confirmed P1-P3 finding remains.
- Publication rehearsal after the first C-103 terminal approval reproduced
  the plan's unbraced zsh variable-colon refspec failure. C-104 uses an
  unambiguous braced variable, requires a complete tracked-plan scan for the
  rejected form, and repeats the exact-object and provider epoch.
- C-104 focused review returned two `APPROVE` verdicts and one `REVISE`
  because the plan's lease still preceded the already successful first
  publication. C-105 preserves the first lease as history and binds the next
  correction publication to exact current remote head `90090a5c...`.
- The mandatory new post-C-105 Sol/max audit returned one P2 and no other
  confirmed P0-P3 finding: P12.2 still declared 18 baseline-relative additions
  after three later owner-test additions made the exact final set 21. C-106
  refreshes that closed set and the then-current C-106 two-file amend staging
  predicate.
- The mandatory new post-C-106 exact-object Sol/max audit of
  `4a828d1be9e3f9cab0e93d4ef5991fef0d2cd475` returned two P2 findings, one P3
  finding, and no other confirmed P0-P3 finding. C-107 closes the exact
  Scorecard output-input set with a surplus mutant; C-108 restores the complete
  30-ID requirement-invariant delta; C-109 removes the four stale
  reverse-decomposition line-count qualifiers.
- C-107 through C-109 focused review returned one `APPROVE` and two `REVISE`
  verdicts. C-110 replaces generic truth normalization with exact decoded
  boolean admission and adds the surviving string-substitution mutant. C-111
  time-indexes the historical two-file set to C-106 while preserving P12.2's
  then-current three-file set.
- C-110 through C-111 focused review returned two `APPROVE` and one `REVISE`
  verdict because one design-history sentence still called C-106 the latest
  current epoch. C-111 now time-indexes every historical 21-path and two-file
  assertion to the C-106 freeze.
- C-111 focused review cycle 3 returned two `APPROVE` and one `REVISE` because
  a differently named second Scorecard action could bypass the selected-step
  input predicate. C-112 closes the complete Scorecard-action subset and adds
  the surviving second-action mutant.
- C-112 focused review cycle 4 returned three `REVISE` verdicts because the
  Scorecard subset classifier was case-sensitive while GitHub
  owner/repository identity is not. C-113 admits the repository portion with
  case-insensitive equality, preserves ref bytes, and adds the surviving
  mixed-case second-action mutant.
- C-113 focused review cycle 5 returned three `REVISE` verdicts because Unicode
  simple case folding was broader than the declared ASCII repository domain.
  C-114 rejects non-ASCII repository bytes and adds the surviving long-s
  mutant.
- Exact provider run `30275221625` for
  `81e2c7d570e1982ffe4a9f1e5a43150438017b41` passed source and macOS quality,
  but `quality / browser runtime` passed only 74 of 75 tests and failed, which
  caused `quality / required aggregate` to fail. The retained Firefox trace
  stops at the auxiliary pre-audit version evaluation after the page state was
  rendered; it does not prove the underlying Firefox/Juggler cause.
- C-115 design review required five correction cycles before cycle 6 returned
  three independent `APPROVE` verdicts. The approved controlled hypothesis
  removes the
  source-only axe wrapper, combines the default and explicit target-size
  projections in one direct pinned-engine run, closes rule/config/frame/result
  and call-topology mutants, and reopens adjudication if a bounded full
  Firefox or exact-provider attempt times out again.
- C-115 plan review cycles 1 through 6 returned at least one `REVISE` verdict
  while closing the exact dependency-inventory selector, materialized and root
  digest remeasurement, canonical Firefox identity parity, one-shell
  lifecycle, bounded server termination, per-process wall-clock deadlines,
  leader-versus-descendant process-group cleanup, pre-spawn wrapper-signal
  forwarding, residual-process non-claims, and exact signal/probe forensic
  records. Cycle 7 returned three independent `APPROVE` verdicts on SHA-256
  `bb8eeb2317018030fbb273e1f18e081c33e1a022c78223947b3a8f989e626d44`
  with no confirmed plan gap.
- C-115 implementation review returned three independent `APPROVE` verdicts
  on exact diff SHA-256
  `4bf170fc8f5ea50619bc414badd88cd0997198e0419e2739357760c0e577d33f`;
  direct axe topology, dependency closure, rollback, concurrency, and
  zero-retry mutants were green.
- The immutable C-115 epoch used input digest
  `sha256:8099d7060ba9033c1e8317b6032a8776ef21c879b371edda9a460732f66281f4`.
  Iterations 1 through 14 passed 25 of 25 Firefox tests. Iteration 15 passed
  24 of 25 and timed out in the graph test after its visible SVG locator
  resolved inside `Locator.boundingBox()`. The epoch stopped; trace SHA-256
  `a08498b0ce74c39a714856c855d7757f0907a8a67df3d06b1cdab3b652904fc7`
  and report SHA-256
  `2e5475d20b3161d6d0128b9097288302ad70a94de57b90c6e569533c114383a9`
  are diagnostic evidence, not product-failure or exact-engine-cause proof.
- C-116 design review cycles 1 through 13 returned at least one `REVISE`
  verdict while closing response causality, local SVG structure and paint,
  graph-table trust-state visibility, CSS and SMIL temporal escapes, exact
  falsifier independence, and cross-engine serialization. Cycle 14 returned
  three independent `APPROVE` verdicts on git blob
  `598dfb89b7567df269b41491b15c7fe527248b3d` with no confirmed P0-P3
  finding.
- C-116 plan review cycle 1 returned one `APPROVE` and two `REVISE` verdicts.
  The correction makes route/observer teardown an awaited fail-closed state
  machine, makes one exact assertion plan observable through an injectable
  branch-free executor, and binds every new epoch to the historical 25-ID
  digest derived from the hash-verified C-115 failure report.
- C-116 plan review cycle 2 returned one `REVISE`, one `APPROVE`, and one
  invalidated review. The correction re-admits the historical 25-ID bytes and
  digest after the second full browser run, composite browser gate, and final
  full gate rather than checking only the first full projection.
- C-116 plan review cycle 3 returned three independent `APPROVE` verdicts on
  git blob `e04c4bdd8859ac71b0d02fde06e7c025813ae459` with no confirmed
  P0-P3 finding. C-116 is approved for implementation.
- The complete C-116 executable epoch passed on runtime candidate
  `0c67de58b0b9837d714e417f64758a76368f3efa`. Its 30 separate Firefox
  processes passed 750 of 750 tests with one worker, zero retries, zero
  skipped, unexpected, or flaky tests, and one immutable input digest
  `sha256:ec3d79218e20831e726bf45e171b1d0276fdf22a04790a13f1e72e6df8dbee0d`.
  Every iteration retained historical test-ID digest
  `sha256:f7b80cd6ea950cad6693a7b11020f746581d6eba4f2b7314700e4161448a554c`;
  the records JSONL SHA-256 is
  `e38754615878a012358d2fe75fd4af031107450a7ec2bc6d70db6bc89c543051`.
  Both following full browser proofs passed 75 of 75, the composite browser
  gate passed 21 static and 75 runtime tests, and the final `npm run check`
  passed. The build, two full-browser, composite, and full-check watchdogs all
  recorded `exited`, leader exit code zero, no leader signal, and empty signal
  and process-group probe error sets.
- Provider run `30297044766`, attempt 1, reported head
  `26e44b79a90b41494f9971b84f66e4b737bc9baa` but checked out synthetic merge
  commit `da27a7a1b3e17a901a47621a31ca8ae3432f9901`; their trees are both
  `ae3b0b16efc3d185425a91488b1f902eee630c2f`. It later timed out in the
  Firefox focus negative control after Playwright 1.61.1 entered
  `evalOnSelectorAll`. Artifact `8665124396` has GitHub digest
  `sha256:db3179664637de3b053bde5efce6b0e2e8b44e3d96c5b7bf07032a270b2b46b5`;
  its report, trace ZIP, and inner trace SHA-256 values are respectively
  `3498361d22679cc87c6560c055750bb3c782bb1d8761b28e5287499e0486a4d2`,
  `b4f5560b9e0e240dab35e631d9b848a6f18817b02ca6c03c2254a32ba989328d`,
  and `86a30f0e21dc41a9961d26506f262e18a1cfd8832cca24d9c70a1504864dc0a4`.
  The inner trace has no matching return. Chromium, WebKit, source, macOS
  smoke, CodeQL, OSV, and semantic diff passed. This falsifies provider
  liveness, not product behavior, and activates the plan's isolated 1.62 A/B.
  Change only `package.json`, `package-lock.json`, the package-verifier exact
  dev-dependency pin, and its fixture. Preserve all tests, one worker, zero
  retries, 30-second tests, production code, and business logic. Require
  package-verifier tests, then a new input digest and immutable 30-process
  Firefox epoch from iteration 1, two full browser proofs, browser static 21
  of 21 plus runtime 75 of 75, the full gate, committed-object review, and a
  fresh attempt-1 provider run.
  Bot PR 80 run `30250528617` used base
  `3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64`, synthetic merge
  `3367101eaf48fd664f1c1975181c15d047d7fac2`, and browser artifact
  `8646807702` with GitHub digest
  `sha256:57de6b30f9a3a82ca33b4ad18f9f36c2b47dbc55dac301c4f11669040b7a4ae1`.
  Its green provider browser job ran only the older six tests per engine, so it
  is supporting A/B evidence only and does not cover the current focus negative
  control. Its red source and aggregate jobs prove that its unsynchronized
  verifier pin is not independently mergeable.
- The first Playwright 1.62 post-epoch full gate exposed C-117. With a retained
  `wheel`-group `TMPDIR` outside the caller's groups, Darwin returned success
  from the setgid `chmod` but cleared the bit. The writer correctly observed
  unchanged `0644`; the test incorrectly treated API success as proof that its
  mutant existed. The subtest passed 100 of 100 under the default
  `staff`-group temp root and failed 100 of 100 under the retained root. Repair
  the test oracle only; production output semantics remain unchanged.
- Final exact-object review found that C-119's HTTP-response and exact-heading
  guards had no guard-specific falsifiers: deleting or weakening them retained
  an 81-test green matrix. C-120 adds distinct open and reload 503 cases and a
  substring-preserving accessible-name drift before a new committed-object and
  provider epoch.
- Provider attempt 1 for exact source
  `dcc824b31f858ab8fea5be683e5d81f12f039279` falsified even the remaining
  `commit` lifecycle wait: Firefox received status 200, loaded every local
  resource, and rendered the initialized workspace while `page.goto` remained
  pending. C-121 replaces lifecycle waiting with a pre-armed exact-URL,
  main-frame navigation-response observer, exact trigger token, response
  admission, and the existing exact heading. A pure classifier truth table,
  live same-URL fetch decoy, static lifecycle-source oracle, and the C-120
  response and heading mutants close the new proof surface.
- Final Sol/max review of exact candidate
  `c2315fdf28be95eab08089008773d7dd234d9c96` reproduced two false-green
  documentation/proof candidates. C-122 makes P12.2's declarative and
  executable post-`c2315fd` correction inventories the same three paths.
  C-123 adds positive
  and negative exact raw-base-URL cases so each local-origin clause is
  executable rather than source-only.
- The same review reproduced C-124 by deleting token admission and waiter
  abort while static 22/22 and runtime 93/93 stayed green. One injected
  pending waiter in the existing navigation test now requires the exact token
  failure, abort observation, and rejection consumption independently.

## Purpose

This plan converts the approved audit-remediation design into an ordered,
test-first implementation graph. It is complete only when every finding has a
durable owner update, an executable counterexample, a passing repair, a
business-logic compatibility disposition, and final full-gate evidence.

## Authority and retirement

The design's authority order, scope, non-claims, and retirement rules apply
unchanged. This plan is temporary execution authority. It retires with the
design only after the durable implementation, exact-object gates and reviews,
validated branch and pull request, the design's closed source-owned required
provider-check inventory is present and successful, every other triggered
check has a terminal disposition, retrospective routing is complete, and the
final pull-request closeout projection satisfies the design's retirement
predicate.

## Execution policy

Implementation uses one writer in the shared worktree. Review agents remain
read-only until code-review rounds. This prevents shared-state mutation from
invalidating independent review evidence.

For every tranche:

```text
owner delta
  -> current-wrong counterexample
  -> observe expected red
  -> minimal production repair
  -> narrow green
  -> adjacent positive regression
  -> contract/binding/non-claim parity
```

No tranche may:

- weaken a durable non-claim to make a test pass;
- infer provider or registry evidence from local artifacts;
- add a shared abstraction with fewer than two genuine consumers;
- split or merge a large file without a separately proven cohesion defect;
- hide an unresolved selective edge behind the full gate;
- retain both old and new release-record owners;
- modify an already published release or historical tag.

The `owner delta` is not deferred to P10. Before the first counterexample in
each P1-P9 tranche, the implementer must update the exact requirement,
non-claim, binding skeleton, and witness selector named by the design's durable
proof table. The binding may point to a test that is red during the tranche,
but the owner and intended proof route must already exist. P10 only validates
cross-owner parity, canonical order, and final freshness.

## Dependency graph

```text
P0 frozen baseline and owner inventory
  |
  +--> P1 release/version foundation
  |      |
  |      +--> P1A artifact-specific SBOM semantics
  |      +--> P4 machine CLI contracts
  |      +--> P8 package/onboarding projections
  |
  +--> P2 evidence/channel classification
  |
  +--> P3 confined filesystem boundaries
  |
  +--> P5 workflow and release oracles
  |
  +--> P6 proof-gap falsifiers
  |
  +--> P7 context wire migration
  |      |
  |      +--> P9 browser state and accessibility
  |
  +--> P8 package/onboarding projections
  |
  +--> P9 browser state and accessibility
         |
         v
      P10 durable proof surfaces
         |
         v
      P11 worktree review and candidate preparation
         |
         v
      P12 committed-object review, push, pull request, provider status
```

Only P1 must precede public contract and package metadata projections. P7 must
precede browser tests that consume the new manifest vocabulary. Other
production tranches may be developed independently in concept, but are applied
serially in the shared worktree.

## P0: Freeze and preflight

### Objective

Prove the implementation starts from the reviewed object and preserve user
changes.

### Actions

1. Before any branch mutation, require the only changed paths to be the two
   reviewed, untracked implementation documents:

   ```bash
   git branch --show-current
   git rev-parse HEAD
   test "$(git status --porcelain=v1 --untracked-files=all)" = \
     $'?? docs/implementation/audit-remediation-design.md\n?? docs/implementation/audit-remediation-plan.md'
   ```

2. Before any switch, reject a target branch attached to another worktree:

   ```bash
   current_worktree="$(git rev-parse --show-toplevel)"
   target_worktree="$(git worktree list --porcelain | awk '
     /^worktree / { worktree = substr($0, 10) }
     $0 == "branch refs/heads/fix/audit-remediation" { print worktree }
   ')"
   test -z "$target_worktree" || test "$target_worktree" = "$current_worktree"
   ```

3. If the target ref already exists, validate its object and base relation
   read-only before switching:

   ```bash
   if git show-ref --verify --quiet refs/heads/fix/audit-remediation; then
     test "$(git rev-parse refs/heads/fix/audit-remediation)" = \
       "3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64"
     test "$(git merge-base refs/heads/fix/audit-remediation origin/main)" = \
       "3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64"
   fi
   ```

4. Create or switch to the branch without force or replacement:

   ```bash
   if git show-ref --verify --quiet refs/heads/fix/audit-remediation; then
     test "$(git branch --show-current)" = "fix/audit-remediation" ||
       git switch fix/audit-remediation
   else
     test "$(git rev-parse HEAD)" = \
       "3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64"
     git switch -c fix/audit-remediation
   fi
   ```

5. Recheck the exact post-switch object and changed-path set:

   ```bash
   test "$(git branch --show-current)" = "fix/audit-remediation"
   test "$(git rev-parse HEAD)" = \
     "3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64"
   test "$(git merge-base HEAD origin/main)" = \
     "3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64"
   test "$(git status --porcelain=v1 --untracked-files=all)" = \
     $'?? docs/implementation/audit-remediation-design.md\n?? docs/implementation/audit-remediation-plan.md'
   ```

6. Capture exact initial file inventory and package versions.
7. Run the cheapest baseline checks:

   ```bash
   git diff --check
   go test ./internal/command/adoptiondoctor \
     ./internal/command/publicapi \
     ./internal/command/readinesscloseout \
     ./internal/tools/releasesbom \
     ./internal/tools/releasechange \
     ./internal/tools/coveragemetrics \
     ./internal/tools/packageverify \
     ./scripts \
     ./internal/app
   ```

8. Do not rerun the full artifact gate before the first production tranche
   unless a narrow baseline unexpectedly fails.

### Stop condition

Any pre-existing test failure, unknown tracked change, or head mismatch stops
implementation until it is adjudicated. It is not relabelled as an audit fix.

## P1: Release and version-policy foundation

### Findings

R-10 and the versioned parts of R-02, R-09, R-24, R-26, R-28.

### Owner changes

- update `REQ-PROOFKIT-QUALITY-024` to own change-record schema v2,
  `previousVersion`, `changeClass`, and compatible bump classification;
- update its binding and witness skeleton before adding the first red case;
- preserve registry/publication non-claims;
- add migration text that the already published `0.1.160` is immutable.

### Test-first edits

1. In `internal/tools/releasechange/record_test.go`, add:

   - `0.1.159 -> 0.1.160` plus breaking changes: rejected;
   - `0.1.160 -> 0.2.0` plus breaking changes: admitted;
   - `1.2.3 -> 1.2.4` plus breaking changes: rejected;
   - `1.2.3 -> 1.3.0` plus compatible changes: admitted;
   - `previousVersion >= version`: rejected;
   - declared `compatible` plus required migration: rejected;
   - invalid or non-canonical SemVer: rejected;
   - duplicate/unknown v2 keys: rejected.
   - generated npm install and rollback commands both include `--save-exact`,
     and rollback names the literal `previousVersion`.

2. Update release closeout tests to require the v2 path and version relation.
3. Confirm the new cases fail against the current v1 implementation.

### Production edits

1. Replace `release/change-record.v1.json` with
   `release/change-record.v2.json`.
2. In `internal/tools/releasechange/record.go`:

   - set `RecordPath` to v2;
   - admit `previousVersion` and closed `changeClass`;
   - implement local SemVer parsing/comparison;
   - derive the required change class from breaking changes and migration;
   - reject patch-range-compatible breaking versions;
   - render exact npm install and rollback commands from the admitted current
     and previous versions.

3. Update every exact consumer:

   - `internal/tools/releasemanifest`;
   - `internal/tools/releasecloseoutinput`;
   - `internal/tools/releasepreflight`;
   - workflow source oracles;
   - package checks;
   - release documentation;
   - binding and witness records.

4. Advance synchronized version surfaces to `0.2.0`. The only authored version
   owners are `package.json` and `package-lock.json`; Python metadata, artifact
   names, release fixtures, and manifests are regenerated or validated
   projections:

   - `package.json` and lockfile;
   - Python project/package metadata;
   - change record current version and `previousVersion=0.1.160`;
   - release fixtures, manifests, expected artifact names, and notes.

5. Record all intentional breaking changes already approved by the design,
   including both `adoption-doctor` blocked-prerequisite state/exit and
   non-enforced advisory rule-status changes, the absolute-symlink rejection,
   and versioned context/browser envelopes.
6. Bind a direct current-record falsifier proving that the adoption-doctor
   change and migration step reach rendered release notes.

### Narrow gate

```bash
go test ./internal/tools/releasechange \
  ./internal/tools/releasemanifest \
  ./internal/tools/releasecloseoutinput \
  ./internal/tools/releasepreflight
```

### Rollback condition

If a live owner proves `0.2.0` conflicts with an unpublished version allocation,
stop. Do not create a special-case validator for `0.1.160`.

## P1A: Artifact-specific SBOM dependency semantics

### Finding

R-02.

### Owner-first changes

Before the red case, update `REQ-PROOFKIT-QUALITY-002`, its binding, and its
witness skeleton to distinguish runtime dependencies of the shipped npm
artifact from source/tool module inventory. Preserve the non-claim that a
source module edge implies an installed-artifact runtime edge.

### Test-first edits

1. Add `TestArtifactSpecificRuntimeEdgesAndExcludedInventory` in
   `internal/tools/releasesbom/main_test.go`.
2. Use two independent fixtures:

   - source/build inventory from a module graph containing source-only,
     test-only, and tool modules;
   - content-bound build-info inventories for individual release binaries.

3. Require:

   - one canonical component per admitted package identity;
   - every source-graph-only component has `scope=excluded`,
     `proofkit:evidence-class=source_build_inventory`, and no runtime edge;
   - a runtime edge exists only from the exact binary BOM reference whose
     build information names the module;
   - stripped binaries with no admitted build information have an empty
     runtime edge set;
   - distribution representations do not invent runtime edges.

4. Mutate one source-only module into a runtime edge and prove failure.
5. Bind each binary inventory to its file content/digest so evidence from one
   binary cannot authorize another binary's edge.

### Production edits

1. Retain `go list -m all` only as excluded source/build inventory.
2. Read each release binary with `debug/buildinfo.ReadFile` or an equivalent
   content-bound parser and create `binary BOM-ref -> module` edges only from
   that binary's admitted build information.
3. Deduplicate components by canonical package identity before emitting
   relationships.
4. Keep package and wheel components edge-free without their own
   artifact-derived evidence.
5. Preserve deterministic order and existing package/provenance non-claims.

### Gate

```bash
go test ./internal/tools/releasesbom
```

## P2: Evidence-state and CLI channel classification

### Findings

R-01 and R-07.

### P2.1 Adoption blocked state

Files:

- `internal/command/adoptiondoctor/adoptiondoctor.go`;
- `internal/command/adoptiondoctor/adoptiondoctor_test.go`;
- `internal/app/cli_abi_test.go`;
- retirement requirement and binding records.

Steps:

1. Update `REQ-PROOFKIT-RETIRE-008`, its binding, non-claim, and witness
   skeleton for unconditional external-precondition blocking.
2. Add `TestBuildBlocksEveryModeForExternalPreconditions`.
3. Cover `observe`, `warn`, `enforce-touched`, and `enforce-all`.
4. Add the adjacent positive case: observe-mode candidate/advisory gap remains
   `passed/0` with a `skipped` rule.
5. Confirm the blocked observe/warn cases fail on current code.
6. Split unconditional blocked gaps from policy-enforced advisory gaps.
7. Compute top-level state, rule state, exit code, and promotion readiness from
   the correct sets.

Gate:

```bash
go test ./internal/command/adoptiondoctor ./internal/kernel/adoptionmode
```

### P2.2 Structural input versus semantic report

Files:

- the nine command packages named in the design;
- `internal/app/app.go`;
- planning and agent-envelope command adapters;
- `internal/app/cli_abi_test.go`;
- CLI contract process metadata.

Steps:

1. Update `REQ-PROOFKIT-QUALITY-004`, the CLI process contract, and the nine
   affected binding/witness
   skeletons for structural-channel versus semantic-report classification.
2. Add `TestRequiredInputCommandsRouteStructuralErrorsByMode` with exact
   command inventory:

   - `branch-authority`;
   - `changed-path-set`;
   - `deployment-evidence-admission`;
   - `external-consumer`;
   - `package-runtime-dependency-admission`;
   - `readiness-closeout`;
   - `registry-consumer`;
   - `registry-consumer-proof-input-compose`;
   - `repo-profile-admission`.

3. For ordinary `{}` input assert exit 1, empty stdout, non-empty sanitized
   stderr.
4. For supported explicit agent-envelope forms assert exit 1, one invalid-input
   JSON envelope, empty stderr.
5. For one structurally admitted semantic failure assert nonzero exit, one
   report JSON value, empty stderr.
6. Confirm all nine ordinary cases fail on current code.
7. Change builders to return admission errors rather than synthetic reports.
8. Keep envelope conversion only in the app adapter.
9. Remove any app-layer inspection of synthetic report IDs.

Gate:

```bash
go test ./internal/app -run RequiredInputCommandsRoute
go test ./internal/command/branchauthority \
  ./internal/command/changedpathset \
  ./internal/command/deploymentevidenceadmission \
  ./internal/command/externalconsumer \
  ./internal/command/packageruntimedependency \
  ./internal/command/readinesscloseout \
  ./internal/command/registryconsumer \
  ./internal/command/registryconsumerinputcompose \
  ./internal/command/repoprofileadmission
```

### Compatibility assertion

No valid admitted semantic decision changes. Only malformed-input channel
routing and impossible `blocked -> passed` outcomes change.

## P3: Handle-confined filesystem boundaries

### Findings

R-03 and R-04.

### P3.1 TypeScript scanner

Files:

- `internal/command/publicapi/public_api.go`;
- `internal/command/publicapi/public_api_test.go`;
- package boundary requirement, CLI contract, and binding.

Test-first steps:

1. Update the package-boundary requirement, binding, non-claim, and witness
   skeleton for handle-confined admission and the absolute-symlink migration.
2. Add a private staged operation seam with channels controlled by same-package
   tests.
3. Add `TestVerifyRejectsDeterministicSymlinkSwap` with two mandatory table
   rows:

   - leaf/source symlink swap;
   - ancestor-directory symlink swap.

   For both rows:

   - pause at the exact legacy validation/use boundary;
   - replace the selected component with an external sentinel route;
   - release execution;
   - assert error/nonzero, no successful report, and no sentinel bytes in
     output.

4. Add stable relative in-root symlink success.
5. Add absolute in-root symlink rejection with exact migration diagnostic.
6. Add canonical `.tsx` target rejection.
7. Add pinned-file size/identity change rejection.
8. Add `TestCanonicalSourceSnapshotRejectsChangedCrossAliasAdmission`: prove
   that stable aliases of one canonical source reuse the first parsed snapshot,
   then replace that canonical source and require a fresh alias to fail on
   identity or digest drift.
9. Add `TestVerifyPinsPackageRootAcrossInRootSiblingSwap`: replace the
   manifest-owning package path with an in-root sibling after source
   resolution, and prove all source bytes still come from the package sub-root
   pinned before manifest admission.
10. Confirm the staged redirects reproduce current vulnerability without a
   polling loop.

Production steps:

1. Open the caller-selected repo with `os.OpenRoot`.
2. Open each referenced package as a confined pinned sub-root before reading
   its manifest.
3. Admit package manifests and all named sources through that same package
   sub-root.
4. Bind their open handles with `os.SameFile`.
5. Read from the pinned lexical handle under existing file and aggregate
   budgets.
6. Verify pre/post identity and size.
7. Cache immutable bytes by admitted relative identity and bind every lexical
   alias of one canonical source to the first admitted identity, digest, and
   parsed exports.
8. Reject a later alias when canonical identity or digest differs.
9. Reject absolute symlink targets as the recorded v0.2 breaking hardening.

Gate:

```bash
go test ./internal/command/publicapi
go test ./internal/app -run TypeScriptPublicAPI
```

### P3.2 Repository-relative output writer

Files:

- `internal/app/requirement_commands.go`;
- `internal/app/cli_abi_test.go`;
- spec-tree output requirement and binding.

Test-first steps:

1. Update the spec-tree output requirement, binding, non-claim, and witness
   skeleton for root-confined publication.
2. Add private root-operation injection plus exact pre-temporary-file,
   pre-object-admission, and irreversible-rename parent-swap barriers.
3. Add `TestOutputWriterRejectsDeterministicParentSwap`.
4. Assert external and in-root replacement sentinels remain unchanged and no
   output or temporary residue reaches the displaced parent.
5. Replace the temporary route, change its permission bits, independently add
   setuid, setgid, and sticky bits, rewrite its content, and substitute a
   symlink before final object admission; require exact rejection, destination
   non-mutation, and cleanup in every case.
6. Preserve stable output bytes, mode `0644`, empty stdout, and cleanup.
7. Confirm the current writer is caught by the staged counterexamples.

Production steps:

1. Open the repository root once.
2. Create/check parents through `os.Root` and pin the admitted destination
   parent.
3. Create an unpredictable temporary file through the pinned parent with
   `O_CREATE|O_EXCL`.
4. Write and chmod through the file handle and retain its admitted identity,
   exact mode, and expected content digest.
5. Close, cross the exact object-admission barrier, re-admit the non-symlink
   temporary entry's identity, exact mode, and content digest, cross the exact
   rename barrier, then re-admit the current parent route at the irreversible
   rename boundary.
6. Rename to the destination and clean failures through the same pinned parent,
   preserving writable-child and nested-filesystem behavior.
7. Keep static symlink/directory diagnostics without relying on them for
   confinement.

Gate:

```bash
go test ./internal/app -run OutputWriter
```

### Non-claims

No checkout freshness, compiler provenance, protection from adversarial
concurrent content or namespace mutation by the same operating-system user
during the operation, fsync durability, or repository-wide transaction is
claimed.

## P4: Complete machine CLI contracts

### Finding

R-09, plus the machine projection needed by R-15 and R-24.

### Files

- `proofkit/cli-contract.v2.json`;
- new `internal/tools/commandcontractgen`;
- new generated `internal/app/command_contract_generated.go`;
- new generated
  `internal/command/stackpreset/preset_ids_generated.go`;
- `internal/app/command_descriptors.go`;
- `internal/app/command_help.go`;
- `internal/app/cli_contract_test.go`;
- `internal/app/cli_abi_test.go`;
- `package.json`.

Before the first red case, update `REQ-PROOFKIT-QUALITY-004` and
`REQ-PROOFKIT-PACKAGE-002`, their bindings/non-claims/witness skeletons, to
name the authored contract, both generated projections, selector-resolution
rule, and freshness gate.

### P4.1 Define the authored contract model

1. Add bounded `root_shape_only` input/output definitions with stable IDs and
   canonical digests.
2. For all 74 required-input commands, author:

   - contract ID and schema version;
   - one or more condition-complete root variants;
   - root kind (`object`, `array`, or explicitly unconstrained `json_value`);
   - exact closed allowed/required top-level fields for object roots;
   - exact owner requirement and native admission witness selector.

3. For every JSON-producing command, author:

   - every supported JSON-producing flag/mode condition;
   - exact root kind and top-level fields for each object variant;
   - first-class array variants where a command can return an array;
   - exact `rootType=union` when bounded variants have more than one root kind;
   - explicit unconstrained `json_value` only where no narrower root contract
     is honestly owned, never as the aggregate for a bounded union.

4. Add exact flag-value choices for stack presets from the same machine owner.
5. State explicitly that nested fields, scalar types, collection cardinality,
   nullability, and cross-field semantics are outside this bounded contract.

### P4.2 Generator

1. Add `internal/tools/commandcontractgen`.
2. Parse the authored contract with strict duplicate-key rejection.
3. Reject the superseded inferred nested/delegated graph grammar.
4. Reject digest mismatches, missing required-input contracts, missing
   JSON-output contracts, duplicate IDs, missing native witness selectors,
   duplicate or empty variant conditions, missing default conditions for
   optional mode flags, invalid root kinds, scalar-capable `json_value` used
   for bounded unions, and allowed/required fields on non-object roots.
5. Resolve each native selector through a deterministic tracked-test inventory:

   - selector identifies an exact `_test.go` path and test function;
   - Go AST confirms the function exists with a valid test signature;
   - the witness command selects that test;
   - stale path, nonexistent test, or unselectable command is rejected.

6. Generate one deterministic Go map used only for private help/descriptor
   metadata and one lower-package preset-ID table. Both outputs come from the
   same authored input and one generator execution.
7. Support `--check` without rewriting.
8. Add:

   ```json
   "command-contract:check": "go run ./internal/tools/commandcontractgen --check"
   ```

9. Place `npm run command-contract:check` in `npm run check` before command
   family and Go gates.

### P4.3 Runtime and compatibility projection

1. Remove manually authored schema summaries where generated metadata owns the
   same fact.
2. Merge generated metadata with private runner/owner/test registration.
3. Render help from generated summaries and flag choices.
4. Include fully resolved input/output contract content and canonical digests
   in the ABI projection.
5. Add mutation tests for:

   - root kind;
   - allowed and required root fields;
   - variant condition;
   - schema version;
   - deleted contract;
   - digest mismatch.
   - stale/nonexistent native witness selector.
   - either generated output stale while the other is current.

6. Classify `nativeAdmissionWitnessSelector` as source-checkout evidence, not a
   package-consumer route. The shipped contract may name that evidence class,
   but does not promise that `_test.go` files are installed.

7. Add direct `app.Run` root-shape assertions for the high-risk multi-mode
   commands, including every object/array and agent-envelope route identified
   by the independent audit ledger.
8. Treat native source digests only as conservative change-review sentinels,
   never as proof that the authored root shape equals native behavior.
9. Update the ABI golden only after every mutation is killed.

### Gate

```bash
npm run command-contract:check
go test ./internal/tools/commandcontractgen ./internal/app -run CLIContract
go test ./internal/app -run CLIABI
```

### Complexity guard

Do not create a second JSON Schema runtime or make the generator validate
command input. It projects and closes the public compatibility declaration;
native admission remains command-owned. Do not infer nested ownership from AST
field-name similarity; leave nested/type/cardinality claims explicit
non-claims until an owner-generated typed schema can prove them.

## P5: Workflow and release source oracles

### Findings

R-05, R-06, R-13, and R-28.

### Files

- `scripts/workflow_package_gate_oracle_test.go`;
- `scripts/workflow_oracle_support_test.go`;
- `scripts/workflow_browser_runtime_oracle_test.go`;
- `scripts/workflow_runtime_preconditions_test.go`;
- `scripts/workflow_source_oracles_test.go`;
- `scripts/workflow_security_scanner_oracles_test.go`;
- sorted exact inventory of every `.github/workflows/*.yml`;
- supply-chain quality requirements and bindings.

Before the first red case, update the affected quality requirements, their
bindings/non-claims/witness skeletons, and add `REQ-PROOFKIT-QUALITY-025`.

### P5.1 Exact expression guards

1. Add negative fixtures for:

   - expected predicate plus `|| true`;
   - `false && expected`;
   - expected text only inside a quoted literal;
   - whitespace inside a quoted literal;
   - empty guard where not explicitly admitted.

2. Replace substring predicates with exact per-job/per-step allowlists.
3. Normalize layout only outside quoted literals.
4. Preserve current owner-reviewed expressions byte-semantically.

### P5.2 Exact CI aggregate

1. Add `TestCIWorkflowDeclaresFailClosedRequiredAggregate`,
   `TestCIRequiredAggregateRejectsNeutralizedScript`,
   `TestCIRequiredAggregateRejectsExecutionOverrides`, and
   `TestCIRequiredAggregateRejectsPlatformSmokeSubstitution` to the exact
   requirement bindings.
2. Mutate fixtures with dead branch, `|| true`, early `exit 0`, and background
   execution.
3. Mutate inherited workflow defaults and environment, job defaults and
   environment, step environment, shell, and working-directory, and literal,
   expression, explicitly false, and explicit YAML `null` forbidden fields.
4. Require exact job identifiers, provider-check names, hosted runners, needs,
   `always()`, and safe workflow run defaults; require no workflow, job, or
   step environment entries, reusable jobs, job defaults, or job-level
   `continue-on-error` on any required leaf or aggregate job, one aggregate run
   step, and no step-level execution override anywhere in those jobs.
5. Compare the whole aggregate shell block, the exact ordered macOS step
   inventory with presence-aware `run`/`uses`/`with` keys, the exact
   repository-local setup-action digest, and the whole fail-closed
   platform-smoke package-script owner command.

### P5.3 External action pins

1. Complete `REQ-PROOFKIT-QUALITY-025` with:

   - external `uses` must be a 40-lowercase-hex commit;
   - local `./` actions remain confined;
   - no claim of action safety, tag equivalence, or provider execution.

2. Add binding/witness IDs from the design.
3. Add `TestWorkflowExternalActionsUseFullCommitSHAs`.
4. Discover and sort the exact tracked workflow inventory, reject any
   unadmitted extension/path, and inspect every YAML `uses`.
5. Replace one fixture ref with a tag and short SHA to prove failure through
   the same common oracle.

### P5.4 Existing release immutability

1. Add `TestExistingReleasePathIsReadOnlyAndFailsOnDrift`.
2. Freeze the complete existing-release shell block as one canonical
   owner-reviewed form.
3. Permit only exact release view/download provider calls inside it.
4. Remove missing-asset upload/backfill logic.
5. Make missing, extra, or different assets terminate nonzero before mutation.
6. Add negative fixtures for upload, edit, delete, `gh api`, `curl`, alternate
   clients, shell indirection, and extra commands.
7. Keep new-release behavior unchanged.

### Gate

```bash
go test ./scripts -run 'WorkflowGuard|RequiredAggregate|ExternalActions|ExistingRelease'
npm run go:actionlint
```

### Non-claims

No local oracle proves provider execution, branch protection, release asset
state, or external action safety.

## P6: Independent blocking falsifiers

### Findings

R-11a through R-11d and R-12.

### P6.1 Self-hosting verdict

1. Apply split owner-first deltas before red tests:

   - R-11a and R-11d:
     `REQ-PROOFKIT-PACKAGE-004`;
   - R-11b:
     `REQ-PROOFKIT-PACKAGE-006` and `REQ-PROOFKIT-QUALITY-023`;
   - R-11c:
     `REQ-PROOFKIT-PACKAGE-001`;
   - R-12:
     `REQ-PROOFKIT-QUALITY-010`.

   Update each exact binding/non-claim/witness skeleton without assigning a
   neighboring invariant as owner.

2. Extract a command-local pure verdict helper over `(process error, output
   bytes)` in `scripts/validate-self-hosting-receipts.go`.
3. Keep the fixed executable invocation unchanged.
4. Add `TestRunProofkitVerdictCases` for nonzero process exit, invalid JSON,
   wrong state, and
   exact passed output.
5. Keep production output unchanged.

### P6.2 Package and wheel integrity

1. Add one-negative-at-a-time tests for:

   - npm name/version, duplicate, missing artifact;
   - wheel version, duplicate, missing file, and SHA mismatch;
   - every root tarball forbidden exact name and suffix;
   - local versus CI receipt identity.

2. Exercise `verifyRootPackage`, not only the leaf deny helper.
3. Use a complete minimal tarball plus exactly one forbidden entry.

### P6.3 Coverage closure

1. Add one case for each of the five command-route arrays.
2. Add one case for each of the four linkage dead-zone arrays.
3. Add all-empty success.
4. Require each mutation to fail at least its named negative test while the
   positive fixture remains green.
5. Preserve `COVERAGE-01` as unresolved; static route metadata still does not
   become semantic execution evidence.

`npm run self:receipt` is intentionally not part of this narrow gate. It is
artifact-dependent and runs only after P10 rebuilds the current package
evidence. The executable P6 gate is:

```bash
go test ./scripts -run 'RunProofkitVerdict|PackageArtifactRefs|PythonArtifactRefs|ReceiptID'
go test ./internal/tools/packageverify -run 'ForbiddenRootEntry|VerifyRootPackage'
go test ./internal/tools/coveragemetrics -run 'EachCommandRoute|EachLinkage'
npm run self:coverage
```

## P7: Honest context/diff/browser wire vocabulary

### Finding

R-24.

### Files

- `internal/command/requirementcontext`;
- `internal/command/requirementdiff`;
- `internal/command/requirementgraph`;
- `internal/command/requirementbrowser`;
- affected app ABI tests and CLI contracts;
- spec requirements and bindings.

Before the first red case, update the context/diff/browser/graph requirements,
bindings, non-claims, and migration witness skeletons for the closed v1 adapter
and v2-only producer boundary.

### P7.1 Versioned model

1. Define context snapshot v2:

   ```text
   expectedDigestCoverage = none | partial | all
   ```

2. Fully admit v1 before adapting:

   ```text
   unverified -> none
   partially_verified -> partial
   verified -> all
   ```

3. Reject mixed v1/v2 keys.
4. Make all producers emit v2 only.

### P7.2 Downstream envelopes

Version and migrate separately:

- semantic-diff input/output v2;
- workspace manifest v2;
- affected workspace API projections v2;
- CLI output contracts and golden corpus.

Legacy terms may appear only in:

- strict v1 adapters;
- migration fixtures;
- compatibility diagnostics.

They must not appear in v2 output, current help, current contract descriptions,
or UI.

### Tests

1. `TestV1DigestCoverageAdapters`.
2. `TestV2DigestCoverageProjections`.
3. Mismatch expected/current remains rejected.
4. V1 normalized output equals the equivalent v2 semantic record.
5. Mixed fields and malformed legacy records fail.
6. Add `TestLegacyDigestVocabularyConfinedToV1AdaptersAndFixtures`. It scans
   Go sources, CLI contract/help, browser assets, and test producers; legacy
   vocabulary is allowed only in exact v1 adapters, migration fixtures, and
   compatibility diagnostics.

### Gate

```bash
go test ./internal/command/requirementcontext \
  ./internal/command/requirementdiff \
  ./internal/command/requirementgraph \
  ./internal/command/requirementbrowser \
  ./internal/app
```

### Non-claims

Coverage does not authenticate a baseline, producer, checkout, or freshness.

## P8: Installed-artifact onboarding and documentation closure

### Findings

R-14 through R-17, R-22, R-25 through R-27, and the documentation portion of
R-10.

Before the first red case, update the exact package/spec requirements,
bindings, non-claims, and witness skeletons for R-14 through R-17, R-22, and
R-25 through R-27.

### P8.1 Canonical install route

1. Update npm install to `--save-exact`.
2. Use `npm exec --offline -- agentic-proofkit` for canonical local commands.
3. Remove unverified Bun execution examples; retain a non-claim until an
   equivalent exact-tarball smoke exists.
4. Explain when a bare command is valid without making it canonical.

### P8.2 Stack preset and family discovery

1. Add defensive-copy `stackpreset.IDs()`.
2. Project IDs from the machine CLI contract/generated metadata.
3. Direct help and invalid-ID diagnostics list all and only valid IDs.
4. Root help adds only the copyable
   `npm exec --offline -- agentic-proofkit help families` discovery route.
5. Preserve token-efficient opt-in family expansion.
6. Preserve one authored vocabulary:
   CLI contract -> generated lower-package table -> defensive-copy
   `stackpreset.IDs()`. A sibling generated app table serves descriptors/help.
   Remove any manual `presetIDs` list and prove exact bidirectional parity with
   the profile map. Both generated files share one freshness gate.

### P8.3 First valid input

1. Add one marker-bounded minimal requirement-source JSON block to README.
2. Add the exact offline invocation.
3. State that example IDs and meaning are caller-replaceable and
   non-authoritative.
4. Do not make `KnownKeys` globally verbose.

### P8.4 Installed-artifact end-to-end witness

Extend `internal/tools/packageverify/main_test.go` with
`TestExactTarballOnboardingTrace`:

1. build/install the exact local tarball in a temporary consumer;
2. run root help through `npm exec --offline` and prove it exposes exactly one
   copyable canonical family-discovery route;
3. parse and execute that exact displayed route, reject a bare executable
   mutant, and prove family output exposes
   `stack-preset`;
4. execute installed `help stack-preset` and extract every preset ID from that
   human/agent help transition;
5. compare help-derived IDs bidirectionally with the installed machine
   contract; the contract is a parity oracle, not a substitute UX route;
6. run every discovered stack preset ID;
7. read the marker-bounded command and JSON together from the installed
   README;
8. execute exactly the admitted README argv through the same local
   `npm exec --offline` and feed it the extracted JSON;
9. require exit 0, passed JSON, and empty stderr.

### P8.5 Markdown and package reference closure

1. Replace raw preset pipes in the contract-map table with separate code spans.
2. Add `TestContractMapDecisionTreeHasThreeCells`.
3. Remove `AGENTS.md` and `CONTRIBUTING.md` from the npm package.
4. Remove the active-backlog route from package-public README.
5. Keep `BACKLOG.md` source-checkout-only.
6. Update or exclude package projections that cite contributor-only files.
7. Treat self-hosting selectors as source-checkout evidence, not
   package-consumer navigation.
8. Add field-aware `TestPackagePublicReferenceClosure`.
9. Bind mutable-release-fact policy separately to
   `TestVerifyNoStalePackageDocsRejectsMutableReleaseFactsInMarkdown`; retain
   reference closure only in its own PACKAGE-001 scenario.

The closure inventory includes README Markdown destinations under the bounded
destination grammar, relative paths in the exact command-navigation statement
and owner-table cells, and every classified reference-bearing string field in
package-public machine projections. It does not claim a complete Markdown
parser or discovery of unclassified code-span paths. A relative reference is
admitted only if the normalized target is a shipped tarball entry;
source-checkout owners are denied explicitly.
`nativeAdmissionWitnessSelector` is an explicit source-checkout evidence class
and is not treated as package-consumer navigation. At minimum, kill:

- the original `Active work ledger | BACKLOG.md` table-cell form;
- one ordinary dangling README link;
- `docs/MISSING.md` substituted into the exact README command-navigation code
  span;
- one dangling package-public machine-field route;
- one false classification of a source-only witness as a shipped route.

### P8.6 Python/platform projection

Add a marker-bounded README block and compare it to owners:

- macOS 12+, arm64/x64;
- Linux manylinux 2.17, arm64/x64;
- Python `>=3.9`;
- Windows unsupported;
- wrapper over the same Go CLI, not an SDK;
- conditional exact version install;
- no current PyPI availability claim.

Document complete conditional chains:

```text
python -m pip install agentic-proofkit==<version>
python -m agentic_proofkit help

uv add --dev agentic-proofkit==<version>
uv run agentic-proofkit help
```

Add `TestREADMEPlatformAndPythonProjection`.
Add `TestReleaseTargetsProjectExactPythonWheelMetadata` and bind it with the
README projection plus `TestVerifyWheelContentsRequiresExactWheelMetadata` to
the exact release-platform Python-wheel scenario.

### P8.7 Browser route diagnostic and launcher contract

1. Include `workspace` in the command-local invalid-view diagnostic.
2. Add runtime/app parity test.
3. Refine `SPEC-021` to prohibit caller-supplied and native-witness execution
   while permitting the fixed OS launcher.
4. Inject launcher operation in tests.
5. Require fixed executable/argv forms and server-generated loopback URL.
6. Add `TestOpenBrowserUsesFixedLauncherAndLoopbackURL`.
7. Keep that selector in the fixed-launcher scenario; bind the distinct
   one-shot cleanup scenario to the three exact `TestServeOneShot*` cleanup and
   concurrency tests.

### Gate

```bash
go test ./internal/command/stackpreset ./internal/app
go test ./internal/tools/packageverify -run 'OnboardingTrace|PackagePublicReferenceClosure'
go test ./internal/tools/pythonpackage ./internal/kernel/releaseplatform
go test ./internal/command/requirementbrowser -run 'InvalidView|OpenBrowser|ServeOneShot'
```

## P9: Browser state, accessibility, reflow, and contrast

### Findings

R-18 through R-23.

Before the first red case, update the browser requirements, bindings,
non-claims, and witness skeletons for the state matrix, semantics, reflow,
target-size, and contrast contracts.

### P9.1 Production state model

1. Server HTML includes a visible bootstrap-loading state.
2. Initialization removes the capability token before API use.
3. Manifest fetch is inside a bounded initializer with sanitized terminal
   failure.
4. View failures and handoff failures use distinct stable state IDs.
5. Active view controls expose `aria-current`.

### P9.2 Native semantics

1. Replace synthetic tree/treeitem roles with `ul`, `li`, and `article`.
2. Remove roving tab index and ArrowUp/ArrowDown handler.
3. Add a visible `Handoff packet` heading.
4. Make the packet a semantic region with `aria-labelledby` pointing to that
   visible heading.
5. Preserve Tab/Shift+Tab, Enter/Space, selection, Unicode coordinates, and
   handoff semantics.
6. Assert `getByRole("region", { name: "Handoff packet" })` in empty,
   successful, and failed handoff states.

### P9.3 Layout and colors

1. Add `box-sizing`, `min-width:0`, and `max-width:100%` to grid regions.
2. Allow long human text and IDs to wrap.
3. Wrap navigation.
4. Add labelled internal graph and table scroll viewports.
5. Never hide document overflow globally.
6. Define explicit light/dark foreground, background, border, and focus tokens.
7. Preserve forced-colors adaptation.

### P9.4 Deterministic state matrix

Refactor `tests/browser/workspace.spec.mjs` around a table:

```text
state
setup/barrier
expected data-state and heading
default axe
explicit target-size
320px reflow
contrast when applicable
```

Required rows:

- bootstrap loading with deferred manifest;
- bootstrap failed;
- specifications loading with a deferred requirements response;
- specifications;
- specifications no-match with an admitted empty requirement projection;
- diff loading with a deferred diff response;
- diff;
- graph loading with a deferred graph response;
- graph;
- unavailable diff/graph;
- view request failed;
- handoff result;
- handoff failed.

For every row:

1. Assert body and stable content-substate identity before any oracle.
2. Run default axe and require no violations.
3. Explicitly enable `target-size`, require applicability, and require no
   violations.
4. At 320 by 800, assert no document-level horizontal overflow.
5. Permit only labelled graph/table internal overflow.
6. Compute effective composited colors from actual rendered and focused
   controls and their adjacent backgrounds in light and dark schemes for
   Chromium, Firefox, and WebKit.
7. Require text contrast at least `4.5:1` and boundary/focus contrast at least
   `3:1`.

In a separate negative test, render an intentionally undersized control,
explicitly enable `target-size`, require applicability, and require at least
one violation. The production state matrix contains only zero-violation rows.

### Gate

```bash
npm run browser:static-check
npm run browser:test
```

### Non-claims

No full WCAG 2.2 conformance, branded Safari, complete screen-reader
interoperability, every OS theme, or 400-percent zoom claim is added.

## P10: Durable proof parity and current artifacts

### Objective

Validate that implementation evidence, not the temporary design/plan, owns
every repair. Exact owners and binding skeletons were already created before
their P1-P9 counterexamples.

### Requirement-source parity

Confirm only these exact affected invariants changed:

- `REQ-PROOFKIT-RETIRE-008`;
- `REQ-PROOFKIT-PACKAGE-001`, `002`, `003`, `004`, `005`, `006`, `007`;
- `REQ-PROOFKIT-SPEC-001`, `009`, `011`, `018`, `019`, `021`;
- `REQ-PROOFKIT-SPEC-022`, `023`;
- `REQ-PROOFKIT-QUALITY-002`, `004`, `005`, `006`, `007`, `010`, `011`,
  `013`, `016`, `019`, `022`, `023`, `024`;
- add `REQ-PROOFKIT-QUALITY-025`.

Do not broaden unrelated requirements.

### Implementation correction epoch

Apply the design's C-01 through C-124 corrections before final parity:

1. prove one immutable release byte snapshot owns hash and build information
   before a same-handle content/identity recheck, and bind TypeScript canonical
   first-admission bytes/digest/identity/parsed exports with deterministic
   same-lexical and cross-alias swap falsifiers;
2. reject any CLI command whose honest root-shape input/output projection is
   absent, open, structurally invalid, condition-ambiguous, or missing a
   supported variant; cover explicit and omitted defaults with direct public
   CLI oracles, while retaining nested fields, leaf types, collection
   cardinalities, and nullability as explicit non-claims;
3. reject witness selectors that are named declarations but not valid
   functions in active `_test.go` files discovered by the current Go build;
4. admit breaking major and pre-1.0 minor version increases without requiring
   a `.0` target, while preserving breaking-patch rejection;
5. treat `SPEC-022` and `SPEC-023` as direct schema-v2 consumer owners;
6. keep source-hygiene identifier-sensitive without treating coincidental
   content-digest substrings as organization-policy leakage;
7. derive receipt-kind mismatch fixtures from the current binding complement
   so a legitimate proof-route expansion cannot silently invert the test;
8. pin package and output parent sub-roots, bind each admitted route to its
   handle, and reject both outside-root and in-root sibling substitutions;
9. render blocked and enforceable adoption gaps as disjoint classes and keep
   unresolved external prerequisites blocking in every mode;
10. admit plural native source ownership only as a sorted, non-empty, unique
    alternative to singular ownership, with freshness checks for every source;
11. route nested deployment scanner admission failures through structural
    `stderr`, not synthetic semantic JSON;
12. declare and execute both submitted and terminal one-shot browser output
    variants;
13. admit the pilot `all` mode through one strict two-input envelope and prove
    the package and public CLI routes;
14. include unstaged tracked deletions in package-artifact snapshot identity;
15. preserve the valid root package in forbidden-root-entry mutation fixtures;
16. remove only report helpers proven unreachable after structural-channel
    migration, then refresh their native-source review sentinels;
17. require the CI aggregate to omit job-level `continue-on-error` rather than
    attempting partial GitHub-expression truth evaluation;
18. hold specifications, diff, and graph requests independently and run the
    complete browser state oracle against each visible loading state.
19. model workflow, job, and step execution controls in the typed workflow
    oracle; reject unsafe inherited defaults, unexpected environment entries,
    job defaults, shell or working-directory overrides, and any
    `continue-on-error` presence on all required leaf and aggregate jobs or any
    of their steps.
20. declare the intentional `adoption-doctor` blocked-state and nonzero-exit
    breaking change plus its consumer migration step in the versioned change
    record, and prove that both reach rendered notes.
21. declare the intentional non-enforced advisory rule transition from
    `passed` to `skipped`, prove its migration reaches rendered notes, require
    exact `observe=skipped` and `warn=warning` rule statuses, prove skipped
    rules outside an `enforce-touched` selection preserve top-level `passed/0`,
    and bind both adjacent semantic oracles to `REQ-PROOFKIT-RETIRE-008`.
22. retain an attempt-scoped browser report and test-results directory after a
    failed proof command, upload only those diagnostic paths under exact
    `failure()` semantics, and keep the passed proof artifact on its existing
    success-only path; bind both lifecycle and workflow selectors only to the
    `REQ-PROOFKIT-QUALITY-022` browser artifact-confinement and
    failure-diagnostics-retention witnesses.
23. initialize the exact pinned axe distribution through the browser-context
    script channel behind a removable anti-corruption module and require its
    reachable builder entrypoint to evaluate only a deterministically tested
    constant loader; configure retained traces to preserve actions, DOM
    snapshots, network, and sources while disabling continuous screenshots;
    request only one bounded best-effort screenshot after a failure, preserve
    the default and target-size axe oracles plus the undersized-control negative
    fixture, and reject either isolated control, retries, or a timeout increase
    as unsupported alternatives; run repeated clean first-attempt browser
    proofs before final exact-object closeout.
24. keep output temporary-file creation and cleanup on the pinned admitted
    parent, but publish only through the repository root with full source and
    destination routes; interleave an exact `before_publish` parent move and
    prove that outside-root and in-root replacement sentinels, destination
    bytes, and displaced temporary-file residue all remain unchanged or absent.
25. supersede C-28's substituted-source route by staging the temporary object
    at the repository root, retaining its identity, and re-admitting that
    identity plus the destination-parent route after the exact barrier; keep
    publication and cleanup repository-root-confined, refresh dependent native
    source projections, reject a deterministic temporary-route substitution
    before final admission, and explicitly exclude adversarial same-user
    namespace mutation after final admission because the cross-platform
    standard-library surface cannot atomically prove both current-root ancestry
    and pinned-parent identity.
26. supersede root-level C-29 staging by returning temporary creation, cleanup,
    and publication to the pinned destination parent; after the exact barrier
    re-admit the non-symlink temporary entry identity, exact mode, and content
    digest, then re-admit the current parent route at the irreversible rename
    boundary; falsify object replacement, permission drift, each special mode
    bit, in-place rewrite, symlink aliasing, and parent replacement
    independently; and retain same-user
    concurrent content/namespace mutation as an explicit non-claim.
27. add the compatible repository-confined same-parent atomic output guarantee
    to the machine release record and prove its exact summary reaches rendered
    release notes.
28. construct a canonical closeout record from the exact final tree, diff
    counts, admitted local gate facts, residual non-claims, and retrospective;
    bind it by digest and unique sentinels in the reviewed body snapshot and
    independently in the final server body.
29. copy every local evidence artifact used by the closeout projection once
    into a private snapshot, validate and project only those exact bytes, and
    recheck final `HEAD` plus tracked-tree cleanliness after record
    construction; compare complete output-file mode to exactly `0644` and
    independently falsify setuid, setgid, and sticky mutations.
30. remove every local artifact field not admitted by an exact closeout
    predicate; retain only final-SHA provenance, enumerated state/count facts,
    and explicitly checked command, tree-state, status, and exit values.
31. slurp every local snapshot during validation, require exactly one JSON
    document, apply its full predicate to that object, and admit the exact
    Chromium, Firefox, and WebKit project inventory before projection.
32. replace the workflow literal-disabled deny-list with closed required-CI and
    release job inventories plus presence-aware exact absent-or-owner
    conditions for every job and step; preserve only named conditional
    exceptions and falsify dynamic false and explicit-null conditions on
    required CI test steps and release candidate routes.
33. bind every required CI job to its exact provider-check name and runner,
    require the macOS job's exact fail-closed platform-smoke command, reject
    no-op and reusable-job substitutions, require positive owner admission
    before each bound mutation table, and route the positive CI inventory
    selector through both owning quality requirements.
34. replace normalized runner lists with exact scalar comparisons, close the
    complete ordered macOS step inventory and exact package-script owner,
    bind one positive selector to both real CI and release package-gate
    workflows, falsify semantic shadowing and mixed-type runners, and execute
    the restored singleton coverage filter before closeout.
35. admit the exact repository-local setup-action bytes, falsify a nested
    action semantic shadow, make `run`, `uses`, and `with` key presence part of
    exact step comparison, and reject whitespace or explicit-empty dual
    execution syntax.
36. require the exact complete selector sets for the QUALITY-011 aggregate and
    QUALITY-013 package-gate anti-vacuity scenarios, falsify missing and surplus
    selectors, parse the marker-bounded README argv with a boundary-local
    expansion-free literal shell-word grammar, preserve safe single quotes,
    double quotes, escapes, and adjacent literal segments, and reject
    operators, expansion, globbing, multiline input, and malformed quoting.
37. key every protected selector inventory by its exact requirement/scenario
    pair and falsify an owner-only transfer of each newly protected critical
    scenario.
38. compare required selector sets before the generic empty-selector path,
    falsify complete deletion for both critical scenarios, reject NUL in every
    lexer state, and require no unresolved confirmed finding from every final
    reviewer.
39. trim only Bash space/tab command delimiters, preserve vertical-tab and
    non-breaking-space argv bytes plus exact JSON fence bytes, reject escaped
    NUL and unescaped double-quoted history expansion, and preserve the literal
    Bash semantics of double-quoted `\\!`.
40. trim only leading Bash space/tab delimiters, leave trailing delimiters to
    the lexer, and preserve trailing escaped space and tab in the final argv.
41. route the generic missing-selector-function mutant through an unprotected
    binding so it remains independent from exact-set admission.
42. consume complete backslash runs before history markers and preserve exact
    Bash-equivalent argv for quoted and unquoted run lengths one through four.
43. remove every severity cutoff from candidate-preparation evidence
    disposition.
44. complete the pure exact-inventory phase before generic AST and active-file
    validation so negative inventory mutants fail without repeated I/O.
45. consume every backslash run once for linear command parsing and retain a
    128-KiB non-history regression.
46. compose pure inventory and generic executability validation in production
    while routing partial fixtures only through their owning phase.
47. bind generic missing-function and invalid-signature falsifiers to
    QUALITY-010 and protect its complete four-selector inventory against empty,
    missing, surplus, and owner-transfer mutants.
48. classify the shared workflow-oracle tests by owner, bind all seventeen
    QUALITY-013 typed package-gate selectors, and protect the complete set
    without absorbing tests owned by other requirements.
49. declare the existing readiness-closeout one-pass strict
    character-reference policy as a breaking release change with exact
    migration and rendered-note projection, admit zero or one Go-test
    parameter name, bind the unnamed-parameter regression, expand the exact
    QUALITY-010 executability inventory to five selectors, and protect the
    three-selector QUALITY-024 release-record inventory.
50. split original Markdown structural segments before one-pass
    character-reference decoding and falsify an encoded pipe; add the stable
    specifications no-match substate to every browser oracle; disclose the
    removed synthetic Arrow-key contract with migration guidance and the
    compatible pilot-all envelope plus optional witness-selector I/O in the
    machine release record and exact rendered-note witness; refresh the
    readiness native-source, generated CLI-contract, and public ABI golden
    projections.
51. project the copyable offline npm exec family-discovery route in root help,
    parse and execute that displayed command in the exact-tarball consumer,
    reject a bare-route mutant, and project the compatible correction through
    release notes plus the app native-source, generated CLI-contract, and
    public ABI golden projections.
52. remove only authored leading ASCII space/tab indentation before parsing
    the displayed npm route, preserve its trailing bytes, and reject both
    leading and trailing NBSP mutants.
53. display, parse, and execute every installed onboarding transition from
    family discovery through leaf help, every contract-owned preset, the
    displayed installed README path, and the README first-valid-input command;
    reject bare or missing intermediate routes.
54. protect the exact onboarding release addition, classify removal of
    installed governance files as breaking with migration guidance, and cover
    TypeScript manifest ancestors plus sources in the absolute-symlink
    migration.
55. admit exact ordered step inventories for CI source quality, CI browser
    runtime, and the release candidate, including execution-key presence and
    values; reject inserted npm-script shadow steps.
56. record every tracked path crossing the deterministic size threshold,
    separate browser/runtime/source/scanner/support workflow responsibilities,
    retain the logically inseparable QUALITY-011/013 cluster, update moved
    binding paths, and protect PACKAGE-005, QUALITY-022, and QUALITY-025
    selector inventories against empty, missing, surplus, owner-transfer, and
    stale-path mutants.
57. add `id` and `timeout-minutes` values and presence to each exact step
    inventory, and reject both fields in source-quality, browser-runtime, and
    release-candidate jobs.
58. require every protected selector inventory to retain its exact
    `witnessPath`, and reject relocation independently.
59. freeze the exact five-file untracked inventory before staging, stage the
    reviewed tracked-plus-untracked path union, and require no unstaged or
    untracked remainder.
60. recompute the final threshold ledger and correct every stale LOC or byte
    measurement, including `internal/app/app_test.go`.
61. bind the extracted CodeQL, OSV, and Scorecard scanner selectors to
    QUALITY-005, QUALITY-006, and QUALITY-007 with exact selector and path
    inventories.
62. traverse every family and leaf route from the exact installed tarball,
    execute each displayed route, and require every installed invocation to be
    the exact npm prefix plus its bare usage before following preset and README
    continuations.
63. retain candidate path inventories in memory and feed the closed untracked
    inventory to `git add` through stdin, preserving exact staged equality
    without temporary-file cleanup.
64. require exact workflow, advisory, and provider permission maps for CodeQL,
    OSV, advisory Scorecard, and public Scorecard, including explicit
    inheritance; reject a missing floor, advisory write, and surplus provider
    write independently.
65. collect unique Usage and Installed invocation lines before comparison,
    require their authored order and exact command-token boundary, and reject
    installed-before-Usage plus prefix-collision mutants.
66. bind the C-69 falsifier to QUALITY-019, protect the exact six-selector set
    and witness path, and align the owner requirement with every displayed
    family and leaf transition.
67. require the final browser closeout snapshot to contain exactly 31 executed
    and passed tests for each of Chromium, Firefox, and WebKit, matching the
    current 93-test committed gate.
68. declare `cli_flag_conjunction_v1` only for a root-shape definition whose
    conditions close one identical sorted allowed-flag dimension set; reject
    malformed, non-canonical, missing, surplus, type-mixed, or overlapping
    assignments; enumerate the native-owner mode and pilot domains over all 80
    combinations and require exactly twelve declared valid states; derive each
    ABI condition from parsed argv; reject repeated `--mode` and `--pilot`;
    update the public ABI digest, requirements, bindings, release record,
    migration, and rendered notes.
69. extend the decomposition-owner inventory from the five extracted workflow
    owners to those files plus
    `internal/tools/commandcontractgen/condition_model.go`; retain exact staged
    path equality and empty unstaged and untracked remainders.
70. reject an explicitly empty `--pilot` value before option normalization,
    require its exact CLI diagnostic without any root-condition projection,
    and include the breaking rejection in the owning requirements, public ABI,
    release record, migration, and rendered notes.
71. distinguish the current correction worktree from the baseline-relative
    candidate: admit exactly one current untracked condition-model owner, stage
    the exact correction path union, and independently prove that the resulting
    baseline-relative additions contain all six decomposition-owner files.
72. derive the test's mode and pilot domains from immutable copies of the same
    internal native lists that construct option-admission maps, while retaining
    exact 80-combination and twelve-valid-state assertions.
73. restrict the condition-model opt-in to the current adoption output
    definition, reject an unowned second definition, and require any future
    extension to arrive with its own native-domain and argv-closure proof.
74. close the complete eighteen-file baseline-relative addition inventory after
    staging and prove that the six decomposition owners are a subset rather
    than misreporting that subset as the whole candidate delta.
75. bind the reachable guidance mode/scope JSON failure argv to its canonical
    guidance condition and `06-guidance-report` root variant before inspecting
    the body.
76. require the condition model to be referenced only by the exact adoption
    command, output direction, and adoption output definition; reject aliases
    of each component independently.
77. remove volatile exact line counts from decomposition rationale and retain
    snapshot measurements only in the deterministic threshold ledger.
78. require every JSON assertion case to carry both exact route coordinates,
    reject coordinates on non-JSON cases, and run condition and variant
    assertions unconditionally for every JSON-emitting argv.
79. require actual non-empty JSON stdout exactly when a case declares a JSON
    assertion, parse every observed stdout, and preserve the exact sorted
    fourteen-case JSON inventory against whole-case deletion.
80. replace the condition-model file's duplicate generic sorted-key helper with
    the existing same-package `sortedKeys` owner and remove the unused import.
81. replace the Mach-O compatibility scenario's README-only selector with the
    exact negative, boundary-positive, truncated-parser, and legacy-parser
    tests; add the requirement/scenario pair and witness path to the coverage
    owner's exact critical inventory, and include it in the existing empty,
    missing, surplus, owner-transfer, and relocation mutation table.
82. require exact selector/path inventories for release-platform Python-wheel
    parity and browser one-shot cleanup; add one all-target wheel
    metadata/filename projection test, retain README and verifier witnesses,
    replace the cleanup route's fixed-launcher selector with the exact three
    cleanup/concurrency tests, and keep the launcher in its separate existing
    package-boundary scenario.
83. replace the mutable-release-fact scenario's reference-closure selector with
    the existing ten-class stale-package-doc falsifier, retain reference
    closure in PACKAGE-001, and add the PACKAGE-007 requirement/scenario/path
    tuple to the five-class exact inventory mutation oracle.
84. require each CodeQL, OSV, and Scorecard workflow job inventory to equal its
    expected advisory/provider union before permission validation, and reject
    an otherwise valid unclassified job carrying `contents: write`.
85. add one immutable `cliexec` renderer with exact `npm_offline`,
    `python_module`, and `path` profiles; make npm and Python wrappers overwrite
    and export `AGENTIC_PROOFKIT_LAUNCHER_PROFILE` and
    `AGENTIC_PROOFKIT_PYTHON_EXECUTABLE`; admit exactly absent-or-`path` with no
    executable, `npm_offline` with no executable, or `python_module` with one
    absolute executable containing no report-visible secret-like or Unicode
    control content and reject every other combination without disclosing the
    value; admit once at the Go process boundary without ambient autodetection;
    thread it explicitly through help, stack-preset,
    gradual-adoption-bootstrap including the adoption aggregate route,
    project-structure, agent-route, adoption-workflow, and
    requirement-coverage producers; test the exact display and structured-argv
    paths listed by D-09, including caller-owned array prefixes and
    native-witness argv, renderer-owned suffixes, envelope command refs,
    decoded materialization payloads, and project workflow source-report
    identity; in
    the exact tarball consumer require every emitted preset command to carry
    the npm-offline prefix and execute one exact self-continuation; in
    `internal/tools/pythonpackage/continuation_test.go` build and install the
    current native wheel in a temporary venv, require the absolute
    venv-interpreter module prefix, execute one exact self-continuation,
    traverse root/family/leaf help, and directly execute exact emitted
    agent-route argv with npm absent from `PATH`; reject malformed profiles,
    secret/control paths, wrong-profile, bare, missing, surplus,
    field-relocation, caller-rewrite, Unicode-whitespace, and shell-expansion
    mutants; bind the
    exact D-09 requirement/scenario/path/selector/command rows and protect them
    in the coverage critical inventory; update
    `REQ-PROOFKIT-PACKAGE-002`, `REQ-PROOFKIT-PACKAGE-003`,
    `REQ-PROOFKIT-PACKAGE-006`, `REQ-PROOFKIT-QUALITY-019`, their exact
    bindings, and the breaking change plus migration witnessed by
    `REQ-PROOFKIT-QUALITY-024` /
    `TestCurrentChangeRecordNamesReviewedSemanticChanges`.
86. close the root-distinct native-output inventory over exactly
    `adoption-contract-envelope`, `pilot-admission`, and `self-check`; set their
    selectors to `internal/app/cli_abi_test.go` /
    `TestAdoptionContractEnvelopeCLIABI`,
    `TestStandaloneMultiVariantCommandsUseExactRootShapes`, and the new focused
    `TestSelfCheckOutputUsesExactRootShape` with each exact anchored
    `go test ./internal/app -run` command; add `internal/app` to pilot output
    `nativeSources`, retain exact adoption
    `{internal/command/adoptioncontract}` and self-check `{internal/app}` source
    sets, and recompute all affected canonical digests and projections; add an
    exact `command + direction + native-source-path-set + path + test +
    executable command + requirement + scenario` inventory tying CLI contract
    selectors and native owners to requirement bindings; map all three
    selectors to `proofkit.package-boundary.cli-output-root-witnesses` and
    `proofkit.supply-chain-quality.cli-abi-golden`, plus adoption to
    `proofkit.spec-proof-core.adoption-contract-envelope-cli-abi`; reject empty,
    missing, surplus, selector-substitution, source-set-substitution,
    nativeSource/nativeSources downgrade, path-relocation, direction-transfer,
    scenario-transfer, command-drift, and owner-transfer mutants; update
    `REQ-PROOFKIT-PACKAGE-002`, `REQ-PROOFKIT-QUALITY-004`,
    `REQ-PROOFKIT-SPEC-011`, their exact binding scenarios/selectors, and both
    generated CLI-contract projections; own the tuple-closure oracle through
    `proofkit.supply-chain-quality.cli-output-witness-contract` at
    `internal/app/cli_output_witness_contract_test.go`, selector
    `TestRootDistinctOutputWitnessBindingsAreExact`, rather than enlarging the
    general CLI topology corpus. C-90 does not change public output roots or
    require a consumer migration.
87. harden `python_module` launcher admission so the executable is a non-empty
    absolute path without report-visible secret-like, Unicode control, or
    Unicode format content; reject with field-only errors that do not disclose
    the value and exercise the shared redaction fixture corpus plus complete
    bidi-control mutants. Update
    `REQ-PROOFKIT-PACKAGE-002`, its overview projection, and D-09's exact
    admission matrix. C-91 adds no credential model or new secret scanner.
88. extend the generated-route closure across the root family route, every
    family and leaf help route, every descriptor installed invocation, help
    forms, stack-preset copyable routes, agent-route next-command and envelope
    argv, direct and aggregate adoption-workflow phase/envelope argv,
    requirement-coverage rerun argv, and project workflow plan argv; require
    display fields to equal `cliexec.DisplayArgv(argv)` where present. Build the
    project workflow plan and its source-report stable hash with the same
    renderer, while separately proving that caller-owned native-witness argv is
    byte-preserved. Bind
    `TestGeneratedCommandInvocationProfileRouteClosure` beside the string-field
    inventory selector and update the coverage exact set. Expand the installed
    Python wheel trace through root help, every family and leaf help route,
    agent-route emission, and direct execution of exact emitted argv with npm
    absent from `PATH`; admit exact four-space route indentation and canonical
    command operands, reject Unicode-whitespace and shell-expansion mutants,
    and never execute generated stdout through a shell. Update
    `REQ-PROOFKIT-PACKAGE-002`, `REQ-PROOFKIT-PACKAGE-006`, their overview and
    bindings, D-09, and the breaking summary plus migration under
    `REQ-PROOFKIT-QUALITY-024`. C-92 adds no public JSON field, ambient
    resolver, or general shell parser.
89. make the output-writer identity mutant cross-platform deterministic:
    create one ordinary replacement file with the exact expected bytes and mode
    before writer entry, prove it coexists with and has an identity distinct
    from the writer-created temporary object, then at `before_publish` remove
    the temporary entry and rename the live replacement into that pathname.
    Require the exact identity diagnostic, unchanged destination bytes, and no
    `.proofkit-output-*` residue; repeat the complete parent-swap test enough
    times to falsify accidental inode-allocation dependence. Neutralizing both
    identity checks must make this same-content, same-mode mutant fail red.
    C-93 changes no production behavior or public contract.
90. replace only the graph table's two page-realm `evaluateAll` calls with one
    shared web-first assertion helper. For each node and edge sequence require
    exact row count and `data-identity` equality at every index. Preserve the
    complete interaction flow, all later graph assertions, one worker, zero
    retries, and the 30-second timeout; falsify missing, surplus, reordered,
    duplicated, substituted, and absent identities. C-94 changes no browser
    product behavior or evidence count.
91. before typed workflow decoding, traverse raw YAML nodes for the exact seven
    tracked workflow owners. Require closed workflow, job, and step key sets;
    reject duplicate and merge keys; admit job `environment` only for release
    `publish` as exact `npm-production` and release `publish-pypi` as the exact
    `{name,url}` owner mapping. Add owner-positive coverage plus root, producer,
    aggregate, step, reusable-job, local-action-escape, environment, and unknown
    mutants; bind the selector under `REQ-PROOFKIT-QUALITY-025`. C-96 changes no
    workflow bytes or provider claim.
92. add `.css` to the existing source-hygiene text inventory. Derive one
    synthetic filename for every unique extension returned by `git ls-files`
    for the tracked requirement-browser asset owner, and run the existing
    staged-blob and current-worktree mutants over that closed set plus Markdown
    and Python. Keep the digest-substring test and token matcher unchanged.
    C-97 adds no MIME, encoding, or binary-detection abstraction.
93. replace the two selection scenarios' repeated `getAttribute`,
    `waitForFunction`, `page.evaluate`, query scan, clamping, and manual event
    dispatch. Use Playwright `selectText` and click for ordinary selection and
    collapse. For the exact emoji selection, read the locator text in the test
    runner, compute strict UTF-16 and code-point bounds independently, then use
    one locator-scoped operation and require the exact quote, nonzero start, a
    two-code-unit DOM span, and one-code-point output span. Do not add retries,
    browser branches, production hooks, timeout, workers, or new test
    identities. C-98 changes no product behavior.
94. distinguish `audit_baseline_sha=3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64`
    from
    `integration_base_sha=0df4c28bac9737f476f7dc66030363b8b40d5417`
    throughout P12.4-P12.6. Bind final parent, remote `main`, PR base, diff,
    provider projection, and closeout integration identity to the latter;
    retain the former only as named historical evidence. Admit the exact
    observed first-publication feature lease
    `1a681c47911680d101d36b48ce818ea1905a7148`, then bind every later
    correction publication to its exact current remote head and fail before
    mutation when any identity differs. C-99 changes no product behavior or
    provider state.
95. require the final coverage snapshot to contain exactly 69 requirements,
    69 bound requirements, 173 scenarios, and 78 commands. Exercise stale 167
    and adjacent 172/174 counts against the singleton snapshot predicate.
    C-100 changes only closeout evidence admission.
96. reject Unicode categories `Cc` and `Cf` at Python launcher admission,
    retain the existing non-disclosing field-only diagnostic, and exhaustively
    equate the helper classification plus admission/non-disclosure result with
    every Unicode scalar in `Cc or Cf`, including non-bidi `Cf`. Update
    `REQ-PROOFKIT-PACKAGE-002`, its overview projection, the breaking change
    record, its migration, and the exact release-projection oracle. C-101 adds
    no Unicode normalization or general path-policy layer.
97. update `REQ-PROOFKIT-PACKAGE-002`, `REQ-PROOFKIT-QUALITY-004`, their
    overview projections, and the existing PACKAGE-002/QUALITY-004
    `TestStandaloneMultiVariantCommandsUseExactRootShapes` binding. Preserve
    `--stack-diverse` as a compatible `pilot-admission` alias and add
    `--contract-envelope --stack-diverse` to the exact input/output condition
    inventories and public root-shape witness. Reject repeated `--pilot`,
    repeated `--stack-diverse`, and both mixed orders with one stable
    selector-ambiguity diagnostic before input admission. Record the formerly
    accepted repeated-selector routes as breaking and add an exact migration
    step. Regenerate both CLI contract projections and update exact condition
    inventories plus the release-projection oracle. C-102 changes no valid
    single-selector route result or output shape.
98. replace the manually selected current change-record assertions with exact
    ordered equality for all breaking change IDs/summaries, addition
    IDs/summaries, and migration steps. Require byte-for-byte equality with one
    independently authored complete current release-note projection, including
    every section and boundary. Delete each current entry; substitute every
    change ID, summary, and migration step; swap every adjacent pair; add one
    valid surplus to each machine inventory; reorder or relocate a note bullet;
    and add an in-block, appended, duplicate, or second-section note. Require the
    existing
    `TestCurrentChangeRecordNamesReviewedSemanticChanges` selector to reject
    every mutant. Update `REQ-PROOFKIT-QUALITY-024` and its overview while
    retaining the existing binding and selector. C-103 adds no source-diff
    inference, public record field, or runtime behavior.
99. replace the publication refspec's unbraced variable-colon form with
    `"${final_sha}:refs/heads/fix/audit-remediation"`. Require a complete scan
    of this tracked plan to contain no unbraced shell variable immediately
    followed by a colon before publication, then execute the corrected refspec
    under the existing exact remote lease. C-104 adds no product behavior or
    permanent shell framework.
100. after the first successful correction publication, preserve
    `1a681c47911680d101d36b48ce818ea1905a7148` only as its historical lease
    and require the next publication lease to equal current remote head
    `90090a5c712efa70b900fed0e115274cfa4773f0`. Abort before mutation on any
    mismatch and require the remote to equal the new literal final SHA after
    publication. C-105 adds no product or provider-state claim.
101. after every later owner-file addition and document correction, recompute
    the complete baseline-relative added-path inventory. Require the final set
    to contain exactly 21 paths, including
    `internal/app/cli_output_witness_contract_test.go`,
    `internal/app/invocation_profile_test.go`, and
    `internal/tools/pythonpackage/continuation_test.go`. At the C-106 freeze,
    require exactly the two reviewed design/plan paths and an empty untracked
    set before staging; retain the six-file decomposition-owner subset.
    C-106 adds no source or runtime behavior.
102. replace the Scorecard public-publish input predicate with exact equality
    over the three required output inputs and their values. Add a `repo_token`
    surplus mutant that must fail through
    `TestScorecardPublicPublishDeclaresRequiredOutputInputs`. C-107 changes no
    workflow byte or public behavior.
103. recompute the base-to-candidate `requirementId -> invariant` delta and
    require the P10 list to contain all 30 changed IDs with no surplus,
    including `SPEC-011` and `QUALITY-005`, `QUALITY-006`, and `QUALITY-007`.
    C-108 changes only temporary parity evidence.
104. remove every numeric line-count qualifier from the four
    reverse-decomposition bullets instead of refreshing the stale values.
    C-109 preserves every owner and split/merge disposition.
105. require `publish_results` to decode as the exact YAML boolean `true`,
    remove the generic truth-expression helper from this predicate, and add a
    `true }}` string-substitution mutant beside the C-107 surplus mutant.
    C-110 changes no workflow byte.
106. time-index every historical 21-path and two-file staging statement to the
    C-106 freeze and the later three-file correction statement to the C-114
    freeze; retain P12.2 as the sole current correction-path owner. C-111
    changes no staged path by itself.
107. require the selected named public-publish step to be the sole
    `ossf/scorecard-action` step. Add a differently named second action with a
    surplus `repo_token` input and require the same boundary predicate to
    reject it. C-112 adds no full step inventory or workflow change.
108. split each action reference at one `@`, compare only owner/repository to
    `ossf/scorecard-action` with ASCII case-insensitive equality, preserve the
    ref bytes, and reject mixed-case second-action, distinct-repository,
    subpath, empty-ref, and repeated-`@` mutants. C-113 adds no general action
    parser or network dependency.
109. reject every non-ASCII repository byte before case-insensitive
    comparison, retain ASCII mixed-case admission, and reject a Unicode
    simple-fold long-s mutant. C-114 adds no normalization or provider lookup.
110. replace the `@axe-core/playwright` two-audit topology with one direct
    pinned `axe-core` audit per state. Test first:
    - freeze exact run options to the sole
      `rules.target-size.enabled = true` override with no `runOnly`;
    - register exact `{content: axeDistributionSource}` exactly once per test
      context and reject zero, wrong, or surplus registrations;
    - use a dedicated Playwright fixture whose fresh `Page`/`BrowserContext`
      owns one test state, initializes before the body, and admits teardown
      only after exactly one audit; reject sequential or concurrent duplicate
      registration/audit attempts before their second page-realm operation,
      prove failed-registration rollback, and make multi-state reuse of one
      page lifetime a non-claim;
    - require the exact pre-run version before any `configure` or `run`, exact
      wrapper-equivalent same-origin and `playwright` branding configuration,
      and returned `testEngine` pair `("axe-core", "4.12.1")`;
    - require `page.frames()` to equal exactly `[page.mainFrame()]`;
    - reject zero or child frames before evaluation and require zero evaluation
      calls for both frame mutants; reject absent/wrong versions or callables,
      missing/wrong/surplus configure and run options, a two-rule `runOnly`,
      a default-rule override, wrong/missing result identity, more than one
      evaluation, and any temporary-page access;
    - in one runtime negative fixture use exactly one undersized named control
      attributed to `target-size` and one independently normal-sized unnamed
      control attributed to default `button-name`; require both violations,
      then preserve the production zero-violation, target applicability, and
      target incomplete predicates;
    - remove `@axe-core/playwright` from package and lock inventories and from
      the package verifier's exact source-only toolchain owner and fixture;
      add a dedicated exact dependency-inventory test whose missing, wrong,
      and surplus subcases otherwise satisfy every earlier manifest predicate
      and therefore reach the `devDependencies` map-equality rejection; use
      retained `@axe-core/playwright` as the surplus mutant;
    - update only QUALITY-022's exact requirement sentence and overview
      projection; retain existing binding and witness identities;
    - preserve one worker, zero retries, 30 seconds, and the diagnostic policy.
    Regenerate the exact dependency lock and run the narrow owners first:

    ```bash
    npm uninstall --save-dev @axe-core/playwright
    node --test \
      --test-name-pattern='^browser accessibility harness closes direct audit topology$' \
      scripts/browser-proof-inputs.test.mjs
    go test ./internal/tools/packageverify \
      -run '^TestVerifyRootManifestBoundaryRejectsDevDependencyDrift$'
    npm run browser:static-check
    ```

    The C-115 epoch was executed and falsified at iteration 15 as recorded in
    review history. Do not rerun or relabel its first 14 passes as success.
    Apply step 111 before running the replacement C-116 epoch below.
111. replace the three avoidable graph pass-path operations with one bounded
    response-derived, web-first witness in the existing
    `workspace renders admitted views and creates a keyboard-authorized
    handoff` test. Test first and keep the total test identity count at 25:
    - retain the exact failed C-115 trace/report identities above and make no
      product or exact Firefox/Juggler cause claim;
    - before Traceability activation, install one exact same-origin POST route
      and request/response observers for `/api/v1/graph`; fetch the real
      upstream response, require a non-empty node projection and a deterministic
      sentinel absent from the upstream bytes, replace only the first node
      label, fulfill the app-issued request, and require exactly one request,
      interception, linked successful response, and rendered sentinel;
    - implement that route and both observers as one attempt-scoped state
      machine `armed -> intercepted -> admitted -> detached`.
      `route.fetch({timeout: 5000, maxRedirects: 0, maxRetries: 0})` must retain
      the original same-origin URL and return success. Fetch, parse, or fulfill
      failure must terminally abort an unfinished route. A `finally` path must
      await every started callback, remove the exact route and both listeners
      on success, assertion failure, and timeout, and fail the witness if
      detachment is incomplete. Close the proof window only after the sentinel,
      exact counters, linked response, and successful detachment are admitted;
    - deep-copy and recursively freeze the admitted response projection.
      Derive expected node/edge identities, exact node/edge table rows, full
      and Unicode-code-point-truncated labels, viewBox, node positions, and
      non-degenerate edge endpoints only from that frozen response and the
      independently restated layout formula;
    - add one immutable exact assertion plan and local closed-record/list
      helpers in `tests/browser/workspace.spec.mjs`. Execute every
      `(surface, element, assertion, expected)` entry through one branch-free
      injectable executor. The production sink performs and awaits the
      Playwright matcher; a recording sink must receive and complete the exact
      ordered call inventory. Missing, surplus, skipped, duplicated, or
      unresolved-call mutants must fail. The same assertion plan must drive
      synchronous one-dimension mutation tables; do not add a second helper
      file or duplicate the contract in a source-string scanner;
    - equate the response with exact graph datasets, root child order, line and
      group identities, `title, rect, text` order, childlessness, attributes,
      direct text, computed rectangle geometry, tables, captions, headers,
      rows, and cells. Require zero document elements from the exact
      declarative SVG animation set `animate`, `animateColor`, `animateMotion`,
      `animateTransform`, `discard`, and `set`;
    - use retryable locator assertions for the exact owned ancestor chain,
      viewport, SVG, nodes, edges, and both table projections. Close the
      design's exact display, visibility, opacity, transform family, overflow,
      zoom, content visibility, animation, transition, filter, clip, mask,
      paint, geometry, font, text-layout, text-security, row/cell visibility,
      count, and ordering inventories. Do not use `boundingBox()`, raw
      pass-path computed-style evaluation, element screenshots, or
      `toBeVisible()` on SVG lines;
    - make every named C-116 falsifier executable through the shared closed
      inventories. Pure topology/style mutation tables must change one owned
      dimension while retaining all unrelated dimensions; cross-engine facts
      already established during design adjudication need not add repeated
      page-realm mutation operations. The runtime sentinel remains the causal
      cache falsifier;
    - require independent mutants for response omission/cache, graph/table
      order/count/text, hidden or alpha-zero surfaces, every retained style
      key, geometry/transform/text layout, inert leaf/root topology, positive
      transition duration, zero-duration positive delay, phase-split local and
      ancestor CSS animation, external graph and ancestor SMIL source
      admission, zero-dash and degenerate edges, static caption/header
      substitution, and visible trust-cell glyph loss;
    - preserve exact console-error absence, all existing trust-state content,
      handoff behavior, one worker, zero retries, 30-second tests,
      failure-only screenshot policy, and screenshot-free traces. Do not
      change production CSS, workspace rendering, requirement text, binding,
      route, public API, packet, or business logic for C-116;
    - run the narrow static owner first:

      ```bash
      npm run browser:static-check
      ```

      Then freeze every browser-runtime input and let iteration 1 of the
      complete executable C-116 epoch below be the first replacement-path
      Firefox runtime. Do not add a public single-project selector merely for
      this correction. Any timeout or test mismatch blocks closeout and
      requires trace adjudication. Playwright 1.61.1-versus-1.62 or
      browser-lifetime A/B remains nonblocking after a 30-of-30 pass and
      becomes blocking only after another replacement-path timeout or an exact
      engine/lifetime cause claim.
111a. because the first provider execution after the 1.61.1 epoch stalled in a
    different raw Playwright page operation, execute the isolated 1.62 A/B:
    - change only `package.json`, `package-lock.json`,
      `internal/tools/packageverify/main.go`, and
      `internal/tools/packageverify/main_test.go`;
    - require all four owners to admit exact version `1.62.0`;
    - preserve every browser test, one worker, zero retries, the 30-second
      timeout, shipped CLI JSON/exit-code behavior, product runtime, and
      business logic; admit the nonbreaking source-only public package-metadata
      pin and the lock-resolved Node `>=20` development-toolchain engine floor
      without projecting that floor onto consuming runtime requirements;
    - reject rerun-only evidence, retry or timeout inflation, test deletion,
      and simultaneous browser-lifetime or raw-operation changes because each
      either weakens the falsifier or mixes causal variables;
    - run the package-verifier suite, then treat the version change as a new
      resolved input digest and execute the complete 30-process epoch below
      from iteration 1, followed in the same frozen-input sequence by both full
      browser proofs, the composite gate, and the full gate;
    - after committed-object review, require fresh provider attempt 1. A green
      attempt admits the candidate without proving version-only causation. Any
      local verdict, identity, package-admission, security, or platform
      regression rolls back all four owner changes together. Another isolated
      provider stall rejects a version-only conclusion and routes to a
      separately reviewed browser-lifetime or remaining raw-operation
      experiment with a new digest and complete epoch;
    - create no new file, adapter, retry layer, configuration surface, or
      version registry: the four existing owners are the minimum synchronized
      boundary and there is no second consumer for another abstraction.
111b. correct C-117 in `internal/app/cli_abi_test.go` only:
    - before creating the setgid temp object, normalize the test root group to
      the caller's effective group so Darwin can materialize the special bit;
    - after every mode `Chmod`, require immediate exact `Lstat` mode equality;
    - retain separate permission, setuid, setgid, and sticky-bit mutants and
      leave the production writer unchanged;
    - prove the setgid case 100 of 100 times with the default temp root and 100
      of 100 times with the retained foreign-group `TMPDIR`, then run the full
      gate;
    - verify that the resolved browser input digest remains the Playwright 1.62
      epoch digest. Any digest change restarts that epoch from iteration 1;
    - reject skip, deletion, rerun-only acceptance, a weaker expected error, or
      a production change because none proves that the intended mutant exists;
    - add no platform adapter, test file, or production hook without a second
      consumer. If a supported Darwin or Linux filesystem cannot materialize
      the postcondition after group normalization, stop for a separately
      reviewed platform-specific fixture.
111c. correct C-118 in the existing workspace asset and browser witness:
    - first add a delayed-handoff counterexample that submits from
      Specifications, opens Diff, then releases the handoff response;
    - require the packet region to publish the valid result while the global
      state and active-view control remain Diff;
    - capture the current view request identity at submission and condition
      only the handoff success/failure global state write on identity equality;
    - do not abort, retry, discard, or resubmit the handoff and do not change
      server one-shot semantics.
111d. correct C-119 in the existing browser witness:
    - retain both provider-attempt report and trace identity sets and classify
      the four Firefox failures only from their observed evidence;
    - route all then-current workspace opens and reloads
      through owner-local helpers using `waitUntil: "commit"`;
    - require a non-null successful main-resource response and the visible
      server-owned workspace heading through Playwright's exact accessible-name
      matcher for every helper call, and retain every downstream semantic
      assertion;
    - leave the `about:blank` axe negative-control navigation unchanged;
    - add no lifecycle-event wait, retry, timeout increase, production change,
      `networkidle` heuristic, or swallowed navigation failure.
111e. correct C-120 in the same browser witness:
    - intercept the main document and preserve its original body while
      returning status 503 for open and reload in independent cases;
    - require each helper to reject with its owner-specific terminal error;
    - preserve successful navigation while changing only the heading to
      `browser.fixture.workspace drift`, so a substring matcher survives but
      the exact matcher rejects;
    - admit the original status 200, byte-changing substitution, and completed
      route fulfillment independently so a fixture or route-handler failure
      cannot satisfy the expected rejection;
    - execute all three falsifiers in Chromium, Firefox, and WebKit and add no
      production hook, retry, timeout increase, or new file.
111f. correct C-121 in the same browser witness and its existing static owner:
    - retain exact provider run `30337477288`, browser job `90205431977`,
      artifact `8679825289`, report and trace digests, and synthetic merge
      identity as the counterexample to `waitUntil: "commit"`;
    - admit the raw configured base URL as exact local HTTP root authority,
      capture the current main frame, and arm an exact-URL main-frame
      navigation-response waiter before scheduling either location assignment
      or reload;
    - require one exact trigger token, a successful response, and the exact
      visible server-owned heading; abort and consume the pending waiter after
      any trigger or admission failure;
    - add a pure classifier truth table for main-frame navigation, same-URL
      main-frame fetch, same-URL child-frame navigation, and foreign URL;
    - rehearse independent deletion of the exact-URL, navigation, main-frame,
      response-status, and exact-heading clauses and require the corresponding
      Chromium falsifier to fail;
    - deliver a same-URL 503 fetch before a classifier-only reload and prove
      that only the navigation response is admitted;
    - close the source corpus to 27 open-helper calls, two reload-helper calls,
      one classifier-only reload trigger, and no direct workspace lifecycle
      wait; preserve only the isolated `about:blank` axe control;
    - execute all 31 tests in Chromium, Firefox, and WebKit; retain zero
      retries and the existing timeout; add no production change, readiness
      hook, dependency churn, or new file.
111g. correct C-122 in P12.2:
    - make its declarative current correction inventory and executable expected
      inventory name the same three exact post-`c2315fd` paths;
    - retain the independent empty-untracked, six-owner-subset, 21-addition,
      staged-equality, and empty-remainder predicates;
    - reject a historical qualifier because both inventories own the same
      current staging operation.
111h. correct C-123 in the existing navigation-classifier test:
    - admit the configured base URL positively before navigation;
    - reject non-string input, HTTPS, hostname drift, missing port, username,
      password, non-root path, query, and fragment as independent rows;
    - keep username and password counterexamples distinct;
    - rehearse deletion of at least one high-boundary local-origin clause and
      require its row to fail;
    - retain 31 tests per engine by extending the cohesive C-121 test rather
      than adding a second browser lifecycle.
111i. correct C-124 in the same test:
    - replace assertion-library token matching with one exact terminal owner
      error so its failure identity is stable;
    - inject a pending response waiter whose abort signal rejects it and whose
      fallback resolves to a distinct unsuccessful response;
    - return a wrong trigger token and require the token error, observed abort,
      and observed waiter-rejection consumption;
    - require exact `waiter-armed`, `trigger-called`, `waiter-aborted`,
      `waiter-consumed` order so pre-arm sequencing is executable;
    - independently delete token admission, signal abort, and explicit
      consumption in Chromium and require each owning assertion to fail;
    - retain the real-page decoy path, one runtime test identity, zero retries,
      and no production or general mocking surface.
112. after C-93, C-94, C-96 through C-124, and all document edits freeze,
    recompute the
    complete threshold ledger and correct every stale path, LOC, or byte count
    before committed-object review. C-95 adds no decomposition requirement.

### C-116 executable falsifier epoch

The Firefox stress evidence is diagnostic bounded-reliability evidence, not a
new merge-proof artifact. It uses one immutable materialized browser-input
snapshot, one bounded server, 30 separate Playwright processes, and 30 unique
attempt directories. Every iteration must prove exactly the same 25 test
identities with 25 expected passes, zero skipped, unexpected, or flaky tests,
one worker, zero retries, and 30-second tests. The first failure stops the epoch
and retains its report, trace, screenshots, source snapshot, and server logs.
The historical identity authority is the exact sorted title projection from
the hash-verified C-115 iteration-15 report:
`sha256:f7b80cd6ea950cad6693a7b11020f746581d6eba4f2b7314700e4161448a554c`.
It is the SHA-256 of the no-newline compact JSON bytes produced by the same
`file::suite > title` jq projection below. Iteration 1 and every stress and
full Firefox projection must equal this digest; iteration 1 is not allowed to
redefine identity authority.
An outer watchdog gives every process a finite wall-clock deadline, owns its
detached process group, forwards wrapper interruption, and rejects a
successful leader that leaves descendants. It returns an ordinary child
result only after proving process-group absence. If bounded
initial forwarded or cleanup signal followed by `KILL` cannot prove absence,
it returns the recorded non-zero `kill-deadline-exceeded` blocker; deadline
and descendant cleanup use `TERM`, while wrapper interruption first forwards
its actual signal. Any signal or group-probe error is retained in the final
record and conservatively treated as continuing residual-process risk. A
blocking result admits no stress or full-gate evidence.

Run from the repository root:

```bash
set -euo pipefail
stress_root="$(mktemp -d "${TMPDIR:-/tmp}/proofkit-firefox-stress.XXXXXX")"
export PROOFKIT_FIREFOX_STRESS_ROOT="$stress_root"
PROOFKIT_BROWSER_INPUT_RESOLUTION="$(
  go run ./internal/tools/browserproofverify --resolve-inputs
)"
export PROOFKIT_BROWSER_INPUT_RESOLUTION
frozen_input_digest="$(
  node --input-type=module <<'NODE'
import {createHash} from "node:crypto";
import {symlinkSync} from "node:fs";
import {join, resolve} from "node:path";
import {
  loadBrowserProofInputResolution,
  materializeInputSnapshot,
} from "./scripts/browser-proof-inputs.mjs";

const root = process.env.PROOFKIT_FIREFOX_STRESS_ROOT;
const resolution = loadBrowserProofInputResolution();
const source = join(root, "source");
const assets = materializeInputSnapshot(resolution.inputPaths, ".", source);
symlinkSync(resolve("node_modules"), join(source, "node_modules"), "dir");
const inputResolution = {
  serverTarget: resolution.serverTarget,
  writerPath: resolution.writerPath,
};
const value = createHash("sha256")
  .update(JSON.stringify({assets, inputResolution}))
  .digest("hex");
process.stdout.write(`sha256:${value}`);
NODE
)"
test -n "$frozen_input_digest"
stress_source="$stress_root/source"
materialized_input_digest() {
  node --input-type=module <<'NODE'
import {createHash} from "node:crypto";
import {join} from "node:path";
import {
  loadBrowserProofInputResolution,
  snapshotInputAssets,
} from "./scripts/browser-proof-inputs.mjs";

const root = process.env.PROOFKIT_FIREFOX_STRESS_ROOT;
const resolution = loadBrowserProofInputResolution();
const assets = snapshotInputAssets(
  resolution.inputPaths,
  join(root, "source"),
);
const inputResolution = {
  serverTarget: resolution.serverTarget,
  writerPath: resolution.writerPath,
};
const value = createHash("sha256")
  .update(JSON.stringify({assets, inputResolution}))
  .digest("hex");
process.stdout.write(`sha256:${value}`);
NODE
}
test "$(materialized_input_digest)" = "$frozen_input_digest"
root_input_digest() {
  node --input-type=module <<'NODE'
import {createHash} from "node:crypto";
import {
  loadBrowserProofInputResolution,
  snapshotInputAssets,
} from "./scripts/browser-proof-inputs.mjs";

const resolution = loadBrowserProofInputResolution();
const assets = snapshotInputAssets(resolution.inputPaths);
const inputResolution = {
  serverTarget: resolution.serverTarget,
  writerPath: resolution.writerPath,
};
const value = createHash("sha256")
  .update(JSON.stringify({assets, inputResolution}))
  .digest("hex");
process.stdout.write(`sha256:${value}`);
NODE
}
test "$(root_input_digest)" = "$frozen_input_digest"
run_with_deadline() {
  deadline_seconds="$1"
  watchdog_record="$2"
  shift 2
  node --input-type=module - \
    "$deadline_seconds" "$watchdog_record" "$@" <<'NODE'
import {spawn} from "node:child_process";
import {writeFileSync} from "node:fs";

const [deadlineText, recordPath, command, ...args] = process.argv.slice(2);
const deadlineSeconds = Number(deadlineText);
if (
  !Number.isSafeInteger(deadlineSeconds) ||
  deadlineSeconds <= 0 ||
  typeof command !== "string" ||
  command.length === 0
) {
  process.exit(125);
}
const startedAt = new Date().toISOString();
let child;
let cleanupStatus;
let cleanupWrapperExitCode;
let deadlineTimer;
let groupPoll;
let finished = false;
let leaderExitCode = null;
let leaderSignal = null;
let pendingWrapperSignal;
const groupProbeErrors = [];
const signalErrors = [];
let termTimer;
let killTimer;
let dispatchWrapperSignal = (value) => {
  pendingWrapperSignal ??= value;
};
process.on("SIGINT", () => {
  dispatchWrapperSignal({
    signal: "SIGINT",
    status: "wrapper-sigint",
    wrapperExitCode: 130,
  });
});
process.on("SIGTERM", () => {
  dispatchWrapperSignal({
    signal: "SIGTERM",
    status: "wrapper-sigterm",
    wrapperExitCode: 143,
  });
});
child = spawn(command, args, {detached: true, stdio: "inherit"});
const record = (status) => {
  writeFileSync(recordPath, `${JSON.stringify({
    args,
    command,
    deadlineSeconds,
    leaderExitCode,
    leaderSignal,
    groupProbeErrors,
    signalErrors,
    startedAt,
    status,
  })}\n`, {encoding: "utf8", mode: 0o600});
};
const groupExists = () => {
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    groupProbeErrors.push({code: error?.code ?? "unknown"});
    return true;
  }
};
const signalGroup = (signal) => {
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") {
      signalErrors.push({code: error?.code ?? "unknown", signal});
    }
  }
};
const finish = (status, wrapperExitCode) => {
  if (finished) return;
  finished = true;
  clearTimeout(deadlineTimer);
  clearTimeout(termTimer);
  clearTimeout(killTimer);
  clearInterval(groupPoll);
  record(status);
  process.exit(wrapperExitCode);
};
const beginCleanup = (status, wrapperExitCode, signal) => {
  if (cleanupStatus !== undefined) return;
  cleanupStatus = status;
  cleanupWrapperExitCode = wrapperExitCode;
  record(`${status}:${signal.toLowerCase()}-requested`);
  signalGroup(signal);
  groupPoll = setInterval(() => {
    if (!groupExists()) finish(cleanupStatus, cleanupWrapperExitCode);
  }, 100);
  termTimer = setTimeout(() => {
    if (!groupExists()) {
      finish(cleanupStatus, cleanupWrapperExitCode);
      return;
    }
    record(`${status}:kill-requested`);
    signalGroup("SIGKILL");
    killTimer = setTimeout(() => {
      if (groupExists()) {
        finish("kill-deadline-exceeded", wrapperExitCode);
        return;
      }
      finish(cleanupStatus, cleanupWrapperExitCode);
    }, 5_000);
  }, 5_000);
};
child.once("error", (error) => {
  record(`spawn-error:${error.code ?? "unknown"}`);
  process.exit(125);
});
child.once("exit", (code, signal) => {
  leaderExitCode = code;
  leaderSignal = signal;
  if (cleanupStatus !== undefined) {
    return;
  }
  if (groupExists()) {
    beginCleanup("descendants-remain", 125, "SIGTERM");
    return;
  }
  finish("exited", Number.isInteger(code) ? code : 125);
});
dispatchWrapperSignal = ({signal, status, wrapperExitCode}) => {
  beginCleanup(status, wrapperExitCode, signal);
};
if (pendingWrapperSignal !== undefined) {
  dispatchWrapperSignal(pendingWrapperSignal);
}
deadlineTimer = setTimeout(() => {
  beginCleanup("deadline-exceeded", 124, "SIGTERM");
}, deadlineSeconds * 1_000);
NODE
}
stress_server="$stress_root/server"
(
  cd "$stress_source"
  run_with_deadline 300 "$stress_root/server-build-watchdog.json" \
    go build -o "$stress_server" ./internal/tools/browsertestserver
)
server_stdout="$stress_root/server.stdout"
server_stderr="$stress_root/server.stderr"
"$stress_server" >"$server_stdout" 2>"$server_stderr" &
server_pid=$!
stop_stress_server() {
  stop_signal=""
  if kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid"
    stop_signal="TERM"
    for _ in $(seq 1 100); do
      if ! kill -0 "$server_pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      kill -KILL "$server_pid" 2>/dev/null || true
      stop_signal="KILL"
      for _ in $(seq 1 50); do
        if ! kill -0 "$server_pid" 2>/dev/null; then
          break
        fi
        sleep 0.1
      done
    fi
  fi
  if kill -0 "$server_pid" 2>/dev/null; then
    printf 'stress server did not terminate after %s\\n' "$stop_signal" >&2
    return 1
  fi
  set +e
  wait "$server_pid"
  server_status=$?
  set -e
  case "$server_status" in
    0|137|143) ;;
    *)
      printf 'stress server terminal status %s is not admitted\\n' \
        "$server_status" >&2
      return 1
      ;;
  esac
}
trap stop_stress_server EXIT
for _ in $(seq 1 300); do
  if grep -q '^Proofkit requirement browser: http://127\.0\.0\.1:[0-9][0-9]*/$' \
    "$server_stdout"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    sed -n '1,120p' "$server_stderr" >&2
    exit 1
  fi
  sleep 0.1
done
stress_url="$(
  sed -n \
    's/^Proofkit requirement browser: \(http:\/\/127\.0\.0\.1:[0-9][0-9]*\/\)$/\1/p' \
    "$server_stdout" |
    head -n 1
)"
test -n "$stress_url"
stress_records="$stress_root/records.jsonl"
historical_test_ids_digest="sha256:f7b80cd6ea950cad6693a7b11020f746581d6eba4f2b7314700e4161448a554c"
expected_test_ids=""
for iteration in $(seq 1 30); do
  test "$(materialized_input_digest)" = "$frozen_input_digest"
  iteration_id="$(printf '%02d' "$iteration")"
  iteration_root="$stress_root/iteration-$iteration_id"
  mkdir -p "$iteration_root"
  report_path="$iteration_root/playwright-report.json"
  output_path="$iteration_root/test-results"
  set +e
  (
    cd "$stress_source"
    PROOFKIT_BROWSER_TEST_URL="$stress_url" \
    PROOFKIT_BROWSER_TEST_REPORT_PATH="$report_path" \
    PROOFKIT_BROWSER_TEST_OUTPUT_DIR="$output_path" \
      run_with_deadline 900 "$iteration_root/watchdog.json" \
        node node_modules/@playwright/test/cli.js test --project=firefox
  )
  exit_status=$?
  set -e
  current_input_digest="$(materialized_input_digest)"
  test "$current_input_digest" = "$frozen_input_digest"
  report_status=1
  watchdog_status="$(
    jq -r .status "$iteration_root/watchdog.json" 2>/dev/null ||
      printf 'invalid'
  )"
  test_ids=""
  executed_count=0
  passed_count=0
  if test -f "$report_path"; then
    executed_count="$(
      jq '[.suites[].specs[].tests[]] | length' "$report_path" 2>/dev/null ||
        printf '0'
    )"
    passed_count="$(
      jq '[
        .suites[].specs[].tests[].results[] |
        select(.status == "passed")
      ] | length' "$report_path" 2>/dev/null ||
        printf '0'
    )"
    if jq -e '
      .errors == [] and
      .config.workers == 1 and
      ([.config.projects[] |
        select(
          .name == "firefox" and
          .retries == 0 and
          .repeatEach == 1 and
          .timeout == 30000
        )] | length) == 1 and
      .stats.expected == 25 and
      .stats.skipped == 0 and
      .stats.unexpected == 0 and
      .stats.flaky == 0 and
      ([.suites[].specs[].tests[]] | length) == 25 and
      all(
        .suites[].specs[].tests[];
        .projectName == "firefox" and
        .status == "expected" and
        (.results | length) == 1 and
        .results[0].status == "passed" and
        .results[0].retry == 0
      )
    ' "$report_path" >/dev/null; then
      report_status=0
      test_ids="$(
        jq -c \
          '[.suites[] |
            .file as $file |
            .title as $suite |
            .specs[] |
            "tests/browser/\($file)::\($suite) > \(.title)"
          ] | sort' \
          "$report_path"
      )"
    fi
  fi
  test_ids_digest="$(
    printf '%s' "$test_ids" |
      shasum -a 256 |
      awk '{print "sha256:" $1}'
  )"
  jq -cn \
    --argjson iteration "$iteration" \
    --arg inputDigest "$current_input_digest" \
    --arg project firefox \
    --arg testIdsDigest "$test_ids_digest" \
    --arg watchdogStatus "$watchdog_status" \
    --argjson executed "$executed_count" \
    --argjson passed "$passed_count" \
    --argjson exitStatus "$exit_status" \
    --argjson reportStatus "$report_status" \
    '{
      iteration: $iteration,
      project: $project,
      executed: $executed,
      passed: $passed,
      inputDigest: $inputDigest,
      testIdsDigest: $testIdsDigest,
      watchdogStatus: $watchdogStatus,
      exitStatus: $exitStatus,
      reportStatus: $reportStatus
    }' >>"$stress_records"
  test "$exit_status" -eq 0
  test "$watchdog_status" = "exited"
  test "$report_status" -eq 0
  test "$test_ids_digest" = "$historical_test_ids_digest"
  if test "$iteration" -eq 1; then
    expected_test_ids="$test_ids"
  else
    test "$test_ids" = "$expected_test_ids"
  fi
done
test "$(materialized_input_digest)" = "$frozen_input_digest"
test "$(
  jq -s '
    length == 30 and
    ([.[].iteration] == [range(1; 31)]) and
    ([.[].inputDigest] | unique | length) == 1 and
    ([.[].testIdsDigest] | unique) ==
      ["sha256:f7b80cd6ea950cad6693a7b11020f746581d6eba4f2b7314700e4161448a554c"] and
    all(.[];
      .project == "firefox" and
      .executed == 25 and
      .passed == 25 and
      .exitStatus == 0 and
      .reportStatus == 0 and
      .watchdogStatus == "exited"
    )
  ' "$stress_records"
)" = "true"
test "$(jq -r .inputDigest "$stress_records" | sort -u)" = \
  "$frozen_input_digest"
kill -0 "$server_pid"
stop_stress_server
trap - EXIT
# Do not edit a browser-proof input after stress materialization. Run two
# owner-valid complete proofs, then the composite and full gates in this shell.
test "$(root_input_digest)" = "$frozen_input_digest"
browser_proof_firefox_test_ids() {
  jq -c '[
    .projects[] |
    select(.name == "firefox") |
    .testIds[]
  ] | sort' artifacts/proofkit/browser-runtime-proof.json
}
assert_historical_firefox_test_ids() {
  current_firefox_test_ids="$(browser_proof_firefox_test_ids)"
  current_firefox_test_ids_digest="$(
    printf '%s' "$current_firefox_test_ids" |
      shasum -a 256 |
      awk '{print "sha256:" $1}'
  )"
  test "$current_firefox_test_ids" = "$expected_test_ids"
  test "$current_firefox_test_ids_digest" = "$historical_test_ids_digest"
}
run_with_deadline 1800 "$stress_root/first-full-watchdog.json" \
  npm run browser:test
first_full_digest="$(jq -r .inputDigest artifacts/proofkit/browser-runtime-proof.json)"
test "$first_full_digest" = "$frozen_input_digest"
assert_historical_firefox_test_ids
test "$(root_input_digest)" = "$frozen_input_digest"
run_with_deadline 1800 "$stress_root/second-full-watchdog.json" \
  npm run browser:test
second_full_digest="$(jq -r .inputDigest artifacts/proofkit/browser-runtime-proof.json)"
test "$second_full_digest" = "$frozen_input_digest"
test "$first_full_digest" = "$second_full_digest"
assert_historical_firefox_test_ids
test "$(root_input_digest)" = "$frozen_input_digest"
run_with_deadline 1800 "$stress_root/composite-watchdog.json" \
  npm run browser:check
composite_digest="$(jq -r .inputDigest artifacts/proofkit/browser-runtime-proof.json)"
test "$composite_digest" = "$frozen_input_digest"
assert_historical_firefox_test_ids
test "$(root_input_digest)" = "$frozen_input_digest"
run_with_deadline 3600 "$stress_root/full-check-watchdog.json" \
  npm run check
assert_historical_firefox_test_ids
test "$(root_input_digest)" = "$frozen_input_digest"
```

No product or proof correction is complete from an implementation change
alone. Its applicable negative test, durable requirement, binding selector,
and generated projection must agree before P11. Temporary closeout corrections
C-99, C-100, C-104 through C-106, C-108, C-109, and C-111 instead require
their exact executable identity/count predicates, named counterexamples, and
independent plan review; they do not invent durable product requirements,
bindings, or generated projections.

### Overview projections

Update each touched spec overview only where the requirement's summarized
claim changes. Overview prose must not become an alternate policy owner.

### Bindings and witness plan

1. Confirm every exact scenario/witness route from the design's durable proof
   table was applied owner-first.
2. Point falsifier witnesses to test files, not production-only files, where a
   test now owns the negative case.
3. Add new command-contract generator check and action-pin witness commands.
4. Preserve environment classes and network non-claims.
5. Recompute binding and witness canonical order.

### Backlog

- do not claim `COVERAGE-01` closed;
- keep signed-tag and live-release rows blocked;
- update only rows whose source-local obligation actually changed;
- do not add provider success.

### Release records

Record:

- public process-channel correction;
- context/diff/browser schema v2 migration;
- absolute symlink hardening;
- package-doc contraction;
- SBOM semantic correction;
- help/onboarding additions;
- accessibility behavior change;
- exact previous version and breaking change class.

### Gate

Run the exact owner and projection tests, rebuild current artifact evidence,
and only then run receipt/coverage validation:

```bash
npm run go:test
npm run command-contract:check
npm run command-family:check
npm run package:artifact
npm run self:receipt
npm run self:coverage
```

## P11: Review and full closeout

### P11.1 Local structural review

1. Run `gofmt` on changed Go files.
2. Run `git diff --check`.
3. Confirm no Cyrillic entered tracked files.
4. Confirm no generated artifacts, package tarballs, caches, or proof residue
   are tracked except exactly these two owner-admitted projections generated
   together and freshness-checked by the same
   `npm run command-contract:check` invocation:

   - `internal/app/command_contract_generated.go`;
   - `internal/command/stackpreset/preset_ids_generated.go`.
5. Inspect `git diff --stat` and exact changed paths.
6. Use semantic diff to identify changed functions/types and unexpected blast
   radius.

### P11.2 Preliminary multi-agent worktree review

Use three read-only reviewers against the final worktree:

- proof/security/confinement and false-green oracles;
- contract/release/package and proof-routing closure;
- UX/accessibility/onboarding and business-logic preservation.

Each finding remains a hypothesis until root reproduction. Fix confirmed
findings and rerun their narrow gates. These worktree reviews reduce risk but
do not replace the committed-object review in P12.

### P11.3 Full gate

Run:

```bash
git diff --check
npm run check
```

`npm run check` must include `command-contract:check`.

Any skipped or unavailable gate is reported with its exact blocker and is not
success.

### P11.4 Candidate preparation

After full worktree green:

1. require exact evidence for all remaining confirmed objections and findings;
2. rerun any narrow gate affected by closeout edits;
3. verify the temporary docs contain no unresolved `pending` review state;
4. set design and plan status to `implementation candidate`, not
   `implemented/validated`;
5. freeze the candidate path inventory and expected diff before the identity
   check and commit.

### Residual non-claims

Final closeout must state:

- no npm/PyPI/GitHub live publication proof;
- no branch-protection or tag-ruleset proof;
- no retroactive correction of `0.1.160`;
- no vulnerability absence or action safety;
- no full `COVERAGE-01` closure;
- no complete fuzz-space or performance-regression proof;
- no full WCAG 2.2 conformance;
- no consumer adoption or production readiness.

## P12: Commit, publish branch, and open pull request

### P12.1 Identity and authority check

Immediately before external mutation:

```bash
gh api user --jq .login
gh api repos/research-engineering/agentic-proofkit --jq .permissions
git config user.name
git config user.email
```

Require:

```text
GitHub login = iperev
permissions.push = true
git user.name = iperev
```

An identity mismatch stops publication. Do not switch to an account with only
pull permission.

### P12.2 Candidate commit

1. Freeze the reviewed correction-path inventory before staging. In the
   current correction epoch, require it to be exactly:

   ```text
   docs/implementation/audit-remediation-design.md
   docs/implementation/audit-remediation-plan.md
   tests/browser/workspace.spec.mjs
   ```

   Require the complete untracked inventory to be empty.

   Independently require this six-file decomposition-owner subset:

   ```text
   internal/tools/commandcontractgen/condition_model.go
   scripts/workflow_browser_runtime_oracle_test.go
   scripts/workflow_oracle_support_test.go
   scripts/workflow_runtime_preconditions_test.go
   scripts/workflow_security_scanner_oracles_test.go
   scripts/workflow_source_oracles_test.go
   ```

   Require the complete candidate index to add exactly these twenty-one files
   relative to the reviewed baseline:

   ```text
   docs/implementation/audit-remediation-design.md
   docs/implementation/audit-remediation-plan.md
   internal/app/cli_output_witness_contract_test.go
   internal/app/command_contract_generated.go
   internal/app/invocation_profile_test.go
   internal/command/requirementbrowser/requirementbrowser_test.go
   internal/command/requirementbrowser/v1_adapter.go
   internal/command/requirementcontext/v1_adapter.go
   internal/command/requirementdiff/v1_adapter.go
   internal/command/stackpreset/preset_ids_generated.go
   internal/tools/commandcontractgen/condition_model.go
   internal/tools/commandcontractgen/main.go
   internal/tools/commandcontractgen/main_test.go
   internal/tools/pythonpackage/continuation_test.go
   release/change-record.v2.json
   scripts/workflow_browser_runtime_oracle_test.go
   scripts/workflow_oracle_support_test.go
   scripts/workflow_runtime_preconditions_test.go
   scripts/workflow_security_scanner_oracles_test.go
   scripts/workflow_source_oracles_test.go
   tests/browser/axe-harness.mjs
   ```

   Then stage exactly the current three-file correction inventory, prove
   staged-path equality, prove the six-file owner subset, and prove the
   complete twenty-one-file baseline-relative addition set:

   ```bash
   set -euo pipefail
   baseline_sha="3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64"
   correction_path_inventory="$(
     {
       git diff --name-only HEAD
       git ls-files --others --exclude-standard
     } | LC_ALL=C sort -u
   )"
   expected_correction_path_inventory="$(
     printf '%s\n' \
       docs/implementation/audit-remediation-design.md \
       docs/implementation/audit-remediation-plan.md \
       tests/browser/workspace.spec.mjs |
       LC_ALL=C sort
   )"
   expected_untracked_inventory=""
   expected_decomposition_owner_inventory="$(
     printf '%s\n' \
       internal/tools/commandcontractgen/condition_model.go \
       scripts/workflow_browser_runtime_oracle_test.go \
       scripts/workflow_oracle_support_test.go \
       scripts/workflow_runtime_preconditions_test.go \
       scripts/workflow_security_scanner_oracles_test.go \
       scripts/workflow_source_oracles_test.go |
       LC_ALL=C sort
   )"
   expected_baseline_added_inventory="$(
     printf '%s\n' \
       docs/implementation/audit-remediation-design.md \
       docs/implementation/audit-remediation-plan.md \
       internal/app/cli_output_witness_contract_test.go \
       internal/app/command_contract_generated.go \
       internal/app/invocation_profile_test.go \
       internal/command/requirementbrowser/requirementbrowser_test.go \
       internal/command/requirementbrowser/v1_adapter.go \
       internal/command/requirementcontext/v1_adapter.go \
       internal/command/requirementdiff/v1_adapter.go \
       internal/command/stackpreset/preset_ids_generated.go \
       internal/tools/commandcontractgen/condition_model.go \
       internal/tools/commandcontractgen/main.go \
       internal/tools/commandcontractgen/main_test.go \
       internal/tools/pythonpackage/continuation_test.go \
       release/change-record.v2.json \
       scripts/workflow_browser_runtime_oracle_test.go \
       scripts/workflow_oracle_support_test.go \
       scripts/workflow_runtime_preconditions_test.go \
       scripts/workflow_security_scanner_oracles_test.go \
       scripts/workflow_source_oracles_test.go \
       tests/browser/axe-harness.mjs |
       LC_ALL=C sort
   )"
   actual_untracked_inventory="$(
     git ls-files --others --exclude-standard | LC_ALL=C sort
   )"
   test "$expected_correction_path_inventory" = \
     "$correction_path_inventory"
   test "$expected_untracked_inventory" = "$actual_untracked_inventory"
   printf '%s\n' "$expected_correction_path_inventory" |
     git add --pathspec-from-file=-
   staged_path_inventory="$(
     git diff --cached --name-only | LC_ALL=C sort
   )"
   actual_baseline_added_inventory="$(
     git diff --cached --diff-filter=A --name-only "$baseline_sha" |
       LC_ALL=C sort
   )"
   missing_decomposition_owner_inventory="$(
     comm -23 \
       <(printf '%s\n' "$expected_decomposition_owner_inventory") \
       <(printf '%s\n' "$actual_baseline_added_inventory")
   )"
   test "$expected_correction_path_inventory" = "$staged_path_inventory"
   test -z "$missing_decomposition_owner_inventory"
   test "$expected_baseline_added_inventory" = \
     "$actual_baseline_added_inventory"
   test -z "$(git diff --name-only)"
   test -z "$(git ls-files --others --exclude-standard)"
   ```

   Any extra or missing path stops candidate creation.
2. Review the staged diff and generated-file freshness.
3. Create the first candidate with a conventional, human-oriented message, or
   amend that commit without changing its reviewed message after a correction
   epoch:

   ```text
   fix: close audit remediation gaps
   ```

   ```bash
   git commit --amend --no-edit
   ```

4. Record the candidate commit SHA.
5. Require a clean worktree apart from ignored local artifacts.

### P12.3 Committed-object validation epoch

Against the candidate SHA:

1. rerun `git diff --check` and `npm run check`;
2. ask three fresh read-only agents to validate the committed diff against the
   design and plan;
3. require all three to return `APPROVE` with no unresolved confirmed finding;
4. after every confirmed finding from those reviews is corrected, run one
   additional independent `gpt-5.6-sol` reviewer with maximum reasoning
   effort against the exact candidate SHA and require no unresolved confirmed
   finding;
5. set design and plan status to `implemented/validated` only within the same
   candidate correction epoch;
6. if any correction or status edit changes bytes, amend the candidate commit,
   record the new SHA, and repeat the entire full gate and three-agent review;
   the independent maximum-reasoning audit must also be repeated when a
   confirmed correction changes bytes;
7. accept exactly one final committed SHA as publication input and substitute
   its literal 40-hex value for `<validated-final-sha>` in every P12.4-P12.6
   command. Re-deriving it from a later mutable `HEAD` is forbidden.

### P12.4 Publish or refresh the branch

Verify the already published remote before replacing its reviewed candidate:

```bash
set -euo pipefail
audit_baseline_sha="3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64"
integration_base_sha="0df4c28bac9737f476f7dc66030363b8b40d5417"
final_sha="<validated-final-sha>"
previous_remote_sha="7e29a8e2a85d36a0c439753dfb5b951ed598078a"
test "$(git branch --show-current)" = "fix/audit-remediation"
test "$(git rev-parse HEAD)" = "$final_sha"
test "$(git rev-list --parents -n 1 "$final_sha")" = \
  "$final_sha $integration_base_sha"
test "$(git merge-base "$audit_baseline_sha" "$integration_base_sha")" = \
  "$audit_baseline_sha"
test "$(git remote get-url --push origin)" = \
  "https://github.com/research-engineering/agentic-proofkit"
test "$integration_base_sha" = \
  "$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$previous_remote_sha" = \
  "$(git ls-remote origin refs/heads/fix/audit-remediation | awk '{print $1}')"
git push \
  --force-with-lease=refs/heads/fix/audit-remediation:"$previous_remote_sha" \
  origin "${final_sha}:refs/heads/fix/audit-remediation"
test "$final_sha" = \
  "$(git ls-remote origin refs/heads/fix/audit-remediation | awk '{print $1}')"
test "$integration_base_sha" = \
  "$(git ls-remote origin refs/heads/main | awk '{print $1}')"
git branch --set-upstream-to=origin/fix/audit-remediation \
  fix/audit-remediation
```

Any remote mismatch stops publication.

### P12.5 Create or refresh the pull request

Create a non-draft pull request into `main` if none exists. If pull request
`#78` already exists for the branch, update that same pull request rather than
creating a duplicate.

Title:

```text
Close proof, contract, release, and onboarding audit gaps
```

The body includes:

- historical audit baseline, integration base, and current PR scope;
- adjudicated fixes and rejected hypotheses;
- intentional compatibility changes and `0.2.0` migration;
- design and plan review history;
- exact narrow and full gates;
- provider failure diagnosis, corrective cycles, and current check status;
- residual non-claims;
- the closed large-file ledger, the remediated workflow god-file
  concentration, and the rejected premature merge/split candidates.

Write the reviewed body to
`/tmp/agentic-proofkit-audit-remediation-pr-body.md`. For the existing pull
request, run:

```bash
set -euo pipefail
integration_base_sha="0df4c28bac9737f476f7dc66030363b8b40d5417"
final_sha="<validated-final-sha>"
repo="research-engineering/agentic-proofkit"
test "$integration_base_sha" = \
  "$(git ls-remote origin refs/heads/main | awk '{print $1}')"
pr_before_edit="$(mktemp)"
gh pr view 78 \
  --repo "$repo" \
  --json author,headRefName,headRefOid,baseRefName,baseRefOid,state,mergedAt \
  > "$pr_before_edit"
jq -e \
  --arg sha "$final_sha" \
  --arg base "$integration_base_sha" \
  '.author.login == "iperev"
   and .headRefName == "fix/audit-remediation"
   and .headRefOid == $sha
   and .baseRefName == "main"
   and .baseRefOid == $base
   and .state == "OPEN"
   and .mergedAt == null' \
  "$pr_before_edit" >/dev/null

gh pr edit 78 \
  --repo "$repo" \
  --title "Close proof, contract, release, and onboarding audit gaps" \
  --body-file /tmp/agentic-proofkit-audit-remediation-pr-body.md
pr_after_edit="$(mktemp)"
gh pr view 78 \
  --repo "$repo" \
  --json url,title,author,headRefName,headRefOid,baseRefName,baseRefOid,isDraft,state,mergedAt,body \
  > "$pr_after_edit"
jq -e \
  --arg sha "$final_sha" \
  --arg base "$integration_base_sha" \
  '.author.login == "iperev"
   and .headRefName == "fix/audit-remediation"
   and .headRefOid == $sha
   and .baseRefName == "main"
   and .baseRefOid == $base
   and .isDraft == false
   and .state == "OPEN"
   and .mergedAt == null
   and .title == "Close proof, contract, release, and onboarding audit gaps"' \
  "$pr_after_edit" >/dev/null
jq -j '.body' "$pr_after_edit" > /tmp/proofkit-pr-body-readback.md
cmp -s /tmp/agentic-proofkit-audit-remediation-pr-body.md \
  /tmp/proofkit-pr-body-readback.md
```

Require `author.login=iperev`, `headRefName=fix/audit-remediation`,
`headRefOid=<validated-final-sha>`, `baseRefName=main`,
`baseRefOid=0df4c28bac9737f476f7dc66030363b8b40d5417`, `isDraft=false`,
`state=OPEN`, `mergedAt=null`, and the exact reviewed title above. The refreshed
body must name the final SHA, tree, file and line counts, gate counts, and
provider disposition; old candidate identities or counts are forbidden.

### P12.6 Provider status

1. Read back the PR author, exact `headRefOid` and `baseRefOid`, head/base refs,
   `state`, and `mergedAt`.
2. Confirm author is `iperev`.
3. Inspect provider checks and require exactly these source-owned closeout
   tuples to be present for the final SHA in provider workflow attempt `1`:
   - `ci` / `quality / source`;
   - `ci` / `quality / platform smoke / macos-15`;
   - `ci` / `quality / browser runtime`;
   - `ci` / `quality / required aggregate`.
   This is the closed inventory owned by `.github/workflows/ci.yml` and its
   typed workflow oracle, not evidence of provider branch-protection settings.
4. Wait for terminal checks when available without converting pending or
   skipped states into success.
5. If a browser failure moves between tests at the same timeout cap, retain and
   inspect the first-failure trace before changing application behavior,
   timeout policy, or retry policy; diagnostic reruns are not merge proof.
6. Do not merge unless the user separately authorizes merge.
7. Treat a required provider failure or an absent required check as a blocker,
   including when the failure is terminal and fully diagnosed; do not retire
   the design or plan while any such blocker exists.
8. After all checks triggered for the final SHA reach terminal states and every
   required check passes, complete retrospective routing.
9. Execute the canonical provider-projection function from step 10 once,
   construct the canonical closeout record from the exact local sources below,
   compute both SHA-256 values, and refresh the reviewed pull-request body with
   exact `provider-projection-sha256: sha256:<digest>` and
   `closeout-record-sha256: sha256:<digest>` markers plus canonical JSON bytes
   between their respective exact `*-json-begin` and `*-json-end` sentinel
   lines. Human-readable summary text remains explicitly non-authoritative.
10. Perform the bounded authoritative readback below. The two identity
    snapshots reject a persistent head mismatch at either boundary, while the
    provider endpoints bind every conclusion read to the literal final SHA:

```bash
set -euo pipefail
audit_baseline_sha="3d86b6d0e4ec4a6c6a7f7a35ff2787011771aa64"
integration_base_sha="0df4c28bac9737f476f7dc66030363b8b40d5417"
final_sha="<validated-final-sha>"
repo="research-engineering/agentic-proofkit"
branch_ref="refs/heads/fix/audit-remediation"
base_ref="refs/heads/main"
expected_title="Close proof, contract, release, and onboarding audit gaps"
pr_snapshot="$(mktemp)"
ci_runs="$(mktemp)"
ci_jobs="$(mktemp)"
check_runs="$(mktemp)"
commit_status="$(mktemp)"
provider_projection_one="$(mktemp)"
provider_projection_two="$(mktemp)"
provider_projection_embedded_one="$(mktemp)"
provider_projection_embedded_server="$(mktemp)"
closeout_record_expected="$(mktemp)"
closeout_record_embedded_one="$(mktemp)"
closeout_record_embedded_server="$(mktemp)"
coverage_snapshot="$(mktemp)"
browser_snapshot="$(mktemp)"
package_execution_snapshot="$(mktemp)"
local_closeout_report="$(mktemp)"
reviewed_body_snapshot="$(mktemp)"
pr_body_readback="$(mktemp)"
test "$final_sha" = "$(git rev-parse HEAD)"
test -z "$(git status --porcelain)"
final_tree="$(git rev-parse "$final_sha^{tree}")"
diff_stats="$(
  git diff --numstat "$integration_base_sha" "$final_sha" |
    awk '
      {
        if ($1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/) {
          invalid = 1
        }
        files++
        added += $1
        deleted += $2
      }
      END {
        if (invalid) {
          exit 1
        }
        print files + 0, added + 0, deleted + 0
      }
    '
)"
read -r diff_file_count diff_added_lines diff_deleted_lines \
  <<< "$diff_stats"
cp artifacts/proofkit/coverage-metrics.json "$coverage_snapshot"
cp artifacts/proofkit/browser-runtime-proof.json "$browser_snapshot"
cp artifacts/proofkit/package-artifact-execution.json \
  "$package_execution_snapshot"
assert_coverage_snapshot() {
  jq -e -s \
    --arg sha "$final_sha" '
    length == 1
    and (.[0] |
      .provenance.sourceRevision == $sha
      and .requirements.totalRecords == 69
      and .proofBindings.boundRequirementCount == 69
      and .proofBindings.scenarioCount == 173
      and .commandRoutes.commandCount == 78
    )
  ' >/dev/null
}
assert_coverage_snapshot < "$coverage_snapshot"
for rejected_scenario_count in 167 172 174; do
  if jq -c \
      --argjson count "$rejected_scenario_count" \
      '.proofBindings.scenarioCount = $count' \
      "$coverage_snapshot" |
      assert_coverage_snapshot; then
    exit 1
  fi
done
jq -e -s \
  --arg sha "$final_sha" '
  length == 1
  and (.[0] |
    .sourceRevision == $sha
    and .sourceTreeState == "clean"
    and .state == "passed"
    and (.projects | length) == 3
    and (.projects | map(.name) | sort)
      == ["chromium", "firefox", "webkit"]
    and (.projects | all(
      .executedTestCount == 31
      and .passedTestCount == 31
    ))
  )
' "$browser_snapshot" >/dev/null
jq -e -s \
  --arg sha "$final_sha" '
  length == 1
  and (.[0] |
    .commandId == "proofkit.package-artifact"
    and .sourceRevision == $sha
    and .status == "passed"
    and .exitCode == 0
  )
' "$package_execution_snapshot" >/dev/null
go run ./internal/tools/releasecloseoutinput |
  go run ./cmd/agentic-proofkit completion-criteria --input - \
    > "$local_closeout_report"
jq -e -s '
  length == 1
  and (.[0] |
    .state == "passed"
    and .summary.blockingCriterionCount == 5
    and .summary.blockingUnsatisfiedCount == 0
    and .summary.advisoryCriterionCount == 1
    and .summary.statusCounts.satisfied == 5
    and .summary.statusCounts.advisory_skipped == 1
  )
' "$local_closeout_report" >/dev/null
jq -S -n \
  --arg finalSha "$final_sha" \
  --arg finalTree "$final_tree" \
  --arg auditBaselineSha "$audit_baseline_sha" \
  --arg integrationBaseSha "$integration_base_sha" \
  --argjson diffFiles "$diff_file_count" \
  --argjson diffAdded "$diff_added_lines" \
  --argjson diffDeleted "$diff_deleted_lines" \
  --slurpfile coverage "$coverage_snapshot" \
  --slurpfile browser "$browser_snapshot" \
  --slurpfile packageExecution "$package_execution_snapshot" \
  --slurpfile closeout "$local_closeout_report" \
  '{
    schemaVersion: 1,
    finalSha: $finalSha,
    finalTree: $finalTree,
    auditBaselineSha: $auditBaselineSha,
    integrationBaseSha: $integrationBaseSha,
    diff: {
      files: $diffFiles,
      addedLines: $diffAdded,
      deletedLines: $diffDeleted
    },
    localGates: {
      packageArtifact: {
        commandId: $packageExecution[0].commandId,
        sourceRevision: $packageExecution[0].sourceRevision,
        status: $packageExecution[0].status,
        exitCode: $packageExecution[0].exitCode
      },
      browserRuntime: {
        sourceRevision: $browser[0].sourceRevision,
        sourceTreeState: $browser[0].sourceTreeState,
        state: $browser[0].state,
        projectCount: ($browser[0].projects | length),
        executedTestCount: (
          $browser[0].projects | map(.executedTestCount) | add
        ),
        passedTestCount: (
          $browser[0].projects | map(.passedTestCount) | add
        )
      },
      coverage: {
        sourceRevision: $coverage[0].provenance.sourceRevision,
        requirementCount: $coverage[0].requirements.totalRecords,
        boundRequirementCount:
          $coverage[0].proofBindings.boundRequirementCount,
        scenarioCount: $coverage[0].proofBindings.scenarioCount,
        commandCount: $coverage[0].commandRoutes.commandCount
      },
      localCloseout: {
        state: $closeout[0].state,
        blockingCriterionCount:
          $closeout[0].summary.blockingCriterionCount,
        blockingUnsatisfiedCount:
          $closeout[0].summary.blockingUnsatisfiedCount,
        satisfiedCount: $closeout[0].summary.statusCounts.satisfied,
        advisorySkippedCount:
          $closeout[0].summary.statusCounts.advisory_skipped
      }
    },
    residualNonClaims: [
      "No registry publication, Trusted Publisher or OIDC provider identity, branch-protection setting, rollout, deployment, or production readiness is proven.",
      "Pinned browser engines do not imply complete WCAG conformance or branded Safari parity.",
      "The output writer does not claim protection from same-user content or namespace mutation during the operation, fsync durability, or a repository-wide transaction.",
      "Local closeout evidence objects are individually admitted snapshots, not an atomic filesystem transaction across all artifacts.",
      "Provider observations are bounded but not atomic across endpoints or immutable after the final response."
    ],
    retrospective: [
      "Single-factor Firefox hypotheses were falsified before the combined axe-initialization and trace-screenshot correction was admitted.",
      "Repeated closeout misses require literal-SHA provider APIs, mutation oracles at irreversible boundaries, admitted byte snapshots, and machine-readable closeout projections."
    ]
  }' > "$closeout_record_expected"
test "$final_sha" = "$(git rev-parse HEAD)"
test -z "$(git status --porcelain)"
cp /tmp/agentic-proofkit-audit-remediation-pr-body.md \
  "$reviewed_body_snapshot"
reviewed_body_digest="sha256:$(
  shasum -a 256 "$reviewed_body_snapshot" | awk '{print $1}'
)"

assert_remote_and_pr_identity() {
  test "$final_sha" = \
    "$(git ls-remote origin "$branch_ref" | awk '{print $1}')"
  test "$integration_base_sha" = \
    "$(git ls-remote origin "$base_ref" | awk '{print $1}')"
  gh pr view 78 --repo "$repo" \
    --json title,author,headRefName,headRefOid,baseRefName,baseRefOid,isDraft,state,mergedAt,body \
    > "$pr_snapshot"
  jq -e \
    --arg sha "$final_sha" \
    --arg base "$integration_base_sha" \
    --arg title "$expected_title" \
    '.author.login == "iperev"
     and .headRefName == "fix/audit-remediation"
     and .headRefOid == $sha
     and .baseRefName == "main"
     and .baseRefOid == $base
     and .isDraft == false
     and .state == "OPEN"
     and .mergedAt == null
     and .title == $title' \
    "$pr_snapshot" >/dev/null
}

assert_provider_disposition() {
local projection_path="$1"
gh api \
  "repos/$repo/actions/workflows/ci.yml/runs?event=pull_request&head_sha=$final_sha&per_page=100" \
  > "$ci_runs"
ci_run_id="$(
  jq -er \
    --arg sha "$final_sha" \
    --arg base "$integration_base_sha" \
    '. as $response
     | select(
         $response.total_count == ($response.workflow_runs | length)
         and $response.total_count > 0
       )
     | [
         $response.workflow_runs[]
         | select(
             .head_sha == $sha
             and .head_branch == "fix/audit-remediation"
             and .event == "pull_request"
             and (.pull_requests | length) == 1
             and .pull_requests[0].number == 78
             and .pull_requests[0].head.ref == "fix/audit-remediation"
             and .pull_requests[0].head.sha == $sha
             and .pull_requests[0].head.repo.url
               == "https://api.github.com/repos/research-engineering/agentic-proofkit"
             and .pull_requests[0].base.ref == "main"
             and .pull_requests[0].base.sha == $base
             and .pull_requests[0].base.repo.url
               == "https://api.github.com/repos/research-engineering/agentic-proofkit"
           )
       ]
     | if length != 1 then error("expected one exact-PR exact-SHA ci run")
       else .[0]
       end
     | select(
         .run_attempt == 1
         and .status == "completed"
         and .conclusion == "success"
       )
     | .id' \
    "$ci_runs"
)"
ci_run_attempt="$(
  jq -er \
    --argjson id "$ci_run_id" \
    '.workflow_runs[]
     | select(.id == $id)
     | .run_attempt' \
    "$ci_runs"
)"
gh api \
  "repos/$repo/actions/runs/$ci_run_id/attempts/$ci_run_attempt/jobs?per_page=100" \
  > "$ci_jobs"
jq -e '
  [
    "quality / source",
    "quality / platform smoke / macos-15",
    "quality / browser runtime",
    "quality / required aggregate"
  ] as $required
  | .jobs as $jobs
  | ($jobs | length) == ($required | length)
    and ([$jobs[].name] | sort) == ($required | sort)
    and ($jobs | all(
      .head_sha == $sha
      and .run_attempt == $attempt
      and .status == "completed"
      and .conclusion == "success"
    ))
' \
  --arg sha "$final_sha" \
  --argjson attempt "$ci_run_attempt" \
  "$ci_jobs" >/dev/null
gh api \
  "repos/$repo/commits/$final_sha/check-runs?filter=all&per_page=100" \
  > "$check_runs"
jq -e '
  .total_count == (.check_runs | length)
  and (.check_runs | all(.status == "completed"))
' "$check_runs" >/dev/null
gh api \
  "repos/$repo/commits/$final_sha/status?per_page=100" \
  > "$commit_status"
jq -e \
  --arg sha "$final_sha" \
  '.sha == $sha
   and (.statuses | length) < 100
   and (.statuses | all(
     .state | IN("success", "failure", "error")
   ))' \
  "$commit_status" >/dev/null
jq -S -n \
  --arg finalSha "$final_sha" \
  --arg integrationBaseSha "$integration_base_sha" \
  --argjson ciRunId "$ci_run_id" \
  --slurpfile runs "$ci_runs" \
  --slurpfile jobs "$ci_jobs" \
  --slurpfile checks "$check_runs" \
  --slurpfile statuses "$commit_status" \
  '{
    schemaVersion: 1,
    finalSha: $finalSha,
    integrationBaseSha: $integrationBaseSha,
    ciRun: (
      $runs[0].workflow_runs[]
      | select(.id == $ciRunId)
      | {
          id,
          runAttempt: .run_attempt,
          event,
          status,
          conclusion,
          headSha: .head_sha,
          headBranch: .head_branch,
          pullRequests: [
            .pull_requests[]
            | {
                number,
                headRef: .head.ref,
                headSha: .head.sha,
                headRepo: .head.repo.url,
                baseRef: .base.ref,
                baseSha: .base.sha,
                baseRepo: .base.repo.url
              }
          ]
        }
    ),
    jobs: (
      $jobs[0].jobs
      | map({
          id,
          name,
          status,
          conclusion,
          headSha: .head_sha,
          runAttempt: .run_attempt
        })
      | sort_by(.name, .id)
    ),
    checkRuns: (
      $checks[0].check_runs
      | map({
          id,
          name,
          status,
          conclusion,
          appSlug: .app.slug,
          externalId: .external_id
        })
      | sort_by(.name, .id)
    ),
    legacyStatuses: (
      $statuses[0].statuses
      | map({
          id,
          context,
          state,
          description,
          targetUrl: .target_url,
          creatorLogin: .creator.login
        })
      | sort_by(.context, .id)
    )
  }' > "$projection_path"
}

assert_embedded_projection() {
  local body_path="$1"
  local projection_path="$2"
  local embedded_path="$3"
  local marker_name="$4"
  local begin_line="$5"
  local end_line="$6"
  local projection_digest
  projection_digest="sha256:$(
    shasum -a 256 "$projection_path" | awk '{print $1}'
  )"
  test "$(
    grep -Ec "^${marker_name}:" "$body_path"
  )" -eq 1
  test "$(
    grep -Ec \
      "^${marker_name}: sha256:[0-9a-f]{64}$" \
      "$body_path"
  )" -eq 1
  grep -Fqx \
    "${marker_name}: $projection_digest" \
    "$body_path"
  awk \
    -v begin_line="$begin_line" \
    -v end_line="$end_line" '
    BEGIN {
      begins = 0
      ends = 0
      inside = 0
      invalid = 0
    }
    $0 == begin_line {
      begins++
      if (inside || ends > 0) {
        invalid = 1
      }
      inside = 1
      next
    }
    $0 == end_line {
      ends++
      if (!inside) {
        invalid = 1
      }
      inside = 0
      next
    }
    inside {
      print
    }
    END {
      if (invalid || begins != 1 || ends != 1 || inside) {
        exit 1
      }
    }
  ' "$body_path" > "$embedded_path"
  cmp -s "$projection_path" "$embedded_path"
}

assert_remote_and_pr_identity
assert_provider_disposition "$provider_projection_one"
assert_embedded_projection \
  "$reviewed_body_snapshot" \
  "$provider_projection_one" \
  "$provider_projection_embedded_one" \
  "provider-projection-sha256" \
  "provider-projection-json-begin" \
  "provider-projection-json-end"
assert_embedded_projection \
  "$reviewed_body_snapshot" \
  "$closeout_record_expected" \
  "$closeout_record_embedded_one" \
  "closeout-record-sha256" \
  "closeout-record-json-begin" \
  "closeout-record-json-end"
assert_remote_and_pr_identity
assert_provider_disposition "$provider_projection_two"
cmp -s "$provider_projection_one" "$provider_projection_two"
assert_remote_and_pr_identity
jq -j '.body' "$pr_snapshot" > "$pr_body_readback"
test "$reviewed_body_digest" = "sha256:$(
  shasum -a 256 "$reviewed_body_snapshot" | awk '{print $1}'
)"
cmp -s "$reviewed_body_snapshot" "$pr_body_readback"
assert_embedded_projection \
  "$pr_body_readback" \
  "$provider_projection_two" \
  "$provider_projection_embedded_server" \
  "provider-projection-sha256" \
  "provider-projection-json-begin" \
  "provider-projection-json-end"
assert_embedded_projection \
  "$pr_body_readback" \
  "$closeout_record_expected" \
  "$closeout_record_embedded_server" \
  "closeout-record-sha256" \
  "closeout-record-json-begin" \
  "closeout-record-json-end"
```

Each provider pass applies the following rules. The workflow-run query is
filtered by the literal final SHA and `ci.yml`; the
filtered set must contain exactly one run bound uniquely to pull request `#78`,
the exact `fix/audit-remediation` head in this repository, and the `main` base
in this repository. Multiple runs for the same PR and SHA fail closed. The sole
run must itself pass, and its exact current attempt must equal `1` and contain
only the four closed-inventory jobs, each bound to that SHA, attempt `1`, and
concluded `success`; a provider rerun or repeated same-object run is diagnostic
evidence only. The commit check-run endpoint independently
requires every triggered check run for the literal SHA to be terminal and
fails closed if pagination would hide a row. The literal-SHA combined-status
endpoint rejects pending legacy contexts, admits terminal `success`, `failure`,
and `error` only for accurate reporting, and fails closed at the page limit.
The first pass emits a canonical projection of every provider
decision-relevant field. Each local artifact used by the closeout record is
copied once to a private file; validation and projection consume only those
same snapshot bytes, after which final `HEAD` and tracked-tree cleanliness are
rechecked. Only fields named by the exact validation predicates are projected;
opaque artifact digests are omitted. The snapshots are individually admitted
and do not claim an atomic filesystem transaction across all artifacts. Before
this final block, use an
earlier execution of the same function and the exact local snapshots admitted
above to put both the provider projection and canonical closeout record into
the reviewed local
pull-request body with their exact digest markers and sentinel pairs. The
closeout record machine-binds the final tree, diff counts, local gate counts,
residual non-claims, and retrospective instead of relying on narrative
presence. At block entry, copy those reviewed bytes once into a private
snapshot and bind that snapshot to its digest; the mutable fixed pathname is
never read again. The block rejects duplicate or malformed markers and
sentinels in that snapshot, extracts both embedded records, and requires byte
equality before requiring the second provider projection to be byte-identical.
The final server body is then compared with the unchanged reviewed snapshot
and independently subjected to the same marker, sentinel, digest, and
embedded-byte validation for both records. Human-readable summary prose is
explicitly non-authoritative. Thus both admitted local bytes and observed
server bytes are bound directly to the stable provider disposition and exact
closeout facts rather than merely asserting that some terminal predicate
passed.
The final identity snapshot is the one used for byte-transparent body
comparison and direct server-body validation. The complete provider pass is
executed twice, with identity checks before, between, and after the passes;
persistent provider reruns or new nonterminal rows therefore invalidate the
second pass. The observations are not an atomic snapshot across endpoints.
Concurrent `A -> B -> A` PR identity history between observations and provider
mutation after the final response remain explicit non-claims, but neither can
substitute provider conclusions for `A` because every provider query is bound
directly to `final_sha`. This final readback must require the exact final SHA,
tree, gate counts, bounded provider observations, residual non-claims, and
retrospective result. It is the final closeout projection and the last
retirement precondition.

## Completion criteria

The implementation is complete only if:

1. all design findings R-01 through R-29 and R-11a through R-11d have their
   exact durable witness routes;
2. every current-wrong counterexample is observed red before repair or is
   otherwise preserved as an isolated mutation proof;
3. every narrow gate and `npm run check` pass on the final committed object;
4. all three final reviewers approve and the independent maximum-reasoning
   audit reports no unresolved confirmed finding;
5. business-logic changes are limited to the design's intentional compatibility
   list;
6. GitHub identity and push permission are reverified;
7. the branch is pushed and the PR authored by `iperev` is open, non-draft,
   unmerged, and bound to the literal final SHA and reviewed integration-base
   SHA;
8. in two consecutive final literal-SHA provider passes, every tuple in the
   closed source-owned required-check inventory is present with a `success`
   conclusion, every other observed check is terminal, and all states are
   reported without claiming an atomic cross-endpoint snapshot;
9. retrospective routing is completed;
10. the final pull-request closeout projection is read back with the exact
    provider disposition, residual non-claims, and retrospective result, while
    bracketing identity snapshots both bind the remote head/base branches and
    pull request to the literal final and integration-base SHAs and the
    server-side
    body equals the reviewed body and uniquely contains both the SHA-256 and
    exact sentinel-delimited bytes of the byte-identical canonical provider
    projections;
11. temporary design/plan retirement conditions are explicit and remain false
    until criteria 1 through 10 all hold.

## Review acceptance criteria

Reviewers approve this plan only if:

- every step is executable and ordered after its dependencies;
- every gate selector matches the test it claims to run;
- no production change precedes its owner and counterexample;
- no plan step invents provider, registry, or selective proof;
- the shared-worktree execution model preserves reviewer independence;
- the final publication account and permissions are explicit;
- the plan can be overturned safely at each named rollback condition.
