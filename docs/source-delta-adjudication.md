# Source Delta Adjudication

Status: current source-repository import ledger.

Owner: `proofkit`.

## Problem

The pre-cutover local repository still differs from the public repository in
many non-document source files. Treating old source bytes as automatically
authoritative would risk deleting current public-source identity, release
hardening, admission hardening, package verification, and self-governance tests.

Treating the delta as irrelevant without a closed inventory would risk losing a
durable source invariant during the public cutover.

## Scope

This ledger compares pre-cutover non-document source files from:

- old local source snapshot:
  `1b9d05f95a334538a705a67d9695e62ebecfd175`
  at `/Users/kisa/Downloads/Ivan/Projects/agentic-proofkit`;
- current public source snapshot:
  `015997a70f36a71967b937fe2123289423496acd`
  at `/Users/kisa/Downloads/Ivan/Projects/research-engineering-agentic-proofkit`.

Excluded from this ledger: `docs/**`, `artifacts/**`, `dist/**`, and `*.md`
files. Documentation import is adjudicated separately in
`docs/design-import-adjudication.md`.

## Inventory Result

| Check | Result |
|---|---:|
| Old non-document source files | 283 |
| Current non-document source files | 288 |
| Old source files missing from current public source | 0 |
| Current-only non-document source files | 5 |
| Identical old/current non-document source files | 75 |
| Different old/current non-document source files | 208 |

Current-only files:

- `internal/kernel/cliexec/cliexec.go`
- `internal/kernel/cliexec/cliexec_test.go`
- `internal/kernel/contractenv/contractenv_test.go`
- `internal/kernel/digest/digest_test.go`
- `internal/kernel/report/report_test.go`

Different files by family:

| Family | Count |
|---|---:|
| `.github workflows` | 2 |
| `.gitignore` | 1 |
| `LICENSE` | 1 |
| `cmd` | 1 |
| `go.mod` | 1 |
| `internal/app` | 25 |
| `internal/command` | 131 |
| `internal/kernel` | 23 |
| `internal/tools` | 17 |
| `package.json` | 1 |
| `proofkit records` | 2 |
| `scripts` | 3 |

## Decision

No old non-document source file is imported over the current public source.

Formal reason:

```text
missing_old_source_files = 0
and current_only_hardening_files > 0
and current_source_contains_public_repository_identity
and current_source passes local package gate
and importing old bytes would remove current hardening or reintroduce old
    repository/provider facts
=> old source bytes are candidate evidence only, not replacement authority
```

The 208 differing files are treated as already-publicly-rewritten or hardened
current source. They remain owned by current code, tests, specs, package
metadata, workflows, and proofkit records. A future old-source comparison may
reopen a specific file only by proving a named invariant absent from the
current owner surface.

## Dominating Current Changes

| Area | Current owner surfaces | Why old bytes are not imported |
|---|---|---|
| Public repository identity | `go.mod`, `package.json`, import paths, workflows, tests | Old source names the pre-cutover repository/account in release and package surfaces. Current source names `research-engineering/agentic-proofkit` and passes public-source text scans. |
| Kernel safety and determinism | `internal/kernel/admit`, `internal/kernel/cliexec`, `internal/kernel/contractenv`, `internal/kernel/digest`, `internal/kernel/report`, tests | Current source adds or preserves stronger path control-rune rejection, shell-safe command display, immutable snapshot tests, digest canonicalization tests, stable report-shape tests, duplicate-key JSON admission, and secret-shaped report redaction. |
| CLI and command contract governance | `internal/app`, `proofkit/cli-contract.v1.json`, command coverage tests | Current source carries public CLI registry, command coverage, route hardening aligned with current specs and package identity, and production inventory validation for semantic command-route ownership. |
| Release and package evidence | `.github/workflows/*`, `internal/tools/*`, `scripts/*`, `package.json` | Current source owns public release workflow, explicit CI proof-class steps, package verification, self-receipt, SBOM, Python wrapper, release-closeout logic, and workflow package-gate oracle tests. Provider publication remains open in `BACKLOG.md`; old release bytes do not prove it. |
| Requirement and proof records | `proofkit/requirement-bindings.json`, `proofkit/witness-plan.json`, `docs/specs/**` | Current records are aligned with the public source tree and self-coverage metrics. Old records are candidate evidence only. |

Concrete regression examples if old bytes were imported:

- old workflow layout would replace explicit current CI proof-class steps with
  a broad package-gate step and remove step-level oracle value;
- old path admission rejected NUL but not every control rune;
- old CLI guidance and tests used stale `proofkit ...` command text instead of
  the public `agentic-proofkit ...` binary contract;
- old command coverage validation lacked the current production inventory
  owner-scope rejection for semantic command routes;
- old release and package surfaces referenced pre-cutover repository identity
  instead of the public organization repository.

## Rejected Alternatives

| Alternative | Rejected because |
|---|---|
| Copy all differing old source files over current source. | This would delete current hardening and public-source identity without proving a missing invariant. |
| Treat file count differences as defects. | Current-only files are additional kernel hardening and tests; file count is not a source-of-truth failure. |
| Re-run a semantic diff of every changed line before closing import. | The closed inventory proves no old source file is absent. Future semantic concerns must name a specific invariant and owner surface instead of blocking the entire cutover. |
| Keep `IMPORT-06` open until provider release evidence exists. | Provider publication, security settings, and consumer adoption are separate backlog rows and separate evidence classes. |

## Future Reopen Rule

A future old-source delta claim is admissible only when it states:

1. the exact old file and current owner file;
2. the invariant missing from current source;
3. why current specs, tests, and package gates do not already own it;
4. the minimal current-owner fix;
5. the proof command that would fail before and pass after the fix.

This prevents historical source from becoming a parallel implementation
authority.
