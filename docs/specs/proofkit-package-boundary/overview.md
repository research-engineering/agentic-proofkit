# Proofkit Package Boundary Spec

This spec owns the first self-hosted Proofkit package-boundary requirements.
It is intentionally narrow: it covers package CLI/report boundary, module import
denial, and package artifact behavior only.

## Requirements

- `REQ-PROOFKIT-PACKAGE-001`: the package artifact set exposes the supported
  CLI through one root package with embedded platform binaries while denying
  root imports, source imports, generated JavaScript imports, and deep internal
  package paths as public contract.
- `REQ-PROOFKIT-PACKAGE-002`: the CLI builds deterministic reports, plans,
  generated source artifacts, and policy-admission results from explicit
  caller-owned JSON, declared no-input command parameters, or declared explicit
  scanner scope classes. Explicit scanners consume only caller-named bounded
  canonical files under documented fail-closed grammars rather than guessing
  layouts or silently accepting unsupported syntax; no command executes native
  witnesses, scans implicit repository state, decides proof freshness, or accepts
  broad caller-supplied phrase suppressors that can hide readiness overclaims.
- `REQ-PROOFKIT-PACKAGE-003`: the root package remains installable and
  executable by an outside consumer on the current native platform without
  claiming registry publication.
- `REQ-PROOFKIT-PACKAGE-004`: CI package-gate receipts used as merge evidence
  are admitted through a declared producer policy and proof-receipt shape
  validator instead of current-build output alone.
- `REQ-PROOFKIT-PACKAGE-005`: tracked source hygiene covers each admitted text
  language in staged blobs and the current worktree; Go formatting, static
  analysis, test, package, and vulnerability gates remain the native
  merge-critical quality floor and explicitly provision every runtime required
  by a merge-critical oracle.
- `REQ-PROOFKIT-PACKAGE-006`: Python/uv distribution is a platform wheel
  wrapper over the same Go CLI, with wheel-safe package metadata, wheel tags,
  embedded binary identity, local install smoke proof, POSIX exec
  process-identity and signal preservation, and explicit non-claims until PyPI
  publication.
- `REQ-PROOFKIT-PACKAGE-007`: package-public Markdown records release-channel
  state only and must not embed exact per-version provider facts that are owned
  by immutable registry, release, and manifest artifacts.

## Non-Claims

- This spec does not claim consumer repository adoption.
- This spec does not claim registry publication.
- This spec does not claim PyPI publication.
- This spec does not claim runtime execution for non-native embedded platform
  binaries unless CI supplies that native OS and CPU tuple.
- This spec does not claim proof freshness, merge approval, rollout approval,
  or production readiness.
- This spec does not make current-build Proofkit output sufficient to admit the
  same current build.
