# Contributing

Thank you for improving `agentic-proofkit`.

This project accepts changes that preserve Proofkit's boundary as a reusable
CLI/JSON proof infrastructure toolkit. Consumer-specific policy, product
semantics, native witness execution, proof freshness decisions, merge
admission, and rollout approval belong in consuming repositories.

## Start Here

1. Read [AGENTS.md](AGENTS.md) for repository authority, proof, and closeout
   rules.
2. Use [README.md](README.md) for human orientation.
3. Use [docs/proofkit-contract-map.md](docs/proofkit-contract-map.md) to find
   the owner command or primitive.
4. Use [ADOPTION.md](ADOPTION.md) for dependency and channel authority.
5. Use [BACKLOG.md](BACKLOG.md) to check active work, blocked claims, and
   deferred work.
6. Use [NON_CLAIMS.md](NON_CLAIMS.md) to understand the boundary between
   Proofkit mechanics and consuming-repository authority.

## Local Checks

Use a POSIX shell on a supported macOS or Linux host. Before running source
checks, install these prerequisites from their canonical version owners:

- Go: use the `toolchain` version in [go.mod](go.mod); the `go` directive is
  the module's language minimum, not a replacement for the tested toolchain.
- Node.js: use `source-quality` / `Setup Node` in
  [.github/workflows/ci.yml](.github/workflows/ci.yml). A working npm is needed
  to bootstrap the repository-pinned npm below.
- npm: [package.json](package.json) `packageManager` owns the version. The
  shell below exposes that npm to every nested `npm run` and `npx` invocation
  without replacing a global installation. CI uses the separately
  checksum-verified [setup action](.github/actions/setup-verified-npm/action.yml).
- Python: provide `python3` on `PATH`, with `venv` and pip available inside a
  new virtual environment. Use `source-quality` / `Setup Python` in
  [.github/workflows/ci.yml](.github/workflows/ci.yml) for CI parity. The
  [Python package consumer minimum](README.md) is not the source-check
  toolchain pin: Go lifecycle tests need Python, and the
  [wheel verifier](internal/tools/pythonpackage/verify.go) creates a venv
  and installs the local wheel with pip.

From the repository root, run before proposing a non-trivial change:

```bash
npm exec --yes --package="$(node -p "require('./package.json').packageManager")" -- sh -eu -c '
  npm run npm:version
  npm ci --ignore-scripts
  npx playwright install chromium firefox webkit
  npm run check
'
git diff --check
git diff --cached --check
```

The browser engine installation is a one-time prerequisite for the pinned
rendered-runtime gate. On Linux, the engines also need system libraries; use
`npx playwright install-deps chromium firefox webkit` with the required host
privileges before the gate, or use an already provisioned host. CI installs
the same engines and Linux system dependencies before running that gate.

The Firefox test project explicitly enables
[site-origin process isolation](https://searchfox.org/mozilla-central/source/dom/ipc/ProcessIsolation.cpp)
with `fission.webContentIsolationStrategy=1`. This avoids the observed navigation
completion failure in the pinned bundle's shared-process configuration, without
replacing its browser binary or weakening CSP, navigation assertions or retries.
The engine fixture checks the requested launch policy. Keep the exact stable SDK
and all three engine gates until a complete qualification admits a successor.

The composed `go:check` and CI source job both run `npm run go:deps`:
`go mod tidy -diff` rejects manifest drift without rewriting `go.mod` or
`go.sum`, then `go mod verify` checks the downloaded module cache. These are
dependency consistency checks, not vulnerability or release approval.

If your local project uses Bun, `bun run check` is acceptable as a convenience
runner only when it invokes the same scripts and leaves `npm run check`
equivalent. Release and package-authority proof remains npm-owned.

For CLI or Go changes, run focused Go tests first. For package or release
changes, inspect [docs/release-process.md](docs/release-process.md).

### Source-Tool Child Ownership

`internal/kernel/processgroup` owns the retained-child lifecycle used only by
`workflowsmoke`, `commandoracle`, and `repositorysnapshot`. Each caller creates
an ordinary `exec.Command` with explicitly owned file-backed streams. The child
is not reaped until the final group signal has completed and the lifecycle has
sealed all further destructive effects. Normal completion requires both a
positive non-reaping terminal observation and complete required output. Abort
signals immediately, joins local streams and the single observer, retains a
final pre-seal sweep, then performs the sole real `Cmd.Wait`. Post-reap signal 0
must observe ESRCH; EPERM, elapsed time and EOF do not establish absence or exit.
Caller-specific output/parser limits and the 2s/5s/10s drain budgets remain owned
by the callers. No library installs a global signal handler; source entrypoints
retain their SIGINT/SIGTERM scopes through cleanup and join.

Darwin observation admits the pinned x/sys `kern.proc.pid` SPI only for these
source tools: full-sized records, matching PID/parent/group, and SZOMB. Linux
uses fresh `waitid(P_PID, WEXITED|WNOWAIT|WNOHANG)` records. Source-check targets
are the configured Ubuntu 24.04 and macos-15 jobs and the native Linux wheel
verifier profile, each requiring actual host/API qualification. A CI label,
cross-build or one local run is not native qualification of another host.
This package is outside the CLI dependency closure on all four shipped targets;
consumer wheel tags and platform minima are unchanged. Import or payload changes
require a fresh closure proof, and unsupported hosts fail before child Start.
Retained identity assumes an owned Setpgid Start and no foreign/second reap,
auto-reap, Release, reparenting or tracing interference.

ECHILD or an identity contradiction revokes authority: no numeric signal,
reacquisition or Wait is permitted. Tools close and join owned local streams,
report fatal ownership loss with child cleanup unverified, and stop further
work. Permanent kernel refusal or a stuck syscall retains an outstanding join
obligation: a userspace timeout cannot promise both finite completion and join.
SIGKILL of the root, escaped/privileged descendants, hostile indefinite forking,
and producers requiring parent reap before output are not containment promises.

Proof requires independent signal/seal/reap traces, adapter classification and
native owned-child controls, preserved inherited-output/parser/stdin witnesses,
and root-coordinated final gates. Removing cleanup, signaling after reap, or
killing at terminal before output drains is not an admissible simplification.
Revisit this owner if a qualified generation handle is cheaper, source-host SPI
changes, or a protected producer requires reap-dependent output. The narrow
lifecycle replaces the unsafe path, not the callers' stream or result policies.

## Change Admission

An accepted change should have:

- one clear owner scope;
- a named invariant or contract it improves;
- the lower-cost alternative considered and rejected;
- proof that matches the changed evidence class;
- explicit non-claims when the change does not prove runtime, release,
  consumer adoption, native witness execution, or rollout readiness.

Do not add generated HTML, generated lookup graphs, local artifacts, package
tarballs, `dist/`, `artifacts/`, `node_modules/`, credentials, or consumer
repository snapshots to source control unless a release owner explicitly
admits the artifact.

## Pull Requests

Pull requests are maintainer-controlled. Public users may open issues, but pull
request creation is restricted to collaborators until the governance model
changes.

Use concise pull requests. The title and summary should state the exact owner
scope and reviewable outcome. Avoid copied logs, stale checklists, and broad
"cleanup" claims.

Good PR descriptions answer:

- what changed;
- why the owner boundary is correct;
- what proof ran;
- what is not claimed.

## Conduct

Be direct, evidence-based, and respectful. Disagreement should focus on the
invariant, owner boundary, proof, and lower-cost alternative.
