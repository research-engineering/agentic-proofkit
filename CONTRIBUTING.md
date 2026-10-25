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
with `fission.webContentIsolationStrategy=1` instead of the bundle default `0`.
With it, no navigation completion failure (a navigation the driver never reports
as finished) has been observed, and it replaces no browser binary and weakens no
CSP, navigation assertion or retry. Without it, Firefox runs of the 1.62.1
bundle and, under host load, of the pinned 1.63.0 bundle reproduced that
failure, so the preference stays until its removal is qualified. Both bundles
predate the Firefox channel-identity repair
([microsoft/playwright@e5d880b](https://github.com/microsoft/playwright/commit/e5d880b05f9a1d7fb5d17dd031b53739e5e39c0e),
Firefox r1551, first released in 1.64.0); 1.63.0 ships Firefox r1543.
The engine fixture checks the requested launch policy. Keep the exact stable SDK,
the preference and all three engine gates until a complete qualification admits
a successor that contains the r1551 repair and lacks the WebKit select/CSP
regression. Remove the preference only when at least five complete Firefox runs
of that successor without it, interleaved with control runs that keep it and
including runs under host load at least as high as the 1.63.0 complete run that
reproduced the failure (1-minute load average median 19 on 8 CPUs), all pass
with zero retries and no navigation completion failure, and update the fixture
and this explanation together with it.

The visual reference gate, `npm run browser:visual`, is separate from
`npm run check`. It compares a canonical pixel digest of every rendered view
with the owner-admitted entry in `tests/visual/references.json`, but only in
the environment recorded in `tests/visual/environment.json`: the digest-pinned
linux/arm64 `mcr.microsoft.com/playwright` image that the
`quality / browser visual references` job runs on `ubuntu-24.04-arm`, with the
font mapping of `tests/visual/fonts.conf`, which the gate copies into its run
directory before it observes the environment. On any other host it detects the
difference before launching a browser, records `unverified` and exits 0; CI
adds `--require-reference-environment`, which makes that a failure. No
reference image is stored in the repository, and the gate never writes
references. Every reference-environment run keeps its captures in
`artifacts/browser-run-*/captures/<engine>/<view>.<scheme>.<width>.png`, with
`candidate-references.json` and `observed-environment.json` beside them; CI
uploads these as the `browser-visual-captures-<sha>-<attempt>` artifact after
every run and keeps it for 30 days. A local reference-environment run keeps
about 30 MB below its `artifacts/browser-run-*` directory, which you may
delete once you no longer need its captures.

To view an admitted image, run the gate at the admitting commit in the pinned
image and look at its captures; when it passes, every capture has the admitted
digest. Use a separate clone rather than a worktree, because the container
sees only the mounted directory and installs Linux `node_modules` into it. The
container user, uid 1001, must be able to write the clone: Docker Desktop
allows that, and on a Linux host the clone must belong to uid 1001. The
container installs the same checksum-verified Node, npm and Go versions as the
CI job:

```bash
git clone https://github.com/research-engineering/agentic-proofkit.git proofkit-visual
cd proofkit-visual
git checkout <admitting commit>
docker run --rm --platform linux/arm64 --user 1001 --ipc=host --init \
  -v "$PWD":/work -w /work \
  mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27 \
  bash -euo pipefail -c '
    git config --global --add safe.directory /work
    tools="$(mktemp -d)"
    cd "$tools"
    curl -fsSLO https://nodejs.org/dist/v26.11.1/node-v26.11.1-linux-arm64.tar.gz
    curl -fsSLO https://go.dev/dl/go1.27.3.linux-arm64.tar.gz
    curl -fsSLO https://registry.npmjs.org/npm/-/npm-12.2.0.tgz
    sha256sum -c - <<SUMS
170454fb022f5e9b5f6cc76c25fa32ef5100895be44eb04e92f9780591491bbf  node-v26.11.1-linux-arm64.tar.gz
a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49  go1.27.3.linux-arm64.tar.gz
6666b48816b39b86c3febac7b51a4ee4de6c5ca589c382ad8004b6b113f86677  npm-12.2.0.tgz
SUMS
    tar -xzf node-v26.11.1-linux-arm64.tar.gz
    tar -xzf go1.27.3.linux-arm64.tar.gz
    tar -xzf npm-12.2.0.tgz
    mkdir bin
    printf "#!/bin/sh\nexec node %s/package/bin/npm-cli.js \"\$@\"\n" "$tools" > bin/npm
    chmod +x bin/npm
    export PATH="$tools/bin:$tools/node-v26.11.1-linux-arm64/bin:$tools/go/bin:$PATH"
    cd /work
    npm ci --ignore-scripts
    npm run browser:visual -- --require-reference-environment'
```

To re-admit references after an intended visual change, let the job fail,
download its `browser-visual-captures-*` artifact, review the captures, and
regenerate `tests/visual/references.json` from that run with
`go run ./internal/tools/browserproofverify --manifest scripts/browser-visual-proof-inputs.v1.json --admit-references --from <extracted artifact>/browser-run-<id>`;
the artifact holds the run directory `browser-run-<id>` below its root.
Admission accepts only a run whose observed environment equals the recorded
one, with exactly one regular capture file per reference ID and no unstable
directory; it recomputes every digest from the PNG files. It cannot tell
whether the run directory changed after the run, so only a passing job proves
the admitted digests. Push until the job passes on the exact final tree.
Before merge, pass the gate on each CPU model named in the non-claims, or
change those non-claims. Merging is the owner's admission. An environment
change, including a Playwright upgrade, takes two steps. First, update
`observed` in `tests/visual/environment.json` from the
`observed-environment.json` of a run in the new environment; that run reports
`unverified` and launches no browser.
Second, run again: the browsers now launch, and if a launched version differs
the engine fixture fails with that version, which then goes into
`browserVersions`. Because `environmentId` changed, that run cannot pass until
its captures are admitted as above. The same image runs natively on Apple
Silicon; an emulated platform is always `unverified`.

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
source tools: exactly one full-sized record, matching PID/parent/group, and
SZOMB. A truncated record or a permission error remains an ordinary observation
failure: the observer runs only before the sole reap, so the unreaped child
still pins its PID and group and retained cleanup may signal them. Linux
uses fresh `waitid(P_PID, WEXITED|WNOWAIT|WNOHANG)` records. Source-check targets
are the configured Ubuntu 24.04 (x86_64), ubuntu-24.04-arm (arm64), macos-15
(arm64) and macos-15-intel (x86_64) jobs and the native Linux wheel verifier
profile, each requiring actual host/API qualification. A CI label, cross-build
or one local run is not native qualification of another host. macOS 13 and 14
are not executed: no hosted macOS 13 image exists, and GitHub retires
`macos-14` on 2026-11-02 after failing brownouts (actions/runner-images#13518).
This package is outside the CLI dependency closure on all four shipped targets;
consumer wheel tags and platform minima are unchanged. Import or payload changes
require a fresh closure proof, and unsupported hosts fail before child Start.
Retained identity assumes an owned Setpgid Start and no foreign/second reap,
auto-reap, Release, reparenting or tracing interference.

ECHILD, ESRCH, a zero-length Darwin `kern.proc.pid` answer (a foreign reap;
the x/sys single-record wrapper reports it as EIO) or an identity contradiction
revokes authority: no numeric signal,
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
