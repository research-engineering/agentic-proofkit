# Proofkit Backlog

This file is the canonical active-work ledger for
`research-engineering/agentic-proofkit`.

It tracks only current `NEXT`, `BLOCKED`, or `DEFERRED` work. It is not a
roadmap, release log, proof registry, architecture document, CLI manual, or
historical completion archive.

## Current State

Active work is limited to the rows below. Durable rules and reusable
architecture live in their owner surfaces:

- `README.md` for human orientation;
- `ADOPTION.md` for adoption, distribution, rendering, requirement, contract,
  test, and agent-guidance models;
- `NON_CLAIMS.md` for boundary denials;
- `docs/proofkit-contract-map.md` for command-family routing and agent
  decision procedure;
- `docs/release-process.md` for release-channel evidence and publication
  process;
- `docs/specs/**/requirements.v2.json` for durable machine requirements;
- `proofkit/*.json` for shipped machine contracts and proof routes;
- source, tests, package metadata, and workflows for executable behavior.

## Admission Rules

Add a row only when new work is accepted and cannot be represented more
precisely by an existing owner surface.

Every row must be falsifiable and include:

- `Status`: `NEXT`, `BLOCKED`, or `DEFERRED`;
- `ID`: stable owner-scoped identifier;
- `Scope`: one bounded reason to change;
- `Completion condition`: objective proof or explicit retirement condition.

When a row is completed, remove it from this active backlog after its durable
rule, evidence, or behavior is represented by the owning source, test,
contract, release artifact, provider record, or documentation surface. Do not
retain completed rows here as history.

Historical evidence belongs in pull requests, release artifacts, registry
records, generated release manifests, or the owning docs named above.

## Open Rows

| Status | ID | Scope | Completion condition |
|---|---|---|---|
| BLOCKED | BROWSER-TOOLCHAIN-01 | Qualify a stable browser-test successor to the pinned 1.63.0 SDK that contains the Firefox channel-identity repair ([microsoft/playwright@e5d880b](https://github.com/microsoft/playwright/commit/e5d880b05f9a1d7fb5d17dd031b53739e5e39c0e), Firefox r1551, first released in 1.64.0; 1.63.0 ships r1543 and lacks it) and lacks the native WebKit select/CSP regression first shipped in 1.64.0: WebKit commit `ef67848e5875` (bug 322676) sets a style attribute on a select element's internal slot before that slot is in the user-agent shadow tree, so the page's `style-src` refuses it and logs a console error (open as WebKit bug 327212). | Unblocked only by a stable Playwright release whose Firefox is r1551 or later and whose WebKit no longer reproduces that select/CSP regression (a native `select` under the workspace CSP logs no console or security-policy error); as of 2026-10-13, 1.64.0, the only stable successor, still has the regression. The complete Chromium, Firefox and WebKit gate must then pass with native navigation, exact engine evidence, strict CSP, console and security-policy checks and zero retries. Keep Firefox site-origin process isolation: on 1.63.0, Firefox runs without it reproduced the navigation completion failure under host load. Remove it only when at least five complete Firefox runs of the successor without it, interleaved with control runs that keep it and including runs under host load at least as high as the 1.63.0 complete run that reproduced the failure (1-minute load average median 19 on 8 CPUs), all pass with zero retries and no navigation completion failure; update its fixture and contributor explanation together with the policy change. Do not substitute a custom engine or ignore console/security-policy failures. |
| BLOCKED | GOVERNANCE-01 | Evaluate a generic explicit-inventory governance-observation command without promoting one consumer's policy into Proofkit; detailed candidate contract is retained in [issue #64](https://github.com/research-engineering/agentic-proofkit/issues/64). | A sanitized reproducible fixture detects one named failure without classifying its false-positive counterexample, existing owners are proven insufficient, and either a second independent consumer reproduces the predicate or the owner admits recurring first-consumer cost; otherwise retire the candidate. |
| DEFERRED | VALUE-01 | Admit exact value-evidence comparisons only after a real producer and downstream consumer establish the public record boundary; detailed candidate contract is retained in [issue #65](https://github.com/research-engineering/agentic-proofkit/issues/65). | A real execution-receipt projection, baseline producer, and downstream consumer prove an exact producer-output-to-admission round trip plus compact/full-graph inclusion or an intentional omission non-claim; otherwise no public command is added. |
| BLOCKED | RELOCATION-01 | Add provenance-bounded witness relocation candidates without introducing a second binding path or trusting a caller-authored prior digest; detailed candidate contract is retained in [issue #66](https://github.com/research-engineering/agentic-proofkit/issues/66). | An owner-admitted content-addressed baseline binds witness id, prior path and digest, source revision, evidence class, authentication non-claims, and freshness non-claims; the scanner then proves the zero/one/many match partition while remaining non-current until fresh execution evidence exists. |
