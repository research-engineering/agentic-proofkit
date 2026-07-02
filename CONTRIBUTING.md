# Contributing

Thank you for improving `agentic-proofkit`.

This project accepts changes that preserve Proofkit's boundary as reusable
CLI/JSON proof infrastructure. Consumer-specific policy, product semantics,
native witness execution, proof freshness decisions, and rollout approval
belong in consuming repositories.

## Current Cutover Note

The current public contract layer does not claim runtime code, package
metadata, machine-readable contracts, specifications, or release workflows. Do
not treat this layer as implementation or release readiness.

## Start Here

1. Read [AGENTS.md](AGENTS.md) for repository authority, proof, and closeout
   rules.
2. Use [README.md](README.md) for human orientation.
3. Use [NON_CLAIMS.md](NON_CLAIMS.md) to understand the boundary between
   Proofkit mechanics and consuming-repository authority.

## Change Admission

An accepted change should have:

- one clear owner scope;
- a named invariant or contract it improves;
- the lower-cost alternative considered and rejected;
- proof that matches the changed evidence class;
- explicit non-claims when the change does not prove runtime, release,
  consumer adoption, native witness execution, or rollout readiness.

Do not add generated HTML, generated lookup graphs, local artifacts, package
tarballs, build outputs, caches, credentials, or consumer repository snapshots
to source control unless a release owner explicitly admits the artifact.

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
