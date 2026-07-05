# Release Process

This is the release how-to for `agentic-proofkit`. It owns the package release
procedure and evidence requirements. It does not own product semantics for
consuming repositories.

## Release Model

```text
reviewed source
  -> version tag
  -> release workflow
  -> candidate package evidence
  -> deterministic SBOM, release manifest, and checksums
  -> public npm publish or exact existing-byte match
  -> optional PyPI publish or exact existing-byte match
  -> post-publish npm registry identity with publication mode
  -> optional post-publish PyPI registry identity with publication mode
  -> root-only npm registry install and JSON CLI ABI proof
  -> optional checksum-bound GitHub artifact attestations
  -> GitHub Release archive assets and release evidence
```

Public npm is the primary dependency authority. The npm package identity is
`@research-engineering/agentic-proofkit`; the installed executable name remains
`agentic-proofkit`. The Python package identity remains `agentic-proofkit`.
GitHub Release assets are archive and provenance lookup. Consumer repositories
still own whether a released version becomes an admitted dependency.

Release and adoption evidence uses canonical `authorityChannel` ids:
`tarball_pilot`, `registry_release`, `python_wheel_candidate`,
`pypi_registry_release`, and `github_release_archive`. Labels such as
`public-npm`, `pypi`, and `github-release` are display projections, not
authority ids.

The target distribution model is multi-channel but single-source:

```text
Go source
  -> npm package for JavaScript/TypeScript/Bun consumers
  -> PyPI wheels for Python/uv consumers
  -> GitHub Release assets with checksums and SBOM for provenance lookup
```

The repository-owned `release:manifest` tool creates `release-manifest.json`,
`checksums.sha256`, `metadata-checksums.sha256`, `sbom-subjects.sha256`,
release notes, and deterministic SBOM candidate evidence from explicit package,
registry, and release evidence. `checksums.sha256` covers distributable archive
assets, including the SBOM file itself. `metadata-checksums.sha256` covers
public release metadata assets such as `release-manifest.json` and release
notes. Post-create workflow evidence such as `github-release.json` and
attestation records is retained under `retained-evidence-checksums.sha256`
instead of being treated as public release assets.
`sbom-subjects.sha256` covers only the package and wheel subjects described by
that SBOM, so SBOM attestations do not make the SBOM file describe itself.
Workflow-local scripts must not own a divergent release manifest or SBOM
algorithm. PyPI wheels may be built and archived as candidate artifacts before
PyPI publication. PyPI publication is enabled only when
`PROOFKIT_ENABLE_PYPI_PUBLISH=true` and the PyPI Trusted Publisher is admitted.
Wheels become PyPI dependency authority only after the dedicated PyPI job either
publishes them through Trusted Publisher or records an exact existing-byte
match, the repository-owned PyPI registry capture tool verifies filename, tag,
URL, and SHA-256 identity against the candidate wheel set, and the release
manifest binds that registry identity to the retained publication-mode sidecar.
When a registry channel records `published_by_workflow` or `mixed`, the release
manifest must also retain the Trusted Publisher identity tuple: provider,
registry, project name, repository, exact `refs/tags/v<version>` workflow ref,
publisher job, and
environment. That tuple is retained provenance evidence for this workflow path;
it does not prove provider UI configuration or provider-side OIDC acceptance by
itself. `existing_byte_match` channels must not invent Trusted Publisher
provenance for bytes that already existed in the registry.

## Preconditions

Before publishing a version:

1. The source tree is clean.
2. `package.json` contains the exact new version.
3. `package.json` repository, license, bin, exports, files, and publishConfig
   match the intended public package contract.
4. The npm account has verified email and write-protective 2FA, or the package
   uses an admitted Trusted Publisher configuration.
5. When `PROOFKIT_ENABLE_PYPI_PUBLISH=true`, the PyPI account has a normal or
   pending Trusted Publisher configured for project `agentic-proofkit`,
   repository `research-engineering/agentic-proofkit`, workflow `release.yml`, and
   environment `pypi`.
6. The release workflow is configured for the package, public npm registry, and
   release environments. PyPI release configuration is required only when the
   PyPI channel is explicitly enabled.
7. `npm run check` passes locally or the release candidate workflow provides
   equivalent current-head evidence.

## Candidate Proof

Run locally before tagging when practical:

```bash
npm run check
npm pack --dry-run --json
git diff --check
```

`npm run check` verifies text policy admission, Go formatting, tests, vet,
static analysis, workflow linting, vulnerability checks, npm package artifact
creation, package artifact verification, Python wheel artifact creation, Python
wheel verification, release SBOM, release manifest and checksum generation,
outside-consumer binary smoke proof, self-hosting receipt validation, and
coverage metrics generation.

The dry-run package identity proves candidate tarball shape only. It does not
prove the bytes served by the registry after publish.

## Publish

Create and push an exact version tag:

```bash
git tag v<version>
git push origin v<version>
```

The `release` workflow must:

1. verify source package identity;
2. run the package gate;
3. build publish candidate evidence through either npm publish dry-run or
   exact existing-byte-match validation for an already published version;
4. build Python wheel candidates for the same embedded Go CLI;
5. prove publish readiness before any registry side effect: the tag must equal
   `v<package.json version>`, target a commit reachable from `main`, and have
   npm publish candidate evidence plus PyPI wheel candidates;
6. publish to public npm through the admitted trusted path, or record
   `existing_byte_match` when the same version already exists with exact
   candidate bytes;
7. when `PROOFKIT_ENABLE_PYPI_PUBLISH=true`, publish to PyPI through the
   admitted trusted path, or record `existing_byte_match` when the same wheel
   set already exists with exact candidate bytes;
8. capture post-publish npm registry identity with package name, version, filename,
   shasum, and integrity;
9. when PyPI publication is enabled, capture post-publish PyPI registry identity
   with package name, version, filename, wheel tags, URL, SHA-256, and retained
   publication mode;
10. verify a root-only npm registry install, signature audit, successful JSON
    report command, and failed-report JSON command with stdout/stderr/exit-code
    discipline;
11. install and verify the pinned Node/npm toolchain before final metadata
    generation, then run the repository-owned release manifest tool against the
    candidate SBOM plus candidate and registry evidence, retaining Trusted
    Publisher identity tuples for workflow-published registry channels;
12. when `PROOFKIT_ENABLE_GITHUB_ATTESTATIONS=true` and the repository is
    public, publish GitHub artifact provenance and SBOM attestations for the
    checksum-bound release artifacts;
13. create GitHub Release assets with checksums, metadata checksums, release
    notes, SBOM, and a release manifest;
14. retain normalized GitHub Release metadata as workflow release evidence at
    `artifacts/release/github-release.json` after byte-for-byte asset
    verification, and bind it plus any attestation record with
    `artifacts/release/retained-evidence-checksums.sha256`. The release
    manifest records GitHub Release channel data as candidate/archive inventory;
    `github-release.json` owns post-create GitHub Release facts only inside
    retained workflow evidence, not as a public release asset.

When `PROOFKIT_REQUIRE_VERIFIED_RELEASE_TAG=true`, the readiness gate also
requires `GITHUB_REF_PROTECTED=true` and a GitHub-verified signed annotated tag.
That hardening mode is enabled only after the repository has an admitted tag
protection and signing-key policy; otherwise it would be an unreachable release
precondition rather than a proof.

## Post-Publish Evidence

After publish, record the registry identity from npm:

```bash
npm view @research-engineering/agentic-proofkit@<version> version dist.tarball dist.integrity dist.shasum repository.url license --json
```

The release workflow records PyPI identity through:

```bash
npm run pypi:registry
```

The evidence must distinguish:

- local candidate tarball facts;
- local candidate wheel facts;
- post-publish npm registry facts;
- optional post-publish PyPI registry facts;
- Trusted Publisher identity tuples for workflow-published npm/PyPI channels;
- GitHub Release archive publication facts from retained workflow evidence
  `github-release.json`;
- retained workflow evidence checksum closure from
  `retained-evidence-checksums.sha256`;
- GitHub Release candidate asset inventory from `release-manifest.json`;
- SBOM inventory facts;
- optional GitHub artifact attestation facts;
- planned but unpublished channel facts;
- consumer install facts.

These evidence classes are not interchangeable.

## Rollback

Published npm versions are immutable. Rollback means pinning consumers back to
the previous admitted version and recording that consumer migration evidence.
It does not delete the published package or mutate release assets.

## Public Source Provenance

Public-source provenance may be claimed only when the source repository is
intentionally public and the release workflow publishes a later version from
that public source. A release from a private source repository may be a valid
package release, but it is not public-source provenance.

Artifact attestation workflow wiring is not the same as completed provenance.
When attestation storage is enabled and the repository visibility supports
provider attestations, the release workflow must complete the attestation job
before the GitHub Release asset job can publish archive assets. Provider-side
attestation evidence becomes release evidence only after that job runs with
attestation storage enabled and records the result. User-owned private
repositories currently cannot store GitHub artifact attestations; in that state
the release may still publish package and archive evidence, but it must not
claim provider artifact attestation or public-source provenance.

## Non-Claims

This process does not:

- approve adoption in a consuming repository;
- execute consumer-native witnesses;
- prove consumer proof freshness;
- approve merge, rollout, deployment, or production readiness;
- make GitHub Release assets package-manager dependency authority;
- make SBOM inventory vulnerability absence or license approval;
- make optional attestation wiring public-source provenance before a qualifying
  public-source tag release exists.
