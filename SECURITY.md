# Security Policy

## Supported Versions

Supported versions are named only after a reviewed public release has
artifact-closed release assets, registry identity, and checksum manifests.
The current source tree may be ahead of the latest supported package version.

## Reporting A Vulnerability

Use GitHub Private Vulnerability Reporting for this repository. If GitHub
returns an unavailable route, open a public issue that requests a private
security contact path and includes no exploit details, credentials, private
data, or step-by-step reproduction.

Do not open a public issue with exploit details.

Do not include live credentials, private keys, access tokens, or third-party
secrets in reports. Use redacted examples and describe how to reproduce the
issue with synthetic data.

## Security Boundary

Proofkit is intended to validate and render caller-owned inputs after those
runtime surfaces are imported. It does not execute native witnesses,
authenticate receipt producers, read implicit repository state, publish
artifacts, approve merge, approve rollout, or decide proof freshness.

Security-sensitive findings usually belong to one of these classes:

- command or argument injection in a Proofkit CLI path;
- unsafe file path, JSON, or JSON Pointer admission;
- secret leakage in reports, rendered views, logs, package metadata, or
  diagnostics;
- incorrect trust-boundary wording that could make consumers treat advisory
  evidence as merge-satisfying proof;
- package artifact or release workflow behavior that changes installed bytes or
  provenance claims.

## Disclosure And Fix Process

1. Maintainers acknowledge the report and identify the affected surface.
2. The fix is developed with a targeted regression proof.
3. A patched version is released only through the documented release process
   after that process exists in this repository.
4. The advisory or release notes state impact, affected versions, fixed
   version, and any required consumer action.

## Non-Claims

This policy does not guarantee a response SLA, third-party dependency support,
consumer repository security coverage, or production readiness of any consuming
system.
