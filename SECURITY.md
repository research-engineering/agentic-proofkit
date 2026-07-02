# Security Policy

## Supported Versions

No public source-based release is claimed by this repository state yet.
Supported versions will be named after a reviewed public release exists.

## Reporting A Vulnerability

Private vulnerability intake is not claimed by this repository layer. Before a
public release, maintainers must enable GitHub private vulnerability reporting
or publish another private reporting channel.

Until a private channel is available, do not open a public issue with exploit
details.

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
