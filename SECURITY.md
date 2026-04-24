# Security policy

## Supported versions

Security fixes are applied to:

- The default development branch (`master`), and
- The **latest** published release line (the most recent `vX.Y.Z` tag).

Older release tags may not receive backports except for critical issues at
maintainer discretion. If you depend on an older line, plan upgrades to a
supported version or coordinate with maintainers via a private report.

**Out of scope for “supported” guarantees:** fork-only tags, experimental
builds, or images not published from this repository’s documented release
process.

## How to report a vulnerability

**Do not** open a public GitHub issue for an undisclosed security vulnerability.

Please report privately using **[GitHub Security Advisories](https://github.com/freshworks/redis-operator/security/advisories/new)**
(**Security** tab → **Report a vulnerability**) so the maintainers can assess
and coordinate a fix before public disclosure.

If you cannot use GitHub’s private reporting flow, contact repository
maintainers through an organization-approved private channel (see
[MAINTAINERS.md](MAINTAINERS.md)) and ask to route the report securely.

## Response expectations

- **Initial triage:** we aim to acknowledge reports within **7 calendar days**.
  Complex reports may need more time for reproduction.
- **Fix timeline:** depends on severity, impact, and release coordination; we
  will communicate realistic expectations in the advisory thread.

These timelines are goals, not guarantees, but we treat security reports
seriously.

## Scope

**In scope**

- The operator controller binary and its default configuration as shipped in
  this repository
- The published container image(s) built from this repository’s release
  process
- The Helm chart defaults under `charts/redisoperator` when used as documented

**Out of scope**

- Vulnerabilities in Redis, Sentinel, or base container images you choose to run
  (report those to the respective vendors or image maintainers)
- Misconfiguration of Kubernetes clusters, RBAC, or network policies
- Issues in third-party Helm repositories or mirrors not controlled by this
  project

## Disclosure

We follow coordinated disclosure: details are published (for example via a
GitHub Security Advisory or release notes) after a fix is available, unless a
reporter and maintainers agree on a different timeline for a specific case.

## Automated checks (supply chain)

Pull requests may run **dependency review** when the repository has dependency
data enabled. That complements manual review and does not replace reporting
suspected vulnerabilities through the private channels above.

## Security-related configuration

Hardening guidance for deploying the operator in production belongs in
documentation and examples; this file focuses on vulnerability reporting and
supported versions.
