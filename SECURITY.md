# Security Policy

Warden is a defensive security tool. We hold ourselves to the same bar we ask of the projects we
scan — including the third vow of the [Warden's Oath](README.md#-the-wardens-oath): *we work in
the open, but a vulnerability is disclosed responsibly first.*

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities in Warden itself.**

Instead, report privately through **GitHub Security Advisories** —
[open a private report](https://github.com/cinfikircom/warden/security/advisories/new). This keeps
the disclosure between you and the maintainers until a fix ships.

Please include:

- affected version / commit,
- a description of the issue and its impact,
- reproduction steps or a proof-of-concept (a minimal repo or diff is ideal),
- any suggested remediation.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | within **72 hours** |
| Initial assessment & severity triage | within **7 days** |
| Fix or mitigation plan | depends on severity; we'll keep you updated |
| Public disclosure / credit | coordinated with you after a fix ships |

We will credit reporters in the release notes unless you prefer to remain anonymous.

## Scope

In scope — the Warden engine, CLI, skill bridge, and the Warden Knight dashboard/backend in this
repository, including:

- ways to make Warden send an **active** request without the authorization gate being open,
- **secret leakage** into any report, JSON, SARIF or log (secrets must always be masked),
- a path that lets the remediation flow **commit to `main`** or bypass the PR/verification gate,
- command injection / path traversal in the CLI, bridge, or `server.mjs`,
- auth bypass in the dashboard backend.

Out of scope — findings produced *about a scanned project* (that's the tool working as intended),
issues that require a already-compromised host, and the local dev `server.mjs` being reachable when
you deliberately expose it to a public network (it is documented as localhost-only).

## Supported versions

Warden is pre-1.0 and moves fast; security fixes land on the latest `main` and the most recent
tagged release. Please test against `main` before reporting.

Thank you for helping keep the realm safe. ⚔️
