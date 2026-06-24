# Warden

> **Portable, defensive production-readiness & security audit tool.**
> Point it at any project — Warden statically analyzes the code, config, dependencies and IaC
> (and, *only with explicit authorization*, the running environment), lists everything
> **missing / broken / risky** ranked by severity with **evidence**, and emits a copy‑paste
> **Claude Code remediation playbook** for every P0/P1 finding.

[![tests](https://img.shields.io/badge/tests-116%20passing-brightgreen)]()
[![node](https://img.shields.io/badge/node-%E2%89%A522-339933)]()
[![license](https://img.shields.io/badge/license-MIT-blue)]()

🇹🇷 [Türkçe README](docs/README.tr.md) · 📚 [Full check catalog](docs/CHECKS.md)

---

## ⛔ READ FIRST — Security & Authorization Principles (binding)

Warden has dual‑use capabilities (active/DAST tests). These rules are enforced **in code**:

1. **Passive / read‑only by default.** No active test ever runs unless explicitly enabled.
2. **Authorization Gate.** Active/DAST tests run *only* when a valid `warden.authz.yml` exists in the
   project root **and** contains:
   - `owner_attestation: true` — "I own these assets / I am authorized to test them"
   - `authorized_targets:` — allow‑list; active tests hit **only** these hosts/domains/IPs
   - `authorized_by:` and `date:` — audit trail

   Missing or incomplete file → Warden stays **passive**. No request ever leaves the allow‑list.
3. **Non‑intrusive.** Even active tests are rate‑limited, non‑destructive and low‑volume.
   **No DoS, no brute‑force, no exploitation, no detection evasion.**
4. **Secret masking at the source.** Any token/password/URL is written to reports as `***`;
   the full value is **never** serialized (report, JSON, SARIF, logs — all masked).
5. **Audit log.** Every command/request Warden runs is written to `warden-report/warden-run.log`.
6. **No production mutation.** Commands stay at inspect/diff/dry‑run level — no deploy/migrate/restart.

> Warden is for authorized self‑assessment, CTF, education and defense. Unauthorized use is prohibited
> and is the user's responsibility.

---

## What it does

- **Module A — Parity & Deployment** (passive): git drift, destructive migrations (Prisma/Django/Laravel/EF Core/Go), runtime freshness, **generic volume‑parity engine**, `.env` ↔ `.env.example`, backup/restore + TLS expiry, external webhooks.
- **Module B — SAST** (passive): hardcoded secrets, vulnerable dependencies (`npm/pnpm audit`), weak crypto (MD5/SHA1/ECB/CryptoJS), JWT‑in‑localStorage, IDOR, SQL/command/eval injection, CORS, frontend XSS sinks — across **TS/JS, Python, PHP, C#, Go**.
- **Module D — Compliance** (passive): observability, secret management, CI/CD, data protection, plus **PCI‑DSS 4.0** (CVV/PAN scanning + checklist) and **Privacy / GDPR‑KVKK** checklist.
- **Module CLOUD** (passive, Terraform): public S3/GCS, IAM wildcards, open security groups/firewalls, public RDS/Cloud SQL, Azure public storage, Cloudflare SSL mode.
- **Module K8S** (passive): privileged/root containers, `:latest` images, plaintext secret env, ingress without TLS.
- **Module AI** (passive): embedded LLM API keys, prompt‑injection surface, system‑prompt leakage.
- **Module C — DAST** (active, **authorization‑gated**): exposed files (`/.env`, `/.git`, swagger), security headers + TLS, open admin panels, rate‑limit probing, cookie flags, sensitive port inventory.

Every finding carries a **CVSS v4** base score + exploitability, standard mappings
(**OWASP Top 10 / ASVS / API / CIS Benchmark / ISO 27001:2022**), evidence (`file:line` or command), and a remediation prompt.

## Architecture

A pnpm monorepo, runs build‑free on Node 22 (`tsx`):

| Package | Responsibility |
|---------|----------------|
| `packages/warden-core` | Stack‑agnostic engine: finding model, authorization gate, detectors, modules, report generator, risk engine, secret masking, audit log. |
| `packages/warden-cli`  | `warden init · scan · pentest · report · monitor`. |
| `packages/warden-skill`| Claude Code Skill bridge (`SKILL.md`). Cursor / Windsurf / VS Code / GitHub Actions also consume the core. |

## Quick start

```bash
pnpm install

# Passive audit (default; never sends an active request)
pnpm warden scan --target <path-to-project>

# Install Warden into a project as a Claude Code skill
pnpm warden init --target <path-to-project>

# Continuous monitoring (periodic re-scan + before/after delta)
pnpm warden monitor --target <path> --interval 1800

# Active/DAST — only after opening the authorization gate
cp warden.authz.example.yml warden.authz.yml   # fill in owner_attestation / authorized_targets / authorized_by / date
pnpm warden pentest --target <path>
```

### Output (`warden-report/`)

| File | Contents |
|------|----------|
| `report.md` | Executive summary, scoreboard, before/after delta, severity‑ranked findings |
| `findings.json` | Machine‑readable (CI gate); stable `id` + `fingerprint`, scoreboard, checklists, delta |
| `findings.sarif` | SARIF 2.1.0 → GitHub Code Scanning / Azure DevOps |
| `remediation-playbook.md` | Copy‑paste **Claude Code prompt** per P0/P1 (risk · standard · locations · steps · acceptance) |
| `parity-report.md` | Module A layer table + **Parity Risk Score** |
| `compliance-report.md` | PCI‑DSS / Privacy / OWASP ASVS / CIS / ISO 27001 checklists (✔/⚠/✖/–) |
| `history.jsonl` | Per‑run trend for the delta engine |
| `warden-run.log` | Audit trail of every command/request |

Severity: **P0** (production blocker / actively exploitable) · **P1** (before first customer) · **P2** (architectural debt) · **P3** (scale/polish).

## The value loop

```
warden init  →  scan  →  hand remediation-playbook.md prompts to an agent  →  fix  →  re-scan
                                                                                        │
            before/after delta proves what got fixed, what's new, what remains  ◀───────┘
```

## CI / GitHub Action

Warden ships a composite action (`action.yml`) that runs a passive scan and uploads SARIF:

```yaml
permissions:
  contents: read
  security-events: write   # required for SARIF upload
jobs:
  warden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: <org>/warden@v1
        with:
          target: "."
          fail-on: "P0"          # fail the job on any P0 finding
          upload-sarif: "true"   # findings.sarif → Code Scanning
```

Local equivalent of the gate: `warden scan --fail-on P0` (exit code 1 on P0+).

## Supported stacks

**Languages/frameworks:** Node/TypeScript (Prisma, Drizzle, Express, Next, NestJS), Python/Django, PHP/Laravel, .NET/ASP.NET (EF Core), Go.
**Infra:** Docker/Compose, Kubernetes manifests, Terraform (AWS/Azure/GCP/Cloudflare).
Adding a stack = one `StackDetector` + optional schema analyzer + declarative SAST rules.

## Status

Actively developed. 116 tests passing; 10 vulnerable‑by‑design fixtures. See [`docs/CHECKS.md`](docs/CHECKS.md)
for the full, per‑check status catalog.

## License

MIT
