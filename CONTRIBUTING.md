# Contributing to Warden

Welcome to the Watch. ⚔️ Whether you're adding a check, teaching Warden a new stack, fixing a
false positive, or polishing the Knight — thank you. This guide gets you productive fast.

## The one rule that matters

Everything in Warden bends to the [Warden's Oath](README.md#-the-wardens-oath). A contribution is
accepted when it keeps all three vows:

1. **Measured, not claimed** — posture and status must derive from real evidence (a scan, a
   fingerprint, a delta), never a hardcoded or manually-set state.
2. **Zero damage** — nothing Warden runs may mutate a scanned project's production state; active
   tests stay behind the authorization gate and are non-destructive.
3. **In the open** — secrets are masked at the source; commands and requests are auditable.

If a change would break one of these, it needs a very good reason and an explicit discussion first.

## Project shape

A pnpm monorepo, build-free on Node 22 via `tsx`:

| Package | What lives here |
|---|---|
| `packages/warden-core` | Engine: finding model, detectors, modules, report generator, risk engine, masking, audit. |
| `packages/warden-cli`  | `warden init · scan · pentest · report · monitor · prompts`. |
| `packages/warden-skill`| Claude Code Skill bridge + the automated-remediation procedure. |
| `security-knight/`     | The Warden Knight dashboard (zero-dependency ES-module widget + local dev backend). |

## Getting started

```bash
pnpm install
pnpm -r typecheck        # exactOptionalPropertyTypes is on — keep it green
pnpm -r test             # 214+ tests; add tests for what you change
pnpm warden scan --target .   # dogfood on this repo
pnpm knight              # launch the dashboard
```

## Adding a new check

1. Add the detector/rule in the relevant module under `packages/warden-core/src/`.
2. Give every finding a **CVSS v4** base score, standard mappings (OWASP/ASVS/CIS/ISO where they
   apply), evidence (`file:line` or command), and a remediation recommendation.
3. Add a **fixture** that the check fires on, plus (ideally) a safe fixture it must *not* fire on
   (false-positive guard).
4. Add a test in the module's `test/` directory. See `packages/warden-core/test/` for the style.

## Adding a stack

A new language/framework is usually one `StackDetector` + optional schema analyzer + declarative
SAST rules. Open an issue first so we can point you at the closest existing detector to copy.

## Pull requests

- Branch from `main`; **never** commit directly to `main`.
- Keep PRs focused; one concern per PR reads better and merges faster.
- `pnpm -r typecheck && pnpm -r test` must pass. Add or update tests for behavior you change.
- Match the surrounding code's style, naming, and comment density — no new runtime dependencies
  (the zero-dependency promise is load-bearing for the Knight widget).
- Fill in the PR template (what / why / how verified).

## Reporting bugs & ideas

- **Bug in a scan result** (false positive/negative) → open a Bug report with the fixture or a
  minimal repro.
- **New check / stack / feature** → open a Feature request; describe the risk it catches.
- **A vulnerability in Warden itself** → do **not** open a public issue; follow [`SECURITY.md`](SECURITY.md).

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). Be the kind of sworn
brother you'd want beside you on the Wall.
