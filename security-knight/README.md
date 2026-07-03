<div align="center">

# ⚔️ Warden Knight <sub>(Security Knight)</sub>

> Part of the **[Warden](../README.md)** security platform — the live, gamified dashboard.
> _Warden Scan finds what to fix; the Knight proves your defenses hold._

### Your bot & abuse defense — a knight that arms up the more you harden it.

**A gamified, _measured_ security-posture dashboard.** Every defense you ship is a piece of armor.
Equip and _prove_ it, and your knight grows from a plain recruit into a fully-armored champion.
Miss one, and the panel raises the alarm — and shows you exactly how to fix it.

<img src="assets/knight-lv6.png" width="300" alt="Security Knight — fully armored" />

[![node](https://img.shields.io/badge/node-%E2%89%A522-339933)]()
[![deps](https://img.shields.io/badge/dependencies-none-brightgreen)]()
[![license](https://img.shields.io/badge/license-MIT-blue)]()
[![framework](https://img.shields.io/badge/framework-agnostic-8a5cf6)]()

</div>

---

## The idea

Security dashboards usually show what you _claim_ is protected — a checklist of green ticks that
quietly lie the moment a defense breaks. **Security Knight shows what's actually _measured_.**

Each defense (honeypot, signed timestamps, rate-limits, silent bot handling, …) is an **armor piece**
on a living knight. The knight’s power is computed from real signals — runtime self-checks and a
black-box **attack harness** that actually tries to break each defense. A defense you can’t prove
shows up as a **translucent “ghost” armor** worth less; a defense that breaks makes the armor **drop**
and fires an alarm. Fixing a weakness is a **quest** with copy-paste steps.

> It can’t show a green tick it hasn’t earned.

## The knight grows as you harden

The character is generated art (via Magnific / Nano Banana Pro) — one consistent hero across a
6-stage progression. Your measured score picks the stage:

| Lv 1 | Lv 2 | Lv 3 | Lv 4 | Lv 5 | Lv 6 |
|:---:|:---:|:---:|:---:|:---:|:---:|
| <img src="assets/knight-lv1.png" width="110"/> | <img src="assets/knight-lv2.png" width="110"/> | <img src="assets/knight-lv3.png" width="110"/> | <img src="assets/knight-lv4.png" width="110"/> | <img src="assets/knight-lv5.png" width="110"/> | <img src="assets/knight-lv6.png" width="110"/> |
| Gambeson recruit | + leather & buckler | + leather cuirass | + steel plate & helm | + full plate & shield | Legendary champion |

## Features

- 🛡️ **Measured posture, not claimed** — power derives from self-checks + attack tests, not a flag.
- 👻 **Ghost armor** — active-but-unproven defenses render translucent and score only partial credit.
- 💥 **Drift alarm** — if a defense stops working, its armor drops and the panel screams.
- ⚔️ **Attack harness** — black-box bot simulation (timing side-channel, rate-limit, enum-parity, honeypot/replay).
- 🎯 **Friendly-fire meter** — measures whether your defense is silently blocking _real users_ (the invisible cost of over-blocking).
- 🤖 **Agent loop** — “Equip” queues a remediation job; an agent applies the fix, runs the attack test, and promotes the armor.
- 🔒 **Hardened backend** — token auth, agent-only mutations, audit log, input validation, CORS lockdown.
- 🧩 **Framework-agnostic & zero-dependency** — drop the ES-module widget into any app; Next.js routes included.
- ✅ **CI regression guard** — a verified defense can never silently regress; CI fails if armor drops.

## Quick start

```bash
cp .env.example .env          # set SK_ADMIN_TOKEN + SK_AGENT_TOKEN
node server.mjs               # → http://127.0.0.1:8137/index.html
```

Run the verification loop (turns claimed armor into _measured_ armor):

```bash
node verify-cycle.mjs --attack attack-results.json   # self-check + attack → verification.json
```

Run the attack harness against **your own** staging (authorization-gated):

```bash
node attack-harness.mjs --base https://staging.example.com \
  --request /api/auth/request-code --authorize --allow staging.example.com --ack-emails
```

## How it works

```
 Panel "Equip"  →  POST /api/security/equip  →  job queue (state/jobs.jsonl)
                                                     │
                                    Agent runner (see AGENT-RUNNER.md)
                                                     ▼
        1) apply the fix in the target repo (as a PR)
        2) run attack-harness against staging  (authorization-gated, non-destructive)
        3) verify-cycle → POST /api/security/verification  (agent token)
                                                     ▼
             Panel re-reads posture → the armor turns solid, the knight levels up
```

- **Measured score** = Σ(weight × factor): `verified` 1.0 · `claimed` (ghost) 0.6 · `open`/`failed` 0.
- The panel shows both **measured** and **claimed** scores — the gap is your “unproven debt”.
- **Friendly-fire**: a positive-path test ensures a legitimate user still gets through. Silent bot
  defenses are great — but that same silence hides real users you might be dropping. Measure it.

## Files

| File | Role |
|---|---|
| `index.html` · `knight.js` · `knight.css` | The widget (zero-dependency ES module). |
| `posture.js` | **Single edit point** — the armor registry (layers + SVG fallback + quests). |
| `assets/knight-lv1..6.png` | Generated knight art (the progression stages). |
| `server.mjs` | Local dev backend: posture / equip / verify / metrics + job queue + auth + audit. |
| `attack-harness.mjs` | Black-box bot-simulation attack & test engine (authorization-gated). |
| `verify-cycle.mjs` | Self-check + attack → `verification.json` (produces the _measured_ posture). |
| `ci-check.mjs` | Regression guard — fails CI if a verified defense dropped. |
| `api-example/nextjs-routes.ts` | Production API routes (session auth + pluggable store). |
| `AGENT-RUNNER.md` · `GO-LIVE.md` | Autonomy contract & production checklist. |

## Add your own armor

Adding a new defense = **one object** in `posture.js` — no other file changes:

```js
{ key:"csrf", icon:"🧿", name:"Double Seal", realName:"CSRF token",
  status:"open", weight:6, z:9, desc:"Double-submit CSRF token on state-changing requests.",
  svg:`<path d="M.." fill="#.."/>`,           // armor piece drawn when active (SVG fallback)
  quest:{ why:"...", steps:["..."], acceptance:["..."] } }
```

## Integrate (Next.js / React)

```tsx
"use client";
import { useEffect, useRef } from "react";
export default function SecurityKnight() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    (async () => {
      const [{ mountSecurityKnight }, { POSTURE }] = await Promise.all([
        import("@/security-knight/knight.js"),
        import("@/security-knight/posture.js"),
      ]);
      mountSecurityKnight(ref.current!, { posture: POSTURE, endpoint: "/api/security/posture", mode: "live" });
    })();
  }, []);
  return <div ref={ref} />;
}
```

Copy `api-example/nextjs-routes.ts` into `app/api/security/*`, wire `requireAdmin()` to your auth,
and **put the panel + API behind admin authentication**. See `GO-LIVE.md` for the full checklist.

## Security & scope

- The attack harness runs **only against targets you own** (attestation + allow-list + email
  acknowledgement) — non-destructive, low-volume. No DoS, no brute-force.
- Backend endpoints require auth; `POST /status`/`/verification` are **agent-token only**.
- This tool is for **authorized self-assessment and defense**.

## Roadmap

- [x] Measured posture + ghost armor + drift alarm
- [x] Friendly-fire (false-positive) measurement
- [x] CI regression guard
- [x] Realistic generated knight art (6-stage progression)
- [ ] Multi-endpoint fronts (one knight per protected route)
- [ ] Live attack-spike auto-escalation (enable challenge, then relax)
- [ ] Edge/WAF signals (JA4, IP reputation)

> UI strings are currently Turkish (i18n-ready); the engine and API are language-neutral.

## License

MIT
