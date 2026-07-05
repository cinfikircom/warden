---
name: "🐛 Bug report"
about: A crash, a wrong scan result (false positive/negative), or broken behavior
title: "[bug] "
labels: bug
---

<!--
⛔ Found a vulnerability in Warden ITSELF? Do not file it here — follow SECURITY.md (private).
This template is for bugs in how Warden runs or what it reports.
-->

## What happened

<!-- Clear description. If it's a scan result: is it a FALSE POSITIVE (fired but shouldn't) or a
FALSE NEGATIVE (should have fired but didn't)? Which check/module (e.g. B3, CLOUD)? -->

## Minimal reproduction

<!-- The smaller the better. A tiny repo, a code snippet, or a fixture that triggers it.
Include the exact command you ran, e.g. `pnpm warden scan --target . --module B`. -->

## Expected vs actual

- **Expected:**
- **Actual:**

## Environment

- Warden version / commit:
- Node version:
- OS:

## Logs / output

<!-- Relevant part of the report or terminal output. REMOVE any real secrets — Warden masks them,
but paste-throughs may not. -->
