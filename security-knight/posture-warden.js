/**
 * WARDEN PROFILE — armor registry for a whole Warden Scan (Phase 2 bridge).
 * =========================================================================
 * Here each armor piece = a Warden SCAN DIMENSION (SAST, Cloud, Compliance, …),
 * not a bot-defense layer. `warden-bridge.mjs` reads Warden's findings.json and fills
 * statuses + verification + metrics, so the same Knight widget visualizes the ENTIRE
 * codebase security posture. The realistic knight art (level-based) is reused as-is.
 *
 * status ∈ active | partial | open | optional  ·  verified when Warden actually scanned it clean.
 * =========================================================================
 */
import { POSTURE } from "./posture.js"; // reuse base SVG + rank thresholds

const q = (dim) => ({
  why: `Warden found issues in ${dim}. Unfixed weaknesses here weaken the whole guard.`,
  steps: [
    "Run `warden scan --target <project>` (or in CI).",
    "Open `warden-report/remediation-playbook.md` and fix the P0/P1 items for this dimension.",
    "Re-scan — the before/after delta proves the fix; this armor turns solid.",
  ],
  acceptance: ["No P0/P1 findings remain in this dimension → armor equipped & verified"],
});

export const WARDEN_POSTURE = {
  base: POSTURE.base,
  ranks: POSTURE.ranks,
  layers: [
    { key:"A", icon:"🏰", name:"Deployment Bulwark", realName:"Parity & Deployment", weight:10, z:6,
      desc:"Prod drift, destructive migrations, env parity, backups, TLS expiry.", quest:q("Deployment/Parity") },
    { key:"B", icon:"🗡️", name:"Code Blade", realName:"SAST — code security", weight:18, z:9,
      desc:"Secrets, injection (SQL/SSRF/SSTI…), weak crypto, IDOR, deserialization.", quest:q("Code (SAST)") },
    { key:"D", icon:"📜", name:"Charter of Law", realName:"Compliance & maturity", weight:10, z:8,
      desc:"Observability, secret management, CI/CD, PCI-DSS, GDPR/KVKK.", quest:q("Compliance") },
    { key:"CLOUD", icon:"☁️", name:"Sky Ward", realName:"Cloud / IaC", weight:12, z:7,
      desc:"Public buckets, IAM wildcards, open security groups, public DBs (Terraform).", quest:q("Cloud/IaC") },
    { key:"K8S", icon:"⚓", name:"Fleet Anchor", realName:"Kubernetes", weight:8, z:6,
      desc:"Privileged/root containers, :latest images, plaintext secrets, ingress TLS.", quest:q("Kubernetes") },
    { key:"FE", icon:"🖥️", name:"Glass Aegis", realName:"Frontend security", weight:7, z:9,
      desc:"XSS sinks, token-in-localStorage, weak CSP, prod source maps.", quest:q("Frontend") },
    { key:"AI", icon:"🤖", name:"Oracle Ward", realName:"AI / LLM security", weight:7, z:8,
      desc:"Embedded LLM keys, prompt-injection surface, system-prompt leakage.", quest:q("AI/LLM") },
    { key:"C", icon:"🛡️", name:"Live Rampart", realName:"DAST — live checks", weight:10, z:9,
      desc:"Exposed files, security headers/TLS, open admin, rate-limit, cookies (gated).", quest:q("Live/DAST") },
  ],
  relics: [],
  metrics: { "Findings": "–", "P0": "–", "P1": "–", "Max CVSS": "–", "Aktif tehdit": "—", breakdown: {} },
};
