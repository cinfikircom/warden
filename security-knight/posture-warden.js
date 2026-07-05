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
// Şövalyenin her zaman görünen çekirdeği (çıplak acemi + temel kılıç) — zırh parçaları
// bunun üzerine eklenir (bkz. knight.js:buildKnightSVG).
const BASE_SVG = /*svg*/`
  <g id="knight-base">
    <rect x="60" y="150" width="13" height="46" rx="5" fill="#8a7660"/>
    <rect x="77" y="150" width="13" height="46" rx="5" fill="#8a7660"/>
    <rect x="58" y="192" width="17" height="9" rx="3" fill="#5a4a38"/>
    <rect x="75" y="192" width="17" height="9" rx="3" fill="#5a4a38"/>
    <rect x="42" y="90" width="12" height="48" rx="6" fill="#9c866a"/>
    <rect x="96" y="90" width="12" height="48" rx="6" fill="#9c866a"/>
    <path d="M54 86 Q75 80 96 86 L100 150 Q75 158 50 150 Z" fill="#a98f6e"/>
    <circle cx="75" cy="60" r="16" fill="#e8c9a0"/>
    <path d="M60 56 Q75 40 90 56 L90 50 Q75 38 60 50 Z" fill="#6b4f36"/>
    <!-- temel kılıç (sağ el) -->
    <g id="base-sword"><rect x="112" y="82" width="6" height="56" rx="2" fill="#d7ddE6" stroke="#9aa2b0"/>
      <rect x="105" y="134" width="20" height="5" rx="2" fill="#8a6216"/></g>
  </g>`;

const RANKS = [
  { min:0,  lv:1, title:"Acemi Nöbetçi" },
  { min:21, lv:2, title:"Çırak Muhafız" },
  { min:41, lv:3, title:"Kalkan Eri" },
  { min:61, lv:4, title:"Muhafız Şövalyesi" },
  { min:81, lv:5, title:"Kale Kumandanı" },
  { min:96, lv:6, title:"Efsane Muhafız" },
];

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
  base: BASE_SVG,
  ranks: RANKS,
  layers: [
    { key:"A", kind:"warden", icon:"🏰", name:"Deployment Bulwark", realName:"Parity & Deployment", weight:10, z:6, status:"open",
      desc:"Prod drift, destructive migrations, env parity, backups, TLS expiry.", quest:q("Deployment/Parity") },
    { key:"B", kind:"warden", icon:"🗡️", name:"Code Blade", realName:"SAST — code security", weight:18, z:9, status:"open",
      desc:"Secrets, injection (SQL/SSRF/SSTI…), weak crypto, IDOR, deserialization.", quest:q("Code (SAST)") },
    { key:"D", kind:"warden", icon:"📜", name:"Charter of Law", realName:"Compliance & maturity", weight:10, z:8, status:"open",
      desc:"Observability, secret management, CI/CD, PCI-DSS, GDPR/KVKK.", quest:q("Compliance") },
    { key:"CLOUD", kind:"warden", icon:"☁️", name:"Sky Ward", realName:"Cloud / IaC", weight:12, z:7, status:"open",
      desc:"Public buckets, IAM wildcards, open security groups, public DBs (Terraform).", quest:q("Cloud/IaC") },
    { key:"K8S", kind:"warden", icon:"⚓", name:"Fleet Anchor", realName:"Kubernetes", weight:8, z:6, status:"open",
      desc:"Privileged/root containers, :latest images, plaintext secrets, ingress TLS.", quest:q("Kubernetes") },
    { key:"FE", kind:"warden", icon:"🖥️", name:"Glass Aegis", realName:"Frontend security", weight:7, z:9, status:"open",
      desc:"XSS sinks, token-in-localStorage, weak CSP, prod source maps.", quest:q("Frontend") },
    { key:"AI", kind:"warden", icon:"🤖", name:"Oracle Ward", realName:"AI / LLM security", weight:7, z:8, status:"open",
      desc:"Embedded LLM keys, prompt-injection surface, system-prompt leakage.", quest:q("AI/LLM") },
    { key:"C", kind:"warden", icon:"🛡️", name:"Live Rampart", realName:"DAST — live checks", weight:10, z:9, status:"open",
      desc:"Exposed files, security headers/TLS, open admin, rate-limit, cookies (gated).", quest:q("Live/DAST") },
  ],
  relics: [],
  metrics: { "Findings": "–", "P0": "–", "P1": "–", "Max CVSS": "–", "Aktif tehdit": "—", breakdown: {} },
};
