import type { Finding } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";

/**
 * Risk skorlama motoru (Faz 5): her bulguya CVSS v4 taban skoru (0–10) + exploitability.
 *
 * NOT: Bu, tam CVSS v4 vektör hesaplayıcısı DEĞİLDİR; bulgu sınıfına göre kalibre edilmiş,
 * gerçekçi taban skorlardan oluşan bir EŞLEME'dir (CVSS v4 ölçeğiyle uyumlu). Bir modül kendi
 * `cvss` değerini verirse o korunur. Amaç: önceliklendirme + SARIF security-severity tutarlılığı.
 */

export type Exploitability = "high" | "medium" | "low";

interface RiskEntry {
  readonly cvss: number;
  readonly exploitability: Exploitability;
}

/** id ön-ekine göre (en spesifik). Üstten alta ilk eşleşen kazanır. */
const BY_PREFIX: ReadonlyArray<readonly [string, RiskEntry]> = [
  ["B6-sql-concat", { cvss: 9.8, exploitability: "high" }],
  ["B6-command-injection", { cvss: 9.8, exploitability: "high" }],
  ["B6-eval", { cvss: 8.8, exploitability: "high" }],
  ["B1-aws-key", { cvss: 9.1, exploitability: "high" }],
  ["B1-private-key", { cvss: 9.1, exploitability: "high" }],
  ["B1-token-literal", { cvss: 8.6, exploitability: "high" }],
  ["B1-hardcoded-secret", { cvss: 7.5, exploitability: "medium" }],
  ["B1-committed-dotenv", { cvss: 7.5, exploitability: "medium" }],
  ["B3-weak-hash", { cvss: 5.9, exploitability: "medium" }],
  ["B3-ecb", { cvss: 5.9, exploitability: "medium" }],
  ["B3-cryptojs", { cvss: 5.9, exploitability: "medium" }],
  ["B3-insecure-random", { cvss: 6.5, exploitability: "medium" }],
  ["B5-idor-candidate", { cvss: 6.5, exploitability: "medium" }],
  ["B7-cors-wildcard", { cvss: 5.4, exploitability: "medium" }],
  ["B9-stack-in-response", { cvss: 4.3, exploitability: "medium" }],
  ["B4-jwt-long-ttl", { cvss: 4.8, exploitability: "low" }],
  ["FE-jwt-localstorage", { cvss: 6.5, exploitability: "medium" }],
  ["FE-dangerous-html", { cvss: 6.1, exploitability: "medium" }],
  ["FE-vue-vhtml", { cvss: 6.1, exploitability: "medium" }],
  // Parity
  ["A2-destructive-migration", { cvss: 7.1, exploitability: "low" }],
  ["A1-production-drift", { cvss: 5.0, exploitability: "low" }],
  ["A4-volume-mismatch", { cvss: 5.3, exploitability: "low" }],
  ["A5-cert-expiry", { cvss: 7.5, exploitability: "high" }],
  // DAST
  ["C1-exposed", { cvss: 7.5, exploitability: "high" }],
  ["C3-open-admin", { cvss: 9.1, exploitability: "high" }],
  ["C2-cert-expired", { cvss: 7.5, exploitability: "high" }],
  ["C2-weak-tls", { cvss: 7.4, exploitability: "medium" }],
  ["C2-header", { cvss: 4.3, exploitability: "medium" }],
  ["C6-cookie", { cvss: 5.4, exploitability: "medium" }],
  ["C4-no-rate-limit", { cvss: 5.3, exploitability: "medium" }],
  // Compliance
  ["D7-cvv-storage", { cvss: 9.1, exploitability: "medium" }],
  ["D7-pan-storage", { cvss: 7.5, exploitability: "medium" }],
  // Kubernetes
  ["K8S-privileged", { cvss: 9.9, exploitability: "high" }],
  ["K8S-plain-secret", { cvss: 7.5, exploitability: "medium" }],
  ["K8S-root", { cvss: 6.0, exploitability: "low" }],
  ["K8S-image-tag", { cvss: 4.0, exploitability: "low" }],
  ["K8S-ingress-no-tls", { cvss: 5.9, exploitability: "medium" }],
  // Cloud / IaC
  ["CLOUD-AWS-s3-public", { cvss: 9.1, exploitability: "high" }],
  ["CLOUD-AWS-iam-wildcard", { cvss: 8.2, exploitability: "medium" }],
  ["CLOUD-AWS-sg-open", { cvss: 7.5, exploitability: "high" }],
  ["CLOUD-AWS-rds-public", { cvss: 8.6, exploitability: "high" }],
  ["CLOUD-AZ-storage-public", { cvss: 8.2, exploitability: "high" }],
  ["CLOUD-CF-ssl-flexible", { cvss: 5.9, exploitability: "medium" }],
  // AI / LLM
  ["AI-3-key", { cvss: 9.1, exploitability: "high" }],
  ["AI-1-prompt-injection", { cvss: 6.5, exploitability: "medium" }],
  ["AI-2-system-leak", { cvss: 4.3, exploitability: "low" }],
];

const BY_SEVERITY: Record<Severity, RiskEntry> = {
  P0: { cvss: 9.0, exploitability: "high" },
  P1: { cvss: 7.0, exploitability: "medium" },
  P2: { cvss: 4.5, exploitability: "medium" },
  P3: { cvss: 2.0, exploitability: "low" },
};

/** Bir bulgunun risk skorunu belirler (id ön-eki → severity fallback). */
export function scoreOf(finding: Finding): RiskEntry {
  for (const [prefix, entry] of BY_PREFIX) {
    if (finding.id.startsWith(prefix)) return entry;
  }
  return BY_SEVERITY[finding.severity];
}

/** Tüm bulgulara cvss + exploitability ekler (modül kendi cvss'ini verdiyse korur). */
export function enrichRisk(findings: readonly Finding[]): Finding[] {
  return findings.map((f) => {
    const r = scoreOf(f);
    return {
      ...f,
      cvss: f.cvss ?? r.cvss,
      exploitability: f.exploitability ?? r.exploitability,
    };
  });
}
