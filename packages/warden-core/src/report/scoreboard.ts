import type { Finding, ModuleId } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";

/**
 * Skor tablosu (iş emri §5): her denetim boyutu /10. Referans: canliya_alma.md puan tablosu.
 * Değerlendirilmeyen (çalışmayan) modüller "n/d" olarak işaretlenir — sıfır puanla karıştırılmaz.
 */

export interface ScoreRow {
  readonly module: ModuleId;
  readonly dimension: string;
  /** 0–10 puan, ya da değerlendirilmediyse null. */
  readonly score: number | null;
  readonly findings: number;
  readonly p0: number;
  readonly p1: number;
}

export const DIMENSIONS: Record<ModuleId, string> = {
  A: "Parity & Deployment",
  B: "Statik Güvenlik (SAST)",
  C: "Dinamik / DAST",
  D: "Uyum & Operasyon",
  E: "OWASP Top 10 / ASVS",
  CLOUD: "Cloud Security",
  K8S: "Kubernetes",
  API: "API Security",
  FE: "Frontend Security",
  AI: "AI / LLM Security",
  PAY: "Payment Security & Reliability",
  ACCESS: "Access Control & Tenant Isolation",
  AUTH: "Identity & Session Hardening",
  PRIV: "Data Privacy & Audit Trail",
};

/** Şiddete göre puan düşüşü ağırlığı. */
const PENALTY: Record<Severity, number> = { P0: 5, P1: 2.5, P2: 1, P3: 0.25 };

/**
 * Verilen bulgulardan ve çalışan modül kümesinden skor tablosu üretir.
 * @param ranModules Gerçekten çalışan modüller. Burada olmayan modül "n/d".
 */
export function buildScoreboard(findings: readonly Finding[], ranModules: ReadonlySet<ModuleId>): ScoreRow[] {
  const rows: ScoreRow[] = [];
  for (const module of Object.keys(DIMENSIONS) as ModuleId[]) {
    const dimension = DIMENSIONS[module];
    const own = findings.filter((f) => f.module === module);
    // Boyut, modülü çalıştıysa VEYA o boyuta ait bulgu varsa değerlendirilir (ör. içe-aktarılan
    // DAST/IaC bulguları kendi boyutunda; SAST'ın ürettiği FE bulguları FE boyutunda).
    if (!ranModules.has(module) && own.length === 0) {
      rows.push({ module, dimension, score: null, findings: 0, p0: 0, p1: 0 });
      continue;
    }
    let score = 10;
    let p0 = 0;
    let p1 = 0;
    for (const f of own) {
      score -= PENALTY[f.severity];
      if (f.severity === "P0") p0++;
      if (f.severity === "P1") p1++;
    }
    rows.push({
      module,
      dimension,
      score: Math.max(0, Math.round(score * 10) / 10),
      findings: own.length,
      p0,
      p1,
    });
  }
  return rows;
}

/** Genel skor: değerlendirilen boyutların ortalaması (n/d hariç). */
export function overallScore(rows: readonly ScoreRow[]): number | null {
  const scored = rows.filter((r) => r.score !== null) as Array<ScoreRow & { score: number }>;
  if (scored.length === 0) return null;
  const sum = scored.reduce((a, r) => a + r.score, 0);
  return Math.round((sum / scored.length) * 10) / 10;
}
