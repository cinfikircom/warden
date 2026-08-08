import type { Finding, ModuleId } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";
import type { CoverageManifest, ModuleStatus } from "./coverage.ts";

/**
 * Skor tablosu (iş emri §5): her denetim boyutu /10. Referans: canliya_alma.md puan tablosu.
 * Değerlendirilmeyen (çalışmayan) modüller "n/d" olarak işaretlenir — sıfır puanla karıştırılmaz.
 *
 * v0.12 — "kapsam dışı" üçüncü durumu:
 *
 * Eskiden yalnızca iki durum vardı: puan ya da "n/d". Bu, en yanıltıcı hâli üretiyordu —
 * `applicable()` gevşek olduğu için bir modül çalışıp hiç yüzey bulamasa bile 10.0/10 alıyordu.
 * Bu repoda 17 boyuttan 11'i böyle 10.0 aldı; oysa Warden'ın HTTP API'si, ödemesi, oturumu,
 * dosya yüklemesi yok. Yani o puanlar "kontrol ettim, temiz" değil, "kontrol edilecek bir şey
 * yoktu" anlamına geliyordu ve rapor ikisini ayırt etmiyordu.
 *
 * Artık modül kendi yüzey sayısını bildiriyorsa (`ModuleRunResult.surface`) ve o sayı 0'sa,
 * boyut puan yerine "kapsam dışı" görünür ve GENEL ORTALAMAYA GİRMEZ.
 */

export interface ScoreRow {
  readonly module: ModuleId;
  readonly dimension: string;
  /** 0–10 puan, ya da değerlendirilmediyse null. */
  readonly score: number | null;
  readonly findings: number;
  readonly p0: number;
  readonly p1: number;
  /** Bu boyutun neden puanlı/puansız olduğu. Rapor bunu puanın yerine yazar. */
  readonly status: ModuleStatus;
  /** İnsan-okunur gerekçe (yalnızca puansız satırlarda). */
  readonly note: string | null;
}

export const DIMENSIONS: Record<ModuleId, string> = {
  A: "Parity & Deployment",
  B: "Statik Güvenlik (SAST)",
  C: "Dinamik / DAST",
  D: "Uyum & Operasyon",
  // "E" v0.10'da kaldırıldı — OWASP Top 10 artık skor boyutu değil, uyum checklist'i
  // (risk/owasp.ts). Kalıcı "n/d" satırı böylece kayboldu; genel skor değişmedi çünkü
  // n/d satırları zaten ortalamaya girmiyordu (bkz. overallScore).
  CLOUD: "Cloud Security",
  K8S: "Kubernetes",
  API: "API Security",
  FE: "Frontend Security",
  AI: "AI / LLM Security",
  PAY: "Payment Security & Reliability",
  ACCESS: "Access Control & Tenant Isolation",
  AUTH: "Identity & Session Hardening",
  PRIV: "Data Privacy & Audit Trail",
  WEB: "CSRF, Clickjacking & Security Headers",
  FLOW: "Workflow & Data Integrity",
  EMAIL: "Email Security",
  UPLOAD: "File Upload Security",
};

/** Şiddete göre puan düşüşü ağırlığı. */
const PENALTY: Record<Severity, number> = { P0: 5, P1: 2.5, P2: 1, P3: 0.25 };

/**
 * Verilen bulgulardan ve çalışan modül kümesinden skor tablosu üretir.
 * @param ranModules Gerçekten çalışan modüller. Burada olmayan modül "n/d".
 */
export function buildScoreboard(
  findings: readonly Finding[],
  ranModules: ReadonlySet<ModuleId>,
  coverage?: CoverageManifest,
): ScoreRow[] {
  const byModule = new Map(coverage?.modules.map((m) => [m.module, m]) ?? []);
  const rows: ScoreRow[] = [];

  for (const module of Object.keys(DIMENSIONS) as ModuleId[]) {
    const dimension = DIMENSIONS[module];
    const own = findings.filter((f) => f.module === module);
    const cov = byModule.get(module);

    // Boyut, modülü çalıştıysa VEYA o boyuta ait bulgu varsa değerlendirilir (ör. içe-aktarılan
    // DAST/IaC bulguları kendi boyutunda; SAST'ın ürettiği FE bulguları FE boyutunda).
    if (!ranModules.has(module) && own.length === 0) {
      rows.push({
        module,
        dimension,
        score: null,
        findings: 0,
        p0: 0,
        p1: 0,
        status: cov?.status ?? "not-run",
        note: cov?.reason ?? "Bu boyut bu çalışmada değerlendirilmedi.",
      });
      continue;
    }

    // Modül çalıştı ama tek bir gerçek yüzey öğesi bulamadı → puan verilmez.
    //
    // Bulgu VARSA bu kural uygulanmaz: bulgu, yüzeyin var olduğunun kesin kanıtıdır ve
    // başka bir modülden (ör. SARIF içe-aktarımı) gelmiş olabilir.
    if (own.length === 0 && (cov?.status === "surface-absent" || cov?.status === "failed")) {
      rows.push({
        module,
        dimension,
        score: null,
        findings: 0,
        p0: 0,
        p1: 0,
        status: cov.status,
        note: cov.reason,
      });
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
      status: "audited",
      note: null,
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
