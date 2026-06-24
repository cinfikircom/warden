/**
 * Uyum (compliance) checklist modeli. PCI-DSS / Privacy / ASVS gibi standartlar için
 * ✔ Passed · ⚠ Partial · ✖ Failed · – Unknown durumlu kontrol listeleri üretilir.
 */

export type ComplianceStatus = "pass" | "partial" | "fail" | "unknown";

export const COMPLIANCE_EMOJI: Record<ComplianceStatus, string> = {
  pass: "✔",
  partial: "⚠",
  fail: "✖",
  unknown: "–",
};

export interface ComplianceItem {
  /** Standart kontrol kodu, örn. "PCI 3.2", "GDPR Art.17". */
  readonly control: string;
  readonly title: string;
  readonly status: ComplianceStatus;
  readonly note: string;
}

export interface Checklist {
  readonly name: string;
  readonly standard: string;
  readonly items: readonly ComplianceItem[];
}

export interface ComplianceResult {
  readonly checklists: readonly Checklist[];
}

/** Bir checklist'in özet skoru: pass tam puan, partial yarım; unknown hariç. */
export function checklistScore(list: Checklist): { passed: number; partial: number; failed: number; pct: number | null } {
  let passed = 0;
  let partial = 0;
  let failed = 0;
  let assessed = 0;
  for (const it of list.items) {
    if (it.status === "unknown") continue;
    assessed++;
    if (it.status === "pass") passed++;
    else if (it.status === "partial") partial++;
    else failed++;
  }
  const pct = assessed === 0 ? null : Math.round(((passed + partial * 0.5) / assessed) * 100);
  return { passed, partial, failed, pct };
}
