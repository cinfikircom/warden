/**
 * Şiddet ölçeği (iş emri §5). Sıralama kritik: rapor bu sıraya göre dizilir.
 *
 *  P0 — production blocker / aktif sömürülebilir
 *  P1 — ilk müşteri öncesi mutlaka
 *  P2 — mimari borç
 *  P3 — ölçek / iyileştirme
 */
export const SEVERITIES = ["P0", "P1", "P2", "P3"] as const;

export type Severity = (typeof SEVERITIES)[number];

/** Düşük sayı = daha kritik. Sıralamada kullanılır. */
export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  P0: "P0 · Production blocker / aktif sömürülebilir",
  P1: "P1 · İlk müşteri öncesi",
  P2: "P2 · Mimari borç",
  P3: "P3 · Ölçek / iyileştirme",
};

/** Raporlarda kullanılan görsel işaret. */
export const SEVERITY_EMOJI: Record<Severity, string> = {
  P0: "🔴",
  P1: "🟠",
  P2: "🟡",
  P3: "⚪",
};
