/**
 * Parity Risk Score (nokta 7). Modül A her katman için skor + durum üretir; rapor
 * "Overall Parity Score: X/10" + katman tablosu gösterir (yönetici raporu için).
 */

/** ✅ ok · 🟡 warn · 🔴 risk · ⏳ unknown (canlı veri gerektiği için doğrulanamadı). */
export type ParityStatus = "ok" | "warn" | "risk" | "unknown";

export const PARITY_EMOJI: Record<ParityStatus, string> = {
  ok: "✅",
  warn: "🟡",
  risk: "🔴",
  unknown: "⏳",
};

export interface ParityLayer {
  /** A1..A6 */
  readonly code: string;
  readonly name: string;
  readonly status: ParityStatus;
  /** 0–10; doğrulanamadıysa null. */
  readonly score: number | null;
  /** Kısa açıklama (rapora yazılır). */
  readonly note: string;
  /** Bu katmana bağlı bulgu id'leri. */
  readonly findingIds: readonly string[];
}

export interface ParityResult {
  readonly layers: readonly ParityLayer[];
  /** Doğrulanan katmanların skor ortalaması; hiçbiri yoksa null. */
  readonly overall: number | null;
}

export function computeOverallParity(layers: readonly ParityLayer[]): number | null {
  const scored = layers.filter((l) => l.score !== null) as Array<ParityLayer & { score: number }>;
  if (scored.length === 0) return null;
  const sum = scored.reduce((a, l) => a + l.score, 0);
  return Math.round((sum / scored.length) * 10) / 10;
}
