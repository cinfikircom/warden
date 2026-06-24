import type { Finding } from "../model/finding.ts";
import { SEVERITY_EMOJI } from "../model/severity.ts";
import type { Severity } from "../model/severity.ts";
import { maskSecrets } from "../secret/mask.ts";

/**
 * Run-to-run delta (öncesi/sonrası). Ürünün değer döngüsü: tara → düzelt → yeniden tara → ispatla.
 * Bulgular `fingerprint` ile eşlenir; böylece düzeltilen/yeni gelen/kalan ayrılır.
 */

export interface PreviousRun {
  readonly findings: readonly Finding[];
  readonly overallScore: number | null;
  readonly parityScore: number | null;
  readonly generatedAt: string | null;
}

export interface Delta {
  readonly isFirstRun: boolean;
  /** Önceki run'da olup şimdi olmayan (düzeltilmiş). */
  readonly fixed: readonly Finding[];
  /** Şimdi olup öncekinde olmayan (yeni). */
  readonly introduced: readonly Finding[];
  /** İki run'da da olan (kalan). */
  readonly persisting: readonly Finding[];
}

export function computeDelta(previous: PreviousRun | null, current: readonly Finding[]): Delta {
  if (!previous) {
    return { isFirstRun: true, fixed: [], introduced: [...current], persisting: [] };
  }
  const prevByFp = new Map(previous.findings.map((f) => [f.fingerprint, f]));
  const currByFp = new Map(current.map((f) => [f.fingerprint, f]));

  const fixed = previous.findings.filter((f) => !currByFp.has(f.fingerprint));
  const introduced = current.filter((f) => !prevByFp.has(f.fingerprint));
  const persisting = current.filter((f) => prevByFp.has(f.fingerprint));
  return { isFirstRun: false, fixed, introduced, persisting };
}

function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { P0: 0, P1: 0, P2: 0, P3: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

function arrow(before: number | null, after: number | null): string {
  if (before === null || after === null) return "→";
  if (after > before) return `↑ +${(after - before).toFixed(1)}`;
  if (after < before) return `↓ ${(after - before).toFixed(1)}`;
  return "→ (değişmedi)";
}

/** report.md için "Değişim (Öncesi → Sonrası)" bölümü. */
export function renderDeltaSection(
  delta: Delta,
  previous: PreviousRun | null,
  scoreAfter: number | null,
  parityAfter: number | null,
): string[] {
  const lines: string[] = [];
  lines.push("## Değişim (Öncesi → Sonrası)");
  lines.push("");
  if (delta.isFirstRun) {
    lines.push("_İlk çalışma — baseline oluşturuldu. Sonraki çalıştırmada öncesi/sonrası karşılaştırması yapılacak._");
    lines.push("");
    return lines;
  }

  const scoreBefore = previous?.overallScore ?? null;
  const parityBefore = previous?.parityScore ?? null;
  lines.push(`> Önceki çalışma: ${previous?.generatedAt ?? "?"}`);
  lines.push("");
  lines.push("| Metrik | Önce | Sonra | Değişim |");
  lines.push("|--------|:----:|:-----:|:-------:|");
  lines.push(`| Genel skor /10 | ${scoreBefore ?? "n/d"} | ${scoreAfter ?? "n/d"} | ${arrow(scoreBefore, scoreAfter)} |`);
  lines.push(`| Parity skor /10 | ${parityBefore ?? "n/d"} | ${parityAfter ?? "n/d"} | ${arrow(parityBefore, parityAfter)} |`);
  lines.push(`| ✅ Düzeltilen | — | **${delta.fixed.length}** | |`);
  lines.push(`| 🆕 Yeni gelen | — | **${delta.introduced.length}** | |`);
  lines.push(`| ⏳ Kalan | — | **${delta.persisting.length}** | |`);
  lines.push("");

  if (delta.fixed.length > 0) {
    lines.push("### ✅ Düzeltilen bulgular");
    for (const f of delta.fixed) lines.push(`- ${SEVERITY_EMOJI[f.severity]} [${f.severity}] ${maskSecrets(f.title)} (\`${f.id}\`)`);
    lines.push("");
  }
  if (delta.introduced.length > 0) {
    lines.push("### 🆕 Yeni gelen bulgular (regresyon olabilir)");
    for (const f of delta.introduced) lines.push(`- ${SEVERITY_EMOJI[f.severity]} [${f.severity}] ${maskSecrets(f.title)} (\`${f.id}\`)`);
    lines.push("");
  }
  if (delta.persisting.length > 0) {
    const c = countBySeverity(delta.persisting);
    lines.push(`### ⏳ Hâlâ açık: ${delta.persisting.length} (P0:${c.P0} P1:${c.P1} P2:${c.P2} P3:${c.P3})`);
    lines.push("");
  }
  return lines;
}

/** history.jsonl'e eklenecek tek satırlık özet. */
export function historyLine(
  generatedAt: string,
  scoreAfter: number | null,
  parityAfter: number | null,
  current: readonly Finding[],
  delta: Delta,
): string {
  return JSON.stringify({
    generatedAt,
    overallScore: scoreAfter,
    parityScore: parityAfter,
    total: current.length,
    bySeverity: countBySeverity(current),
    fixed: delta.fixed.length,
    introduced: delta.introduced.length,
    persisting: delta.persisting.length,
  });
}
