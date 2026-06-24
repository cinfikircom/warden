import type { Finding, ModuleId, Confidence, EvidenceType } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";
import { maskSecrets } from "../../secret/mask.ts";

/**
 * Bildirimsel kaynak kuralı. SAST kontrollerinin çoğu (B1/B3/B4/B6/FE) bununla ifade edilir;
 * yeni kural = bu listeye bir nesne. Her eşleşme kanıtlı (file:line) bir bulguya dönüşür.
 */
export interface SourceRule {
  readonly id: string;
  readonly check: string;
  readonly module: ModuleId;
  readonly title: string;
  readonly severity: Severity;
  readonly category: string;
  readonly confidence: Confidence;
  /** Satır bazında test edilen desen. */
  readonly pattern: RegExp;
  /** Yalnızca bu yola uyan dosyalarda çalışır (verilmezse tüm kod dosyaları). */
  readonly pathInclude?: RegExp;
  readonly pathExclude?: RegExp;
  readonly impact: string;
  readonly recommendation: string;
  readonly references?: readonly string[];
  readonly effort: "S" | "M" | "L";
  readonly evidenceType?: EvidenceType;
  /** Dosya başına aynı kuraldan en fazla bulgu (gürültüyü sınırlar). */
  readonly maxPerFile?: number;
}

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|astro|py|go|php|rb|java|cs)$/i;
const SKIP_PATH =
  /(^|\/)(node_modules|dist|build|\.next|coverage|warden-report|vendor)\/|\.min\.js$|\.(test|spec)\.[a-z]+$|(^|\/)(test|tests|__tests__|fixtures)\//i;

export interface ScanSourceOptions {
  readonly maxFiles?: number;
  readonly maxBytesPerFile?: number;
}

/** Kaynak ağacını tarar; kural setini uygular; kanıtlı bulgular döndürür. */
export function scanSource(ctx: DetectContext, rules: readonly SourceRule[], opts: ScanSourceOptions = {}): Finding[] {
  const maxFiles = opts.maxFiles ?? 5000;
  const maxBytes = opts.maxBytesPerFile ?? 1_000_000;

  const files = ctx.find((p) => CODE_FILE.test(p) && !SKIP_PATH.test(p), { limit: maxFiles });
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const text = ctx.readFile(file);
    if (text === null || text.length > maxBytes) continue;
    const lines = text.split(/\r?\n/);

    for (const rule of rules) {
      if (rule.pathInclude && !rule.pathInclude.test(file)) continue;
      if (rule.pathExclude && rule.pathExclude.test(file)) continue;
      let hits = 0;
      const cap = rule.maxPerFile ?? 3;
      for (let i = 0; i < lines.length && hits < cap; i++) {
        const line = lines[i] as string;
        rule.pattern.lastIndex = 0;
        if (!rule.pattern.test(line)) continue;
        hits++;
        const f = makeFinding({
          id: `${rule.id}:${file}:${i + 1}`,
          title: rule.title,
          severity: rule.severity,
          module: rule.module,
          check: rule.check,
          category: rule.category,
          confidence: rule.confidence,
          evidence: [
            {
              type: rule.evidenceType ?? "file",
              source: file,
              location: String(i + 1),
              excerpt: maskSecrets(line.trim().slice(0, 200)),
            },
          ],
          impact: rule.impact,
          recommendation: rule.recommendation,
          effort: rule.effort,
          autoFixable: false,
          ...(rule.references ? { references: rule.references } : {}),
        });
        if (seen.has(f.fingerprint)) continue;
        seen.add(f.fingerprint);
        findings.push(f);
      }
    }
  }
  return findings;
}
