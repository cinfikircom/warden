import { createHash } from "node:crypto";
import type { Finding, Evidence, ModuleId, Confidence } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";
import { maskSecrets } from "../secret/mask.ts";

export interface FindingInput {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly module: ModuleId;
  readonly check: string;
  readonly category: string;
  readonly confidence: Confidence;
  readonly evidence: readonly Evidence[];
  readonly impact: string;
  readonly recommendation: string;
  readonly effort: "S" | "M" | "L";
  readonly autoFixable: boolean;
  readonly references?: readonly string[];
  readonly cvss?: number;
  readonly cves?: readonly string[];
  readonly reachable?: boolean;
}

/** İçerik-türevli kararlı fingerprint (çalıştırmalar arası dedup + CI gate). */
export function fingerprintOf(module: string, check: string, title: string, signatures: readonly string[]): string {
  const basis = `${module}|${check}|${title}|${[...signatures].sort().join(",")}`;
  return createHash("sha1").update(basis).digest("hex").slice(0, 16);
}

function normalize(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

/**
 * Bulguyu fingerprint ile birlikte üretir. Fingerprint, SATIR NUMARASINA değil eşleşen
 * İÇERİĞE dayanır (excerpt); böylece satırlar kayınca aynı bulgu sahte "fixed+new" üretmez
 * (öncesi/sonrası delta kararlılığı — bkz. report/delta.ts).
 */
export function makeFinding(input: FindingInput): Finding {
  // TEK CHOKE-POINT: tüm evidence excerpt'leri burada maskelenir. Böylece findings.json,
  // SARIF, report.md — HER çıktı maskeli olur (§2.4; ham secret asla serialize edilmez).
  const evidence: Evidence[] = input.evidence.map((e) =>
    e.excerpt === undefined ? e : { ...e, excerpt: maskSecrets(e.excerpt) },
  );
  const signatures = evidence.map((e) => `${e.source}|${normalize(e.excerpt ?? e.location ?? "")}`);
  const fingerprint = fingerprintOf(input.module, input.check, input.title, signatures);
  return { ...input, evidence, fingerprint };
}
