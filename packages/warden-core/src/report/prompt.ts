import type { Finding } from "../model/finding.ts";
import type { Severity } from "../model/severity.ts";
import { maskSecrets } from "../secret/mask.ts";

/**
 * Bir bulgunun ajana devredilebilir (kopyala-yapıştır ya da doğrudan dispatch) saf temsili.
 * `remediation-playbook.md`'nin ```text``` bloğu VE otomatik ajan-dağıtım akışı (Warden Knight
 * kuyruğu) aynı veriyi kullanır — tek kaynak.
 */
export interface FindingPrompt {
  readonly id: string;
  readonly fingerprint: string;
  readonly severity: Severity;
  readonly title: string;
  readonly risk: string;
  readonly category: string;
  readonly check: string;
  readonly standards: readonly string[];
  readonly impact: string;
  readonly locations: readonly string[];
  readonly recommendation: string;
  readonly confidence: Finding["confidence"];
  readonly autoFixable: boolean;
  readonly effort: Finding["effort"];
}

/** Finding → FindingPrompt. Saf dönüşüm (I/O yok); maskeleme burada uygulanır. */
export function buildFindingPrompt(f: Finding): FindingPrompt {
  const risk = `${f.cvss !== undefined ? `CVSS ${f.cvss.toFixed(1)}` : f.severity}${f.exploitability ? ` / exploitability ${f.exploitability}` : ""}`;
  return {
    id: f.id,
    fingerprint: f.fingerprint,
    severity: f.severity,
    title: f.title,
    risk,
    category: f.category,
    check: f.check,
    standards: f.references ?? [],
    impact: maskSecrets(f.impact),
    locations: f.evidence.length > 0 ? f.evidence.map((e) => `${e.source}${e.location ? `:${e.location}` : ""}`) : [],
    recommendation: maskSecrets(f.recommendation),
    confidence: f.confidence,
    autoFixable: f.autoFixable,
    effort: f.effort,
  };
}

/** FindingPrompt → `remediation-playbook.md`'de kullanılan ```text``` fenced blok metni. */
export function renderFindingPromptMd(p: FindingPrompt): string {
  const lines: string[] = [];
  lines.push("```text");
  lines.push(`Görev: Aşağıdaki güvenlik bulgusunu düzelt (Warden denetimi).`);
  lines.push(`Bulgu: ${p.title}`);
  lines.push(`Şiddet/Risk: ${p.severity} · ${p.risk} · güven: ${p.confidence}`);
  lines.push(`Kategori/Kontrol: ${p.category} (${p.check})`);
  if (p.standards.length > 0) lines.push(`Standart: ${p.standards.join(", ")}`);
  lines.push(`Etki: ${p.impact}`);
  lines.push(`Etkilenen konum(lar):`);
  if (p.locations.length > 0) {
    for (const loc of p.locations) lines.push(`  - ${loc}`);
  } else {
    lines.push(`  - (rapora bakın)`);
  }
  lines.push(`Adımlar:`);
  lines.push(`  1) Yukarıdaki konum(lar)ı aç ve sorunu doğrula.`);
  lines.push(`  2) Şu yaklaşımı uygula: ${p.recommendation}`);
  lines.push(`  3) Aynı sınıftaki diğer örnekleri de tara (grep ile yaygınlaştır).`);
  lines.push(`Test/Kabul:`);
  lines.push(`  - İlgili birim/entegrasyon testini ekle/güncelle; regresyon olmamalı.`);
  lines.push(`  - Warden'i yeniden çalıştır: bu bulgu (\`${p.id}\`) "düzeltilen"e geçmeli (öncesi/sonrası delta).`);
  lines.push("```");
  return lines.join("\n");
}
