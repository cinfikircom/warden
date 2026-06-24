import type { Finding, Evidence } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

export interface MigrationFile {
  readonly path: string;
  readonly content: string;
}

const DESTRUCTIVE = [
  { re: /Schema::dropIfExists\b/, label: "dropIfExists" },
  { re: /Schema::drop\b/, label: "Schema::drop" },
  { re: /->dropColumn\b/, label: "dropColumn" },
  { re: /->dropColumns\b/, label: "dropColumns" },
  { re: /->drop\(\)/, label: "drop()" },
];

export function collectLaravelData(ctx: DetectContext): MigrationFile[] {
  const paths = ctx.find((p) => /database\/migrations\/[^/]+\.php$/.test(p), { limit: 1000 });
  const out: MigrationFile[] = [];
  for (const p of paths) {
    const content = ctx.readFile(p);
    if (content !== null) out.push({ path: p, content });
  }
  return out;
}

/** A2 (Laravel) — yıkıcı migration (dropColumn/drop/dropIfExists). */
export function analyzeLaravelMigrations(migrations: readonly MigrationFile[]): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];
  let score = 10;

  for (const mig of migrations) {
    const lines = mig.content.split(/\r?\n/);
    const hits: Array<{ label: string; line: number; text: string }> = [];
    lines.forEach((ln, i) => {
      for (const d of DESTRUCTIVE) if (d.re.test(ln)) hits.push({ label: d.label, line: i + 1, text: ln.trim() });
    });
    if (hits.length === 0) continue;
    const ev: Evidence[] = hits.slice(0, 5).map((h) => ({ type: "file", source: mig.path, location: String(h.line), excerpt: h.text.slice(0, 160) }));
    findings.push(
      makeFinding({
        id: `A2-laravel-destructive:${mig.path}`,
        title: `Laravel yıkıcı migration: ${[...new Set(hits.map((h) => h.label))].join(", ")}`,
        severity: "P0",
        module: "A",
        check: "A2",
        category: "Schema Parity",
        confidence: "high",
        evidence: ev,
        impact: "dropColumn/drop uygulanınca VERİ KAYBI olur; geri dönüşü yoktur.",
        recommendation: "Çok-aşamalı geçiş; down() ile geri-alınabilirlik; önce yedek + restore drill.",
        effort: "M",
        autoFixable: false,
        references: ["Laravel migrations"],
      }),
    );
    score -= 6;
  }

  if (migrations.length === 0) {
    return { findings, layer: { code: "A2", name: "Schema Parity", status: "unknown", score: null, note: "Laravel migration bulunamadı.", findingIds: [] } };
  }
  const status = findings.some((f) => f.severity === "P0") ? "risk" : findings.length > 0 ? "warn" : "ok";
  return {
    findings,
    layer: {
      code: "A2", name: "Schema Parity", status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note: findings.length === 0 ? "Yıkıcı migration yok." : `${findings.length} yıkıcı Laravel migration.`,
      findingIds: findings.map((f) => f.id),
    },
  };
}
