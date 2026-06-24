import type { Finding, Evidence } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * A2 (Go) — golang-migrate / goose tarzı SQL migration'larda yıkıcı operasyon tespiti.
 * `*.up.sql` ve `migrations/*.sql` dosyalarında DROP TABLE/COLUMN, TRUNCATE.
 */

export interface MigrationFile {
  readonly path: string;
  readonly sql: string;
}

const DESTRUCTIVE = [
  { re: /\bDROP\s+TABLE\b/i, label: "DROP TABLE" },
  { re: /\bDROP\s+COLUMN\b/i, label: "DROP COLUMN" },
  { re: /\bALTER\s+TABLE\b[\s\S]*?\bDROP\b/i, label: "ALTER ... DROP" },
  { re: /\bTRUNCATE\b/i, label: "TRUNCATE" },
];

export function collectGoMigrations(ctx: DetectContext): MigrationFile[] {
  const paths = ctx.find(
    (p) => /(^|\/)(migrations|migration|db\/migrations|sql\/migrations)\/[^/]+\.sql$/i.test(p) || /\.up\.sql$/i.test(p),
    { limit: 1000 },
  );
  const out: MigrationFile[] = [];
  for (const p of paths) {
    // down migration'larda DROP normaldir; yalnızca up/forward'ları değerlendir.
    if (/\.down\.sql$/i.test(p)) continue;
    const sql = ctx.readFile(p);
    if (sql !== null) out.push({ path: p, sql });
  }
  return out;
}

export function analyzeGoMigrations(migrations: readonly MigrationFile[]): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];
  let score = 10;

  for (const mig of migrations) {
    const lines = mig.sql.split(/\r?\n/);
    const hits: Array<{ label: string; line: number; text: string }> = [];
    lines.forEach((ln, i) => {
      for (const d of DESTRUCTIVE) if (d.re.test(ln)) hits.push({ label: d.label, line: i + 1, text: ln.trim() });
    });
    if (hits.length === 0) continue;
    const ev: Evidence[] = hits.slice(0, 5).map((h) => ({ type: "file", source: mig.path, location: String(h.line), excerpt: h.text.slice(0, 160) }));
    findings.push(
      makeFinding({
        id: `A2-go-destructive:${mig.path}`,
        title: `Yıkıcı SQL migration (Go): ${[...new Set(hits.map((h) => h.label))].join(", ")}`,
        severity: "P0", module: "A", check: "A2", category: "Schema Parity", confidence: "high",
        evidence: ev,
        impact: "Forward migration veri kaybına yol açar (DROP/TRUNCATE); geri dönüşü yok.",
        recommendation: "Çok-aşamalı geçiş; .down.sql ile geri-alınabilirlik; önce yedek + restore drill.",
        effort: "M", autoFixable: false, references: ["golang-migrate"],
      }),
    );
    score -= 6;
  }

  if (migrations.length === 0) {
    return { findings, layer: { code: "A2", name: "Schema Parity", status: "unknown", score: null, note: "Go SQL migration bulunamadı.", findingIds: [] } };
  }
  const status = findings.some((f) => f.severity === "P0") ? "risk" : findings.length > 0 ? "warn" : "ok";
  return {
    findings,
    layer: {
      code: "A2", name: "Schema Parity", status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note: findings.length === 0 ? "Yıkıcı migration yok." : `${findings.length} yıkıcı Go migration.`,
      findingIds: findings.map((f) => f.id),
    },
  };
}
