import type { Finding, Evidence } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/** Django migration dosyası. */
export interface DjangoMigration {
  readonly path: string;
  readonly content: string;
}

const DESTRUCTIVE = [
  { re: /migrations\.DeleteModel\b/, label: "DeleteModel", sev: "P0" as const },
  { re: /migrations\.RemoveField\b/, label: "RemoveField", sev: "P0" as const },
  { re: /migrations\.RenameField\b/, label: "RenameField", sev: "P1" as const },
  { re: /migrations\.RenameModel\b/, label: "RenameModel", sev: "P1" as const },
];

export function collectDjangoData(ctx: DetectContext): DjangoMigration[] {
  const paths = ctx.find((p) => /(^|\/)migrations\/[^/]+\.py$/.test(p) && !p.endsWith("__init__.py"), { limit: 1000 });
  const out: DjangoMigration[] = [];
  for (const p of paths) {
    const content = ctx.readFile(p);
    if (content !== null) out.push({ path: p, content });
  }
  return out;
}

/** A2 (Django) — yıkıcı migration operasyonlarını saf analizle yakalar. */
export function analyzeDjangoMigrations(migrations: readonly DjangoMigration[]): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];
  let score = 10;

  for (const mig of migrations) {
    const lines = mig.content.split(/\r?\n/);
    const hits: Array<{ label: string; sev: "P0" | "P1"; line: number; text: string }> = [];
    lines.forEach((ln, i) => {
      for (const d of DESTRUCTIVE) if (d.re.test(ln)) hits.push({ label: d.label, sev: d.sev, line: i + 1, text: ln.trim() });
    });
    if (hits.length === 0) continue;
    const worst = hits.some((h) => h.sev === "P0") ? "P0" : "P1";
    const ev: Evidence[] = hits.slice(0, 5).map((h) => ({ type: "file", source: mig.path, location: String(h.line), excerpt: h.text.slice(0, 160) }));
    findings.push(
      makeFinding({
        id: `A2-django-destructive:${mig.path}`,
        title: `Django yıkıcı migration: ${[...new Set(hits.map((h) => h.label))].join(", ")}`,
        severity: worst,
        module: "A",
        check: "A2",
        category: "Schema Parity",
        confidence: "high",
        evidence: ev,
        impact: "RemoveField/DeleteModel uygulanınca VERİ KAYBI olur; geri dönüşü yoktur.",
        recommendation: "Çok-aşamalı geçiş (önce deprecate, veri taşı, sonra kaldır); önce yedek + restore drill.",
        effort: "M",
        autoFixable: false,
        references: ["Django migrations"],
      }),
    );
    score -= worst === "P0" ? 6 : 2.5;
  }

  if (migrations.length === 0) {
    return { findings, layer: { code: "A2", name: "Schema Parity", status: "unknown", score: null, note: "Django migration bulunamadı.", findingIds: [] } };
  }
  const status = findings.some((f) => f.severity === "P0") ? "risk" : findings.length > 0 ? "warn" : "ok";
  return {
    findings,
    layer: {
      code: "A2", name: "Schema Parity", status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note: findings.length === 0 ? "Yıkıcı migration yok." : `${findings.length} yıkıcı Django migration.`,
      findingIds: findings.map((f) => f.id),
    },
  };
}
