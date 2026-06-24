import type { Finding, Evidence } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

export interface MigrationFile {
  readonly path: string;
  readonly sql: string;
}

export interface PrismaData {
  readonly schemaText: string | null;
  readonly schemaPath: string | null;
  readonly migrations: readonly MigrationFile[];
  readonly scripts: Readonly<Record<string, string>>;
}

const DESTRUCTIVE = [
  { re: /\bDROP\s+TABLE\b/i, label: "DROP TABLE" },
  { re: /\bDROP\s+COLUMN\b/i, label: "DROP COLUMN" },
  { re: /\bALTER\s+TABLE\b[\s\S]*?\bDROP\b/i, label: "ALTER TABLE ... DROP" },
  { re: /\bTRUNCATE\b/i, label: "TRUNCATE" },
];

/** Hangi satırlarda yıkıcı ifade var. */
function findDestructive(sql: string): Array<{ label: string; line: number; text: string }> {
  const hits: Array<{ label: string; line: number; text: string }> = [];
  const lines = sql.split(/\r?\n/);
  lines.forEach((ln, i) => {
    for (const d of DESTRUCTIVE) {
      if (d.re.test(ln)) hits.push({ label: d.label, line: i + 1, text: ln.trim() });
    }
  });
  return hits;
}

export function collectPrismaData(ctx: DetectContext): PrismaData {
  const schemaPath = ctx.exists("prisma/schema.prisma")
    ? "prisma/schema.prisma"
    : (ctx.find((p) => p.endsWith("schema.prisma"), { limit: 1 })[0] ?? null);
  const schemaText = schemaPath ? ctx.readFile(schemaPath) : null;

  const migPaths = ctx.find((p) => /prisma\/migrations\/.+\/migration\.sql$/.test(p), { limit: 1000 });
  const migrations: MigrationFile[] = [];
  for (const p of migPaths) {
    const sql = ctx.readFile(p);
    if (sql !== null) migrations.push({ path: p, sql });
  }

  let scripts: Record<string, string> = {};
  const pkgRaw = ctx.readFile("package.json");
  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw) as { scripts?: Record<string, string> };
      scripts = pkg.scripts ?? {};
    } catch {
      /* yok say */
    }
  }
  return { schemaText, schemaPath, migrations, scripts };
}

/** A2 — saf analiz. Prisma şema/migration parity bulguları + katman skoru. */
export function analyzePrismaSchema(data: PrismaData): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];
  let score = 10;

  // Yıkıcı migration'lar (veri kaybı) — P0.
  for (const mig of data.migrations) {
    const hits = findDestructive(mig.sql);
    if (hits.length === 0) continue;
    const ev: Evidence[] = hits.slice(0, 5).map((h) => ({
      type: "file",
      source: mig.path,
      location: String(h.line),
      excerpt: h.text.slice(0, 160),
    }));
    findings.push(
      makeFinding({
        id: `A2-destructive-migration:${mig.path}`,
        title: `Destructive migration: ${[...new Set(hits.map((h) => h.label))].join(", ")}`,
        severity: "P0",
        module: "A",
        check: "A2",
        category: "Schema Parity",
        confidence: "high",
        evidence: ev,
        impact: "Migration uygulandığında VERİ KAYBI olur (kolon/tablo siliniyor). Geri dönüşü yok.",
        recommendation: "Yıkıcı adımı çok-aşamalı geçişe böl (expand/contract); önce yedek + restore drill; CI'da destructive-migration gate.",
        effort: "M",
        autoFixable: false,
        references: ["Prisma migrate", "Expand-Contract pattern"],
      }),
    );
    score -= 6;
  }

  // `prisma db push` kullanımı (migration'sız şema değişikliği = drift).
  const pushScript = Object.entries(data.scripts).find(([, v]) => /prisma\s+db\s+push/.test(v));
  if (pushScript) {
    findings.push(
      makeFinding({
        id: "A2-db-push",
        title: "prisma db push kullanımı (migration'sız şema değişikliği = drift riski)",
        severity: "P1",
        module: "A",
        check: "A2",
        category: "Schema Parity",
        confidence: "high",
        evidence: [{ type: "config", source: `package.json scripts.${pushScript[0]}`, excerpt: pushScript[1] }],
        impact: "db push migration üretmez; prod ile local şema sessizce ayrışır, geçmiş izlenemez.",
        recommendation: "Üretimde `prisma migrate deploy` kullan; db push'u yalnızca prototipte tut.",
        effort: "S",
        autoFixable: false,
      }),
    );
    score -= 2.5;
  }

  // Şema model içeriyor ama hiç migration yok.
  if (data.schemaText && /\bmodel\s+\w+\s*\{/.test(data.schemaText) && data.migrations.length === 0) {
    findings.push(
      makeFinding({
        id: "A2-no-migrations",
        title: "Prisma modelleri var ama hiç migration yok (şema db push ile mi yönetiliyor?)",
        severity: "P1",
        module: "A",
        check: "A2",
        category: "Schema Parity",
        confidence: "medium",
        evidence: [{ type: "file", source: data.schemaPath ?? "prisma/schema.prisma" }],
        impact: "Versiyonlu migration olmadan şema değişiklikleri izlenemez ve güvenle dağıtılamaz.",
        recommendation: "`prisma migrate dev` ile migration geçmişi başlat; üretimde `migrate deploy`.",
        effort: "M",
        autoFixable: false,
      }),
    );
    score -= 2.5;
  }

  // Shadow database — düşük güvenli bilgilendirme.
  if (data.migrations.length > 0 && data.schemaText && !/shadowDatabaseUrl/.test(data.schemaText)) {
    findings.push(
      makeFinding({
        id: "A2-no-shadow-db",
        title: "shadowDatabaseUrl tanımlı değil (bazı sağlayıcılarda migrate güvenliği için gerekir)",
        severity: "P2",
        module: "A",
        check: "A2",
        category: "Schema Parity",
        confidence: "low",
        evidence: [{ type: "config", source: data.schemaPath ?? "prisma/schema.prisma", location: "datasource" }],
        impact: "Gölge veritabanı olmadan bazı yönetilen DB'lerde migration doğrulaması zayıflar.",
        recommendation: "Yönetilen DB kullanıyorsan datasource'a shadowDatabaseUrl ekle.",
        effort: "S",
        autoFixable: false,
      }),
    );
    score -= 1;
  }

  if (!data.schemaText) {
    return {
      findings,
      layer: { code: "A2", name: "Schema Parity", status: "unknown", score: null, note: "Prisma şeması bulunamadı.", findingIds: [] },
    };
  }

  const hasP0 = findings.some((f) => f.severity === "P0");
  const status = hasP0 ? "risk" : findings.length > 0 ? "warn" : "ok";
  return {
    findings,
    layer: {
      code: "A2",
      name: "Schema Parity",
      status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note: findings.length === 0 ? "Migration geçmişi sağlıklı, yıkıcı adım yok." : `${findings.length} şema bulgusu.`,
      findingIds: findings.map((f) => f.id),
    },
  };
}
