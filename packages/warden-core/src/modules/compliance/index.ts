import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { DetectContext } from "../../detect/types.ts";
import { analyzeCompliance } from "./checks.ts";
import type { ComplianceData, CardHit } from "./checks.ts";

const CVV_RE = /\b(cvv2?|cvc2?|card_?verification|security_?code)\b/i;
const PAN_RE = /\b(card_?number|cardnumber|cardno|primary_?account_?number)\b/i;
const CODE_OR_SCHEMA = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|php|rb|java|cs|prisma)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures)\//i;
const BACKUP_RE = /backup|pg_dump|mysqldump|mongodump|dump\.sql/i;
const RESTORE_RE = /restore|pg_restore|mongorestore|mysql\s*<|drill/i;

function readPkgDeps(ctx: DetectContext): Record<string, string> {
  const deps: Record<string, string> = {};
  // Node
  const raw = ctx.readFile("package.json");
  if (raw) {
    try {
      const p = JSON.parse(raw) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      Object.assign(deps, p.dependencies ?? {}, p.devDependencies ?? {});
    } catch {
      /* yok say */
    }
  }
  // Python — requirements.txt
  const req = ctx.readFile("requirements.txt");
  if (req) {
    for (const line of req.split(/\r?\n/)) {
      const name = line.trim().split(/[=<>!~;\[\s]/)[0];
      if (name && !name.startsWith("#")) deps[name.toLowerCase()] = "py";
    }
  }
  // Python — pyproject.toml (kaba ayrıştırma)
  const pyproject = ctx.readFile("pyproject.toml");
  if (pyproject) {
    for (const m of pyproject.matchAll(/^\s*["']?([A-Za-z0-9_.-]+)["']?\s*=\s*["']/gm)) {
      if (m[1]) deps[m[1].toLowerCase()] = "py";
    }
    for (const m of pyproject.matchAll(/["']([A-Za-z0-9_.-]+)\s*[><=~]/g)) {
      if (m[1]) deps[m[1].toLowerCase()] = "py";
    }
  }
  // PHP — composer.json (require + require-dev)
  const composer = ctx.readFile("composer.json");
  if (composer) {
    try {
      const c = JSON.parse(composer) as { require?: Record<string, string>; "require-dev"?: Record<string, string> };
      for (const k of [...Object.keys(c.require ?? {}), ...Object.keys(c["require-dev"] ?? {})]) deps[k.toLowerCase()] = "php";
    } catch {
      /* yok say */
    }
  }
  // .NET — *.csproj PackageReference Include="..."
  for (const cs of ctx.find((p) => p.endsWith(".csproj"), { limit: 50 })) {
    const t = ctx.readFile(cs) ?? "";
    for (const m of t.matchAll(/<PackageReference\s+Include="([^"]+)"/g)) {
      if (m[1]) deps[m[1].toLowerCase()] = "dotnet";
    }
  }
  // Go — go.mod require
  const gomod = ctx.readFile("go.mod");
  if (gomod) {
    for (const m of gomod.matchAll(/^\s*([\w./-]+)\s+v\d[\w.+-]*/gm)) {
      if (m[1] && m[1] !== "go") deps[m[1].toLowerCase()] = "go";
    }
  }
  return deps;
}

function readScripts(ctx: DetectContext): string {
  const raw = ctx.readFile("package.json");
  if (!raw) return "";
  try {
    return JSON.stringify((JSON.parse(raw) as { scripts?: unknown }).scripts ?? {});
  } catch {
    return "";
  }
}

export function collectComplianceData(ctx: DetectContext): ComplianceData {
  const deps = readPkgDeps(ctx);
  const scripts = readScripts(ctx);
  const fileList = ctx.find(() => true, { limit: 5000 });

  // CI tespiti
  const ciFiles = fileList.filter((p) => /(^|\/)\.github\/workflows\/.+\.ya?ml$|(^|\/)\.gitlab-ci\.yml$|(^|\/)\.circleci\/|(^|\/)azure-pipelines\.yml$|(^|\/)Jenkinsfile$/.test(p));
  const hasCI = ciFiles.length > 0;
  let ciHasTestGate = false;
  for (const f of ciFiles) {
    const t = ctx.readFile(f) ?? "";
    if (/\b(test|vitest|jest|pytest|go test|phpunit|eslint|lint|playwright|cypress)\b/i.test(t)) {
      ciHasTestGate = true;
      break;
    }
  }

  // Prisma şema + kişisel veri bağlamı
  const schemaPath = ctx.exists("prisma/schema.prisma")
    ? "prisma/schema.prisma"
    : (ctx.find((p) => p.endsWith("schema.prisma"), { limit: 1 })[0] ?? null);
  const prismaSchema = schemaPath ? ctx.readFile(schemaPath) : null;

  // Django models.py'da kişisel veri bağlamı.
  let djangoPersonal = false;
  let djangoModels = "";
  const modelFiles = ctx.find((p) => /(^|\/)models\.py$/.test(p), { limit: 50 });
  for (const mf of modelFiles) {
    const t = ctx.readFile(mf) ?? "";
    djangoModels += `\n${t}`;
    if (/class\s+\w+\(.*models\.Model.*\)/.test(t) && /email|EmailField|first_name|phone|tckimlik/i.test(t)) {
      djangoPersonal = true;
    }
  }

  // Soft-delete tespiti prisma + django model metninde aranır.
  const combinedSchema = `${prismaSchema ?? ""}${djangoModels}` || null;

  const hasPersonalData =
    djangoPersonal ||
    (prismaSchema !== null && (/model\s+(User|Customer|Account|Person|Patient|Member|Client)\b/i.test(prismaSchema) || /\bemail\b/i.test(prismaSchema)));

  // Kart verisi taraması (D7)
  const cardHits: CardHit[] = [];
  const scanFiles = fileList.filter((p) => CODE_OR_SCHEMA.test(p) && !SKIP.test(p)).slice(0, 3000);
  for (const f of scanFiles) {
    const text = ctx.readFile(f);
    if (!text || text.length > 1_000_000) continue;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      // CVV ve PAN aynı satırda olabilir; ikisini de bağımsız kaydet.
      if (CVV_RE.test(ln)) cardHits.push({ file: f, line: i + 1, kind: "cvv", excerpt: ln.trim().slice(0, 160) });
      if (PAN_RE.test(ln)) cardHits.push({ file: f, line: i + 1, kind: "pan", excerpt: ln.trim().slice(0, 160) });
      if (cardHits.length >= 50) break;
    }
    if (cardHits.length >= 50) break;
  }

  const hasBackup = fileList.some((p) => BACKUP_RE.test(p)) || BACKUP_RE.test(scripts);
  const hasRestore = fileList.some((p) => RESTORE_RE.test(p)) || RESTORE_RE.test(scripts);

  return { deps, hasCI, ciFiles, ciHasTestGate, prismaSchema: combinedSchema, hasPersonalData: Boolean(hasPersonalData), cardHits, hasBackup, hasRestore };
}

/**
 * Modül D — Uyum & Operasyonel Olgunluk (pasif).
 * D1 backup/DR · D2 observability · D3 secret mgmt · D4 veri koruma · D5 CI/CD · D6 rollback
 * + D7 PCI-DSS 4.0 (kart verisi + checklist) + D8 Privacy (KVKK/GDPR checklist).
 * artifact: ComplianceResult (checklist'ler).
 */
export const complianceModule: WardenModule = {
  id: "D",
  title: "Uyum & Operasyonel Olgunluk",
  active: false,
  applicable() {
    return true;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const data = collectComplianceData(ctx.fs);
    const { findings, result } = analyzeCompliance(data);
    ctx.audit.info(
      `Compliance: ${findings.length} bulgu; checklist'ler: ${result.checklists.map((c) => c.name).join(", ")}; kart isabeti: ${data.cardHits.length}`,
    );
    return { findings, artifact: result };
  },
};
