import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül FLOW — İş-Akışı & Veri Bütünlüğü (pasif, statik).
 * =========================================================================
 * CRM/ERP güvenilirliği: para/stok/durum tutan iş akışlarında sessiz veri bozulması.
 * PAY-9'un (orphan ödeme) genelleştirmesi — ödemeye özel değil, TÜM iş akışları için.
 *   FLOW-1  Transaction'sız çok-adımlı yazma (yarıda kalırsa yarım/tutarsız durum)
 *   FLOW-2  Atomik olmayan oku-değiştir-yaz sayaç/bakiye/stok (lost update / race condition)
 *   FLOW-3  İdempotent olmayan sipariş/transfer/rezervasyon oluşturma (çift-gönderim → çift kayıt)
 *
 * Handler gövdeleri brace-eşlemeyle çıkarılır; her kontrol handler bazında değerlendirilir.
 * Yokluk-temelli → düşük güven, `.warden-ignore.yml` ile bastırılır.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__|migrations?)\//i;

export function stripComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

// Bir handler/fonksiyon gövdesinin başlangıç işaretleri (route ya da controller metodu).
const HANDLER_ANCHOR = /\b(app|router)\.(get|post|put|patch|delete)\s*\([^)]*?(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>\s*\{|\b(async\s+)?function\s+\w+\s*\([^)]*\)\s*\{|@(Post|Put|Patch|Delete|Get)\s*\([^)]*\)[\s\S]{0,120}?\b\w+\s*\([^)]*\)\s*\{/g;

const MUTATION = /\.(create|createMany|update|updateMany|upsert|delete|deleteMany|save|insert|insertMany|remove|destroy|findOneAndUpdate|findByIdAndUpdate)\s*\(|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM/gi;
const TX_SIG = /\$transaction|\.transaction\s*\(|sequelize\.transaction|getManager\(\)\.transaction|manager\.transaction|BEGIN\b|START\s+TRANSACTION|unitOfWork|db\.transaction|knex\.transaction|withTransaction|runInTransaction|prisma\.\$transaction|@Transaction/i;
// Atomik sayaç güncellemesi (güvenli) sinyalleri.
const ATOMIC_SIG = /\bincrement\b|\bdecrement\b|\$inc\b|increment\s*:|decrement\s*:|FOR\s+UPDATE|SELECT[\s\S]{0,80}FOR\s+UPDATE|findOneAndUpdate|\.raw\s*\(|sql`[^`]*[-+]=|lock\s*:\s*|SELECT\s+FOR\s+UPDATE/i;
// Oku-değiştir-yaz: entity alanına aritmetik atama (x.balance = x.balance - n VEYA x.stock -= n).
const RMW = /(\w+)\.(\w+)\s*(?:\+=|-=)\s*|(\w+)\.(\w+)\s*=\s*\1?\.?\2?\s*[-+]\s*|(\w+)\.(\w+)\s*=\s*\w+\.\w+\s*[-+]/;
const RMW_SAVE = /\.(save|update)\s*\(/i;
// İdempotency guard sinyalleri.
const IDEMPOTENT = /idempotency[_-]?key|idempotencyKey|Idempotency-Key|X-Idempotency|Request-Id|\.upsert\s*\(|findFirst[\s\S]{0,80}(already|exist)|ON\s+CONFLICT|unique\s*:\s*true|dedupe|deduplicat/i;
// FLOW-3 hedef iş akışları (çift-gönderim maliyetli olanlar).
const CRITICAL_CREATE = /\b(order|booking|reservation|transfer|checkout|enrol|enroll|invoice|payout|withdraw|shipment)\b/i;

export interface FlowHandler {
  readonly path: string;
  readonly line: number;
  readonly body: string;
}
export interface FlowFile {
  readonly path: string;
  readonly content: string;
  readonly handlers: readonly FlowHandler[];
}
export interface FlowData {
  readonly usesWeb: boolean;
  readonly files: readonly FlowFile[];
}

/** Bir anchor eşleşmesinden itibaren dengeli süslü parantezle gövdeyi çıkarır. */
function extractBody(content: string, braceOpenIdx: number): string {
  let depth = 0;
  for (let i = braceOpenIdx; i < content.length && i < braceOpenIdx + 12000; i++) {
    const c = content[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return content.slice(braceOpenIdx, i + 1);
    }
  }
  return content.slice(braceOpenIdx, braceOpenIdx + 3000);
}

function lineOf(content: string, idx: number): number {
  let n = 1;
  for (let i = 0; i < idx && i < content.length; i++) if (content[i] === "\n") n++;
  return n;
}

export function collectFlowData(ctx: DetectContext): FlowData {
  const candidates = ctx.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: 6000 });
  const files: FlowFile[] = [];
  let usesWeb = false;
  const WEB_SURFACE = /\b(app|router)\.(get|post|put|delete|patch)\s*\(|@(Post|Put|Patch|Delete|Get|Controller)\b/;

  for (const f of candidates) {
    const raw = ctx.readFile(f);
    if (raw === null || raw.length > 1_000_000) continue;
    const content = stripComments(raw);
    if (!WEB_SURFACE.test(content)) continue;
    usesWeb = true;

    const handlers: FlowHandler[] = [];
    HANDLER_ANCHOR.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = HANDLER_ANCHOR.exec(content)) !== null) {
      const braceIdx = content.indexOf("{", m.index + m[0].length - 1);
      if (braceIdx < 0) continue;
      const body = extractBody(content, braceIdx);
      handlers.push({ path: f, line: lineOf(content, m.index), body });
      // Anchor'ı gövde sonuna atla ki iç içe eşleşmelerde döngü ilerlesin.
      HANDLER_ANCHOR.lastIndex = braceIdx + body.length;
    }
    files.push({ path: f, content, handlers });
  }
  return { usesWeb, files };
}

function countMutations(body: string): number {
  MUTATION.lastIndex = 0;
  let count = 0;
  while (MUTATION.exec(body) !== null) count++;
  return count;
}

// Yazma çağrılarının hedef adlarını çıkarır (prisma.account.update → "account").
// İçerik-türevli olduğundan aynı dosyadaki farklı handler'ları ayrıştırır (satır bağımsız).
const MUT_TARGET = /(\w+)\.(create|createMany|update|updateMany|upsert|delete|deleteMany|save|insert|insertMany|remove|destroy|findOneAndUpdate|findByIdAndUpdate)\s*\(/gi;
function mutationTargets(body: string): string {
  const set = new Set<string>();
  MUT_TARGET.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MUT_TARGET.exec(body)) !== null) {
    const t = (m[1] ?? "").toLowerCase();
    if (t && t !== "prisma" && t !== "db" && t !== "this" && t !== "await") set.add(t);
  }
  return [...set].join(", ") || "?";
}

export function analyzeFlow(data: FlowData): Finding[] {
  if (!data.usesWeb) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };

  for (const file of data.files) {
    for (const h of file.handlers) {
      const body = h.body;

      // FLOW-1 — transaction'sız çok-adımlı yazma.
      const mutations = countMutations(body);
      if (mutations >= 2 && !TX_SIG.test(body)) {
        push(makeFinding({
          id: `FLOW-1-no-transaction:${h.path}:${h.line}`, title: "Transaction'sız çok-adımlı yazma (yarıda kalırsa tutarsız durum)",
          severity: "P1", module: "FLOW", check: "FLOW-1", category: "Data Integrity", confidence: "low",
          evidence: [{ type: "file", source: h.path, location: String(h.line), excerpt: `handler ${mutations} ayrı DB yazma yapıyor (${mutationTargets(body)}); transaction ($transaction/BEGIN) sarmalayıcı yok` }],
          impact: "Bir handler birden fazla kaydı transaction olmadan güncelliyorsa; hata/timeout/çökme yarıda kesince yarım işlem kalır (ör. hesap borçlandırıldı ama karşı hesap alacaklandırılmadı; sipariş oluştu ama stok düşmedi).",
          recommendation: "İlişkili yazmaları tek bir transaction'a al (prisma.$transaction / sequelize.transaction / knex.transaction / BEGIN…COMMIT); hepsi ya birlikte işlensin ya da geri alınsın (atomicity).",
          effort: "M", autoFixable: false, references: ["CWE-662", "CWE-460", "ASVS 11.1"],
        }));
      }

      // FLOW-2 — atomik olmayan oku-değiştir-yaz (lost update / race).
      if (RMW.test(body) && RMW_SAVE.test(body) && !TX_SIG.test(body) && !ATOMIC_SIG.test(body)) {
        const idx = file.content.indexOf(body);
        const off = body.search(RMW);
        const ln = idx >= 0 && off >= 0 ? lineOf(file.content, idx + off) : h.line;
        push(makeFinding({
          id: `FLOW-2-lost-update:${h.path}:${ln}`, title: "Atomik olmayan oku-değiştir-yaz (eşzamanlı istekte kayıp güncelleme / race)",
          severity: "P1", module: "FLOW", check: "FLOW-2", category: "Race Condition", confidence: "low",
          evidence: [{ type: "file", source: h.path, location: String(ln), excerpt: `kaydı oku → alanı aritmetikle değiştir → kaydet (${mutationTargets(body)}); atomik increment/decrement, kilit (FOR UPDATE) veya transaction yok` }],
          impact: "İki istek aynı anda okuyup yazarsa ikincisi birincinin değişikliğini ezer (lost update): stok fazla satılır, bakiye/sayaç yanlış hesaplanır, kupon/kontenjan aşılır.",
          recommendation: "Atomik alan operasyonu kullan (Prisma `{ increment: n }` / Mongo `$inc` / SQL `SET x = x - n`), ya da `SELECT … FOR UPDATE` kilidi veya optimistic locking (version sütunu) uygula.",
          effort: "M", autoFixable: false, references: ["CWE-362", "CWE-567", "OWASP A04:2021"],
        }));
      }

      // FLOW-3 — idempotent olmayan kritik oluşturma (çift-gönderim).
      const createsCritical = /\.(create|insert|save)\s*\(/i.test(body) && CRITICAL_CREATE.test(body);
      const isPost = /\b(app|router)\.post\s*\(|@Post\b/i.test(file.content.slice(Math.max(0, file.content.indexOf(body) - 200), file.content.indexOf(body) + 40));
      if (createsCritical && isPost && !IDEMPOTENT.test(body)) {
        push(makeFinding({
          id: `FLOW-3-no-idempotency:${h.path}:${h.line}`, title: "İdempotent olmayan kritik oluşturma (çift-gönderim → çift sipariş/transfer)",
          severity: "P2", module: "FLOW", check: "FLOW-3", category: "Idempotency", confidence: "low",
          evidence: [{ type: "file", source: h.path, location: String(h.line), excerpt: `sipariş/transfer/rezervasyon oluşturan POST handler (${mutationTargets(body)}); idempotency anahtarı / upsert / mükerrer kontrolü yok` }],
          impact: "Kullanıcı iki kez tıklarsa, ağ retry ederse ya da geri-ileri yaparsa aynı sipariş/transfer/rezervasyon iki kez oluşur — çift tahsilat, çift stok rezervasyonu, mükerrer kayıt.",
          recommendation: "İstemciden idempotency anahtarı al ve tekrarını reddet; ya da doğal anahtarla `upsert` / `ON CONFLICT DO NOTHING` kullan; UI'da çift-gönderimi engelle (buton kilidi tek başına yeterli değildir).",
          effort: "M", autoFixable: false, references: ["CWE-799", "Stripe Idempotency", "ASVS 11.1"],
        }));
      }
    }
  }
  return findings;
}

export const flowModule: WardenModule = {
  id: "FLOW",
  title: "İş-Akışı & Veri Bütünlüğü",
  active: false,
  applicable(ctx: ScanContext) {
    return collectFlowData(ctx.fs).usesWeb;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings = analyzeFlow(collectFlowData(ctx.fs));
    ctx.audit.info(`FLOW: ${findings.length} bulgu.`);
    return { findings };
  },
};
