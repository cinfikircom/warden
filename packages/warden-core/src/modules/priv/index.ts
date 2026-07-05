import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül PRIV — Veri Gizliliği & Denetim İzi (pasif, statik).
 * =========================================================================
 * CRM/ERP hassas kişisel veriyle (PII) dolu — KVKK/GDPR uyumu ve denetlenebilirlik şart:
 *   PRIV-1  PII loglanıyor (email/telefon/TCKN/IBAN log satırlarında)
 *   PRIV-2  PII URL/query string'inde (access-log + referrer sızıntısı)
 *   PRIV-3  Yüksek-hassas alan (TCKN/IBAN/kart/sağlık) at-rest şifreleme olmadan saklanıyor
 *   PRIV-4  Silme/anonimleştirme (KVKK/GDPR "unutulma hakkı") mekanizması yok
 *   PRIV-5  Hassas veri erişim/değişiklik denetim izi (audit trail) yok — CRM/ERP uyumu
 *
 * Yalnızca PII alanları tespit edilirse koşar. Yokluk-temelli bayraklar YORUMSUZ kodda aranır.
 * Heuristik → düşük/orta güven, `.warden-ignore.yml` ile bastırılır.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|cs|java)$/i;
const SCHEMA_FILE = /\.prisma$|schema\.sql$|models?\.(py|rb)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__)\//i;

export function stripComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/(^|\s)#[^\n]*/g, "$1");
}

// PII alan adları (uygulanabilirlik + PRIV-1/2).
const PII_FIELD = /\b(e_?mail|phone|telefon|gsm|tc_?kimlik|tckn|ssn|national_?id|passport|iban|address|adres|birth_?date|dogum_?tarihi|full_?name|first_?name|last_?name|surname|credit_?card|card_?number|health|medical|salary|maas|biometric|dni|vat_?number)\b/i;
// Yüksek-hassas (PRIV-3 at-rest şifreleme + PRIV-5 audit için).
const SENSITIVE_HIGH = /\b(tc_?kimlik|tckn|ssn|national_?id|passport|iban|credit_?card|card_?number|health|medical|biometric|salary|maas)\b/i;
// Şifreleme (at-rest) sinyalleri.
const ENCRYPTION_SIG = /\b(encrypt|cipher|pgcrypto|vault|\bkms\b|field.?encrypt|sequelize-encrypted|@Encrypt|EncryptedField|fernet|libsodium|crypto\.createCipheriv|column_?encryption|tde)\b/i;
// Silme/anonimleştirme (KVKK/GDPR erasure) sinyalleri.
const ERASURE_SIG = /\b(anonymi[sz]e|pseudonymi[sz]e|right.?to.?be.?forgotten|gdpr.?delete|kvkk|data.?retention|retention.?policy|purge|deleteAccount|delete_?user|deleteUser|erase.?data|forget.?user|scrub.?pii|hard.?delete)\b/i;
// Denetim izi (audit trail) sinyalleri.
const AUDIT_SIG = /\b(audit.?log|auditlog|audit_?trail|activity.?log|activitylog|paper_?trail|papertrail|django-auditlog|auditing|createAuditLog|logActivity|change.?log|history.?table|record.?history|who.?changed)\b/i;
// Web/handler yüzeyi (PRIV-5 için).
const HANDLER_SIG = /\breq\.(body|params|query)\b|\b(app|router)\.(get|post|put|delete|patch)\s*\(|@(Get|Post|Controller)\b|def\s+\w+\(self,\s*request|ViewSet|\$request->/;

// PRIV-1: log çağrısı + PII.
const LOG_CALL = /(console\.(log|info|debug|warn|error)|logger?\.(info|debug|warn|error|log)|print\(|printf|fmt\.Print|System\.out|Rails\.logger|log\.(info|debug|warn|error))/i;
const PII_ACCESS = /\.(e_?mail|phone|telefon|gsm|tc_?kimlik|tckn|ssn|iban|passport|credit_?card|card_?number|salary|maas|address|adres|health)\b|\b(user|customer|account|profile|patient|member|kullanici|musteri)\b/i;
// PRIV-2: PII URL/query string'inde.
const PII_IN_URL = /[?&](e_?mail|phone|tckn|tc_?kimlik|ssn|iban|token|reset_?token|password|national_?id)=/i;

export interface PrivFile {
  readonly path: string;
  readonly content: string;
}
export interface PrivData {
  readonly usesPii: boolean;
  readonly hasSensitiveHigh: boolean;
  readonly hasEncryption: boolean;
  readonly hasErasure: boolean;
  readonly hasAudit: boolean;
  readonly usesWeb: boolean;
  readonly files: readonly PrivFile[];
}

export function collectPrivData(ctx: DetectContext): PrivData {
  const candidates = ctx.find((p) => (CODE_FILE.test(p) || SCHEMA_FILE.test(p)) && !SKIP.test(p), { limit: 6000 });
  const files: PrivFile[] = [];
  let usesPii = false, hasSensitiveHigh = false, hasEncryption = false, hasErasure = false, hasAudit = false, usesWeb = false;

  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    const code = stripComments(content);
    if (PII_FIELD.test(code)) usesPii = true;
    if (SENSITIVE_HIGH.test(code)) hasSensitiveHigh = true;
    if (ENCRYPTION_SIG.test(code)) hasEncryption = true;
    if (ERASURE_SIG.test(code)) hasErasure = true;
    if (AUDIT_SIG.test(code)) hasAudit = true;
    if (HANDLER_SIG.test(content)) usesWeb = true;
    if (CODE_FILE.test(f)) files.push({ path: f, content });
  }
  return { usesPii, hasSensitiveHigh, hasEncryption, hasErasure, hasAudit, usesWeb, files };
}

export function analyzePriv(data: PrivData): Finding[] {
  if (!data.usesPii) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };
  const anchor = data.files[0]?.path ?? "pii-data";

  // --- Proje düzeyi (yokluk-temelli) ---
  if (data.hasSensitiveHigh && !data.hasEncryption) {
    push(makeFinding({
      id: "PRIV-3-no-encryption-at-rest", title: "Yüksek-hassas alan at-rest şifreleme olmadan saklanıyor",
      severity: "P1", module: "PRIV", check: "PRIV-3", category: "Data Protection", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "TCKN/IBAN/kart/sağlık gibi yüksek-hassas alan var; alan-düzeyi şifreleme (encrypt/pgcrypto/vault) sinyali yok" }],
      impact: "Şifrelenmemiş TCKN/IBAN/kart/sağlık verisi bir DB sızıntısında doğrudan açığa çıkar (KVKK/GDPR özel nitelikli veri).",
      recommendation: "Yüksek-hassas alanlara alan-düzeyi şifreleme uygula (KMS/Vault + envelope encryption ya da pgcrypto/TDE); anahtarları ayrı yönet; maskeleme + erişim kısıtı ekle.",
      effort: "L", autoFixable: false, references: ["KVKK m.12", "GDPR Art.32", "PCI-DSS 3.4", "CWE-311"],
    }));
  }
  if (data.usesPii && !data.hasErasure) {
    push(makeFinding({
      id: "PRIV-4-no-erasure", title: "Silme/anonimleştirme (KVKK/GDPR unutulma hakkı) mekanizması yok",
      severity: "P2", module: "PRIV", check: "PRIV-4", category: "Data Protection", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "PII saklanıyor; silme/anonimleştirme/retention (erasure) mekanizması bulunamadı" }],
      impact: "Silme/anonimleştirme yoksa veri sahibinin talebi karşılanamaz ve süresi dolmuş veri birikir — KVKK/GDPR ihlali, ihlal etki alanı büyür.",
      recommendation: "Hesap silme + anonimleştirme akışı, saklama süresi (retention) politikası ve süresi dolan veriyi otomatik purge/anonymize eden job ekle.",
      effort: "L", autoFixable: false, references: ["KVKK m.7", "GDPR Art.17", "GDPR Art.5(1)(e)"],
    }));
  }
  if (data.usesPii && data.usesWeb && !data.hasAudit) {
    push(makeFinding({
      id: "PRIV-5-no-audit-trail", title: "Hassas veri erişim/değişiklik denetim izi (audit trail) yok",
      severity: "P2", module: "PRIV", check: "PRIV-5", category: "Auditability", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "PII + web/API var; kim-neye-erişti/değiştirdi denetim izi (audit log) sinyali yok" }],
      impact: "Denetim izi olmadan yetkisiz erişim/değişiklik tespit edilemez, ihlal sonrası kapsam belirlenemez — CRM/ERP uyum denetimlerinde zorunlu.",
      recommendation: "Hassas kayıt okuma/yazma/silme işlemlerini değişmez bir audit log'a yaz (aktör, zaman, kayıt, önce/sonra); log'ları koru ve düzenli gözden geçir.",
      effort: "M", autoFixable: false, references: ["KVKK m.12", "GDPR Art.30", "ISO 27001 A.12.4", "SOC 2 CC7"],
    }));
  }

  // --- Dosya/satır düzeyi ---
  for (const { path, content } of data.files) {
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      const loc = String(i + 1);

      // PRIV-1 — PII loglanıyor.
      if (LOG_CALL.test(ln) && PII_ACCESS.test(ln)) {
        push(makeFinding({
          id: `PRIV-1-pii-in-logs:${path}:${i + 1}`, title: "Kişisel veri (PII) log'a yazılıyor",
          severity: "P2", module: "PRIV", check: "PRIV-1", category: "Data Protection", confidence: "low",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "Log'a düşen PII (email/telefon/TCKN/IBAN) merkezi log sistemine, yedeklere ve 3. taraf log servislerine sızar; erişim kontrolü zayıftır.",
          recommendation: "PII'yi loglama; gerekiyorsa maskele/redakte et (yalnızca son 2-4 hane), stabil bir kullanıcı id'si logla; log işleyicide otomatik PII redaksiyonu kur.",
          effort: "S", autoFixable: false, references: ["KVKK m.12", "GDPR Art.5", "OWASP A09:2021", "CWE-532"],
        }));
      }

      // PRIV-2 — PII URL/query string'inde.
      if (PII_IN_URL.test(ln)) {
        push(makeFinding({
          id: `PRIV-2-pii-in-url:${path}:${i + 1}`, title: "Kişisel veri/token URL veya query string'inde",
          severity: "P2", module: "PRIV", check: "PRIV-2", category: "Data Protection", confidence: "medium",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "URL'deki PII/token access-log'lara, tarayıcı geçmişine, proxy'lere ve Referer header ile 3. taraflara sızar.",
          recommendation: "PII/token'ı URL/query'de taşıma; POST gövdesinde ya da güvenli (httpOnly) çerezde tut; doğrulama token'larını tek kullanımlık + kısa ömürlü yap.",
          effort: "M", autoFixable: false, references: ["GDPR Art.5", "OWASP A09:2021", "CWE-598"],
        }));
      }
    }
  }
  return findings;
}

export const privModule: WardenModule = {
  id: "PRIV",
  title: "Veri Gizliliği & Denetim İzi",
  active: false,
  applicable(ctx: ScanContext) {
    return collectPrivData(ctx.fs).usesPii;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings = analyzePriv(collectPrivData(ctx.fs));
    ctx.audit.info(`PRIV: ${findings.length} bulgu.`);
    return { findings };
  },
};
