import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül UPLOAD — Dosya Yükleme Güvenliği (pasif, statik).
 * =========================================================================
 * SaaS/CRM/ERP'lerde neredeyse her yerde dosya yükleme var; klasik yüksek-etkili açık sınıfı.
 *   UPLOAD-1  Kısıtsız dosya tipi (fileFilter / uzantı-mimetype whitelist yok → webshell)
 *   UPLOAD-2  Kullanıcı adıyla path traversal (originalname fs yoluna basename'siz giriyor)
 *   UPLOAD-3  Boyut limiti yok (limits.fileSize yok → DoS / disk doldurma)
 *   UPLOAD-4  Yüklenenler web-root'ta / çalıştırılabilir servis altında saklanıyor
 *
 * Yalnızca bir yükleme yüzeyi (multer/formidable/busboy/express-fileupload…) varsa koşar.
 * Yokluk-temelli bayraklar YORUMSUZ kodda aranır. Heuristik → düşük/orta güven.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__|migrations?)\//i;

export function stripComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/(^|\s)#[^\n]*/g, "$1");
}

// Yükleme yüzeyi.
const UPLOAD_SIG = /\bmulter\b|formidable|busboy|express-fileupload|@fastify\/multipart|multiparty|multipart\/form-data|\.single\s*\(|\.array\s*\(|\.fields\s*\(|req\.files?\b|request\.files\b|\bUploadedFile\b|MultipartFile/i;
// Tip kısıtlama sinyalleri (whitelist / fileFilter).
const TYPE_RESTRICT = /fileFilter|allowedMimeTypes|allowedExtensions|mimetype\s*===|mimetype\s*==|\.(includes|test|match)\s*\([^)]*(image|pdf|mime|ext)|whitelist|accept\s*:|ALLOWED_(TYPES|EXT|MIME)|magic\s*number|file-type/i;
// Boyut limiti sinyalleri.
const SIZE_LIMIT = /limits\s*:\s*\{[^}]*fileSize|fileSize\s*:|maxFileSize|MAX_(FILE_)?SIZE|max_size|content-length[\s\S]{0,40}(limit|max)/i;
// UPLOAD-2: kullanıcı adıyla dosya yolu — originalname/filename fs yoluna giriyor.
const NAME_IN_PATH = /(path\.(join|resolve)|createWriteStream|writeFileSync|writeFile|\.mv\s*\(|rename(Sync)?|fs\.)[^;\n]*\b(originalname|req\.body\.\w*(name|file)|filename)\b|\b(dest|path|filepath|filePath)\s*[:=][^;\n]*\boriginalname\b/i;
const SANITIZED = /path\.basename|sanitize|slugify|uuid|randomUUID|nanoid|crypto\.random|Date\.now\(\)|replace\s*\([^)]*[\\/]/i;
// UPLOAD-4: web-root / public servis altında saklama.
const WEBROOT_STORE = /(dest|destination|uploadDir|path)\s*[:=]\s*[`'"][^`'"]*(public|static|www|htdocs|wwwroot|assets)[\\/][^`'"]*/i;

export interface UploadFile {
  readonly path: string;
  readonly content: string;
}
export interface UploadData {
  readonly usesUpload: boolean;
  readonly hasTypeRestrict: boolean;
  readonly hasSizeLimit: boolean;
  readonly files: readonly UploadFile[];
}

export function collectUploadData(ctx: DetectContext): UploadData {
  const candidates = ctx.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: 6000 });
  const files: UploadFile[] = [];
  let usesUpload = false, hasTypeRestrict = false, hasSizeLimit = false;
  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    const code = stripComments(content);
    if (!UPLOAD_SIG.test(content)) continue;
    usesUpload = true;
    if (TYPE_RESTRICT.test(code)) hasTypeRestrict = true;
    if (SIZE_LIMIT.test(code)) hasSizeLimit = true;
    files.push({ path: f, content });
  }
  return { usesUpload, hasTypeRestrict, hasSizeLimit, files };
}

export function analyzeUpload(data: UploadData): Finding[] {
  if (!data.usesUpload) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };
  const anchor = data.files[0]?.path ?? "upload-surface";

  // UPLOAD-1 — kısıtsız dosya tipi (whitelist/fileFilter yok).
  if (!data.hasTypeRestrict) {
    push(makeFinding({
      id: "UPLOAD-1-no-type-restriction", title: "Kısıtsız dosya tipi (uzantı/MIME whitelist yok → webshell riski)",
      severity: "P1", module: "UPLOAD", check: "UPLOAD-1", category: "Unrestricted Upload", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "yükleme yüzeyi var; fileFilter / izinli uzantı-MIME whitelist sinyali bulunamadı" }],
      impact: "Dosya tipi kısıtlanmazsa saldırgan çalıştırılabilir dosya (.php/.jsp/.svg/polyglot) yükleyip sunucuda kod çalıştırabilir (webshell) veya stored-XSS tetikleyebilir.",
      recommendation: "İzinli MIME/uzantı whitelist'i uygula (deny-list değil); içeriği magic-number/file-type ile doğrula; dosyayı rastgele adla, çalıştırılamayan bir depoda (tercihen imzalı obje storage) sakla.",
      effort: "M", autoFixable: false, references: ["OWASP A04:2021", "CWE-434", "ASVS 12.1"],
    }));
  }

  // UPLOAD-3 — boyut limiti yok.
  if (!data.hasSizeLimit) {
    push(makeFinding({
      id: "UPLOAD-3-no-size-limit", title: "Yükleme boyut limiti yok (DoS / disk doldurma)",
      severity: "P2", module: "UPLOAD", check: "UPLOAD-3", category: "Resource Limit", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "yükleme yüzeyi var; limits.fileSize / maxFileSize sinyali bulunamadı" }],
      impact: "Boyut limiti yoksa çok büyük dosyalar bellek/diski tüketip servisi düşürebilir (DoS) veya depolama maliyetini şişirebilir.",
      recommendation: "Yükleme boyutunu sınırla (multer `limits.fileSize`, `@fastify/multipart` limits, reverse-proxy `client_max_body_size`); dosya sayısı/alan limitlerini de ayarla.",
      effort: "S", autoFixable: false, references: ["OWASP A04:2021", "CWE-400", "CWE-770"],
    }));
  }

  // UPLOAD-2 (satır) — kullanıcı adıyla path traversal · UPLOAD-4 (satır) — web-root'ta saklama.
  for (const { path, content } of data.files) {
    const lines = stripComments(content).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      const window = ln + " " + (lines[i + 1] ?? "");
      if (NAME_IN_PATH.test(ln) && !SANITIZED.test(window)) {
        push(makeFinding({
          id: `UPLOAD-2-path-traversal:${path}:${i + 1}`, title: "Kullanıcı dosya adıyla path traversal (basename/sanitize yok)",
          severity: "P0", module: "UPLOAD", check: "UPLOAD-2", category: "Path Traversal", confidence: "medium",
          evidence: [{ type: "file", source: path, location: String(i + 1), excerpt: ln.trim().slice(0, 160) }],
          impact: "Kullanıcı kontrollü dosya adı (originalname) doğrudan dosya sistemi yoluna girerse `../../` ile dizin dışına yazma yapılabilir (ör. mevcut dosyaların üzerine yazma, cron/webshell yerleştirme).",
          recommendation: "Kullanıcı adını asla yol olarak kullanma; `path.basename()` uygula ve rastgele/uuid ad üret; hedef dizini kök-dışına çıkamayacak şekilde çözümleyip doğrula.",
          effort: "S", autoFixable: false, references: ["OWASP A01:2021", "CWE-22", "CWE-23"],
        }));
      }
      if (WEBROOT_STORE.test(ln)) {
        push(makeFinding({
          id: `UPLOAD-4-webroot-storage:${path}:${i + 1}`, title: "Yüklenenler web-root'ta / public servis altında saklanıyor",
          severity: "P1", module: "UPLOAD", check: "UPLOAD-4", category: "Insecure Storage", confidence: "low",
          evidence: [{ type: "file", source: path, location: String(i + 1), excerpt: ln.trim().slice(0, 160) }],
          impact: "Yüklenen dosyalar public/static kök altında saklanırsa doğrudan URL ile servis edilir; yüklenen bir script sunucuda çalışabilir (webshell) veya HTML/SVG stored-XSS tetikler.",
          recommendation: "Yüklenenleri web-root DIŞINDA (ya da obje storage'da) sakla; imzalı/kısa-ömürlü URL ile ver; servis dizininde script çalıştırmayı kapat (X-Content-Type-Options, Content-Disposition:attachment).",
          effort: "M", autoFixable: false, references: ["OWASP A04:2021", "CWE-434", "CWE-552"],
        }));
      }
    }
  }
  return findings;
}

export const uploadModule: WardenModule = {
  id: "UPLOAD",
  title: "Dosya Yükleme Güvenliği",
  active: false,
  applicable(ctx: ScanContext) {
    return collectUploadData(ctx.fs).usesUpload;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings = analyzeUpload(collectUploadData(ctx.fs));
    ctx.audit.info(`UPLOAD: ${findings.length} bulgu.`);
    return { findings };
  },
};
