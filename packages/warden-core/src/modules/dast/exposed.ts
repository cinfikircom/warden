import type { Finding } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import { makeFinding } from "../../util/finding.ts";
import type { ProbeResponse } from "./client.ts";

/**
 * C1 — açıkta kalan hassas dosya probe'u. SPA'lar her yola 200 dönebildiği için her yolun
 * içerik DOĞRULAYICISI vardır (yalnızca gerçekten o dosyaya benziyorsa bulgu üretilir).
 */
export interface ExposedPath {
  readonly path: string;
  readonly severity: Severity;
  readonly title: string;
  /** Gövde gerçekten bu hassas dosya mı (HTML 404/SPA değil). */
  validate(body: string, contentType: string): boolean;
}

const notHtml = (ct: string): boolean => !ct.includes("text/html");

export const EXPOSED_PATHS: readonly ExposedPath[] = [
  { path: "/.env", severity: "P0", title: "Açıkta .env dosyası",
    validate: (b, ct) => notHtml(ct) && /^[A-Z0-9_]+\s*=/m.test(b) },
  { path: "/.git/config", severity: "P0", title: "Açıkta .git/config",
    validate: (b) => /\[core\]|\[remote /.test(b) },
  { path: "/.git/HEAD", severity: "P0", title: "Açıkta .git deposu (/.git/HEAD)",
    validate: (b) => /^ref:\s+refs\//.test(b.trim()) },
  { path: "/.aws/credentials", severity: "P0", title: "Açıkta AWS credentials",
    validate: (b) => /aws_access_key_id/i.test(b) },
  { path: "/.terraform.tfstate", severity: "P0", title: "Açıkta Terraform state",
    validate: (b) => /"terraform_version"|"resources"/.test(b) },
  { path: "/backup.sql", severity: "P0", title: "Açıkta SQL yedeği",
    validate: (b, ct) => notHtml(ct) && /(CREATE TABLE|INSERT INTO|DROP TABLE)/i.test(b) },
  { path: "/.npmrc", severity: "P1", title: "Açıkta .npmrc (token sızıntısı)",
    validate: (b) => /_authToken|registry=/.test(b) },
  { path: "/swagger.json", severity: "P1", title: "Public Swagger/OpenAPI",
    validate: (b) => /"swagger"|"openapi"/.test(b) },
  { path: "/api-docs", severity: "P1", title: "Public API dokümantasyonu",
    validate: (b) => /"swagger"|"openapi"|swagger-ui/i.test(b) },
  { path: "/actuator/health", severity: "P1", title: "Açıkta Spring Actuator",
    validate: (b) => /"status"\s*:\s*"(UP|DOWN)"/.test(b) },
  { path: "/.DS_Store", severity: "P2", title: "Açıkta .DS_Store",
    validate: (b) => b.includes("Bud1") || b.charCodeAt(0) === 0 },
];

/**
 * C1 (ikinci sınıf) — dizin listeleme (autoindex). Ayrı ele alınır çünkü hedef belirli bir
 * DOSYA değil, bir DİZİN yolunun sunucu tarafından listelenmesi. GET-only, non-destructive.
 */
export const LISTING_PATHS: readonly string[] = ["/uploads/", "/files/", "/static/", "/assets/", "/backup/", "/logs/"];

// nginx · Apache · Python http.server · IIS · Node serve-index
const AUTOINDEX_TITLE = /<title>\s*(?:Index of|Directory listing for)\s*\/|<h1>\s*(?:Index of|Directory listing for)\s*\//i;
const AUTOINDEX_BODY =
  /\[To Parent Directory\]|>\s*Parent Directory\s*<|href="\.\.\/?"|<table\s+id="indexlist"|<ul\s+id="files"|<hr>\s*<pre>/i;
// Listede görünen hassas dosya adları şiddeti yükseltir (tahmin değil, kanıt).
const SENSITIVE_IN_LISTING = /href="[^"]*\.(?:env|sql|bak|pem|key|p12|pfx|dump|zip|log|sqlite3?|db)"/i;

/**
 * Bir dizin probe'unu değerlendirir. İKİ BAĞIMSIZ SİNYAL zorunlu (başlık + gövde işareti);
 * tek sinyal yeterli sayılsaydı "Index of /our products" başlıklı normal bir sayfa ya da
 * her yola 200 dönen bir SPA false-positive üretirdi.
 */
export function analyzeDirectoryListing(path: string, res: ProbeResponse): Finding | null {
  if (res.status !== 200) return null;
  const ct = res.headers["content-type"] ?? "";
  if (!ct.includes("text/html")) return null;
  if (!AUTOINDEX_TITLE.test(res.body)) return null;
  if (!AUTOINDEX_BODY.test(res.body)) return null;
  const sensitive = SENSITIVE_IN_LISTING.test(res.body);
  return makeFinding({
    id: `C1-directory-listing:${path}`,
    title: sensitive ? `Dizin listeleme açık ve hassas dosya içeriyor: ${path}` : `Dizin listeleme (autoindex) açık: ${path}`,
    severity: sensitive ? "P0" : "P1",
    module: "C",
    check: "C1",
    category: "Directory Listing",
    confidence: "high",
    evidence: [{ type: "endpoint", source: res.url, location: String(res.status), excerpt: res.body.slice(0, 200) }],
    impact: sensitive
      ? "Dizin listesi internetten okunabiliyor ve yedek/anahtar/log dosyaları görünüyor — doğrudan veri sızıntısı."
      : "Dizin listesi internetten okunabiliyor; dosya envanteri ve yükleme yolları saldırgana keşif kolaylığı sağlar.",
    recommendation:
      "Autoindex'i kapat (nginx `autoindex off;`, Apache `Options -Indexes`, IIS Directory Browsing kapalı, serve-index middleware'ini kaldır); yüklenen dosyaları web kökü dışında sakla ve imzalı URL ile sun.",
    effort: "S",
    autoFixable: false,
    references: ["OWASP A05:2021", "CWE-548", "ASVS 14.3"],
  });
}

/** Tek bir probe yanıtını değerlendirir. */
export function analyzeExposedFile(def: ExposedPath, res: ProbeResponse): Finding | null {
  if (res.status !== 200) return null;
  const ct = res.headers["content-type"] ?? "";
  if (!def.validate(res.body, ct)) return null;
  return makeFinding({
    id: `C1-exposed:${def.path}`,
    title: def.title,
    severity: def.severity,
    module: "C",
    check: "C1",
    category: "Exposed Sensitive File",
    confidence: "high",
    evidence: [{ type: "endpoint", source: res.url, location: String(res.status), excerpt: res.body.slice(0, 120) }],
    impact: "Hassas dosya internetten erişilebilir; secret/şema/altyapı sızıntısı.",
    recommendation: `Bu yolu engelle (web sunucu kuralı/WAF); dosyayı public kökten çıkar; sızan secret'ları rotasyon yap.`,
    effort: "S",
    autoFixable: false,
    references: ["OWASP A05:2021"],
  });
}
