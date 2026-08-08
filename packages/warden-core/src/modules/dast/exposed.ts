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

// Sık kullanılan doğrulayıcılar — aynı içerik imzası birden çok yolda geçiyor.
const isDotEnv = (b: string, ct: string): boolean => notHtml(ct) && /^[A-Z0-9_]+\s*=/m.test(b);
const isSqlDump = (b: string, ct: string): boolean =>
  notHtml(ct) && /(CREATE TABLE|INSERT INTO|DROP TABLE)/i.test(b);
const isPrivateKey = (b: string): boolean => /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(b);

/**
 * C1 yol kataloğu.
 *
 * v0.12'de 11 → 34 yola çıkarıldı. Yollar Strix'in `information_disclosure` /
 * `path_traversal_lfi_rfi` yüzey listelerinden **olgu olarak** alındı (Apache-2.0; olgusal
 * yol adları telif kapsamında değil) — bkz. docs/STRIX-ADOPTION.md.
 *
 * İKİ KURAL, istisnasız:
 *
 *  1. **Her yolun bir içerik doğrulayıcısı olmalı.** SPA'lar ve catch-all router'lar her yola
 *     200 döner; doğrulayıcı olmadan bu liste bir yanlış pozitif fabrikasına dönerdi. Yolun
 *     "200 dönmesi" hiçbir zaman tek başına bulgu değildir.
 *  2. **Büyük/binary indirilebilecek yollar listeye girmez** (ör. `/actuator/heapdump`,
 *     `/debug/pprof/heap`). Warden non-destructive ve düşük hacimlidir; yüzlerce MB'lık bir
 *     dump çekmek hedefe yük bindirir ve yetki kapısının "non-intrusive" vaadini bozar.
 *
 * Not: liste büyüdükçe hedef başına istek sayısı da artar (34 GET, saniyede 2 istek sınırıyla
 * ~17 sn). Bu bilinçli bir denge: keşif derinliği, hâlâ non-intrusive sayılan bir hacimde.
 */
export const EXPOSED_PATHS: readonly ExposedPath[] = [
  // ---- Ortam / secret dosyaları -------------------------------------------------
  { path: "/.env", severity: "P0", title: "Açıkta .env dosyası", validate: isDotEnv },
  { path: "/.env.local", severity: "P0", title: "Açıkta .env.local", validate: isDotEnv },
  { path: "/.env.production", severity: "P0", title: "Açıkta .env.production", validate: isDotEnv },
  { path: "/.env.bak", severity: "P0", title: "Açıkta .env yedeği", validate: isDotEnv },
  { path: "/.aws/credentials", severity: "P0", title: "Açıkta AWS credentials",
    validate: (b) => /aws_access_key_id/i.test(b) },
  { path: "/.docker/config.json", severity: "P0", title: "Açıkta Docker registry kimlik bilgileri",
    validate: (b) => /"auths"\s*:/.test(b) },
  { path: "/.npmrc", severity: "P1", title: "Açıkta .npmrc (token sızıntısı)",
    validate: (b) => /_authToken|registry=/.test(b) },
  { path: "/.vscode/sftp.json", severity: "P0", title: "Açıkta SFTP dağıtım kimlik bilgileri",
    validate: (b) => /"(password|privateKeyPath|passphrase)"\s*:/.test(b) },

  // ---- Özel anahtarlar ----------------------------------------------------------
  { path: "/id_rsa", severity: "P0", title: "Açıkta SSH özel anahtarı", validate: isPrivateKey },
  { path: "/.ssh/id_rsa", severity: "P0", title: "Açıkta SSH özel anahtarı (/.ssh)", validate: isPrivateKey },
  { path: "/server.key", severity: "P0", title: "Açıkta TLS özel anahtarı", validate: isPrivateKey },
  // GCP service-account JSON: iki alanın BİRLİKTE bulunması aranır — tek başına
  // "private_key" bir OpenAPI şemasında da geçebilir.
  { path: "/credentials.json", severity: "P0", title: "Açıkta GCP service-account anahtarı",
    validate: (b) => /"private_key"\s*:/.test(b) && /"client_email"\s*:/.test(b) },
  { path: "/service-account.json", severity: "P0", title: "Açıkta GCP service-account anahtarı",
    validate: (b) => /"private_key"\s*:/.test(b) && /"client_email"\s*:/.test(b) },

  // ---- Sürüm kontrolü ağaçları --------------------------------------------------
  { path: "/.git/config", severity: "P0", title: "Açıkta .git/config",
    validate: (b) => /\[core\]|\[remote /.test(b) },
  { path: "/.git/HEAD", severity: "P0", title: "Açıkta .git deposu (/.git/HEAD)",
    validate: (b) => /^ref:\s+refs\//.test(b.trim()) },
  // Git index binary'dir ve "DIRC" magic ile başlar — kaynak kodun tamamının
  // yeniden kurulabileceği anlamına gelir.
  { path: "/.git/index", severity: "P0", title: "Açıkta git index (kaynak kod kurtarılabilir)",
    validate: (b) => b.startsWith("DIRC") },
  { path: "/.svn/wc.db", severity: "P0", title: "Açıkta SVN çalışma kopyası veritabanı",
    validate: (b) => b.startsWith("SQLite format 3") },
  { path: "/.hg/requires", severity: "P1", title: "Açıkta Mercurial deposu",
    validate: (b) => /^(revlogv1|dotencode|store|fncache|generaldelta)/m.test(b) },

  // ---- Uygulama yapılandırması --------------------------------------------------
  { path: "/web.config", severity: "P0", title: "Açıkta IIS web.config",
    validate: (b) => /<configuration[\s>]/.test(b) },
  { path: "/appsettings.json", severity: "P0", title: "Açıkta .NET appsettings.json",
    validate: (b) => /"(ConnectionStrings|Logging|AllowedHosts)"\s*:/.test(b) },
  { path: "/settings.py", severity: "P0", title: "Açıkta Django settings.py",
    validate: (b) => /SECRET_KEY\s*=|DATABASES\s*=/.test(b) },
  // PHP normalde yorumlanıp sunulur; ham `<?php` görünmesi kaynak sızıntısıdır.
  { path: "/config.php", severity: "P0", title: "Açıkta PHP yapılandırma kaynağı",
    validate: (b) => /<\?php/.test(b) },
  { path: "/wp-config.php.bak", severity: "P0", title: "Açıkta WordPress yapılandırma yedeği",
    validate: (b) => /DB_PASSWORD|DB_NAME/.test(b) },
  { path: "/docker-compose.yml", severity: "P1", title: "Açıkta docker-compose.yml",
    validate: (b, ct) => notHtml(ct) && /^\s*services\s*:/m.test(b) },
  { path: "/.htaccess", severity: "P1", title: "Açıkta .htaccess",
    validate: (b) => /RewriteEngine|AuthType|Order\s+(allow|deny)/i.test(b) },
  { path: "/.terraform.tfstate", severity: "P0", title: "Açıkta Terraform state",
    validate: (b) => /"terraform_version"|"resources"/.test(b) },

  // ---- Veritabanı yedekleri ------------------------------------------------------
  { path: "/backup.sql", severity: "P0", title: "Açıkta SQL yedeği", validate: isSqlDump },
  { path: "/dump.sql", severity: "P0", title: "Açıkta SQL dump", validate: isSqlDump },
  { path: "/database.sql", severity: "P0", title: "Açıkta veritabanı dökümü", validate: isSqlDump },

  // ---- Debug / teşhis yüzeyleri --------------------------------------------------
  // Not: /actuator/heapdump ve /debug/pprof/heap BİLEREK yok — yüzlerce MB indirir.
  { path: "/actuator/health", severity: "P1", title: "Açıkta Spring Actuator",
    validate: (b) => /"status"\s*:\s*"(UP|DOWN)"/.test(b) },
  { path: "/actuator/env", severity: "P0", title: "Açıkta Spring Actuator /env (secret sızıntısı)",
    validate: (b) => /"propertySources"\s*:/.test(b) },
  { path: "/debug/pprof/", severity: "P1", title: "Açıkta Go pprof profilleyici",
    validate: (b) => /Types of profiles available|<a href="(goroutine|heap|allocs)\?/.test(b) },
  { path: "/metrics", severity: "P1", title: "Açıkta Prometheus metrikleri",
    validate: (b, ct) => notHtml(ct) && /^#\s+(HELP|TYPE)\s+\w+/m.test(b) },
  { path: "/_profiler", severity: "P0", title: "Açıkta Symfony profiler (üretimde debug açık)",
    validate: (b) => /Symfony Profiler|sf-profiler/i.test(b) },
  { path: "/phpinfo.php", severity: "P1", title: "Açıkta phpinfo() çıktısı",
    validate: (b) => /<title>phpinfo\(\)|PHP Version\s*<\/td>/i.test(b) },
  { path: "/server-status", severity: "P1", title: "Açıkta Apache server-status",
    validate: (b) => /Apache Server Status/i.test(b) },

  // ---- API yüzeyi ----------------------------------------------------------------
  { path: "/swagger.json", severity: "P1", title: "Public Swagger/OpenAPI",
    validate: (b) => /"swagger"|"openapi"/.test(b) },
  { path: "/openapi.json", severity: "P1", title: "Public OpenAPI şeması",
    validate: (b) => /"openapi"\s*:/.test(b) },
  { path: "/api-docs", severity: "P1", title: "Public API dokümantasyonu",
    validate: (b) => /"swagger"|"openapi"|swagger-ui/i.test(b) },

  // ---- Düşük şiddetli keşif sinyalleri --------------------------------------------
  { path: "/.DS_Store", severity: "P2", title: "Açıkta .DS_Store",
    validate: (b) => b.includes("Bud1") || b.charCodeAt(0) === 0 },
  { path: "/.idea/workspace.xml", severity: "P2", title: "Açıkta IDE proje dosyası",
    validate: (b) => /<project\s+version=/.test(b) },
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
    references: ["OWASP A05:2021", "CWE-538", "ASVS 14.3"],
  });
}
