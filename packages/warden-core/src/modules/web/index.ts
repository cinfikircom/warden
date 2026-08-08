import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül WEB — CSRF, Clickjacking & Güvenlik Başlıkları (pasif, statik).
 * =========================================================================
 * Sunucu-taraflı web sertleştirme; B (CORS/XSS/CSP) ve C/DAST (canlı header) dışında kalanlar:
 *   WEB-1  CSRF koruması yok (çerez-tabanlı oturum + state-değiştiren route var, CSRF yok)
 *   WEB-2  Güvenlik başlıkları / clickjacking koruması yok (helmet/frameguard/X-Frame/HSTS/CSP yok)
 *   WEB-3  Yansıtılan CORS origin + credentials (origin: req.origin → herkese kimlikli erişim)
 *
 * Yalnızca bir web yüzeyi tespit edilirse koşar. Yokluk-temelli bayraklar YORUMSUZ kodda aranır.
 * Heuristik → düşük/orta güven, `.warden-ignore.yml` ile bastırılır.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|cs|java)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__|migrations?)\//i;

export function stripComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/(^|\s)#[^\n]*/g, "$1");
}

/*
 * Web yüzeyi. Django'nun EN YAYGIN view biçimi (function-based view) burada eksikti:
 * `def my_view(request):`. Sonuç, modülün Django projelerinde hiç çalışmaması oldu —
 * pygoat'ta `introduction/views.py` (1200+ satır, 60+ zafiyet) dosya listesine bile
 * girmiyordu. Class-based view (`def get(self, request)`) tanınıyordu, function-based olan
 * tanınmıyordu; oysa Django ekosisteminde ikincisi daha yaygın.
 */
const WEB_SURFACE =
  /\b(app|router)\.(get|post|put|delete|patch|use)\s*\(|express\(\)|fastify\(\)|new Koa|@(Get|Post|Controller)\b|@app\.route|@(?:csrf_exempt|login_required|require_http_methods)\b|\bdef\s+\w+\s*\(\s*request\b|\brender\s*\(\s*request\b|\bHttpResponse\b|\burlpatterns\b/i;

/*
 * State-değiştiren uç. Django/Flask'ta yönlendirme metoda göre değil, gövde içinde
 * `if request.method == "POST"` ile ayrışır — Express'in `app.post(...)` kalıbı yoktur.
 */
const ROUTE_MUT =
  /\b(app|router)\.(post|put|patch|delete)\s*\(|request\.method\s*==\s*["'`](?:POST|PUT|PATCH|DELETE)["'`]|\brequest\.(POST|FILES)\b|@require_(?:POST|http_methods)/i;
// Çerez-tabanlı oturum (CSRF alakalı).
const COOKIE_SESSION = /\b(express-session|cookie-session|cookie-parser|req\.session|passport\.session|connect\.sid|next-auth|iron-session|express-openid-connect)\b|res\.cookie\s*\(/i;
// CSRF koruması sinyalleri.
const CSRF_SIG = /\b(csurf|csrf|xsrf|csrf-csrf|lusca|csrfToken|X-CSRF-Token|X-XSRF-TOKEN|anti.?forgery|antiforgery|double.?submit|@fastify\/csrf|edge-csrf|next-csrf)\b|sameSite\s*:\s*["'`]?strict/i;

/*
 * CSRF korumasının KAPATILDIĞI yerler.
 *
 * Bunlar `CSRF_SIG`'i tetikleyip korumanın VAR olduğu izlenimi veriyordu — içlerinde "csrf"
 * kelimesi geçtiği için. Django'da `@csrf_exempt` tam tersini söyler: middleware'in sağladığı
 * korumayı o view için kaldırır. Sonuç: `@csrf_exempt` ile dolu bir Django projesi
 * "CSRF koruması var" sayılıyor ve WEB-1 hiç tetiklenmiyordu.
 *
 * (pygoat benchmark'ında 20 CSRF maddesinin tamamı bu yüzden kaçtı.)
 */
const CSRF_DISABLED = /@?csrf_exempt\b|@method_decorator\s*\(\s*csrf_exempt|csrf\s*\(\s*\{\s*enabled\s*:\s*false|\.csrf\s*\(\s*(?:csrf\s*=>\s*)?csrf\.disable\(\)\s*\)|csrfProtection\s*:\s*false|CSRF_ENABLED\s*=\s*False/;
// Güvenlik başlıkları / clickjacking koruması.
const SEC_HEADERS_SIG = /\b(helmet|@fastify\/helmet|secure-headers|frameguard|contentSecurityPolicy|Strict-Transport-Security|\bhsts\b|X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|permissionsPolicy|referrerPolicy|secure_headers|django\.middleware\.security)\b/i;
// WEB-3: yansıtılan CORS origin + credentials.
const CORS_REFLECT = /origin\s*:\s*true|origin\s*:\s*req\.(headers\.origin|get\s*\(\s*["'`]origin)|Access-Control-Allow-Origin["'`]?\s*[,:]\s*req\.|setHeader\s*\(\s*["'`]Access-Control-Allow-Origin["'`]\s*,\s*req\./i;
const CREDENTIALS_SIG = /credentials\s*:\s*true|Access-Control-Allow-Credentials["'`]?\s*[,:]\s*["'`]?true/i;

export interface WebFile {
  readonly path: string;
  readonly content: string;
}
export interface WebData {
  readonly usesWeb: boolean;
  readonly hasCookieSession: boolean;
  readonly hasMutRoute: boolean;
  readonly hasCsrf: boolean;
  readonly hasSecHeaders: boolean;
  readonly files: readonly WebFile[];
}

export function collectWebData(ctx: DetectContext): WebData {
  const candidates = ctx.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: 6000 });
  const files: WebFile[] = [];
  let usesWeb = false, hasCookieSession = false, hasMutRoute = false, hasCsrf = false, hasSecHeaders = false;

  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    const code = stripComments(content);
    if (COOKIE_SESSION.test(code)) hasCookieSession = true;
    if (ROUTE_MUT.test(code)) hasMutRoute = true;
    // Kapatma ifadeleri ÖNCE silinir; aksi halde `@csrf_exempt` içindeki "csrf" kelimesi
    // korumanın varlığı sanılır (bkz. CSRF_DISABLED yorumu).
    // Kapatma ifadeleri ve IMPORT satırları önce silinir. `@csrf_exempt` içindeki "csrf"
    // kelimesi korumanın varlığı sanılıyordu; `from django.views.decorators.csrf import
    // csrf_exempt` satırı da aynı şekilde. İkisi de korumanın YOKLUĞUNU gösterir.
    const csrfProbe = code
      .replace(/@?csrf_exempt\b/g, "")
      .replace(/^.*\bimport\b.*$/gm, "");
    if (CSRF_SIG.test(csrfProbe)) hasCsrf = true;
    if (SEC_HEADERS_SIG.test(code)) hasSecHeaders = true;
    if (WEB_SURFACE.test(content)) {
      usesWeb = true;
      files.push({ path: f, content });
    }
  }
  return { usesWeb, hasCookieSession, hasMutRoute, hasCsrf, hasSecHeaders, files };
}

export function analyzeWeb(data: WebData): Finding[] {
  if (!data.usesWeb) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };
  const anchor = data.files[0]?.path ?? "web-surface";

  /*
   * WEB-1 (satır düzeyi) — CSRF koruması AÇIKÇA kapatılmış.
   *
   * Proje-düzeyi "hiç CSRF yok" kontrolünden farklı ve daha kesin: burada framework koruma
   * sağlıyor ama geliştirici onu bu uç için bilerek devre dışı bırakmış. Her biri ayrı bir
   * karardır ve ayrı gerekçe ister.
   */
  for (const { path, content } of data.files) {
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      // Import satırı muafiyetin KULLANIMI değil, yalnızca içe aktarımıdır — bulgu üretmez.
      // (Aksi halde her dosyanın başındaki `from ...csrf import csrf_exempt` sahte bulgu olurdu.)
      if (!CSRF_DISABLED.test(ln) || /\b(import|require)\b/.test(ln)) continue;
      push(makeFinding({
        id: `WEB-1-csrf-disabled:${path}:${i + 1}`,
        title: "CSRF koruması bu uç için devre dışı bırakılmış",
        severity: "P1", module: "WEB", check: "WEB-1", category: "CSRF", confidence: "medium",
        evidence: [{ type: "file", source: path, location: String(i + 1), excerpt: ln.trim().slice(0, 160) }],
        impact:
          "Framework'ün sağladığı CSRF koruması bu uç için kaldırılmış. Çerez tabanlı oturum " +
          "kullanılıyorsa, başka bir site kullanıcının tarayıcısından bu ucu tetikleyebilir.",
        recommendation:
          "Muafiyeti kaldır. Uç gerçekten çerezsiz bir API ise (yalnızca Authorization başlığı) " +
          "bunu açıkça belgele ve oturum çerezini o yolda kabul etme.",
        effort: "S", autoFixable: false,
        references: ["OWASP A01:2021", "CWE-352", "ASVS 4.2.2"],
      }));
    }
  }

  // WEB-1 — CSRF koruması yok (çerez oturumu + yazma route'u var).
  if (data.hasCookieSession && data.hasMutRoute && !data.hasCsrf) {
    push(makeFinding({
      id: "WEB-1-no-csrf", title: "CSRF koruması yok (çerez-tabanlı oturum + state-değiştiren route)",
      severity: "P1", module: "WEB", check: "WEB-1", category: "CSRF", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "çerez oturumu + post/put/patch/delete route var; CSRF token / SameSite=strict sinyali yok" }],
      impact: "Çerezle kimlik doğrulanan yazma endpoint'lerinde CSRF token yoksa saldırgan kurbanın tarayıcısından yetkili istek tetikleyebilir (para transferi, ayar değişikliği).",
      recommendation: "CSRF koruması ekle (senkronizasyon token / double-submit; csurf/csrf-csrf/@fastify/csrf); oturum çerezini SameSite=Lax/Strict + Secure yap; token'lı API'lerde CORS'u sıkı tut.",
      effort: "M", autoFixable: false, references: ["OWASP A01:2021", "CWE-352", "ASVS 4.2"],
    }));
  }

  // WEB-2 — güvenlik başlıkları / clickjacking koruması yok.
  if (!data.hasSecHeaders) {
    push(makeFinding({
      id: "WEB-2-no-security-headers", title: "Güvenlik başlıkları / clickjacking koruması yok",
      severity: "P2", module: "WEB", check: "WEB-2", category: "Security Headers", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "web yüzeyi var; helmet/frameguard/X-Frame-Options/HSTS/CSP sinyali bulunamadı" }],
      impact: "X-Frame-Options/CSP frame-ancestors yoksa clickjacking; HSTS yoksa SSL-strip; nosniff yoksa MIME-sniffing; CSP yoksa XSS etkisi büyür.",
      recommendation: "helmet (veya @fastify/helmet / secure-headers) ekle: X-Frame-Options=DENY veya CSP frame-ancestors 'none', HSTS, X-Content-Type-Options=nosniff, sıkı CSP, Referrer-Policy.",
      effort: "S", autoFixable: false, references: ["OWASP A05:2021", "CWE-1021", "CWE-693"],
    }));
  }

  // WEB-3 — yansıtılan CORS origin + credentials (satır düzeyi).
  for (const { path, content } of data.files) {
    if (!CREDENTIALS_SIG.test(content)) continue;
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      if (CORS_REFLECT.test(ln)) {
        push(makeFinding({
          id: `WEB-3-cors-reflect-credentials:${path}:${i + 1}`, title: "Yansıtılan CORS origin + credentials (herkese kimlikli erişim)",
          severity: "P1", module: "WEB", check: "WEB-3", category: "CORS", confidence: "medium",
          evidence: [{ type: "file", source: path, location: String(i + 1), excerpt: ln.trim().slice(0, 160) }],
          impact: "İstek origin'ini yansıtıp credentials:true vermek, HER kökene çerezli/kimlikli erişim açar — kötü niyetli site kullanıcı adına veri okuyabilir/yazabilir.",
          recommendation: "CORS origin'ini sıkı bir allow-list'e sabitle; credentials ile birlikte ASLA origin'i yansıtma; gerekmiyorsa credentials'ı kapat.",
          effort: "S", autoFixable: false, references: ["OWASP A05:2021", "CWE-942"],
        }));
      }
    }
  }
  return findings;
}

export const webModule: WardenModule = {
  id: "WEB",
  title: "CSRF, Clickjacking & Güvenlik Başlıkları",
  active: false,
  applicable(ctx: ScanContext) {
    return collectWebData(ctx.fs).usesWeb;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const data = collectWebData(ctx.fs);
    const findings = analyzeWeb(data);
    ctx.audit.info(`WEB: ${findings.length} bulgu (${data.files.length} yüzey dosyası).`);
    return { findings, surface: data.files.length };
  },
};
