import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";
import { scanSource, SKIP_PATH } from "../sast/scanner.ts";
import { FE_RULES } from "./rules.ts";

/**
 * Modül FE — Frontend Security (pasif, statik).
 * =========================================================================
 * Tarayıcıda çalışan kodun kendi saldırı yüzeyi:
 *   FE-1  Token web storage'da            FE-5  postMessage / message origin
 *   FE-2  Zayıf CSP (unsafe-inline/eval)  FE-6  target=_blank + rel yok (tabnabbing)
 *   FE-3  DOM-XSS sink'leri               FE-7  Harici script/stylesheet SRI yok
 *   FE-4  Üretimde source map
 *
 * İKİ KATMAN:
 *   (a) FE_RULES  → scanSource: tek satırda kanıtlanabilen sink'ler (rules.ts).
 *   (b) analyzeFe → saf pencere analizi: tek satıra SIĞMAYAN ilişkiler. Satır-bazlı tarayıcı
 *       bunları yapısal olarak yakalayamaz (CSP direktifi ile 'unsafe-inline' tipik helmet
 *       yazımında farklı satırlardadır; <a> etiketinde target ve rel JSX'te ayrı satırlara düşer).
 *
 * Yalnızca bir frontend yüzeyi tespit edilirse koşar; yüzey yoksa FE boyutu doğru şekilde
 * "n/d" kalır, yüzey varsa ve bulgu yoksa 10/10 puanlanır.
 * =========================================================================
 */

// ---- KATMAN 1: dosya filtreleri + sinyal regexleri ----------------------

/** FE taramasına giren dosyalar. scanner CODE_FILE'ından farkı: html/htm/njk/ejs/hbs/mdx. */
const FE_SCAN_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|mts|cts|vue|svelte|astro|html|htm|njk|ejs|hbs|mdx)$/i;

/** scanner SKIP_PATH + frontend build çıktıları + tip tanımları + hash'li bundle'lar. */
const FE_SKIP = new RegExp(
  SKIP_PATH.source +
    "|(^|\\/)(\\.svelte-kit|\\.nuxt|\\.astro|\\.output|out|storybook-static|\\.cache)\\/" +
    "|\\.d\\.ts$|\\.bundle\\.js$|-[0-9a-f]{8}\\.js$",
  "i",
);

/** Frontend yüzey sinyalleri. */
const FE_EXT = /\.(jsx|tsx|vue|svelte|astro)$/i;
const FE_DEP =
  /"(react|react-dom|next|vue|nuxt|svelte|@sveltejs\/kit|astro|@angular\/core|solid-js|preact|remix|@remix-run\/react|gatsby|lit|alpinejs|htmx\.org)"\s*:/;
/** Framework'süz ("vanilla") frontend: tarayıcıya servis edilen, script içeren bir HTML sayfası. */
const FE_HTML = /\.html?$/i;
const HTML_HAS_SCRIPT = /<script[\s>]/i;

// FE-2 — CSP. Anchor'dan sonra bir PENCERE içinde unsafe-* aranır (çok satırlı helmet/Next yazımı).
const CSP_ANCHOR = /(Content-Security-Policy|contentSecurityPolicy|(?:script|style|default)[-_]?[sS]rc)/g;
const CSP_UNSAFE = /'?unsafe-(?:inline|eval)'?/i;
const CSP_WINDOW = 500; // ~12 satırlık helmet directives bloğu

// FE-5b — message dinleyicisinde origin doğrulaması.
const MSG_LISTENER = /addEventListener\s*\(\s*["'`]message["'`]/g;
const ORIGIN_CHECK = /\.origin\b|origin\s*(?:===|==|!==|!=)|ALLOWED_ORIGINS|allowedOrigins|trustedOrigins?|isTrustedOrigin/i;
const MSG_WINDOW = 1200; // ~30 satırlık handler gövdesi

// FE-6 — tabnabbing.
const ANCHOR_TAG = /<(?:a|Link|NuxtLink|area)\b[^>]*>/gi;
const BLANK_TARGET = /target\s*=\s*["'{`]?\s*_blank/i;
const REL_SAFE = /rel\s*=\s*["'{`][^"'}`]*\bno(?:opener|referrer)\b/i;

// FE-7 — Subresource Integrity.
const SCRIPT_OR_LINK = /<(script|link)\b[^>]*>/gi;
const EXTERNAL_URL = /\b(?:src|href)\s*=\s*["']?(?:https?:)?\/\/[^"'\s>]+/i;
const HAS_INTEGRITY = /\bintegrity\s*=\s*["'][^"']{10,}["']/i;
const IS_STYLESHEET = /\brel\s*=\s*["']?stylesheet["']?/i;

/** Pencere kuralı başına dosya başına en fazla bulgu (gürültü tavanı). */
const MAX_PER_FILE = 3;

// ---- Yardımcılar --------------------------------------------------------

/**
 * Yorumları AYNI UZUNLUKTA boşlukla değiştirir (satır sonları korunur).
 * `stripComments`'ten farkı: karakter offset'leri ve satır numaraları BOZULMAZ — pencere
 * analizinde bulguyu doğru satıra bağlamak için zorunlu.
 * `(^|[^:"'\`\\])` ön-koşulu `https://` ve `"//cdn.example.com"` protokol-göreli URL'lerini korur.
 */
export function blankComments(s: string): string {
  const blank = (m: string): string => m.replace(/[^\n]/g, " ");
  return s
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, (m, p1: string) => p1 + " ".repeat(m.length - p1.length));
}

/** HTML yorumlarını (<!-- -->) uzunluk koruyarak siler. */
export function blankHtmlComments(s: string): string {
  return s.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
}

/** Dosya başına BİR KEZ kurulan offset→satır çevirici (ikili arama; O(n) tarama yerine). */
function lineIndexer(text: string): (index: number) => number {
  const starts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (index) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((starts[mid] as number) <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

/** Kanıt metnini tek satıra indirger ve kırpar. */
function excerptOf(s: string): string {
  return s.replace(/\s+/g, " ").trim().slice(0, 200);
}

const isTemplate = (path: string): boolean => /\.(html?|njk|ejs|hbs)$/i.test(path);

// ---- KATMAN 2: toplama --------------------------------------------------

export interface FeFile {
  readonly path: string;
  readonly content: string;
}
export interface FeData {
  readonly hasSurface: boolean;
  readonly files: readonly FeFile[];
}

/**
 * Frontend yüzeyi var mı — UCUZ probe, ScanContext başına MEMOIZE edilir.
 * Diğer modüllerdeki "applicable() ve run() ikisi de tam collect eder" israfını tekrarlamamak
 * için: applicable yalnız bu boolean'ı sorar, run tam collectFeData'yı bir kez çağırır.
 */
const surfaceCache = new WeakMap<DetectContext, boolean>();

export function hasFrontendSurface(fs: DetectContext): boolean {
  const cached = surfaceCache.get(fs);
  if (cached !== undefined) return cached;
  const out = detectSurface(fs);
  surfaceCache.set(fs, out);
  return out;
}

function detectSurface(fs: DetectContext): boolean {
  const pkg = fs.readFile("package.json") ?? "";
  if (FE_DEP.test(pkg)) return true;
  if (fs.find((p) => FE_EXT.test(p) && !FE_SKIP.test(p), { limit: 1, maxDepth: 6 }).length > 0) return true;
  // Framework yoksa da tarayıcı kodu olabilir: script içeren bir HTML sayfası da frontend'dir.
  // (Aksi halde vanilla ES-module panelleri Modül FE'ye tamamen görünmez kalırdı.)
  for (const p of fs.find((p) => FE_HTML.test(p) && !FE_SKIP.test(p), { limit: 20, maxDepth: 6 })) {
    if (HTML_HAS_SCRIPT.test(fs.readFile(p) ?? "")) return true;
  }
  return false;
}

/** Pencere analizi için ham dosya içerikleri. */
export function collectFeData(fs: DetectContext): FeData {
  if (!hasFrontendSurface(fs)) return { hasSurface: false, files: [] };
  const paths = fs.find((p) => FE_SCAN_FILE.test(p) && !FE_SKIP.test(p), { limit: 4000, maxDepth: 6 });
  const files: FeFile[] = [];
  for (const p of paths) {
    const content = fs.readFile(p);
    if (content === null || content.length > 1_000_000) continue;
    files.push({ path: p, content });
  }
  return { hasSurface: true, files };
}

// ---- KATMAN 3: saf analiz (pencere kuralları) ---------------------------

type Push = (f: Finding) => void;

/** FE-2 — CSP 'unsafe-inline'/'unsafe-eval'. Dosya başına en fazla bir bulgu. */
function checkCspUnsafe(file: FeFile, push: Push): void {
  const code = isTemplate(file.path) ? blankHtmlComments(file.content) : blankComments(file.content);
  const lineOf = lineIndexer(code);
  CSP_ANCHOR.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = CSP_ANCHOR.exec(code)) !== null) {
    const window = code.slice(m.index, m.index + CSP_WINDOW);
    if (!CSP_UNSAFE.test(window)) continue;
    const line = lineOf(m.index);
    push(
      makeFinding({
        id: `FE-csp-unsafe:${file.path}:${line}`,
        title: "CSP 'unsafe-inline'/'unsafe-eval' (XSS koruması zayıf)",
        severity: "P2",
        module: "FE",
        check: "FE-2",
        category: "Security Misconfiguration",
        confidence: "medium",
        evidence: [{ type: "file", source: file.path, location: String(line), excerpt: excerptOf(window) }],
        impact:
          "unsafe-inline/unsafe-eval CSP'nin XSS korumasını büyük ölçüde etkisizleştirir; script enjeksiyonu tarayıcı tarafından engellenmez.",
        recommendation:
          "nonce veya hash tabanlı CSP'ye geç ('strict-dynamic'); inline script/style'ı çıkar; eval/new Function kullanımını kaldır.",
        effort: "M",
        autoFixable: false,
        references: ["OWASP A05:2021", "CWE-1021", "ASVS 14.4"],
      }),
    );
    return; // dosya başına tek bulgu — aynı directives bloğu birden çok anchor içerir
  }
}

/** FE-5b — message dinleyicisinde origin doğrulaması yok (yokluk temelli → düşük güven). */
function checkMessageOrigin(file: FeFile, push: Push): void {
  if (isTemplate(file.path)) return;
  const code = blankComments(file.content);
  const lineOf = lineIndexer(code);
  MSG_LISTENER.lastIndex = 0;
  let m: RegExpExecArray | null;
  let hits = 0;
  while ((m = MSG_LISTENER.exec(code)) !== null && hits < MAX_PER_FILE) {
    const window = code.slice(m.index, m.index + MSG_WINDOW);
    if (ORIGIN_CHECK.test(window)) continue;
    hits++;
    const line = lineOf(m.index);
    push(
      makeFinding({
        id: `FE-message-no-origin:${file.path}:${line}`,
        title: "postMessage dinleyicisinde gönderici origin doğrulaması yok",
        severity: "P1",
        module: "FE",
        check: "FE-5",
        category: "Cross-Origin Messaging",
        confidence: "low",
        evidence: [{ type: "file", source: file.path, location: String(line), excerpt: excerptOf(window.slice(0, 200)) }],
        impact:
          "message dinleyicisi göndericinin kökenini doğrulamıyor; herhangi bir site iframe/opener üzerinden komut veya veri enjekte edebilir.",
        recommendation:
          "Handler'ın ilk satırında `if (event.origin !== 'https://app.example.com') return;` kontrolü yap; mümkünse MessageChannel kullan.",
        effort: "S",
        autoFixable: false,
        references: ["OWASP A05:2021", "CWE-346", "ASVS 14.4"],
      }),
    );
  }
}

/** FE-6 — target="_blank" var, rel="noopener|noreferrer" yok (reverse tabnabbing). */
function checkTabnabbing(file: FeFile, push: Push): void {
  const code = isTemplate(file.path) ? blankHtmlComments(file.content) : file.content;
  const lineOf = lineIndexer(code);
  ANCHOR_TAG.lastIndex = 0;
  let m: RegExpExecArray | null;
  let hits = 0;
  while ((m = ANCHOR_TAG.exec(code)) !== null && hits < MAX_PER_FILE) {
    const tag = m[0];
    if (!BLANK_TARGET.test(tag) || REL_SAFE.test(tag)) continue;
    hits++;
    const line = lineOf(m.index);
    push(
      makeFinding({
        id: `FE-tabnabbing:${file.path}:${line}`,
        title: 'target="_blank" bağlantısında rel="noopener" yok (reverse tabnabbing)',
        severity: "P3",
        module: "FE",
        check: "FE-6",
        category: "Frontend Hardening",
        confidence: "medium",
        evidence: [{ type: "file", source: file.path, location: String(line), excerpt: excerptOf(tag) }],
        impact:
          "target=_blank ile açılan sayfa window.opener üzerinden kaynak sekmeyi başka bir URL'e yönlendirebilir (reverse tabnabbing → phishing).",
        recommendation:
          'rel="noopener noreferrer" ekle. Modern tarayıcılar örtük noopener uygular; eski tarayıcı desteği için hâlâ gerekli.',
        effort: "S",
        autoFixable: false,
        references: ["OWASP A05:2021", "CWE-1022"],
      }),
    );
  }
}

/** FE-7 — harici script/stylesheet integrity (SRI) hash'i yok. */
function checkSubresourceIntegrity(file: FeFile, push: Push): void {
  const code = isTemplate(file.path) ? blankHtmlComments(file.content) : file.content;
  const lineOf = lineIndexer(code);
  SCRIPT_OR_LINK.lastIndex = 0;
  let m: RegExpExecArray | null;
  let hits = 0;
  while ((m = SCRIPT_OR_LINK.exec(code)) !== null && hits < MAX_PER_FILE) {
    const tag = m[0];
    // Yalnız HARİCİ kaynaklar: göreli/aynı-köken yollar SRI gerektirmez.
    if (!EXTERNAL_URL.test(tag) || HAS_INTEGRITY.test(tag)) continue;
    if (m[1]?.toLowerCase() === "link" && !IS_STYLESHEET.test(tag)) continue; // preconnect/icon vb. değil
    hits++;
    const line = lineOf(m.index);
    push(
      makeFinding({
        id: `FE-sri-missing:${file.path}:${line}`,
        title: "Harici script/stylesheet integrity (SRI) hash'i olmadan yükleniyor",
        severity: "P2",
        module: "FE",
        check: "FE-7",
        category: "Supply Chain",
        confidence: "medium",
        evidence: [{ type: "file", source: file.path, location: String(line), excerpt: excerptOf(tag) }],
        impact:
          "Harici CDN kaynağı integrity hash'i olmadan yükleniyor; CDN ele geçirilirse veya MITM olursa keyfi script çalışır (Magecart sınıfı saldırı).",
        recommendation:
          'integrity="sha384-..." + crossorigin="anonymous" ekle; mümkünse bağımlılığı self-host et.',
        effort: "S",
        autoFixable: false,
        references: ["OWASP A08:2021", "CWE-353", "ASVS 14.2"],
      }),
    );
  }
}

/** Pencere kurallarını uygular. Saf fonksiyon — I/O yok, doğrudan unit-testlenebilir. */
export function analyzeFe(data: FeData): Finding[] {
  if (!data.hasSurface) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push: Push = (f) => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };
  for (const file of data.files) {
    checkCspUnsafe(file, push);
    checkMessageOrigin(file, push);
    checkTabnabbing(file, push);
    checkSubresourceIntegrity(file, push);
  }
  return findings;
}

// ---- KATMAN 4: modül sözleşmesi -----------------------------------------

export const feModule: WardenModule = {
  id: "FE",
  title: "Frontend Security",
  active: false,
  applicable(ctx: ScanContext) {
    return hasFrontendSurface(ctx.fs); // memoize → run'da ağaç ikinci kez yürünmez
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    try {
      const line = scanSource(ctx.fs, FE_RULES, {
        maxFiles: 4000,
        include: FE_SCAN_FILE,
        skip: FE_SKIP,
        maxDepth: 6,
      });
      const window = analyzeFe(collectFeData(ctx.fs));
      const seen = new Set<string>();
      const findings = [...line, ...window].filter((f) => (seen.has(f.fingerprint) ? false : (seen.add(f.fingerprint), true)));
      ctx.audit.info(`FE: ${findings.length} bulgu (${line.length} satır-kuralı + ${window.length} pencere).`);
      return { findings };
    } catch (err) {
      // Sözleşme (model/module.ts): run hata FIRLATMAMALI; üretemezse boş sonuç + uyarı.
      ctx.audit.warn(`FE modülü analiz hatası, boş sonuç döndürüldü: ${String(err)}`);
      return { findings: [] };
    }
  },
};
