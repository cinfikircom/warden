import type { SourceRule } from "../sast/scanner.ts";

/**
 * Modül FE — satır bazında kanıtlanabilen frontend kuralları.
 * =========================================================================
 * BÖLME KURALI: tek satırda kanıtlanabilen kontrol BURAYA (scanSource ile taranır);
 * pencere/yokluk/etiket-içi ilişki gerektiren kontrol `index.ts::analyzeFe`'ye gider
 * (CSP direktifi ↔ unsafe-*, <a target> ↔ rel, <script src> ↔ integrity,
 *  addEventListener("message") ↔ origin kontrolü).
 * =========================================================================
 */

/**
 * Sanitize/kaçış sinyali aynı satırdaysa bulguyu düşür — tüm XSS sink'lerinde ortak FP azaltıcı.
 * Kütüphane sanitizer'ları (DOMPurify) kadar elle yazılmış kaçış yardımcılarını da tanır:
 * `esc(x)` / `escapeHtml(x)` / `htmlEscape(x)` yaygın ve doğru kalıplardır; bunları bulgulamak
 * gürültüdür. (Warden'ın kendi panelinde ölçüldü — bkz. security-knight/knight.js.)
 */
const notSanitized = (line: string): boolean =>
  !/\b(DOMPurify|sanitize(Html|d|Url)?|purify|xss\s*\(|escapeHtml|escapeHTML|htmlEscape|encodeHTML|esc\s*\()/i.test(line);

/** XSS sink'lerinin ortak kanıt metinleri (tekrarları önler). */
const XSS_REFS = ["OWASP A03:2021", "CWE-79", "ASVS 5.3"] as const;

export const FE_RULES: readonly SourceRule[] = [
  // ---- FE-1: token web storage'da ----------------------------------------
  {
    id: "FE-jwt-localstorage",
    check: "FE-1",
    module: "FE",
    title: "JWT/token localStorage/sessionStorage'da (XSS'e açık)",
    severity: "P1",
    category: "Auth Design",
    confidence: "high",
    // Üç yazım biçimini birden yakalar: setItem("access_token") · ["jwt"] = · .authToken =
    pattern:
      /(localStorage|sessionStorage)\s*(?:\.setItem\s*\(\s*|\[\s*)['"`][^'"`]*(token|jwt|auth|access|refresh|session|bearer|credential)|(localStorage|sessionStorage)\.\w*(token|jwt|auth|session)\w*\s*=[^=]/i,
    impact:
      "XSS ile token çalınabilir; web storage HttpOnly korumasından yoksundur; CSP/sandbox atlanınca oturum tamamen ele geçirilir.",
    recommendation:
      "Token'ı httpOnly + Secure + SameSite=Lax/Strict cookie'de tut; storage'dan çıkar; refresh rotation uygula.",
    references: ["OWASP A07:2021", "ASVS 3.4", "OWASP API2"],
    effort: "M",
  },

  // ---- FE-3: XSS sink'leri ------------------------------------------------
  {
    id: "FE-dangerous-html", taintAware: true,
    check: "FE-3",
    module: "FE",
    title: "dangerouslySetInnerHTML (XSS sink)",
    severity: "P1",
    category: "Frontend XSS",
    confidence: "medium",
    pattern: /dangerouslySetInnerHTML/,
    validate: notSanitized,
    // .js/.ts dahil: pek çok proje JSX'i .js içinde tutar (CRA/Next legacy). React'e özgü, FP yok.
    pathInclude: /\.(jsx|tsx|js|ts|mjs|cjs|mdx)$/i,
    impact: "Sanitize edilmemiş HTML React ağacına enjekte ediliyorsa DOM-XSS; oturum çalma/aksiyon tetikleme.",
    recommendation: "DOMPurify.sanitize() ile temizle (ALLOWED_TAGS dar tut) veya metin binding kullan.",
    references: XSS_REFS,
    effort: "S",
    maxPerFile: 3,
  },
  {
    id: "FE-vue-vhtml", taintAware: true,
    check: "FE-3",
    module: "FE",
    title: "Vue v-html (XSS sink)",
    severity: "P1",
    category: "Frontend XSS",
    confidence: "medium",
    pattern: /\bv-html\s*=/,
    validate: notSanitized,
    // .html artık GERÇEKTEN taranıyor: FE modülü scanSource'a kendi `include`'unu geçiyor.
    pathInclude: /\.(vue|html|htm|njk|ejs)$/i,
    impact: "v-html sanitize edilmemiş HTML render eder; DOM-XSS.",
    recommendation: "DOMPurify ile sanitize et veya `{{ }}` metin interpolasyonu kullan.",
    references: XSS_REFS,
    effort: "S",
    maxPerFile: 3,
  },
  {
    id: "FE-svelte-html", taintAware: true,
    check: "FE-3",
    module: "FE",
    title: "Svelte {@html ...} (XSS sink)",
    severity: "P1",
    category: "Frontend XSS",
    confidence: "medium",
    pattern: /\{@html\s+/,
    validate: notSanitized,
    pathInclude: /\.svelte$/i,
    impact: "{@html} ham HTML basar, Svelte'in otomatik kaçışını devre dışı bırakır; DOM-XSS.",
    recommendation: "DOMPurify ile sanitize et veya `{expr}` metin interpolasyonu kullan.",
    references: XSS_REFS,
    effort: "S",
    maxPerFile: 3,
  },
  {
    id: "FE-astro-set-html", taintAware: true,
    check: "FE-3",
    module: "FE",
    title: "Astro set:html (XSS sink)",
    severity: "P1",
    category: "Frontend XSS",
    confidence: "medium",
    pattern: /\bset:html\s*=/,
    validate: notSanitized,
    pathInclude: /\.(astro|mdx)$/i,
    impact: "set:html direktifi ham HTML enjekte eder; Astro'nun otomatik kaçışını atlar → DOM-XSS.",
    recommendation: "DOMPurify/rehype-sanitize ile temizle; markdown için sanitize eklentisi kullan.",
    references: XSS_REFS,
    effort: "S",
    maxPerFile: 3,
  },
  {
    id: "FE-innerhtml-sink", taintAware: true,
    check: "FE-3",
    module: "FE",
    title: "innerHTML/outerHTML/document.write ile HTML yazımı (XSS sink)",
    severity: "P1",
    category: "Frontend XSS",
    confidence: "medium",
    // `\s*(?:\+?=)[^=]` → `===`/`==` karşılaştırmalarını eler; `x = el.innerHTML` (okuma) eşleşmez.
    pattern: /\.(innerHTML|outerHTML)\s*(?:\+?=)[^=]|\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\(/,
    validate: (line) =>
      // `el.innerHTML = ""` (temizleme) meşru ve çok yaygın → FP değil.
      !/\.(inner|outer)HTML\s*=\s*(?:''|""|``|null|undefined)\s*;?\s*$/.test(line) && notSanitized(line),
    pathInclude: /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|astro|html|htm)$/i,
    pathExclude: /\.d\.ts$/i,
    impact:
      "Dinamik string innerHTML/document.write ile DOM'a basılıyor; girdi kullanıcıdan geliyorsa DOM-XSS (oturum çalma, keylogger enjeksiyonu).",
    recommendation:
      "textContent kullan; HTML gerekiyorsa DOMPurify.sanitize(); document.write'ı tamamen kaldır (CSP ve doküman ayrıştırmayı da bozar).",
    references: ["OWASP A03:2021", "CWE-79", "CWE-116", "ASVS 5.3"],
    effort: "M",
    maxPerFile: 2,
  },
  {
    id: "FE-javascript-url", taintAware: true,
    check: "FE-3",
    module: "FE",
    title: "javascript: URL (script çalıştıran bağlantı)",
    severity: "P1",
    category: "Frontend XSS",
    confidence: "high",
    pattern:
      /\b(?:href|src|action|formaction|xlink:href|to)\s*=\s*["'`{]?\s*(?:javascript|data:text\/html|vbscript)\s*:/i,
    // `href="javascript:void(0)"` yaygın bir no-op kalıbı; gürültüyü ciddi düşürür.
    validate: (line) => !/javascript:\s*void\s*\(\s*0\s*\)/i.test(line),
    pathInclude: /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|astro|html|htm|njk|ejs)$/i,
    impact:
      "javascript:/data:text/html URL'i tıklamada keyfi script çalıştırır; kullanıcı girdisinden türeyen URL'lerde XSS.",
    recommendation:
      "Şemayı allow-list ile doğrula (yalnız http/https/mailto); `new URL()` ile parse edip protocol kontrol et.",
    references: XSS_REFS,
    effort: "S",
    maxPerFile: 3,
  },
  {
    id: "FE-unsafe-url-binding",
    check: "FE-3",
    module: "FE",
    title: "Doğrulanmamış dinamik URL binding (javascript: enjeksiyonu adayı)",
    severity: "P2",
    category: "Frontend XSS",
    confidence: "low",
    // href={expr} · :href="expr" — sabit yol ("/", "#") ve string literal hariç.
    pattern:
      /\b(?:href|src|action|formAction)\s*=\s*\{\s*(?!["'`/#])[A-Za-z_$][\w$.?[\]]*\s*\}|:href\s*=\s*["'](?!\/|#)[A-Za-z_$][\w$.?[\]]*["']/,
    // Yalnız GÜVENİLMEYEN görünen değişken adlarında bayrakla; sanitizer varsa düşür.
    validate: (line) =>
      /(user|input|param|quer|search|props\.|data\.|item\.|row\.|record\.|redirect|returnUrl|nextUrl|callback|target|external|link|website|profileUrl)/i.test(
        line,
      ) && !/(sanitizeUrl|isSafeUrl|new URL\(|encodeURI)/i.test(line),
    pathInclude: /\.(jsx|tsx|vue|svelte|astro)$/i,
    impact: "URL doğrudan kullanıcı/DB verisinden geliyorsa `javascript:` payload'ı tıklamada çalışır (stored XSS).",
    recommendation:
      "Render'dan önce şemayı doğrula: `const u = new URL(raw, base); if (!/^https?:$/.test(u.protocol)) throw` ya da hazır bir `sanitizeUrl` yardımcısı kullan.",
    references: ["OWASP A03:2021", "CWE-79"],
    effort: "S",
    maxPerFile: 1,
  },

  // ---- FE-5: cross-origin mesajlaşma -------------------------------------
  {
    id: "FE-postmessage-wildcard",
    check: "FE-5",
    module: "FE",
    title: "postMessage wildcard origin ('*') — veri her kökene sızar",
    severity: "P1",
    category: "Cross-Origin Messaging",
    confidence: "high",
    pattern: /\.postMessage\s*\(\s*[^;]*?,\s*["'`]\*["'`]\s*\)/,
    pathInclude: /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|astro|html|htm)$/i,
    impact:
      "targetOrigin='*' mesajı HERHANGİ bir kökene teslim eder; iframe/açılır pencere ele geçirilmişse token/PII sızar.",
    recommendation: "targetOrigin'i kesin köken olarak ver (`https://app.example.com`); asla '*' kullanma.",
    references: ["OWASP A05:2021", "CWE-942", "ASVS 14.4"],
    effort: "S",
    maxPerFile: 3,
  },

  // ---- FE-4: üretimde source map -----------------------------------------
  {
    id: "FE-source-map-prod",
    check: "FE-4",
    module: "FE",
    title: "Üretimde source map açık (kaynak sızıntısı)",
    severity: "P3",
    category: "Information Leak",
    confidence: "low",
    pattern:
      /(productionSourceMap\s*:\s*true|sourcemap\s*:\s*true|sourceMap\s*:\s*true|devtool\s*:\s*["'](?:source-map|eval-source-map|inline-source-map)["']|productionBrowserSourceMaps\s*:\s*true)/,
    // `[cm]?[jt]s` — önceki desen `next.config.mjs`'i (en yaygın dosya) KAÇIRIYORDU.
    pathInclude:
      /(^|\/)(vite|webpack(\.\w+)?|rollup|next|nuxt|vue|svelte|astro|quasar|craco)\.config\.[cm]?[jt]s$|\.config\.[cm]?[jt]s$/i,
    impact: "Yayınlanan source map orijinal kaynağı, iç mantığı ve bazen gömülü sabitleri ifşa eder.",
    recommendation:
      "Üretim derlemesinde kapat; yalnızca gizli hata-izleme (Sentry) yüklemesine gönder ve public dizinden sil.",
    references: ["OWASP A05:2021", "CWE-540"],
    effort: "S",
  },
];
