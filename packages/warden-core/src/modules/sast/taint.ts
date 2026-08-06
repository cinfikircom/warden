/**
 * Dosya-içi taint (veri-akışı) analizi — Strix devralma §1.2, bkz. docs/STRIX-ADOPTION.md.
 *
 * ── Neden ──
 * Warden'ın en büyük zayıflığı regex'in bağlam körlüğüydü: sabit bir string ile çağrılan
 * `exec("ls -la")` ile kullanıcı girdisi taşıyan `exec(req.body.cmd)` aynı bulguyu, aynı
 * güvenle üretiyordu. Bu katman ikisini ayırır.
 *
 * ── Kapsam ve dürüst sınırlar ──
 * Bu TAM bir veri-akışı analizi DEĞİLDİR ve öyle raporlanmamalıdır:
 *   • Yalnızca dosya içi. Fonksiyonlar arası ve dosyalar arası akış izlenmez.
 *   • Yalnızca düz atama zinciri. Nesne alanları, diziler, destructuring kısmen; closure,
 *     callback, async zinciri ve takma adlar izlenmez.
 *   • Kontrol akışı yok: bir dalda temizlenen değer, tüm dosyada temizlenmiş sayılır.
 * Doğru okuma: "kullanıcı girdisi bu satıra ULAŞIYOR OLABİLİR" — kanıt değil, güçlü ipucu.
 * Bu yüzden çıktısı bulgu ÜRETMEZ, yalnızca var olan bulgunun `confidence`'ını ayarlar.
 *
 * ── Fingerprint güvencesi (K5) ──
 * Bu katman `title`, `check` veya `evidence`'a DOKUNMAZ. Fingerprint yalnızca o üçlüden
 * türediği için (util/finding.ts) mevcut waiver'lar ve delta geçmişi aynen tutar. Taint
 * bilgisi ayrı bir `taint` alanında taşınır.
 */

/** Kullanıcı-kontrollü girdi kaynakları. Sunucu ve tarayıcı tarafı bir arada. */
const SOURCE_PATTERNS: readonly RegExp[] = [
  // HTTP istek gövdesi/parametreleri (Express, Koa, Fastify, Next route handler)
  /\breq(uest)?\s*\.\s*(body|query|params|headers|cookies)\b/,
  /\bctx\s*\.\s*(request\s*\.\s*body|query|params)\b/,
  /\bevent\s*\.\s*(body|queryStringParameters|pathParameters|headers)\b/,
  // Web platform
  /\bnew\s+URLSearchParams\s*\(/,
  /\bsearchParams\s*\.\s*get\s*\(/,
  /\buseSearchParams\s*\(/,
  /\blocation\s*\.\s*(hash|search|href)\b/,
  /\bdocument\s*\.\s*(URL|referrer|location)\b/,
  /\bwindow\s*\.\s*name\b/,
  // Form / mesajlaşma
  /\bformData\s*\.\s*get\s*\(/,
  /\baddEventListener\s*\(\s*["']message["']/,
  // Süreç girdisi
  /\bprocess\s*\.\s*argv\b/,
  /\bprocess\s*\.\s*env\s*\[/,
];

/**
 * Temizleyiciler. Bir atamanın sağ tarafında bunlardan biri varsa, sonuç DEĞİŞKEN artık
 * tainted sayılmaz.
 *
 * ⚠ Bu liste bilerek TEMKİNLİ: bir şeyi yanlışlıkla "temizlenmiş" saymak gerçek bir zafiyeti
 * düşük güvenle raporlamaya (ve gözden kaçmasına) yol açar. Yalnızca sonucu tartışmasız
 * güvenli kılan dönüşümler var — `String()` ya da `.trim()` gibi taint'i taşımaya devam eden
 * işlemler kasıtlı olarak YOK.
 */
const SANITIZER_PATTERNS: readonly RegExp[] = [
  // Tip daraltma: sayıya çevrilen değer injection taşıyamaz
  /\b(parseInt|parseFloat|Number)\s*\(/,
  /\bMath\s*\.\s*(floor|ceil|round|abs)\s*\(/,
  // Şema doğrulama (zod/joi/yup/valibot) — parse edilmiş çıktı tiplenmiştir
  /\.\s*(parse|safeParse|validateSync|validateAsync)\s*\(/,
  // Açık kaçış/temizleme kütüphaneleri
  /\b(DOMPurify\s*\.\s*sanitize|sanitizeHtml|escapeHtml|escape)\s*\(/,
  /\bencodeURIComponent\s*\(/,
  // Allow-list eşlemesi: sabit bir kümeden seçim
  /\b(ALLOW|ALLOWED|WHITELIST|VALID)[A-Z_]*\s*[.[]/,
];

/** Değişken adı: JS/TS tanımlayıcısı. */
const IDENT = "[A-Za-z_$][A-Za-z0-9_$]*";

/** `const x = ...` / `let x = ...` / `var x = ...` / `x = ...` biçimindeki atamalar. */
const ASSIGN_RE = new RegExp(`(?:const|let|var)?\\s*(${IDENT})\\s*=\\s*([^;]*)`);

/** `const { a, b } = ...` biçimindeki nesne destructuring'i. */
const DESTRUCT_RE = new RegExp(`(?:const|let|var)\\s*\\{([^}]*)\\}\\s*=\\s*(.+)`);

export interface TaintInfo {
  /** Kullanıcı girdisi bu satıra ulaşıyor olabilir mi. */
  readonly reached: boolean;
  /** Kaynağın bulunduğu satır (1-tabanlı) — kanıt olarak değil, açıklama olarak. */
  readonly sourceLine: number;
  /** Kaynak ifadenin kısa gösterimi, ör. "req.body". */
  readonly sourceExpr: string;
  /** Yol üzerinde bir temizleyici görüldü mü. */
  readonly sanitized: boolean;
}

/** Bir dosyanın taint haritası: satır no (1-tabanlı) → o satırda geçerli taint bilgisi. */
export interface TaintMap {
  /** Tainted değişken adları → ilk kaynak bilgisi. */
  readonly vars: ReadonlyMap<string, TaintInfo>;
  /** Doğrudan bir kaynak ifadesi içeren satırlar (1-tabanlı). */
  readonly sourceLines: ReadonlyMap<number, string>;
}

function matchAny(patterns: readonly RegExp[], text: string): RegExpExecArray | null {
  for (const re of patterns) {
    const m = re.exec(text);
    if (m) return m;
  }
  return null;
}

/**
 * Dosyayı tek geçişte tarayıp tainted değişkenleri toplar.
 *
 * Tek geçiş bilinçli bir sadeleştirme: değişkenin tanımından ÖNCE kullanıldığı durumları
 * (hoisting, geri-atama) kaçırır. Bunlar gerçek kodda nadir, ve kaçırmanın bedeli yalnızca
 * "güven yükseltilmez" — yani bulgu yine raporlanır. Ters yön (yanlışlıkla tainted sayıp
 * güveni şişirmek) daha pahalı olurdu.
 */
export function buildTaintMap(lines: readonly string[]): TaintMap {
  const vars = new Map<string, TaintInfo>();
  const sourceLines = new Map<number, string>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    const lineNo = i + 1;

    // Yorum satırlarını atla: `// req.body.x` bir veri akışı değildir.
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;

    const srcMatch = matchAny(SOURCE_PATTERNS, line);
    if (srcMatch) sourceLines.set(lineNo, srcMatch[0].trim());

    // Sağ tarafta tainted bir değişken ya da doğrudan kaynak var mı?
    const rhsTainted = (rhs: string): TaintInfo | null => {
      const direct = matchAny(SOURCE_PATTERNS, rhs);
      if (direct) {
        return {
          reached: true,
          sourceLine: lineNo,
          sourceExpr: direct[0].trim(),
          sanitized: matchAny(SANITIZER_PATTERNS, rhs) !== null,
        };
      }
      for (const [name, info] of vars) {
        // Kelime sınırıyla ara: `id` değişkeni `idx` içinde eşleşmemeli.
        if (new RegExp(`\\b${name}\\b`).test(rhs)) {
          return {
            ...info,
            sanitized: info.sanitized || matchAny(SANITIZER_PATTERNS, rhs) !== null,
          };
        }
      }
      return null;
    };

    const destruct = DESTRUCT_RE.exec(line);
    if (destruct) {
      const info = rhsTainted(destruct[2] as string);
      if (info) {
        for (const raw of (destruct[1] as string).split(",")) {
          // `{ a, b: c, d = 1 }` → bağlanan ad son tanımlayıcıdır.
          const name = raw.split(":").pop()?.split("=")[0]?.trim();
          if (name && new RegExp(`^${IDENT}$`).test(name) && !info.sanitized) vars.set(name, info);
        }
      }
      continue;
    }

    const assign = ASSIGN_RE.exec(line);
    if (assign) {
      const name = assign[1] as string;
      const rhs = assign[2] as string;
      const info = rhsTainted(rhs);
      if (info && !info.sanitized) vars.set(name, info);
      // Temizlendiyse taint'i DÜŞÜR: `x = escape(x)` sonrası x güvenlidir.
      else if (info?.sanitized) vars.delete(name);
    }
  }

  return { vars, sourceLines };
}

/**
 * Bir sink satırına kullanıcı girdisinin ulaşıp ulaşmadığını değerlendirir.
 * Aynı satırdaki doğrudan kaynak kullanımı da (ör. `exec(req.body.cmd)`) sayılır.
 */
export function evaluateTaint(map: TaintMap, line: string, lineNo: number): TaintInfo | null {
  const direct = matchAny(SOURCE_PATTERNS, line);
  if (direct) {
    return {
      reached: true,
      sourceLine: lineNo,
      sourceExpr: direct[0].trim(),
      sanitized: matchAny(SANITIZER_PATTERNS, line) !== null,
    };
  }
  for (const [name, info] of map.vars) {
    if (new RegExp(`\\b${name}\\b`).test(line)) {
      return { ...info, sanitized: info.sanitized || matchAny(SANITIZER_PATTERNS, line) !== null };
    }
  }
  return null;
}

/**
 * Taint sonucuna göre güven düzeyini ayarlar. Sinyal bilerek ASİMETRİKTİR.
 *
 * Bu motorun pozitif kararı ("girdi ulaşıyor") güvenilirdir: bir kaynaktan sink'e giden
 * atama zinciri gerçekten görülmüştür. Negatif kararı ("ulaşmıyor") ise güvenilir DEĞİLDİR:
 * analiz dosya-içi ve düz atamalarla sınırlı, dolayısıyla fonksiyonlar arası ya da dosyalar
 * arası akışla gelen gerçek bir zafiyeti göremez.
 *
 * Bu yüzden:
 *   • ulaşıyor + temizlenmemiş → güven YÜKSELİR (yeni bilgi kazanıldı)
 *   • temizlenmiş            → bir kademe düşer, `low`'un altına inmez
 *   • bulunamadı             → HİÇ DOKUNULMAZ (mevcut davranış aynen korunur)
 *
 * Son madde bu katmanın en önemli güvencesi: taint eklemek hiçbir mevcut bulgunun görünürlüğünü
 * azaltamaz. Aksi olsaydı, motorun körlüğü sessizce gerçek zafiyetleri gölgelerdi.
 *
 * `severity` de bilerek dokunulmadan bırakıldı: severity CI gate'ini (`--fail-on`) sürüyor ve
 * heuristik bir sinyalin build kırma kararını değiştirmesi, bu katmanın hak ettiğinden fazla
 * yetki almasıdır.
 */
export function adjustConfidence(
  current: "high" | "medium" | "low",
  taint: TaintInfo | null,
): "high" | "medium" | "low" {
  if (!taint) return current;
  if (taint.sanitized) return current === "high" ? "medium" : "low";
  return current === "low" ? "medium" : "high";
}
