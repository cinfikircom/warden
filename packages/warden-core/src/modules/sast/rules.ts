import type { SourceRule } from "./scanner.ts";
import { looksHighEntropySecret, shannonEntropy, extractStringLiterals } from "../../util/entropy.ts";

/**
 * SAST kural seti (Modül B). Her kural OWASP Top 10 / ASVS'e `references` üzerinden eşlidir;
 * uyum tablosunu bu referanslardan `risk/owasp.ts` üretir. Desenler bilinçli olarak düşük
 * false-positive; şüpheli olanlar confidence=medium/low.
 * (Frontend kuralları v0.10'da ayrıldı → modules/fe/rules.ts.)
 */

/** Zayıf/sözlük JWT secret sözcükleri (kaba kuvvetle dakikalar içinde kırılır). */
const WEAK_SECRET_WORDS =
  /^(?:secret|mysecret|supersecret|jwt|jwtsecret|token|key|secretkey|changeme|changeme123|password|passwd|pass|admin|test|dev|demo|local|foo|bar|abc\d*|12345\d*|qwerty)[\w-]{0,8}$/i;

/**
 * Bir string literal, JWT imza secret'ı olarak zayıf mı?
 * Env/interpolasyon/algoritma adları ve JWT token örnekleri elenir; kalanlar sözlük eşleşmesi
 * VEYA "kısa + düşük entropi" ölçütüyle değerlendirilir.
 */
function isWeakSecretLiteral(lit: string): boolean {
  if (!lit || /^\$\{|^process\.env|^HS\d{3}$|^RS\d{3}$|^ES\d{3}$|^none$/i.test(lit)) return false;
  if (lit.split(".").length === 3) return false; // "a.b.c" — token örneği, secret değil
  if (WEAK_SECRET_WORDS.test(lit)) return true;
  return lit.length < 32 && shannonEntropy(lit) < 3.5;
}

/**
 * SECRET ARGÜMANI konumundaki literaller: `sign(payload, "SECRET", opts)` ya da
 * `verify(t, process.env.X || "dev")`. Yalnızca `,` / `||` / `??` sonrası GELEN literaller
 * alınır — `{ expiresIn: "15m" }` gibi opsiyon değerleri (`:` sonrası) böylece elenir.
 * Bu ayrım kritik: tüm literalleri tarasaydık her kısa opsiyon değeri false-positive üretirdi.
 */
function secretArgLiterals(line: string): string[] {
  const out: string[] = [];
  const re = /(?:,|\|\||\?\?)\s*(['"`])([^'"`\n]{1,64})\1/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) if (m[2]) out.push(m[2]);
  return out;
}

/** Yapılandırma ataması konumundaki literaller: `JWT_SECRET = "..."` / `jwtSecret: "..."`. */
function configSecretLiterals(line: string): string[] {
  const out: string[] = [];
  const re = /[:=]\s*(['"`])([^'"`\n]{1,64})\1/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) if (m[2]) out.push(m[2]);
  return out;
}
export const SAST_RULES: readonly SourceRule[] = [
  // ---- B1 Secret taraması -------------------------------------------------
  {
    id: "B1-aws-key", check: "B1", module: "B", title: "Hardcoded AWS Access Key",
    severity: "P0", category: "Secret", confidence: "high",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    impact: "Sızdırılmış AWS anahtarı hesap ele geçirme/maliyet/veri sızıntısı demektir.",
    recommendation: "Anahtarı hemen iptal et + rotasyon yap; secret manager/KMS kullan; git geçmişini temizle.",
    references: ["OWASP A07:2021", "ASVS 6.4"], effort: "M",
  },
  {
    id: "B1-private-key", check: "B1", module: "B", title: "Kodda private key bloğu",
    severity: "P0", category: "Secret", confidence: "high",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    impact: "Özel anahtar repoda; imzalama/şifre çözme/erişim tehlikede.",
    recommendation: "Anahtarı iptal/rotasyon; secret store'a taşı; geçmişi temizle (BFG/filter-repo).",
    references: ["OWASP A07:2021"], effort: "M",
  },
  {
    id: "B1-token-literal", check: "B1", module: "B", title: "Hardcoded token/secret (Slack/GitHub vb.)",
    severity: "P0", category: "Secret", confidence: "high",
    pattern: /\b(xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{36}|sk-[A-Za-z0-9]{20,})\b/,
    impact: "Üçüncü-taraf servis token'ı sızmış; yetkisiz erişim mümkün.",
    recommendation: "Token'ı iptal/rotasyon; env/secret manager'a taşı.",
    references: ["OWASP A07:2021"], effort: "M",
  },
  {
    id: "B1-hardcoded-secret", check: "B1", module: "B", title: "Sabit string'e atanmış secret/parola",
    severity: "P1", category: "Secret", confidence: "medium",
    pattern: /\b(api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|access[_-]?token)\b\s*[:=]\s*['"][^'"$\s]{8,}['"]/i,
    pathExclude: /\.(md|txt)$/i,
    impact: "Gizli değer kaynak kodda; env'den okunmuyor olabilir (process.env değilse risk).",
    recommendation: "Değeri process.env/secret manager'dan oku; koddan kaldır; rotasyon yap.",
    references: ["OWASP A07:2021", "ASVS 6.4"], effort: "S",
  },

  // ---- B3 Zayıf kripto ----------------------------------------------------
  {
    id: "B3-weak-hash", check: "B3", module: "B", title: "Zayıf hash (MD5/SHA1)",
    severity: "P1", category: "Cryptographic Failure", confidence: "high",
    pattern: /createHash\(\s*['"](?:md5|sha1)['"]\s*\)/i,
    impact: "MD5/SHA1 çakışmaya/kırılmaya açık; parola/integrity için güvensiz.",
    recommendation: "Parola için bcrypt/argon2; integrity için SHA-256+.",
    references: ["OWASP A02:2021", "ASVS 6.2.3"], effort: "S",
  },
  {
    id: "B3-ecb", check: "B3", module: "B", title: "ECB mod şifreleme (desen sızdırır)",
    severity: "P1", category: "Cryptographic Failure", confidence: "high",
    pattern: /['"]aes-\d{3}-ecb['"]|\bECB\b/,
    impact: "ECB aynı bloğu aynı çıktıya çevirir; veri deseni sızar.",
    recommendation: "AES-GCM (authenticated) veya AES-CBC + rastgele IV kullan.",
    references: ["OWASP A02:2021"], effort: "S",
  },
  {
    id: "B3-cryptojs", check: "B3", module: "B", title: "CryptoJS kullanımı (standart-dışı KDF/EvpKDF riski)",
    severity: "P1", category: "Cryptographic Failure", confidence: "medium",
    pattern: /\bCryptoJS\b/,
    impact: "CryptoJS varsayılan KDF (EvpKDF) zayıf; yanlış kullanımda kırılabilir şifreleme.",
    recommendation: "WebCrypto/Node crypto (AES-GCM, PBKDF2/scrypt) kullan; CryptoJS'i kaldır.",
    references: ["OWASP A02:2021"], effort: "M",
  },
  {
    id: "B3-insecure-random", check: "B3", module: "B", title: "Token/secret için Math.random() (öngörülebilir)",
    severity: "P1", category: "Cryptographic Failure", confidence: "medium",
    pattern: /(token|secret|password|otp|nonce|session|api[_-]?key|reset)[\s\S]{0,40}Math\.random\(\)/i,
    impact: "Math.random() kriptografik değil; üretilen token tahmin edilebilir.",
    recommendation: "crypto.randomBytes / crypto.randomUUID kullan.",
    references: ["OWASP A02:2021", "ASVS 6.3.1"], effort: "S",
  },

  // ---- B4 Auth tasarımı ---------------------------------------------------
  // NOT: JWT-in-localStorage kuralı v0.10'da Modül FE'ye taşındı (modules/fe/rules.ts, FE-1).
  {
    id: "B4-jwt-long-ttl", check: "B4", module: "B", title: "Uzun JWT geçerlilik süresi (TTL)",
    severity: "P2", category: "Auth Design", confidence: "medium",
    pattern: /expiresIn\s*:\s*['"]?(?:30d|60d|90d|180d|365d|\d{3,}h|\d{6,})/i,
    impact: "Uzun ömürlü token çalınırsa uzun süre kötüye kullanılabilir.",
    recommendation: "Kısa access token (dk) + refresh rotation kullan.",
    references: ["OWASP A07:2021", "ASVS 3.3"], effort: "M",
  },

  // ---- B5 Authz / multi-tenancy (heuristic, düşük güven) ------------------
  {
    id: "B5-idor-candidate", check: "B5", module: "B", title: "IDOR adayı: id doğrudan istemciden sorguya geçiyor",
    severity: "P1", category: "Broken Access Control", confidence: "low",
    pattern: /(findUnique|findFirst|findById|update|delete)\s*\(\s*\{[^}]*\bid\s*:\s*(req\.params|req\.query|req\.body|ctx\.params)/i,
    impact: "Kaynak yalnızca id ile çekiliyor; sahiplik/tenant kontrolü yoksa başka kullanıcının verisi okunabilir (IDOR).",
    recommendation: "Sorguya tenant/owner filtresi ekle (where: { id, userId }) veya erişimi politika/RLS ile doğrula.",
    references: ["OWASP A01:2021", "OWASP API1 (BOLA)", "ASVS 4.2.1"], effort: "M",
  },

  // ---- B6 Injection -------------------------------------------------------
  {
    id: "B6-sql-concat", check: "B6", module: "B", title: "SQL string birleştirme (SQL Injection)",
    severity: "P0", category: "Injection", confidence: "medium",
    pattern: /(query|execute|raw|\$queryRawUnsafe)\s*\(\s*[`'"].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)\b[\s\S]*?(\+|\$\{)/i,
    impact: "Kullanıcı girdisi SQL'e birleştiriliyor; SQL Injection mümkün.",
    recommendation: "Parametreli sorgu/prepared statement; ORM'in güvenli API'leri (Prisma typed).",
    references: ["OWASP A03:2021", "OWASP API8", "ASVS 5.3.4"], effort: "M",
  },
  {
    id: "B6-command-injection", check: "B6", module: "B", title: "Komut enjeksiyonu yüzeyi (exec + dinamik girdi)",
    severity: "P0", category: "Injection", confidence: "medium",
    pattern: /\b(exec|execSync|spawnSync)\s*\(\s*[`'"][^`'"]*(\$\{|['"]\s*\+)/i,
    impact: "Kullanıcı girdisi shell komutuna giriyor; RCE riski.",
    recommendation: "execFile + argüman dizisi kullan; shell=false; girdiyi allow-list ile doğrula.",
    references: ["OWASP A03:2021", "ASVS 5.3.8"], effort: "M",
  },
  {
    id: "B6-eval", check: "B6", module: "B", title: "eval() kullanımı (kod enjeksiyonu)",
    severity: "P1", category: "Injection", confidence: "high",
    pattern: /(^|[^.\w])eval\s*\(/,
    impact: "eval dinamik kod çalıştırır; girdi kontrol edilemiyorsa RCE.",
    recommendation: "eval'i kaldır; JSON.parse / güvenli alternatif kullan.",
    references: ["OWASP A03:2021"], effort: "S",
  },

  // ---- B7 Web sertleştirme ------------------------------------------------
  {
    id: "B7-cors-wildcard", check: "B7", module: "B", title: "CORS origin '*' (her kaynağa açık)",
    severity: "P2", category: "Security Misconfiguration", confidence: "high",
    pattern: /origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/i,
    impact: "Herhangi bir site API'ye kimlikli istek atabilir; CSRF/veri sızıntısı yüzeyi.",
    recommendation: "Origin allow-list kullan; credentials ile birlikte '*' kullanma.",
    references: ["OWASP A05:2021", "OWASP API"], effort: "S",
  },

  // ---- B9 Bilgi sızıntısı -------------------------------------------------
  {
    id: "B9-stack-in-response", check: "B9", module: "B", title: "Hata stack'i yanıtta dönüyor",
    severity: "P2", category: "Information Leak", confidence: "medium",
    pattern: /res\.(send|json|status\([^)]*\)\.(?:send|json))\([^)]*\.stack\b/,
    impact: "Stack trace iç yapıyı/yolları sızdırır; saldırgana bilgi verir.",
    recommendation: "Üretimde genel hata mesajı; detayları sunucu log'una yaz.",
    references: ["OWASP A05:2021"], effort: "S",
  },

  // ---- Python / Django kuralları -----------------------------------------
  {
    id: "B3-py-weak-hash", check: "B3", module: "B", title: "Zayıf hash (hashlib.md5/sha1)",
    severity: "P1", category: "Cryptographic Failure", confidence: "high",
    pattern: /hashlib\.(md5|sha1)\s*\(/, pathInclude: /\.py$/,
    impact: "MD5/SHA1 parola/integrity için güvensiz.", recommendation: "Parola için argon2/bcrypt; integrity için sha256+.",
    references: ["OWASP A02:2021", "ASVS 6.2.3"], effort: "S",
  },
  {
    id: "B6-py-shell-true", check: "B6", module: "B", title: "subprocess shell=True (komut enjeksiyonu)",
    severity: "P0", category: "Injection", confidence: "medium",
    pattern: /subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True/, pathInclude: /\.py$/,
    impact: "shell=True + dinamik girdi RCE'ye yol açar.", recommendation: "Argüman listesi kullan; shell=False; girdiyi doğrula.",
    references: ["OWASP A03:2021", "ASVS 5.3.8"], effort: "M",
  },
  {
    id: "B9-django-debug", check: "B9", module: "B", title: "Django DEBUG = True (bilgi sızıntısı)",
    severity: "P1", category: "Security Misconfiguration", confidence: "medium",
    pattern: /^\s*DEBUG\s*=\s*True/, pathInclude: /settings.*\.py$|\.py$/,
    impact: "Üretimde DEBUG=True stack trace + ayar sızdırır.", recommendation: "Üretimde DEBUG=False; env ile yönet.",
    references: ["OWASP A05:2021"], effort: "S",
  },
  {
    id: "B1-django-secret-key", check: "B1", module: "B", title: "Django SECRET_KEY hardcoded",
    severity: "P1", category: "Secret", confidence: "medium",
    pattern: /SECRET_KEY\s*=\s*['"][^'"$]{12,}['"]/, pathInclude: /\.py$/,
    impact: "Sabit SECRET_KEY session/CSRF/token imzalarını riske atar.", recommendation: "SECRET_KEY'i env/secret manager'dan oku; rotasyon yap.",
    references: ["OWASP A07:2021", "ASVS 6.4"], effort: "S",
  },
  {
    id: "B7-django-allowed-hosts", check: "B7", module: "B", title: "ALLOWED_HOSTS = ['*'] (her host kabul)",
    severity: "P2", category: "Security Misconfiguration", confidence: "high",
    pattern: /ALLOWED_HOSTS\s*=\s*\[[^\]]*['"]\*['"]/, pathInclude: /\.py$/,
    impact: "Host header doğrulaması kapalı; host header saldırıları/cache poisoning.", recommendation: "ALLOWED_HOSTS'u kesin domain listesiyle sınırla.",
    references: ["OWASP A05:2021"], effort: "S",
  },

  // ---- PHP / Laravel kuralları -------------------------------------------
  {
    id: "B3-php-weak-hash", check: "B3", module: "B", title: "Zayıf hash (PHP md5/sha1)",
    severity: "P1", category: "Cryptographic Failure", confidence: "medium",
    pattern: /\b(md5|sha1)\s*\(/, pathInclude: /\.php$/,
    impact: "md5/sha1 parola/integrity için güvensiz.", recommendation: "password_hash() (bcrypt/argon2); integrity için hash('sha256').",
    references: ["OWASP A02:2021", "ASVS 6.2.3"], effort: "S",
  },
  {
    id: "B6-php-command", check: "B6", module: "B", title: "PHP komut çalıştırma (exec/shell_exec/system)",
    severity: "P0", category: "Injection", confidence: "medium",
    pattern: /\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\([^)]*\$/, pathInclude: /\.php$/,
    impact: "Dinamik girdi shell'e giriyor; RCE riski.", recommendation: "escapeshellarg/escapeshellcmd; mümkünse komut çalıştırmaktan kaçın.",
    references: ["OWASP A03:2021"], effort: "M",
  },
  {
    id: "B6-laravel-raw-sql", check: "B6", module: "B", title: "Laravel ham SQL (DB::raw/whereRaw + birleştirme)",
    severity: "P1", category: "Injection", confidence: "medium",
    pattern: /(DB::raw|->whereRaw|->selectRaw|DB::select)\s*\([^;)]*\.\s*\$/, pathInclude: /\.php$/,
    impact: "Kullanıcı girdisi ham SQL'e birleştiriliyor; SQL Injection.", recommendation: "Parametre bağla (binding); Eloquent/Query Builder güvenli API.",
    references: ["OWASP A03:2021"], effort: "M",
  },
  {
    id: "B5-laravel-tenant-escape", check: "B5", module: "B", title: "Laravel withoutGlobalScope(s) — tenant/scope atlama",
    severity: "P1", category: "Broken Access Control", confidence: "low",
    pattern: /(->|::)withoutGlobalScopes?\b/, pathInclude: /\.php$/,
    impact: "Global scope (ör. tenant filtresi) devre dışı; cross-tenant veri sızıntısı riski.", recommendation: "Scope'u yalnızca gerekli yerde, açık yetki kontrolüyle kaldır.",
    references: ["OWASP A01:2021"], effort: "M",
  },
  {
    id: "B5-laravel-mass-assign", check: "B5", module: "B", title: "Laravel mass-assignment açık ($guarded = [])",
    severity: "P2", category: "Broken Access Control", confidence: "low",
    pattern: /\$guarded\s*=\s*\[\s*\]/, pathInclude: /\.php$/,
    impact: "Tüm alanlar toplu atanabilir; yetki/rol alanları istemciden değiştirilebilir.", recommendation: "$fillable allow-list kullan; $guarded'ı boş bırakma.",
    references: ["OWASP A01:2021"], effort: "S",
  },
  {
    id: "B9-php-debug-leftover", check: "B9", module: "B", title: "Bırakılmış dd()/dump()/var_dump() (bilgi sızıntısı)",
    severity: "P3", category: "Information Leak", confidence: "low",
    pattern: /\b(dd|dump|var_dump)\s*\(/, pathInclude: /\.php$/,
    impact: "Üretimde değişken/iç durum sızdırabilir.", recommendation: "Hata ayıklama çağrılarını kaldır.",
    references: ["OWASP A05:2021"], effort: "S",
  },

  // ---- C# / .NET kuralları ------------------------------------------------
  {
    id: "B3-dotnet-weak-hash", check: "B3", module: "B", title: "Zayıf hash (.NET MD5/SHA1)",
    severity: "P1", category: "Cryptographic Failure", confidence: "high",
    pattern: /\b(MD5|SHA1)\.Create\s*\(|new\s+(MD5|SHA1)CryptoServiceProvider/, pathInclude: /\.cs$/,
    impact: "MD5/SHA1 parola/integrity için güvensiz.", recommendation: "Parola için PBKDF2/Argon2 (Rfc2898DeriveBytes); integrity için SHA256.",
    references: ["OWASP A02:2021", "ASVS 6.2.3"], effort: "S",
  },
  {
    id: "B6-dotnet-sql", check: "B6", module: "B", title: ".NET ham SQL (FromSqlRaw/ExecuteSqlRaw + birleştirme)",
    severity: "P0", category: "Injection", confidence: "medium",
    pattern: /(FromSqlRaw|ExecuteSqlRaw|new\s+SqlCommand)\s*\(\s*[$@]*["'].*\+/, pathInclude: /\.cs$/,
    impact: "Kullanıcı girdisi ham SQL'e giriyor; SQL Injection.", recommendation: "Parametreli sorgu (FromSqlInterpolated / SqlParameter).",
    references: ["OWASP A03:2021"], effort: "M",
  },
  {
    id: "B6-dotnet-process", check: "B6", module: "B", title: ".NET Process.Start (dinamik girdi)",
    severity: "P1", category: "Injection", confidence: "low",
    pattern: /Process\.Start\s*\(/, pathInclude: /\.cs$/,
    impact: "Dinamik girdiyle komut çalıştırma; injection riski.", recommendation: "Argümanları ProcessStartInfo ile ayır; girdiyi doğrula.",
    references: ["OWASP A03:2021"], effort: "M",
  },
  {
    id: "B9-dotnet-dev-exception", check: "B9", module: "B", title: "UseDeveloperExceptionPage (prod'da bilgi sızıntısı)",
    severity: "P2", category: "Security Misconfiguration", confidence: "medium",
    pattern: /UseDeveloperExceptionPage\s*\(/, pathInclude: /\.cs$/,
    impact: "Geliştirici hata sayfası stack/iç detay sızdırır.", recommendation: "Yalnızca Development ortamında; üretimde UseExceptionHandler.",
    references: ["OWASP A05:2021"], effort: "S",
  },

  // ---- Go kuralları -------------------------------------------------------
  {
    id: "B3-go-weak-hash", check: "B3", module: "B", title: "Zayıf hash (Go crypto/md5|sha1)",
    severity: "P1", category: "Cryptographic Failure", confidence: "high",
    pattern: /\b(md5|sha1)\.(New|Sum)\s*\(/, pathInclude: /\.go$/,
    impact: "md5/sha1 parola/integrity için güvensiz.", recommendation: "Parola için bcrypt/argon2; integrity için sha256.",
    references: ["OWASP A02:2021", "ASVS 6.2.3"], effort: "S",
  },
  {
    id: "B3-go-insecure-tls", check: "B7", module: "B", title: "TLS doğrulaması kapalı (InsecureSkipVerify: true)",
    severity: "P1", category: "Cryptographic Failure", confidence: "high",
    pattern: /InsecureSkipVerify\s*:\s*true/, pathInclude: /\.go$/,
    impact: "Sertifika doğrulaması kapalı; MITM mümkün.", recommendation: "InsecureSkipVerify'ı kaldır; geçerli sertifika/CA kullan.",
    references: ["OWASP A02:2021"], effort: "S",
  },
  {
    id: "B6-go-sql", check: "B6", module: "B", title: "Go SQL birleştirme/Sprintf (SQL Injection)",
    severity: "P0", category: "Injection", confidence: "medium",
    pattern: /\.(Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(\s*(fmt\.Sprintf|[^,)]*\+)/, pathInclude: /\.go$/,
    impact: "Girdi SQL'e birleştiriliyor (Sprintf/+); SQL Injection.", recommendation: "Parametreli sorgu ($1, ?) ve argümanlar kullan.",
    references: ["OWASP A03:2021"], effort: "M",
  },
  {
    id: "B6-go-command", check: "B6", module: "B", title: "Go exec.Command (dinamik girdi birleştirme)",
    severity: "P1", category: "Injection", confidence: "low",
    pattern: /exec\.Command(Context)?\s*\([^)]*\+/, pathInclude: /\.go$/,
    impact: "Dinamik girdiyle komut; injection riski.", recommendation: "Argümanları ayrı geç; girdiyi allow-list ile doğrula.",
    references: ["OWASP A03:2021"], effort: "M",
  },

  // NOT: Frontend XSS sink kuralları (dangerouslySetInnerHTML, v-html, ...) v0.10'da
  // Modül FE'ye taşındı — bkz. modules/fe/rules.ts (FE-3).

  // ===================================================================================
  // KAPSAM GENİŞLETME (2026): B1 ek token'lar · entropi · SSRF · SSTI · path traversal ·
  // güvensiz deserialization · XXE · open redirect · JWT alg=none · CSP · source map.
  // ===================================================================================

  // ---- B1 Ek sağlayıcı token'ları (yüksek güven, belirgin ön-ek) ---------
  {
    id: "B1-provider-token", check: "B1", module: "B", title: "Hardcoded sağlayıcı anahtarı (Stripe/Google/GitLab/npm/SendGrid/Twilio)",
    severity: "P0", category: "Secret", confidence: "high",
    pattern:
      /\b(sk_live_[0-9A-Za-z]{16,}|rk_live_[0-9A-Za-z]{16,}|AIza[0-9A-Za-z_\-]{35}|glpat-[0-9A-Za-z_\-]{20}|npm_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}|SG\.[\w\-]{22}\.[\w\-]{43}|SK[0-9a-fA-F]{32})\b/,
    pathExclude: /\.(md|txt)$/i,
    impact: "Canlı üçüncü-taraf servis anahtarı kodda; ödeme/e-posta/repo erişimi ele geçirilebilir.",
    recommendation: "Anahtarı hemen iptal/rotasyon yap; secret manager'a taşı; git geçmişini temizle.",
    references: ["OWASP A07:2021", "ASVS 6.4"], effort: "M",
  },
  {
    id: "B1-high-entropy-secret", check: "B1", module: "B", title: "Yüksek-entropili sabit secret (rastgele token'a benziyor)",
    severity: "P1", category: "Secret", confidence: "medium",
    // Desen ucuz bir ön-filtredir; asıl karar entropi doğrulayıcısında verilir (FP düşük).
    pattern: /['"`][^'"`\s]{20,}['"`]/,
    validate: (line) => looksHighEntropySecret(line),
    pathExclude: /\.(md|txt|lock|snap)$|lock\.(json|yaml)$/i,
    impact: "Secret-benzeri anahtara atanmış yüksek-entropili sabit değer; sızmış bir sır olabilir.",
    recommendation: "Değeri env/secret manager'dan oku; koddan kaldır; gerçek secret ise rotasyon yap.",
    references: ["OWASP A07:2021"], effort: "S", maxPerFile: 5,
  },

  // ---- SSRF (OWASP A10) --------------------------------------------------
  {
    id: "B6-ssrf-node", check: "B6", module: "B", title: "SSRF adayı: sunucu isteği URL'i istemci girdisinden",
    severity: "P1", category: "SSRF", confidence: "low",
    pattern: /\b(axios|fetch|got|superagent|http|https)\s*(\.\w+)?\s*\(\s*[`'"]?[^)]*(req\.(params|query|body)|ctx\.(request|query|params))/i,
    pathInclude: /\.(ts|js|mjs|cjs)$/i,
    impact: "İstek hedefi kullanıcı girdisiyle belirleniyor; iç ağ/metadata servisine (169.254.169.254) erişim mümkün.",
    recommendation: "Hedef host'u allow-list ile doğrula; şema/IP aralığını kısıtla; DNS-rebinding'e karşı çözümlenmiş IP'yi denetle.",
    references: ["OWASP A10:2021", "ASVS 12.6"], effort: "M",
  },
  {
    id: "B6-ssrf-py", check: "B6", module: "B", title: "SSRF adayı: requests/urlopen hedefi girdiden",
    severity: "P1", category: "SSRF", confidence: "low",
    pattern: /\b(requests\.(get|post|put|delete|head)|urllib\.request\.urlopen|urlopen|httpx\.(get|post))\s*\(\s*[^)]*request\.(GET|POST|data|args)/,
    pathInclude: /\.py$/,
    impact: "İstek hedefi kullanıcı girdisiyle belirleniyor; iç ağ/metadata servisine erişim mümkün.",
    recommendation: "Hedef host'u allow-list ile doğrula; iç IP aralıklarını engelle.",
    references: ["OWASP A10:2021"], effort: "M",
  },

  // ---- SSTI (Server-Side Template Injection) -----------------------------
  {
    id: "B6-ssti-py", check: "B6", module: "B", title: "SSTI adayı: render_template_string dinamik girdiyle",
    severity: "P0", category: "Injection", confidence: "medium",
    pattern: /render_template_string\s*\(\s*[^)]*(\+|%|\.format\(|f['"]|request\.)/,
    pathInclude: /\.py$/,
    impact: "Kullanıcı girdisi Jinja2 template'ine gömülüyor; SSTI → RCE mümkün.",
    recommendation: "Template'i sabit tut; kullanıcı verisini yalnızca bağlam değişkeni olarak geçir; autoescape.",
    references: ["OWASP A03:2021"], effort: "M",
  },
  {
    id: "B6-ssti-node", check: "B6", module: "B", title: "SSTI adayı: template derleme dinamik girdiyle",
    severity: "P1", category: "Injection", confidence: "low",
    pattern: /\b(Handlebars\.compile|ejs\.render|pug\.compile|_\.template)\s*\(\s*[^)]*(req\.|\$\{|\+)/,
    pathInclude: /\.(ts|js|mjs|cjs)$/i,
    impact: "Kullanıcı girdisi template motoruna derleniyor; SSTI/kod çalıştırma riski.",
    recommendation: "Template kaynağını sabit tut; girdiyi yalnızca veri olarak geçir.",
    references: ["OWASP A03:2021"], effort: "M",
  },

  // ---- Path traversal ----------------------------------------------------
  {
    id: "B6-path-traversal-node", check: "B6", module: "B", title: "Path traversal adayı: dosya yolu istemci girdisinden",
    severity: "P1", category: "Path Traversal", confidence: "low",
    pattern: /\b(readFile|readFileSync|createReadStream|sendFile|res\.sendFile|res\.download)\s*\(\s*[^)]*(req\.(params|query|body)|ctx\.params)/,
    pathInclude: /\.(ts|js|mjs|cjs)$/i,
    impact: "Dosya yolu kullanıcıdan geliyor; `../` ile keyfi dosya okuma (LFI) mümkün.",
    recommendation: "path.basename ile sınırla; kök dizine göre normalize edip prefix doğrula; allow-list kullan.",
    references: ["OWASP A01:2021", "ASVS 12.3"], effort: "M",
  },
  {
    id: "B6-path-traversal-py", check: "B6", module: "B", title: "Path traversal adayı: open() istemci girdisiyle",
    severity: "P1", category: "Path Traversal", confidence: "low",
    pattern: /\bopen\s*\(\s*[^)]*(request\.(GET|POST|args|data)|os\.path\.join\([^)]*request\.)/,
    pathInclude: /\.py$/,
    impact: "Dosya yolu kullanıcıdan geliyor; `../` ile keyfi dosya okuma mümkün.",
    recommendation: "os.path.realpath ile kökü doğrula; kullanıcı girdisini allow-list'e bağla.",
    references: ["OWASP A01:2021"], effort: "M",
  },

  // ---- Güvensiz deserialization (OWASP A08) ------------------------------
  {
    id: "B8-deserialize-node", check: "B8", module: "B", title: "Güvensiz deserialization (node-serialize/vm)",
    severity: "P0", category: "Insecure Deserialization", confidence: "medium",
    pattern: /\b(unserialize\s*\(|node-serialize|vm\.runInNewContext|vm\.runInThisContext)\b/,
    pathInclude: /\.(ts|js|mjs|cjs)$/i,
    impact: "Güvensiz kaynaktan nesne deserialize ediliyor; node-serialize/vm ile RCE mümkün.",
    recommendation: "JSON.parse + şema doğrulama kullan; güvenilmeyen veriyi asla deserialize etme.",
    references: ["OWASP A08:2021"], effort: "M",
  },
  {
    id: "B8-pickle-py", check: "B8", module: "B", title: "Güvensiz deserialization (pickle/yaml.load/marshal)",
    severity: "P0", category: "Insecure Deserialization", confidence: "medium",
    pattern: /\b(pickle\.loads?|cPickle\.loads?|marshal\.loads?|yaml\.load)\s*\(/,
    validate: (line) => !/SafeLoader|safe_load|Loader\s*=\s*yaml\.Safe/.test(line),
    pathInclude: /\.py$/,
    impact: "Güvenilmeyen veri pickle/yaml.load ile deserialize ediliyor; RCE mümkün.",
    recommendation: "yaml.safe_load kullan; pickle yerine JSON; güvenilmeyen veriyi deserialize etme.",
    references: ["OWASP A08:2021"], effort: "M",
  },
  {
    id: "B8-unserialize-php", check: "B8", module: "B", title: "PHP unserialize() (nesne enjeksiyonu)",
    severity: "P1", category: "Insecure Deserialization", confidence: "low",
    pattern: /\bunserialize\s*\(\s*\$/,
    pathInclude: /\.php$/,
    impact: "Kullanıcı verisi unserialize ediliyor; PHP object injection → RCE/POP zinciri.",
    recommendation: "json_decode kullan; unserialize'a allowed_classes=false geç; güvenilmeyen veriyi deserialize etme.",
    references: ["OWASP A08:2021"], effort: "M",
  },
  {
    id: "B8-dotnet-deserialize", check: "B8", module: "B", title: ".NET güvensiz deserialization (BinaryFormatter/TypeNameHandling)",
    severity: "P0", category: "Insecure Deserialization", confidence: "medium",
    pattern: /\b(BinaryFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects))\b/,
    pathInclude: /\.cs$/,
    impact: "Tip bilgisiyle deserialization RCE gadget'larına açık.",
    recommendation: "BinaryFormatter'ı kaldır; System.Text.Json kullan; TypeNameHandling.None.",
    references: ["OWASP A08:2021"], effort: "M",
  },

  // ---- XXE (XML External Entity) -----------------------------------------
  {
    id: "B6-xxe-py", check: "B6", module: "B", title: "XXE adayı: XML parser dış-varlık çözümlü",
    severity: "P1", category: "XXE", confidence: "low",
    pattern: /(etree\.parse|XMLParser\s*\([^)]*resolve_entities\s*=\s*True|lxml.*no_network\s*=\s*False)/,
    pathInclude: /\.py$/,
    impact: "XML dış varlık çözümlemesi açık; dosya sızıntısı/SSRF (XXE) mümkün.",
    recommendation: "defusedxml kullan; resolve_entities=False; DTD/harici varlıkları kapat.",
    references: ["OWASP A05:2021", "ASVS 5.5"], effort: "M",
  },

  // ---- Open redirect -----------------------------------------------------
  {
    id: "B7-open-redirect", check: "B7", module: "B", title: "Open redirect adayı: yönlendirme hedefi girdiden",
    severity: "P2", category: "Security Misconfiguration", confidence: "low",
    pattern: /\bres\.redirect\s*\(\s*(req\.(query|params|body)|[^)]*\+\s*req\.)/,
    pathInclude: /\.(ts|js|mjs|cjs)$/i,
    impact: "Yönlendirme hedefi kullanıcıdan; phishing için açık yönlendirme.",
    recommendation: "Yalnızca göreli yol veya allow-list'teki host'lara yönlendir.",
    references: ["OWASP A01:2021"], effort: "S",
  },

  // ---- Zayıf JWT: algorithm none -----------------------------------------
  {
    id: "B4-jwt-alg-none", check: "B4", module: "B", title: "JWT algorithm 'none' (imza doğrulaması atlanabilir)",
    severity: "P0", category: "Auth Design", confidence: "high",
    pattern: /algorithms?\s*:\s*\[?\s*['"]none['"]/i,
    impact: "alg=none imzasız token'ı kabul eder; kimlik doğrulama tamamen atlanabilir.",
    recommendation: "İzinli algoritmayı açıkça belirt (HS256/RS256); 'none'a asla izin verme.",
    references: ["OWASP A02:2021", "OWASP A07:2021", "ASVS 3.5"], effort: "S",
  },

  // NOT: Zayıf CSP (FE-2) ve üretim source map (FE-4) kuralları v0.10'da Modül FE'ye taşındı.
  // FE-2 artık satır-bazlı değil PENCERE analiziyle çalışıyor (modules/fe/index.ts) — eski
  // `[\s\S]{0,120}` deseni satır-bazlı tarayıcıyla yapısal olarak uyumsuzdu ve çok satırlı
  // helmet/Next.js yazımını sessizce kaçırıyordu.

  // ===================================================================================
  // v0.10 — OWASP kapsam boşlukları: NoSQL/LDAP injection (A03), sabit IV & zayıf JWT
  // secret (A02/A07). Bunlar CHECKS.md'de vaat edilmiş ama hiç uygulanmamıştı.
  // ===================================================================================

  // ---- B6 NoSQL injection (A03) ------------------------------------------
  {
    id: "B6-nosql-where", check: "B6", module: "B", title: "NoSQL injection: $where/$function JavaScript'i dinamik girdiyle",
    severity: "P0", category: "Injection", confidence: "medium",
    pattern: /\$(?:where|function|accumulator)\s*[:=]\s*(?:[`'"][^\n]{0,120}?(?:\$\{|['"]\s*\+|\+\s*['"`])|[A-Za-z_$][\w$]*\s*\+|(?:req|ctx|request)\.)/i,
    impact: "$where MongoDB sunucusunda JavaScript çalıştırır; istemci girdisi buraya girerse tam koleksiyon okuma ve veri sızıntısı mümkün.",
    recommendation: "$where/$function kullanma; $expr + tipli operatörlerle yaz. Zorunluysa girdiyi allow-list ile doğrula, asla string'e gömme.",
    references: ["OWASP A03:2021", "ASVS 5.3.4", "CWE-943"], effort: "M",
  },
  {
    id: "B6-nosql-operator", check: "B6", module: "B", title: "NoSQL operatör enjeksiyonu adayı: istemci değeri doğrudan sorgu filtresinde",
    severity: "P1", category: "Injection", confidence: "low",
    pattern: /\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(\s*\{[^}\n]*:\s*(?:req|ctx)\.(?:body|query|params)\.[A-Za-z_$][\w$]*\s*[,}]/,
    // Cast/şema doğrulaması varsa operatör enjeksiyonu kapalıdır → FP'yi bu eler.
    validate: (line) => !/\bString\(|\.toString\(|\bNumber\(|parseInt\(|parseFloat\(|ObjectId\(|\bz\.|Joi\.|yup\.|\.parse\(/.test(line),
    impact: 'Gövde/query değeri nesne olabilir ({"$ne":null}); doğrudan filtreye konursa kimlik doğrulama bypass\'ı veya kayıt sızıntısı olur.',
    recommendation: "Değeri String()/Number() ile cast et veya Zod/Joi şemasıyla doğrula; Mongoose'ta sanitizeFilter/strictQuery aç, express-mongo-sanitize kullan.",
    references: ["OWASP A03:2021", "ASVS 5.3.4", "CWE-943"], effort: "M",
  },

  // ---- B6 LDAP injection (A03) -------------------------------------------
  {
    id: "B6-ldap-injection", check: "B6", module: "B", title: "LDAP injection: arama filtresi istemci girdisiyle birleştiriliyor",
    severity: "P0", category: "Injection", confidence: "medium",
    // İKİ SİNYAL aynı satırda: LDAP bağlamı + (attr=...) filtresinde birleştirme/interpolasyon.
    pattern: /(?:ldap|\bsearch\b|\bfilter\b|\bbind\b|DirectorySearcher|InitialDirContext)[^\n]{0,120}?\(\s*(?:uid|cn|sn|mail|sAMAccountName|userPrincipalName|objectClass|memberOf|distinguishedName)\s*=[^)\n]{0,60}(?:\$\{|['"]\s*\+|\+\s*['"`]|%s|\{\})/i,
    impact: "LDAP filtresine kaçışsız girdi girerse saldırgan `*)(uid=*` ile kimlik doğrulamayı atlar veya tüm dizini okur.",
    recommendation: "Parametreli/escape'li API kullan (ldapjs filter nesnesi, ldap.escape, .NET LdapFilterEncode, python-ldap3 escape_filter_chars); girdiyi allow-list ile doğrula.",
    references: ["OWASP A03:2021", "ASVS 5.3.7", "CWE-90"], effort: "M",
  },

  // ---- B3 Sabit/statik IV (A02) ------------------------------------------
  {
    id: "B3-static-iv", check: "B3", module: "B", title: "createCipheriv sabit/sıfır IV ile (deterministik şifreleme)",
    severity: "P1", category: "Cryptographic Failure", confidence: "high",
    pattern: /createCipheriv\s*\([^)\n]*,\s*(?:Buffer\.from\s*\(\s*['"]|Buffer\.alloc\s*\(\s*\d+\s*\)|['"][^'"\n]{8,}['"]|new\s+Uint8Array\s*\(\s*\[)/i,
    validate: (line) => !/randomBytes|randomFillSync|getRandomValues|randomUUID/.test(line),
    impact: "Sabit IV aynı düz metni her seferinde aynı şifreli metne çevirir; CBC'de blok deseni sızar, GCM/CTR'de nonce tekrarı anahtar akışını ifşa eder → düz metin kurtarılabilir.",
    recommendation: "Her şifreleme için crypto.randomBytes(12|16) ile IV/nonce üret; IV'yi şifreli metnin başına ekleyip birlikte sakla (gizli değil, TEKRARSIZ olmalı).",
    references: ["OWASP A02:2021", "ASVS 6.2.3", "CWE-329"], effort: "S",
  },
  {
    id: "B3-static-iv-const", check: "B3", module: "B", title: "Sabit IV/nonce tanımı (modül düzeyinde değişmez başlangıç vektörü)",
    severity: "P1", category: "Cryptographic Failure", confidence: "medium",
    pattern: /\b(?:const|let|var|static\s+readonly|private\s+static)\s+[\w$]*(?:iv|IV|Iv|nonce|Nonce)[\w$]*\s*(?::\s*[\w<>[\]]+)?\s*=\s*(?:Buffer\.from\s*\(\s*['"]|Buffer\.alloc\s*\(\s*\d+\s*\)|['"][0-9a-fA-F]{16,}['"]|new\s+(?:Uint8Array|byte\[\])\s*[([]\s*[\d{])/,
    validate: (line) => !/randomBytes|randomFillSync|getRandomValues/.test(line),
    impact: "IV sabit bir sabitten geliyorsa tüm şifreleme çağrıları aynı IV'yi paylaşır — sabit IV ile aynı sonuç.",
    recommendation: "IV'yi sabit tanımlama; çağrı başına crypto.randomBytes ile üret.",
    references: ["OWASP A02:2021", "ASVS 6.2.3", "CWE-329"], effort: "S",
  },
  {
    id: "B3-static-iv-py", check: "B3", module: "B", title: "Sabit IV (PyCryptodome AES.new)",
    severity: "P1", category: "Cryptographic Failure", confidence: "high",
    pattern: /AES\.new\s*\([^)\n]*,\s*AES\.MODE_(?:CBC|CFB|OFB|CTR|GCM|OCB)\s*,\s*(?:b?['"][^'"\n]+['"]|bytes\s*\(\s*\d+\s*\)|IV\b|iv\b)/,
    validate: (line) => !/get_random_bytes|os\.urandom|secrets\./.test(line),
    impact: "Sabit IV ile AES deterministik olur; CTR/GCM'de nonce tekrarı anahtarı pratikte kırar.",
    recommendation: "get_random_bytes(16) / os.urandom(12) ile IV üret; şifreli metinle birlikte sakla.",
    references: ["OWASP A02:2021", "ASVS 6.2.3", "CWE-329"], effort: "S",
  },

  // ---- B4 Zayıf JWT secret (A02/A07) -------------------------------------
  {
    id: "B4-weak-jwt-secret", check: "B4", module: "B", title: "Zayıf/tahmin edilebilir JWT imza secret'ı",
    severity: "P0", category: "Auth Design", confidence: "medium",
    pattern: /\b(?:sign|verify|signAsync|verifyAsync)\s*\([^\n]{0,160}['"`]/,
    // İki koşul birden: satırda JWT bağlamı VE secret argümanı konumunda zayıf bir literal.
    validate: (line) =>
      /\b(?:jwt|jsonwebtoken|jose|jwtVerify|SignJWT)\b/i.test(line) && secretArgLiterals(line).some(isWeakSecretLiteral),
    impact: "Zayıf HMAC secret'ı çevrimdışı kaba kuvvetle (hashcat -m 16500) dakikalar içinde kırılır; saldırgan istediği kullanıcı için geçerli token üretir → tam kimlik doğrulama bypass'ı.",
    recommendation: "En az 32 bayt rastgele secret kullan (crypto.randomBytes(32).toString('base64')); secret manager'dan oku, koda gömme; mümkünse RS256/ES256'ya geç ve rotasyon planla.",
    references: ["OWASP A02:2021", "OWASP A07:2021", "ASVS 3.5", "CWE-321", "CWE-326"], effort: "M",
  },
  {
    id: "B4-weak-jwt-secret-config", check: "B4", module: "B", title: "Yapılandırmada zayıf JWT/token secret'ı",
    severity: "P1", category: "Auth Design", confidence: "medium",
    pattern: /\b(?:jwt[_-]?secret|jwtSecret|secretOrKey|secretOrPrivateKey|token[_-]?secret|access[_-]?token[_-]?secret|refresh[_-]?token[_-]?secret|app[_-]?secret)\b\s*[:=]\s*['"`]/i,
    validate: (line) => configSecretLiterals(line).some(isWeakSecretLiteral),
    impact: "Yapılandırmadaki zayıf secret tüm ortamlarda aynı olur; sızarsa veya kırılırsa saldırgan geçerli token forge eder.",
    recommendation: "Secret'ı env/secret manager'dan oku; ≥32 bayt rastgele üret; ortam başına farklı olsun.",
    references: ["OWASP A07:2021", "ASVS 3.5", "CWE-321"], effort: "S",
  },
];
