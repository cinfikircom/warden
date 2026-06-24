import type { SourceRule } from "./scanner.ts";

/**
 * SAST kural seti (Faz 2). Modül B + Frontend (FE) statik kuralları; her kural OWASP/ASVS'e eşli
 * (Modül E mapping). Desenler bilinçli olarak düşük false-positive; şüpheli olanlar confidence=medium/low.
 */
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

  // ---- B4 / FE Auth tasarımı ---------------------------------------------
  {
    id: "FE-jwt-localstorage", check: "B4", module: "FE", title: "JWT/token localStorage/sessionStorage'da (XSS'e açık)",
    severity: "P1", category: "Auth Design", confidence: "high",
    pattern: /(localStorage|sessionStorage)\.setItem\(\s*['"][^'"]*(token|jwt|auth|access|refresh)/i,
    impact: "XSS ile token çalınabilir; web storage HttpOnly korumasından yoksun.",
    recommendation: "Token'ı httpOnly + Secure + SameSite cookie'de tut; storage'dan çıkar.",
    references: ["OWASP A07:2021", "ASVS 3.4", "OWASP API2"], effort: "M",
  },
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

  // ---- FE Frontend güvenlik ----------------------------------------------
  {
    id: "FE-dangerous-html", check: "FE-3", module: "FE", title: "dangerouslySetInnerHTML (XSS sink)",
    severity: "P1", category: "Frontend XSS", confidence: "medium",
    pattern: /dangerouslySetInnerHTML/,
    pathInclude: /\.(jsx|tsx)$/i,
    impact: "Sanitize edilmemiş HTML enjekte ediliyorsa DOM-XSS.",
    recommendation: "DOMPurify ile sanitize et veya bu kullanımdan kaçın.",
    references: ["OWASP A03:2021"], effort: "S",
  },
  {
    id: "FE-vue-vhtml", check: "FE-3", module: "FE", title: "Vue v-html (XSS sink)",
    severity: "P1", category: "Frontend XSS", confidence: "medium",
    pattern: /\bv-html\s*=/,
    pathInclude: /\.(vue|html)$/i,
    impact: "v-html sanitize edilmemiş HTML render eder; DOM-XSS.",
    recommendation: "DOMPurify ile sanitize et veya metin binding kullan.",
    references: ["OWASP A03:2021"], effort: "S",
  },
];
