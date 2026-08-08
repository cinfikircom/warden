import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül AUTH — Kimlik & Oturum Sertleştirme (pasif, statik).
 * =========================================================================
 * SaaS/CRM/ERP'de hesap devri (account takeover) yüzeyini denetler:
 *   AUTH-1  MFA/2FA yok (login var ama ikinci faktör sinyali yok)
 *   AUTH-2  Tahmin edilebilir/güvensiz reset·doğrulama token'ı (Math.random/Date.now → crypto değil)
 *   AUTH-3  Güvensiz oturum çerezi (httpOnly/secure/sameSite eksik veya false)
 *   AUTH-4  JWT süresi (expiry) olmadan imzalanıyor → çalınan token sonsuza dek geçerli
 *   AUTH-5  Login'de brute-force koruması yok (rate-limit / lockout / deneme sayacı yok)
 *   AUTH-6  Zayıf parola politikası (parola hash'leniyor ama güç/karmaşıklık kontrolü yok)
 *
 * Yalnızca bir kimlik/oturum yüzeyi (login/parola/jwt/session) tespit edilirse koşar. Yokluk-temelli
 * kontroller (AUTH-1/5/6) heuristiktir → düşük güven, `.warden-ignore.yml` ile bastırılabilir.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|cs|java)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__)\//i;

// Kimlik/oturum yüzeyi (uygulanabilirlik).
const AUTH_SURFACE = /\b(login|signin|sign-in|signup|sign-up|register|password|passwd|bcrypt|argon2|scrypt|pbkdf2|jsonwebtoken|jwt\.sign|passport|next-auth|nextauth|express-session|\.hash\s*\(|authenticate|oauth)\b/i;
const LOGIN_SIG = /\b(login|signin|sign-in|authenticate|passport\.authenticate|signInWith|log_in|session_create)\b/i;
const MFA_SIG = /\b(mfa|2fa|two.?factor|totp|otpauth|authenticator|speakeasy|otplib|webauthn|passkey|verify.?otp|second.?factor|backup.?codes?)\b/i;
const BRUTE_FORCE_SIG = /\b(rate.?limit|ratelimit|express-rate-limit|rate-limiter|rateLimiter|lockout|failed.?attempts|loginAttempts|login_attempts|too.?many.?attempts|brute.?force|express-brute|account.?lock)\b/i;
/*
 * Parola hash'leme — İMPORT DEĞİL, ÇAĞRI aranır.
 *
 * Eski desen kütüphane adının geçmesini yeterli sayıyordu. NodeGoat'ta
 * `const bcrypt = require("bcrypt-nodejs")` satırı duruyor ama tek kullanımı yorum içinde:
 * parolalar düz metin saklanıyor, buna rağmen "hash var" sonucuna varılıyordu. Kullanılmayan
 * bir import, uygulanmış bir koruma değildir.
 */
const PASSWORD_HASH =
  /\b(bcrypt|argon2|scrypt)\s*\.\s*\w*(hash|compare|verify)\w*\s*\(|\bpbkdf2(Sync)?\s*\(|\bpassword_hash\s*\(|\bmake_password\s*\(|\bcheck_password\s*\(|\bBCryptPasswordEncoder\b|\bPassword(Hasher|Encoder)\b|\bhashPassword\s*\(|\bcreateHash\s*\([^)]*\)\s*\.\s*update\s*\([^)]*password/i;
const PASSWORD_STRENGTH = /\b(zxcvbn|password.?strength|password.?policy|passwordSchema|min.?length|complexity|owasp.?password|haveibeenpwned|pwned|password.?validator)\b/i;

// AUTH-2: zayıf reset/doğrulama token üretimi.
const RESET_TOKEN_WEAK = /(reset|verification|verify|confirm|otp|activation|magic|token)[\w]*\s*[:=][\s\S]{0,50}(Math\.random|Date\.now|uuidv1|uuid\.v1|new Date\(\)\.getTime|rand\(\)|mt_rand)/i;
// AUTH-3: güvensiz çerez bayrakları.
const COOKIE_INSECURE = /httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*["'`]?none["'`]?/i;
const COOKIE_SET = /\bres\.cookie\s*\(|\bsetCookie\s*\(|response\.set_cookie\s*\(/i;
// AUTH-4: JWT imzalama.
const JWT_SIGN = /\bjwt\.sign\s*\(|jsonwebtoken[\s\S]{0,20}sign|\.sign\s*\([^)]*secret/i;
const JWT_EXP = /expiresIn|["'`]exp["'`]|setExpiration|\.exp\s*=|maxAge/i;
// AUTH-8: girişte oturuma kimlik yazımı ve oturum yenileme.
const SESSION_LOGIN_WRITE = /\b(req|request|ctx)\.session\.(user(Id|Name)?|userId|currentUser|uid|account)\s*=/i;
const SESSION_REGENERATE = /\.session\.regenerate\s*\(|\bregenerateSession\s*\(|session_regenerate_id\s*\(|\.cycleKey\s*\(/i;
// AUTH-9: giriş hatasında kullanıcı/parola ayrımı (enumeration).
const ERR_USER_SPECIFIC = /\b\w*(invalid|incorrect|wrong|unknown|no)\w*[_\s]*(user(name)?|email|account)\w*\b\s*[:=]|["'`][^"'`]*(user\s*(name)?\s*(not\s*found|does\s*not\s*exist)|no\s+such\s+user)[^"'`]*["'`]/i;
const ERR_PASS_SPECIFIC = /\b\w*(invalid|incorrect|wrong)\w*[_\s]*(pass(word|wd)?)\w*\b\s*[:=]|["'`][^"'`]*(incorrect|invalid|wrong)\s+password[^"'`]*["'`]/i;

export interface AuthFile {
  readonly path: string;
  readonly content: string;
}
export interface AuthData {
  readonly usesAuth: boolean;
  readonly hasLogin: boolean;
  readonly hasMfa: boolean;
  readonly hasBruteForce: boolean;
  readonly hasPasswordHash: boolean;
  readonly hasPasswordStrength: boolean;
  readonly files: readonly AuthFile[];
}

/**
 * Yorumları çıkarır. "Bir kontrolün YOKLUĞU" bulgusu (AUTH-1/5/6) yorumdaki bir sözden
 * ("// TODO: MFA ekle", "// rate limit yok") sahte-bastırılmamalı — sinyal GERÇEK kodda aranmalı.
 * http:// gibi URL'leri korur (öncesindeki ':' varsa // silinmez).
 */
export function stripComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/(^|\s)#[^\n]*/g, "$1");
}

export function collectAuthData(ctx: DetectContext): AuthData {
  const candidates = ctx.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: 6000 });
  const files: AuthFile[] = [];
  let usesAuth = false, hasLogin = false, hasMfa = false, hasBruteForce = false, hasPasswordHash = false, hasPasswordStrength = false;

  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    // Yokluk-temelli kontrollerin bayrakları YORUMSUZ kodda aranır (yorumdaki söz bastırmasın).
    const code = stripComments(content);
    if (LOGIN_SIG.test(code)) hasLogin = true;
    if (MFA_SIG.test(code)) hasMfa = true;
    if (BRUTE_FORCE_SIG.test(code)) hasBruteForce = true;
    if (PASSWORD_HASH.test(code)) hasPasswordHash = true;
    if (PASSWORD_STRENGTH.test(code)) hasPasswordStrength = true;
    if (AUTH_SURFACE.test(content)) {
      usesAuth = true;
      files.push({ path: f, content });
    }
  }
  return { usesAuth, hasLogin, hasMfa, hasBruteForce, hasPasswordHash, hasPasswordStrength, files };
}

export function analyzeAuth(data: AuthData): Finding[] {
  if (!data.usesAuth) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };
  const anchor = data.files[0]?.path ?? "auth-surface";

  // --- Proje düzeyi (yokluk-temelli) ---
  if (data.hasLogin && !data.hasMfa) {
    push(makeFinding({
      id: "AUTH-1-no-mfa", title: "Çok faktörlü kimlik doğrulama (MFA/2FA) tespit edilemedi",
      severity: "P2", module: "AUTH", check: "AUTH-1", category: "Authentication", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "login/kimlik akışı var; MFA/TOTP/WebAuthn/2FA sinyali bulunamadı" }],
      impact: "MFA olmadan tek bir sızmış/tahmin edilmiş parola hesap devrine yeter — SaaS/CRM/ERP'de yönetici hesabı = tüm kiracı verisi.",
      recommendation: "En azından yönetici/hassas roller için MFA (TOTP/WebAuthn/passkey) ekle; kademeli olarak tüm kullanıcılara yay; hassas işlemlerde step-up auth uygula.",
      effort: "L", autoFixable: false, references: ["OWASP A07:2021", "ASVS 2.8", "NIST 800-63B"],
    }));
  }
  if (data.hasLogin && !data.hasBruteForce) {
    push(makeFinding({
      id: "AUTH-5-no-brute-force", title: "Login'de brute-force / kaba-kuvvet koruması yok",
      severity: "P2", module: "AUTH", check: "AUTH-5", category: "Authentication", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "login akışı var; rate-limit / hesap kilitleme / deneme sayacı sinyali bulunamadı" }],
      impact: "Hız sınırı/kilit olmadan saldırgan parola/OTP tahminini sınırsız deneyebilir (credential stuffing, brute-force).",
      recommendation: "Login'e IP+hesap bazlı rate-limit, artan gecikme/lockout, CAPTCHA (şüpheli trafik), ve credential-stuffing tespiti ekle.",
      effort: "M", autoFixable: false, references: ["OWASP A07:2021", "ASVS 2.2.1", "CWE-307"],
    }));
  }
  /*
   * AUTH-7 — parola hiç hash'lenmiyor.
   *
   * AUTH-6 "hash var ama güç politikası yok" diyordu; hash'in kendisinin YOKLUĞU hiç
   * kontrol edilmiyordu. Oysa bu daha temel ve daha ağır bir kusur: veritabanı sızıntısında
   * tüm parolalar doğrudan okunur ve kullanıcıların diğer servislerdeki hesapları da düşer.
   *
   * Ölçüt yorumsuz KODDUR: düzeltilmiş sürüm (`bcrypt.hashSync(...)`) sıklıkla yorumda
   * bekler — NodeGoat'ta tam olarak öyle — ve yorumu saymak kusuru görünmez kılardı.
   */
  if (data.hasLogin && !data.hasPasswordHash) {
    push(makeFinding({
      id: "AUTH-7-plaintext-password", title: "Parola hash'leme tespit edilemedi (düz metin saklama riski)",
      severity: "P0", module: "AUTH", check: "AUTH-7", category: "Authentication", confidence: "medium",
      evidence: [{ type: "config", source: anchor, excerpt: "login/kayıt akışı var; bcrypt/argon2/scrypt/pbkdf2 gibi parola hash'leme çağrısı yorumsuz kodda bulunamadı" }],
      impact:
        "Parolalar düz metin (veya tersine çevrilebilir) saklanıyorsa, veritabanı sızıntısında tüm " +
        "hesaplar anında düşer; kullanıcılar parolalarını tekrar kullandığı için etki diğer servislere yayılır.",
      recommendation:
        "Parolaları argon2id (tercihen) veya bcrypt ile, kullanıcı başına salt üreterek hash'le. " +
        "Doğrulamada sabit-zamanlı karşılaştırma kullan (`bcrypt.compare`), asla `===` ile karşılaştırma.",
      effort: "M", autoFixable: false, references: ["OWASP A02:2021", "ASVS 2.4", "CWE-256", "CWE-916"],
    }));
  }
  if (data.hasPasswordHash && !data.hasPasswordStrength) {
    push(makeFinding({
      id: "AUTH-6-weak-password-policy", title: "Parola güç/politika kontrolü tespit edilemedi",
      severity: "P2", module: "AUTH", check: "AUTH-6", category: "Authentication", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "parola hash'leniyor; güç/karmaşıklık/pwned-parola kontrolü sinyali yok" }],
      impact: "Zayıf parolalar kabul edilirse (12345678, şirket adı) brute-force ve credential-stuffing kolaylaşır.",
      recommendation: "Uzunluk-öncelikli politika (≥12), yaygın/pwned-parola engelleme (HaveIBeenPwned k-anonimlik), zxcvbn güç ölçümü ekle; kompozisyon kurallarına takılıp kalma.",
      effort: "M", autoFixable: false, references: ["OWASP A07:2021", "ASVS 2.1", "NIST 800-63B"],
    }));
  }

  // --- Dosya/satır düzeyi ---
  for (const { path, content } of data.files) {
    const lines = content.split(/\r?\n/);

    /*
     * AUTH-8 — oturum sabitleme (session fixation).
     *
     * Başarılı girişte oturum kimliği YENİLENMEZSE, saldırganın önceden kurbana verdiği
     * oturum kimliği giriş sonrası da geçerli kalır ve saldırgan kurbanın oturumuna sahip olur.
     * Düzeltme tek satırdır (`req.session.regenerate(...)`) ama sıklıkla atlanır.
     */
    const li8 = lines.findIndex((l) => SESSION_LOGIN_WRITE.test(l));
    if (li8 >= 0 && !SESSION_REGENERATE.test(content)) {
      push(makeFinding({
        id: `AUTH-8-session-fixation:${path}:${li8 + 1}`,
        title: "Girişte oturum kimliği yenilenmiyor (session fixation)",
        severity: "P1", module: "AUTH", check: "AUTH-8", category: "Session Management", confidence: "medium",
        evidence: [{ type: "file", source: path, location: String(li8 + 1), excerpt: (lines[li8] ?? "").trim().slice(0, 160) }],
        impact:
          "Saldırgan kurbana bilinen bir oturum kimliği verirse, kurban giriş yaptıktan sonra o kimlik " +
          "hâlâ geçerli olur ve saldırgan kurbanın kimliğiyle oturuma girer (session fixation).",
        recommendation:
          "Başarılı girişte oturumu yenile: Express'te `req.session.regenerate()`, ardından kullanıcı " +
          "bilgisini yeni oturuma yaz. Yetki yükselten her adımda (ör. sudo modu) aynısını uygula.",
        effort: "S", autoFixable: false, references: ["OWASP A07:2021", "ASVS 3.2.1", "CWE-384"],
      }));
    }

    /*
     * AUTH-9 — kullanıcı adı enumeration.
     *
     * Giriş başarısızlığında "kullanıcı bulunamadı" ile "parola yanlış" ayrı ayrı
     * söyleniyorsa, saldırgan hangi hesapların var olduğunu tek tek öğrenebilir; bu, hedefli
     * parola püskürtme (password spraying) ve kimlik avı için hazır bir liste demektir.
     *
     * İki ayrı mesajın AYNI dosyada bulunması aranır — tek başına biri normaldir.
     */
    if (ERR_USER_SPECIFIC.test(content) && ERR_PASS_SPECIFIC.test(content)) {
      const li9 = lines.findIndex((l) => ERR_USER_SPECIFIC.test(l));
      push(makeFinding({
        id: `AUTH-9-user-enumeration:${path}`,
        title: "Giriş hataları kullanıcı adını ele veriyor (enumeration)",
        severity: "P2", module: "AUTH", check: "AUTH-9", category: "Authentication", confidence: "low",
        evidence: [{ type: "file", source: path, ...(li9 >= 0 ? { location: String(li9 + 1) } : {}), excerpt: (lines[li9] ?? "").trim().slice(0, 160) }],
        impact:
          "\"Geçersiz kullanıcı\" ve \"geçersiz parola\" ayrı mesajlar olduğunda saldırgan geçerli hesapları " +
          "tek tek doğrulayabilir; bu, hedefli parola püskürtme ve kimlik avı için hesap listesi üretir.",
        recommendation:
          "Her iki durumda da aynı genel mesajı ve aynı yanıt süresini döndür (\"E-posta veya parola hatalı\"). " +
          "Kayıt ve parola sıfırlama akışlarında da aynı ilkeyi uygula.",
        effort: "S", autoFixable: false, references: ["OWASP A07:2021", "ASVS 2.2.2", "CWE-204"],
      }));
    }

    // AUTH-4 — JWT süresiz imzalanıyor (dosya düzeyi).
    if (JWT_SIGN.test(content) && !JWT_EXP.test(content)) {
      const li = lines.findIndex((l) => JWT_SIGN.test(l));
      push(makeFinding({
        id: `AUTH-4-jwt-no-expiry:${path}`, title: "JWT son kullanma (expiry) olmadan imzalanıyor",
        severity: "P1", module: "AUTH", check: "AUTH-4", category: "Session Management", confidence: "medium",
        evidence: [{ type: "file", source: path, ...(li >= 0 ? { location: String(li + 1) } : {}), excerpt: "jwt.sign var; expiresIn/exp yok" }],
        impact: "Süresiz JWT bir kez çalınırsa (log, XSS, cihaz) sonsuza dek geçerlidir; iptal edilemez, oturum sonlandırılamaz.",
        recommendation: "Kısa ömürlü access token (expiresIn) + refresh token rotasyonu kullan; sunucu tarafı iptal listesi/oturum kaydı tut.",
        effort: "M", autoFixable: false, references: ["OWASP A07:2021", "CWE-613"],
      }));
    }

    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      const loc = String(i + 1);

      // AUTH-2 — tahmin edilebilir reset/doğrulama token'ı.
      if (RESET_TOKEN_WEAK.test(ln)) {
        push(makeFinding({
          id: `AUTH-2-weak-reset-token:${path}:${i + 1}`, title: "Tahmin edilebilir reset/doğrulama token'ı (Math.random/Date.now)",
          severity: "P1", module: "AUTH", check: "AUTH-2", category: "Authentication", confidence: "medium",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "Math.random/Date.now kriptografik değildir; saldırgan reset/doğrulama token'ını tahmin edip hesabı ele geçirir.",
          recommendation: "Token'ı kriptografik rastgelelikle üret (crypto.randomBytes/randomUUID, ≥128 bit); tek kullanımlık + kısa expiry + kullanınca iptal.",
          effort: "S", autoFixable: false, references: ["OWASP A07:2021", "CWE-330", "CWE-640"],
        }));
      }

      // AUTH-3 — güvensiz oturum çerezi.
      if (COOKIE_INSECURE.test(ln) || (COOKIE_SET.test(ln) && !/httpOnly/i.test(ln))) {
        push(makeFinding({
          id: `AUTH-3-insecure-cookie:${path}:${i + 1}`, title: "Güvensiz oturum çerezi (httpOnly/secure/sameSite eksik veya kapalı)",
          severity: "P1", module: "AUTH", check: "AUTH-3", category: "Session Management", confidence: "medium",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "httpOnly yoksa XSS ile oturum çerezi çalınır; secure yoksa düz HTTP'de sızar; sameSite=none+secure değilse CSRF yüzeyi açılır.",
          recommendation: "Oturum çerezini httpOnly + secure + sameSite=lax/strict ile ayarla; token'ı asla localStorage'da tutma; oturumları rotasyonla.",
          effort: "S", autoFixable: false, references: ["OWASP A05:2021", "ASVS 3.4", "CWE-1004"],
        }));
      }
    }
  }
  return findings;
}

export const authModule: WardenModule = {
  id: "AUTH",
  title: "Kimlik & Oturum Sertleştirme",
  active: false,
  applicable(ctx: ScanContext) {
    return collectAuthData(ctx.fs).usesAuth;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const data = collectAuthData(ctx.fs);
    const findings = analyzeAuth(data);
    ctx.audit.info(`AUTH: ${findings.length} bulgu (${data.files.length} yüzey dosyası).`);
    return { findings, surface: data.files.length };
  },
};
