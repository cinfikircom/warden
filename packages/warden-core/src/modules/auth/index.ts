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
const PASSWORD_HASH = /\b(bcrypt|argon2|scrypt|pbkdf2|password_hash|make_password|BCryptPasswordEncoder)\b|\.hash\s*\(/i;
const PASSWORD_STRENGTH = /\b(zxcvbn|password.?strength|password.?policy|passwordSchema|min.?length|complexity|owasp.?password|haveibeenpwned|pwned|password.?validator)\b/i;

// AUTH-2: zayıf reset/doğrulama token üretimi.
const RESET_TOKEN_WEAK = /(reset|verification|verify|confirm|otp|activation|magic|token)[\w]*\s*[:=][\s\S]{0,50}(Math\.random|Date\.now|uuidv1|uuid\.v1|new Date\(\)\.getTime|rand\(\)|mt_rand)/i;
// AUTH-3: güvensiz çerez bayrakları.
const COOKIE_INSECURE = /httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*["'`]?none["'`]?/i;
const COOKIE_SET = /\bres\.cookie\s*\(|\bsetCookie\s*\(|response\.set_cookie\s*\(/i;
// AUTH-4: JWT imzalama.
const JWT_SIGN = /\bjwt\.sign\s*\(|jsonwebtoken[\s\S]{0,20}sign|\.sign\s*\([^)]*secret/i;
const JWT_EXP = /expiresIn|["'`]exp["'`]|setExpiration|\.exp\s*=|maxAge/i;

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
    const findings = analyzeAuth(collectAuthData(ctx.fs));
    ctx.audit.info(`AUTH: ${findings.length} bulgu.`);
    return { findings };
  },
};
