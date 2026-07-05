import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül EMAIL — E-posta Güvenliği (pasif, statik).
 * =========================================================================
 * Yalnızca KOD-seviyesinde statik saptanabilen e-posta açıkları. NOT: SPF/DKIM/DMARC
 * DNS/runtime kontrolüdür (canlı domain gerekir) — Modül C/DAST'ın yeri, burada değil.
 *   EMAIL-1  E-posta header injection (kullanıcı girdisi from/replyTo/sender/headers'a)
 *   EMAIL-2  HTML e-posta gövdesine kaçışsız kullanıcı girdisi (içerik enjeksiyonu / phishing)
 *   EMAIL-3  TLS'siz SMTP taşıması (secure:false / port 25 / ignoreTLS / smtp:// düz metin)
 *
 * Yalnızca bir e-posta gönderim yüzeyi (mailer/SMTP) tespit edilirse koşar.
 * Heuristik → düşük/orta güven, `.warden-ignore.yml` ile bastırılır.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__|migrations?)\//i;

// E-posta gönderim yüzeyi sinyalleri.
const MAILER_SIG = /nodemailer|createTransport|sendMail\s*\(|@sendgrid\/mail|sgMail|@aws-sdk\/client-ses|SendEmailCommand|new\s+SES\b|mailgun|postmark|resend|@react-email|\.messages\(\)\.send|smtplib|Mail::send|ActionMailer|swiftmailer|phpmailer/i;
const USER_INPUT = /\breq\.(body|query|params|headers)\b|\brequest\.(GET|POST|args|form)\b|\bparams\[|\$_(GET|POST|REQUEST)\b/i;

// EMAIL-1: kullanıcı girdisi bir e-posta BAŞLIĞI alanına (to hariç — to:userEmail meşru).
const HEADER_FIELD = /\b(from|replyTo|reply_to|sender|cc|bcc|headers)\s*:/i;
// EMAIL-2: html gövdesine string birleştirme/şablonla kullanıcı girdisi.
const HTML_FIELD = /\bhtml\s*:/i;
// EMAIL-3: TLS'siz SMTP taşıması.
const SMTP_NO_TLS = /secure\s*:\s*false|ignoreTLS\s*:\s*true|requireTLS\s*:\s*false|port\s*:\s*25\b|smtp:\/\/[^s]|tls\s*:\s*\{[^}]*rejectUnauthorized\s*:\s*false/i;

export function stripComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/(^|\s)#[^\n]*/g, "$1");
}

export interface EmailFile {
  readonly path: string;
  readonly content: string;
}
export interface EmailData {
  readonly usesMail: boolean;
  readonly files: readonly EmailFile[];
}

export function collectEmailData(ctx: DetectContext): EmailData {
  const candidates = ctx.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: 6000 });
  const files: EmailFile[] = [];
  let usesMail = false;
  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    if (MAILER_SIG.test(content)) {
      usesMail = true;
      files.push({ path: f, content });
    }
  }
  return { usesMail, files };
}

/** Bir başlık/html alanının değerinde kullanıcı girdisi var mı (aynı satır ya da devamı). */
function fieldTakesUserInput(lines: readonly string[], i: number): boolean {
  const window = (lines[i] ?? "") + " " + (lines[i + 1] ?? "");
  return USER_INPUT.test(window);
}

export function analyzeEmail(data: EmailData): Finding[] {
  if (!data.usesMail) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };

  for (const { path, content } of data.files) {
    const lines = stripComments(content).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;

      // EMAIL-1 — header injection (from/replyTo/sender/cc/bcc/headers + kullanıcı girdisi).
      if (HEADER_FIELD.test(ln) && fieldTakesUserInput(lines, i)) {
        push(makeFinding({
          id: `EMAIL-1-header-injection:${path}:${i + 1}`, title: "E-posta header injection (kullanıcı girdisi başlık alanında)",
          severity: "P1", module: "EMAIL", check: "EMAIL-1", category: "Header Injection", confidence: "low",
          evidence: [{ type: "file", source: path, location: String(i + 1), excerpt: ln.trim().slice(0, 160) }],
          impact: "Kullanıcı girdisi from/replyTo/sender/cc/bcc/headers alanına sanitize edilmeden girerse CRLF ile ek başlık enjekte edilebilir (gizli Bcc ile veri sızdırma, gönderen sahteciliği/phishing).",
          recommendation: "Başlık alanlarını asla ham kullanıcı girdisinden kurma; CR/LF'i temizle/redded; kütüphanenin başlık kodlamasına güven (nodemailer otomatik sanitize eder — elle string birleştirmeden kaçın).",
          effort: "S", autoFixable: false, references: ["CWE-93", "CWE-159", "OWASP A03:2021"],
        }));
      }

      // EMAIL-2 — HTML gövdesine kaçışsız kullanıcı girdisi.
      if (HTML_FIELD.test(ln) && fieldTakesUserInput(lines, i) && /[`+]|\$\{/.test(ln + (lines[i + 1] ?? ""))) {
        push(makeFinding({
          id: `EMAIL-2-html-injection:${path}:${i + 1}`, title: "HTML e-posta gövdesine kaçışsız kullanıcı girdisi (içerik enjeksiyonu / phishing)",
          severity: "P2", module: "EMAIL", check: "EMAIL-2", category: "Content Injection", confidence: "low",
          evidence: [{ type: "file", source: path, location: String(i + 1), excerpt: ln.trim().slice(0, 160) }],
          impact: "Kullanıcı girdisi HTML e-posta gövdesine kaçışsız girerse saldırgan sahte içerik/bağlantı enjekte edip alıcıyı kandırabilir (phishing); bazı istemcilerde script/stil ile içerik manipülasyonu.",
          recommendation: "E-posta gövdesindeki kullanıcı verisini HTML-escape et; şablon motoru (otomatik kaçışlı) kullan; ham string birleştirmeyle html kurma.",
          effort: "S", autoFixable: false, references: ["CWE-79", "CWE-80", "OWASP A03:2021"],
        }));
      }

      // EMAIL-3 — TLS'siz SMTP taşıması.
      if (SMTP_NO_TLS.test(ln)) {
        push(makeFinding({
          id: `EMAIL-3-smtp-no-tls:${path}:${i + 1}`, title: "TLS'siz / doğrulamasız SMTP taşıması (kimlik & içerik açıkta)",
          severity: "P2", module: "EMAIL", check: "EMAIL-3", category: "Transport Security", confidence: "medium",
          evidence: [{ type: "file", source: path, location: String(i + 1), excerpt: ln.trim().slice(0, 160) }],
          impact: "SMTP TLS olmadan (secure:false / port 25 / ignoreTLS / rejectUnauthorized:false) çalışırsa SMTP kimlik bilgileri ve e-posta içeriği ağda açık taşınır; MITM okuyabilir/değiştirebilir.",
          recommendation: "SMTP'yi TLS ile kur (secure:true / port 465 ya da STARTTLS + requireTLS:true); rejectUnauthorized:false kullanma; kimlik bilgilerini env'den al.",
          effort: "S", autoFixable: false, references: ["CWE-319", "OWASP A02:2021"],
        }));
      }
    }
  }
  return findings;
}

export const emailModule: WardenModule = {
  id: "EMAIL",
  title: "E-posta Güvenliği",
  active: false,
  applicable(ctx: ScanContext) {
    return collectEmailData(ctx.fs).usesMail;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings = analyzeEmail(collectEmailData(ctx.fs));
    ctx.audit.info(`EMAIL: ${findings.length} bulgu.`);
    return { findings };
  },
};
