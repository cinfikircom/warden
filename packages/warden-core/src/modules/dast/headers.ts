import type { Finding } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import { makeFinding } from "../../util/finding.ts";
import type { ProbeResponse } from "./client.ts";

/** C2 — canlı security header değerlendirmesi. */
interface HeaderRule {
  readonly header: string;
  readonly title: string;
  readonly severity: Severity;
  readonly recommendation: string;
}

const HEADER_RULES: readonly HeaderRule[] = [
  { header: "strict-transport-security", title: "HSTS header yok", severity: "P1",
    recommendation: "Strict-Transport-Security ekle (max-age>=15552000; includeSubDomains)." },
  { header: "content-security-policy", title: "Content-Security-Policy yok", severity: "P1",
    recommendation: "CSP ekle; en azından default-src 'self' ile başla." },
  { header: "x-frame-options", title: "X-Frame-Options yok (clickjacking)", severity: "P2",
    recommendation: "X-Frame-Options: DENY veya CSP frame-ancestors 'none'." },
  { header: "x-content-type-options", title: "X-Content-Type-Options yok", severity: "P2",
    recommendation: "X-Content-Type-Options: nosniff ekle." },
];

export function analyzeSecurityHeaders(res: ProbeResponse): Finding[] {
  if (res.status === 0) return [];
  const findings: Finding[] = [];
  for (const rule of HEADER_RULES) {
    if (res.headers[rule.header]) continue;
    findings.push(
      makeFinding({
        id: `C2-header:${rule.header}`,
        title: rule.title,
        severity: rule.severity,
        module: "C",
        check: "C2",
        category: "Security Header",
        confidence: "high",
        evidence: [{ type: "endpoint", source: res.url, location: String(res.status), excerpt: `eksik: ${rule.header}` }],
        impact: "Eksik güvenlik header'ı tarayıcı korumalarını zayıflatır.",
        recommendation: rule.recommendation,
        effort: "S",
        autoFixable: false,
        references: ["OWASP A05:2021"],
      }),
    );
  }
  return findings;
}

/** C6 — Set-Cookie bayrakları (Secure/HttpOnly/SameSite). */
export function analyzeCookies(res: ProbeResponse): Finding[] {
  const findings: Finding[] = [];
  for (const cookie of res.setCookies) {
    const name = cookie.split("=")[0]?.trim() ?? "cookie";
    const lc = cookie.toLowerCase();
    const missing: string[] = [];
    if (!lc.includes("httponly")) missing.push("HttpOnly");
    if (!lc.includes("secure")) missing.push("Secure");
    if (!lc.includes("samesite")) missing.push("SameSite");
    if (missing.length === 0) continue;
    // Oturum/token çerezi ise daha kritik.
    const sessiony = /sess|token|jwt|auth|sid/i.test(name);
    findings.push(
      makeFinding({
        id: `C6-cookie:${name}`,
        title: `Cookie '${name}' eksik bayrak: ${missing.join(", ")}`,
        severity: sessiony ? "P1" : "P2",
        module: "C",
        check: "C6",
        category: "Cookie Security",
        confidence: "high",
        evidence: [{ type: "endpoint", source: res.url, location: "Set-Cookie", excerpt: `${name}: eksik ${missing.join("/")}` }],
        impact: "Eksik bayrak: HttpOnly yoksa XSS ile çalınabilir; Secure yoksa düz HTTP'de sızar; SameSite yoksa CSRF.",
        recommendation: "Çerezi HttpOnly + Secure + SameSite=Lax/Strict ile ayarla.",
        effort: "S",
        autoFixable: false,
        references: ["OWASP A05:2021", "ASVS 3.4"],
      }),
    );
  }
  return findings;
}
