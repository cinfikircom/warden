import type { Finding } from "../../model/finding.ts";
import { makeFinding } from "../../util/finding.ts";
import type { ProbeResponse } from "./client.ts";

/** C3 yol listesi (GET ile erişilebilirlik; default-credential DENEMESİ yapılmaz). */
export const ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin", "/manager/html", "/.git/"] as const;

/** C3 — korumasız admin paneli (GET 200 + login/oturum istemiyor görünüyor). */
export function analyzeAdminExposure(res: ProbeResponse): Finding | null {
  if (res.status !== 200) return null;
  const b = res.body.toLowerCase();
  // 200 dönüp login formu YOKSA açık panel olabilir; login varsa zaten korumalı.
  const looksLoginGated = /password|şifre|sign in|giriş yap|login/.test(b);
  if (looksLoginGated) return null;
  const looksAdmin = /dashboard|admin|yönetim|console|manager/.test(b);
  if (!looksAdmin) return null;
  return makeFinding({
    id: `C3-open-admin:${new URL(res.url).pathname}`,
    title: `Korumasız admin paneli erişilebilir: ${new URL(res.url).pathname}`,
    severity: "P0",
    module: "C",
    check: "C3",
    category: "Broken Access Control",
    confidence: "low",
    evidence: [{ type: "endpoint", source: res.url, location: String(res.status), excerpt: res.body.slice(0, 120) }],
    impact: "Admin arayüzü kimlik doğrulaması olmadan açık olabilir; tam ele geçirme riski.",
    recommendation: "Admin'i auth + IP allow-list arkasına al; bu yolu internete kapat.",
    effort: "M",
    autoFixable: false,
    references: ["OWASP A01:2021", "OWASP A05:2021"],
  });
}

/** C4 — düşük hacimli rate-limit eşik testi. statuses: aynı yola yapılan ardışık GET'lerin kodları. */
export function analyzeRateLimit(url: string, statuses: readonly number[]): Finding | null {
  // Hiç 429 görülmediyse VE anlamlı sayıda istek başarılıysa rate-limit yok olabilir.
  const successful = statuses.filter((s) => s >= 200 && s < 500).length;
  const limited = statuses.some((s) => s === 429);
  if (limited || successful < 5) return null;
  return makeFinding({
    id: `C4-no-rate-limit:${new URL(url).pathname}`,
    title: `Rate-limit tespit edilmedi: ${successful} ardışık istek 429 almadı`,
    severity: "P1",
    module: "C",
    check: "C4",
    category: "Rate Limiting",
    confidence: "low",
    evidence: [{ type: "endpoint", source: url, excerpt: `kodlar: ${statuses.join(",")}` }],
    impact: "Rate-limit yoksa kaba kuvvet/abuse/credential-stuffing kolaylaşır.",
    recommendation: "Hassas uçlara (login/register) rate-limit + CAPTCHA/lockout ekle.",
    effort: "M",
    autoFixable: false,
    references: ["OWASP API4:2023", "OWASP A07:2021"],
  });
}
