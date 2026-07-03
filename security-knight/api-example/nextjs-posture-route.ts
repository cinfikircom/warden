/**
 * Örnek Next.js (App Router) API rotası: app/api/security/posture/route.ts
 * =========================================================================
 * Zırh durumunun GERÇEK kaynağı burasıdır. Her savunma katmanının aktif olup
 * olmadığını GERÇEK sinyallerden türet: config bayrakları, env, feature-flag,
 * hatta canlı self-check. Panel bu JSON'u okuyup şövalyeyi çizer.
 *
 * Sözleşme:  GET -> { statuses: Record<key, "active"|"partial"|"open"|"optional">, metrics?: {...} }
 * Bu ucu ADMIN kimlik doğrulaması arkasına koy (posture bilgisi hassastır).
 */

export const dynamic = "force-dynamic";

// Kod tabanındaki gerçek durumu yansıtacak şekilde bunları besle.
// Örn. bir flag/env/DB veya doğrudan kodun o özelliği içerip içermediği.
function readStatuses(): Record<string, "active" | "partial" | "open" | "optional"> {
  const flags = {
    honeypot: true,
    hmac: true,
    tokenSingleUse: false,       // ← nonce + bağlama uygulandığında true yap
    rateLimitIp: true,
    rateLimitEmail: true,
    rateLimitVerify: true,
    silentBot: true,
    constantTimeResponse: false, // ← e-posta kuyruğa alındığında true yap
    observability: false,        // ← metrik/alarm eklendiğinde true yap
    enumParity: "partial" as const,
  };

  return {
    honeypot:  flags.honeypot ? "active" : "open",
    hmac:      flags.hmac ? "active" : "open",
    token1x:   flags.tokenSingleUse ? "active" : "open",
    rlip:      flags.rateLimitIp ? "active" : "open",
    rlmail:    flags.rateLimitEmail ? "active" : "open",
    rlverify:  flags.rateLimitVerify ? "active" : "open",
    silent:    flags.silentBot ? "active" : "open",
    consttime: flags.constantTimeResponse ? "active" : "open",
    observ:    flags.observability ? "active" : "open",
    enum:      flags.enumParity,
    // opsiyonel kalıntılar:
    globalcap: "optional", challenge: "optional", fairscale: "optional", a11y: "optional",
  };
}

// Gerçek sayaçlarını (Redis/DB) buradan doldur.
async function readMetrics() {
  return {
    "Püskürtülen saldırı": 348,
    "Korunan istek": 1240,
    "Ulaşan elçi (e-posta)": 892,
    "Aktif tehdit": "Yok",
    breakdown: { "Tuzağa düşen": 210, "Çok hızlı (<1,5sn)": 96, "Replay / eski damga": 25, "Rate-limit reddi": 17 },
  };
}

export async function GET() {
  // TODO: admin oturumu değilse 401 döndür.
  const body = { statuses: readStatuses(), metrics: await readMetrics() };
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
