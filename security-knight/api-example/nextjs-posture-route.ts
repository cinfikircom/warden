/**
 * Örnek Next.js (App Router) API rotası: app/api/warden/posture/route.ts
 * =========================================================================
 * Standalone, minimal örnek — yalnızca posture'u OKUR. Daha tam bir kurulum
 * (gaps/jobs/scan/fix-queue rotaları dahil) için `nextjs-routes.ts`'e bak.
 *
 * Zırh durumunun GERÇEK kaynağı `warden-bridge.mjs`'in bir Warden taramasından ürettiği
 * `state/warden-posture.json`'dur — bu route hiçbir şeyi doğrudan yazmaz, yalnızca CI/agent'ın
 * (`pnpm warden scan` → `node warden-bridge.mjs`) ürettiği sonucu okur.
 *
 * Sözleşme:  GET -> { statuses: Record<ModuleId, "active"|"partial"|"open"|"optional">,
 *                      verification?: {...}, metrics?: {...} }
 * Bu ucu ADMIN kimlik doğrulaması arkasına koy (posture bilgisi hassastır).
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

export const dynamic = "force-dynamic";

const POSTURE_FILE = join(process.cwd(), "security-knight", "state", "warden-posture.json");

async function readPosture() {
  try { return JSON.parse(await readFile(POSTURE_FILE, "utf8")); }
  catch { return { statuses: {}, verification: { results: {} }, metrics: {}, note: "warden-bridge.mjs koşulmadı" }; }
}

export async function GET() {
  // TODO: admin oturumu değilse 401 döndür (bkz. nextjs-routes.ts'teki requireAdmin).
  const body = await readPosture();
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
