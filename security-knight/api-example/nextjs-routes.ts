/**
 * ÜRETİM API'si — Next.js (App Router) route'ları + auth + store soyutlaması
 * =========================================================================
 * Bu dosya, kopyalanacak birkaç dosyanın referansıdır (her bölümün üstünde hedef yol var).
 * server.mjs YEREL geliştirme içindir; ÜRETİMDE bu route'ları kullan — oturum-tabanlı admin auth ile.
 *
 * Mimari (yerel dev'deki gibi): posture'un GERÇEK kaynağı her zaman `warden-bridge.mjs`'in bir
 * Warden taramasından ürettiği veridir. Hiçbir route doğrudan "active" yazmaz — yalnızca CI/agent
 * tetiklediği bir taramanın SONUCU okunur. Bu, `server.mjs`'in kendi tasarım ilkesiyle birebir aynı.
 *
 * ⚠ `POST /api/warden/scan` bir alt-süreç (`pnpm warden scan`) başlatır — bu KALICI bir Node
 * süreci (Docker/VM) gerektirir; serverless (Vercel gibi) fonksiyonlarda ÇALIŞMAZ (uzun sürebilir,
 * repo checkout'u yok, dosya yazımı kalıcı değil). Serverless'teysen bunun yerine bir CI workflow'unu
 * (`workflow_dispatch`) tetikle ve sonucu polling'le bekle — aşağıda `triggerScanViaCi` iskeleti var.
 *
 * Kurulum:
 *   1) requireAdmin()'i kendi oturum sistemine (Auth.js) bağla.
 *   2) Serverless (Vercel) isen FileStore YERİNE RedisStore kullan (dosya-yazımı kalıcı değil) VE
 *      POST /api/warden/scan'i triggerScanViaCi'ye çevir.
 * =========================================================================
 */

// ===================== app/lib/warden-store.ts =====================
export type Status = "active" | "partial" | "open" | "optional";
export interface Job { id: string; module: string; kind: "warden-fix"; requestedAt: string; state: string; fingerprints?: string[]; note?: string }
export interface Finding { id: string; fingerprint: string; severity: string; title: string; module: string; [k: string]: unknown }
export interface WardenStore {
  getPosture(): Promise<{ statuses: Record<string, Status>; verification?: unknown; metrics: any }>;
  getGaps(module: string): Promise<{ module: string; findings: Finding[] }>;
  enqueueFixJob(job: Job): Promise<void>;
  listJobs(): Promise<Job[]>;
}

// Dev/tek-instance: dosya tabanlı (aynı şeyi server.mjs de okur/yazar). Serverless'te KULLANMA.
import { readFile, appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
const DIR = join(process.cwd(), "security-knight", "state");
export const fileStore: WardenStore = {
  async getPosture() {
    try { return JSON.parse(await readFile(join(DIR, "warden-posture.json"), "utf8")); }
    catch { return { statuses: {}, metrics: {} }; }
  },
  async getGaps(module) {
    try { return JSON.parse(await readFile(join(DIR, "warden-gaps", `${module}.json`), "utf8")); }
    catch { return { module, findings: [] }; }
  },
  async enqueueFixJob(job) {
    await mkdir(DIR, { recursive: true });
    await appendFile(join(DIR, "jobs.jsonl"), JSON.stringify(job) + "\n");
  },
  async listJobs() {
    try { return (await readFile(join(DIR, "jobs.jsonl"), "utf8")).trim().split("\n").filter(Boolean).map(l => JSON.parse(l)); }
    catch { return []; }
  },
};
/* Serverless/çok-instance için (öneri):
   export const redisStore: WardenStore = {  // ör. @upstash/redis
     getPosture: async () => JSON.parse((await redis.get("wk:posture")) ?? '{"statuses":{},"metrics":{}}'),
     getGaps: async (m) => JSON.parse((await redis.get(`wk:gaps:${m}`)) ?? `{"module":"${m}","findings":[]}`),
     enqueueFixJob: async (j) => { await redis.rpush("wk:jobs", JSON.stringify(j)); },
     listJobs:   async () => (await redis.lrange("wk:jobs",0,-1)).map(JSON.parse),
   };
   // getPosture/getGaps'i CI'ın yazdığı yerden (ör. deploy sonrası bir "publish posture" adımı
   // Redis'e yazar) besle — API route'u kendisi tarama ÇALIŞTIRMAZ.
*/
export const store: WardenStore = fileStore; // ↔ prod'da redisStore

// ===================== app/lib/warden-auth.ts =====================
// requireAdmin: kendi oturum sistemine (Auth.js) bağla. Admin değilse false döndürür.
export async function requireAdmin(_req: Request): Promise<boolean> {
  // ÖRNEK — kendi auth'unla değiştir:
  //   const session = await auth();
  //   return session?.user?.role === "admin";
  return false; // güvenli varsayılan: bağlanana kadar REDDET
}
const deny = () => new Response(JSON.stringify({ error: "yetkisiz" }), { status: 401, headers: { "content-type": "application/json" } });
const ok = (b: any, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
// Warden'ın modül kayıt defteriyle (packages/warden-core/src/model/finding.ts) eşleşmeli.
const KNOWN_MODULES = new Set(["A", "B", "C", "D", "E", "CLOUD", "K8S", "API", "FE", "AI"]);

// ===================== app/api/warden/posture/route.ts =====================
export async function GET_posture(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  return ok(await store.getPosture());
}

// ===================== app/api/warden/gaps/route.ts =====================
// GET /api/warden/gaps?module=B — o modülün en son taramadan gelen GERÇEK bulguları.
export async function GET_gaps(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  const module = new URL(req.url).searchParams.get("module");
  if (!module || !KNOWN_MODULES.has(module)) return ok({ error: "geçersiz module" }, 400);
  return ok(await store.getGaps(module));
}

// ===================== app/api/warden/jobs/route.ts =====================
export async function GET_jobs(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  return ok({ jobs: await store.listJobs() });
}

// ===================== app/api/warden/scan/route.ts =====================
// KALICI bir Node süreci gerektirir (Docker/VM) — serverless'te triggerScanViaCi'ye çevir.
export async function POST_scan(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  const { module } = await req.json().catch(() => ({}));
  if (!module || !KNOWN_MODULES.has(module)) return ok({ error: "geçersiz module" }, 400);
  const { spawn } = await import("node:child_process");
  const child = spawn("node", ["warden-equip.mjs", "--module", module], {
    cwd: join(process.cwd(), "security-knight"), detached: true, stdio: "ignore",
  });
  child.unref();
  return ok({ started: true, note: `${module} için gerçek tarama başladı.` }, 202);
}
/* Serverless alternatifi — bir GitHub Actions workflow'unu tetikle, sonucu CI'ın posture'u
   yazmasını (redisStore'a) bekleyerek/polling'le izle:
   async function triggerScanViaCi(module: string) {
     await fetch(`https://api.github.com/repos/<org>/<repo>/actions/workflows/warden-scan.yml/dispatches`, {
       method: "POST", headers: { authorization: `Bearer ${process.env.GH_TOKEN}` },
       body: JSON.stringify({ ref: "main", inputs: { module } }),
     });
   } // workflow'un son adımı: tarama sonucunu redisStore'a "publish posture" olarak yazmak.
*/

// ===================== app/api/warden/fix-queue/route.ts =====================
// "Ajana kuyruğa al": zengin bir warden-fix görevi ekler; SKILL.md prosedürü (ya bir /schedule
// cron ajanı ya da bir mühendisin canlı Claude Code oturumu) kuyruğu işler.
export async function POST_fixQueue(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  const { module } = await req.json().catch(() => ({}));
  if (!module || !KNOWN_MODULES.has(module)) return ok({ error: "geçersiz module" }, 400);
  const gaps = await store.getGaps(module);
  const job: Job = {
    id: `wjob_${Date.now()}_${module}`, module, kind: "warden-fix",
    requestedAt: new Date().toISOString(), state: "queued",
    fingerprints: gaps.findings.map((f) => f.fingerprint),
    note: "Ajan: SKILL.md → 'Otomatik Düzeltme Prosedürü'nü işlet.",
  };
  await store.enqueueFixJob(job);
  return ok({ queued: true, job }, 202);
}

/* Not: App Router her route.ts'de HTTP metodunu adıyla export eder (GET/POST). Yukarıdaki
   GET_posture vb. isimleri ilgili dosyada `export { GET_posture as GET }` gibi bağla.
   Zırh durumu (statuses) hiçbir zaman bu route'lardan doğrudan yazılmaz — yalnızca
   warden-bridge.mjs'in ürettiği posture'u okurlar. Bu, "asla sahte gösterme" ilkesinin
   üretim API'sindeki karşılığıdır. */
