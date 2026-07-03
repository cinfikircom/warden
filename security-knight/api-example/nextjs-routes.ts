/**
 * ÜRETİM API'si — Next.js (App Router) route'ları + auth + store soyutlaması
 * =========================================================================
 * Bu dosya, kopyalanacak birkaç dosyanın referansıdır (her bölümün üstünde hedef yol var).
 * server.mjs YEREL geliştirme içindir; ÜRETİMDE bu route'ları kullan — oturum-tabanlı admin auth ile.
 *
 * Kurulum:
 *   1) SK_AGENT_TOKEN env'i ata (ajan koşucusu /status'u bununla yazar).
 *   2) requireAdmin()'i kendi oturum sistemine (Auth.js) bağla.
 *   3) Serverless (Vercel) isen FileStore YERİNE RedisStore kullan (dosya-yazımı kalıcı değil).
 * =========================================================================
 */

// ===================== app/lib/security-store.ts =====================
export type Status = "active" | "partial" | "open" | "optional";
export interface Job { id: string; key: string; requestedAt: string; state: string; note?: string }
export interface PostureStore {
  getPosture(): Promise<{ statuses: Record<string, Status>; metrics: any }>;
  setStatus(key: string, status: Status): Promise<void>;
  enqueueJob(job: Job): Promise<void>;
  listJobs(): Promise<Job[]>;
}

// Dev/tek-instance: dosya tabanlı. (Serverless'te KULLANMA — aşağıdaki RedisStore'a geç.)
import { readFile, writeFile, appendFile } from "node:fs/promises";
import { join } from "node:path";
const DIR = join(process.cwd(), "security-knight", "state");
export const fileStore: PostureStore = {
  async getPosture() { return JSON.parse(await readFile(join(DIR, "posture.json"), "utf8")); },
  async setStatus(key, status) {
    const p = JSON.parse(await readFile(join(DIR, "posture.json"), "utf8"));
    p.statuses[key] = status;
    await writeFile(join(DIR, "posture.json"), JSON.stringify(p, null, 2));
  },
  async enqueueJob(job) { await appendFile(join(DIR, "jobs.jsonl"), JSON.stringify(job) + "\n"); },
  async listJobs() {
    try { return (await readFile(join(DIR, "jobs.jsonl"), "utf8")).trim().split("\n").filter(Boolean).map(l => JSON.parse(l)); }
    catch { return []; }
  },
};
/* Serverless/çok-instance için (öneri):
   export const redisStore: PostureStore = {  // ör. @upstash/redis
     getPosture: async () => JSON.parse((await redis.get("sk:posture")) ?? '{"statuses":{},"metrics":{}}'),
     setStatus: async (k,s) => { const p = await this.getPosture(); p.statuses[k]=s; await redis.set("sk:posture", JSON.stringify(p)); },
     enqueueJob: async (j) => { await redis.rpush("sk:jobs", JSON.stringify(j)); },
     listJobs:   async () => (await redis.lrange("sk:jobs",0,-1)).map(JSON.parse),
   };
*/
export const store: PostureStore = fileStore; // ↔ prod'da redisStore

// ===================== app/lib/security-auth.ts =====================
// requireAdmin: kendi oturum sistemine (Auth.js) bağla. Admin değilse null döndürür.
export async function requireAdmin(_req: Request): Promise<boolean> {
  // ÖRNEK — kendi auth'unla değiştir:
  //   const session = await auth();
  //   return session?.user?.role === "admin";
  return false; // güvenli varsayılan: bağlanana kadar REDDET
}
// requireAgent: ajan koşucusu için sabit token (env). /status yalnız bununla yazılır.
export function requireAgent(req: Request): boolean {
  const token = process.env.SK_AGENT_TOKEN;
  return !!token && req.headers.get("authorization") === `Bearer ${token}`;
}
const deny = () => new Response(JSON.stringify({ error: "yetkisiz" }), { status: 401, headers: { "content-type": "application/json" } });
const ok = (b: any, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const KNOWN = new Set(["honeypot","hmac","token1x","rlip","rlmail","rlverify","silent","consttime","observ","enum","globalcap","challenge","fairscale","a11y"]);

// ===================== app/api/security/posture/route.ts =====================
export async function GET_posture(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  return ok(await store.getPosture());
}

// ===================== app/api/security/metrics/route.ts =====================
export async function GET_metrics(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  return ok((await store.getPosture()).metrics ?? {});
}

// ===================== app/api/security/jobs/route.ts =====================
export async function GET_jobs(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  return ok({ jobs: await store.listJobs() });
}

// ===================== app/api/security/equip/route.ts =====================
export async function POST_equip(req: Request) {
  if (!(await requireAdmin(req))) return deny();
  const { key } = await req.json().catch(() => ({}));
  if (!key || !KNOWN.has(key)) return ok({ error: "geçersiz key" }, 400);
  const posture = await store.getPosture();
  if (posture.statuses[key] === "active") return ok({ queued: false, message: "zaten aktif" });
  const job: Job = { id: `job_${Date.now()}_${key}`, key, requestedAt: new Date().toISOString(), state: "queued",
    note: "Ajan işleyecek: düzeltme → saldırı testi → posture güncelle." };
  await store.enqueueJob(job);
  // TODO: audit log + (isteğe bağlı) ajanı tetikleyen webhook/queue push
  return ok({ queued: true, job }, 202);
}

// ===================== app/api/security/status/route.ts =====================
// Yalnız AJAN yazar (SK_AGENT_TOKEN). Görev tamamlanınca çağrılır.
export async function POST_status(req: Request) {
  if (!requireAgent(req)) return deny();
  const { key, status } = await req.json().catch(() => ({}));
  if (!key || !KNOWN.has(key)) return ok({ error: "geçersiz key" }, 400);
  if (!["active","partial","open","optional"].includes(status)) return ok({ error: "geçersiz status" }, 400);
  await store.setStatus(key, status);
  // TODO: audit log
  return ok({ ok: true });
}

/* Not: App Router her route.ts'de HTTP metodunu adıyla export eder (GET/POST). Yukarıdaki
   GET_posture vb. isimleri ilgili dosyada `export { GET_posture as GET }` gibi bağla. */
