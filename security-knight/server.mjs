/**
 * Güvenlik Şövalyesi — YEREL GELİŞTİRME backend'i (bağımlılıksız Node HTTP)
 * =========================================================================
 * ⚠ Bu YEREL geliştirme köprüsüdür (yalnız 127.0.0.1). ÜRETİMDE bunu public çalıştırma —
 *   uçları uygulamanın içine, oturum-tabanlı admin auth ile taşı (bkz. api-example/nextjs-routes.ts).
 *
 * Güvenlik:
 *   • Yalnız 127.0.0.1'e bağlanır.
 *   • SK_ADMIN_TOKEN set ise TÜM uçlar `Authorization: Bearer <token>` ister.
 *     Set değilse "dev-open" modda yalnız localhost'tan çağrılara izin verir (yüksek sesle uyarır).
 *   • /api/security/status (posture'u değiştirir) yalnız SK_AGENT_TOKEN ile (ajan koşucusu).
 *   • CORS wildcard YOK — yalnız SK_ALLOWED_ORIGIN.
 *   • Basit IP rate-limit, girdi doğrulama, ve state/audit.log denetim izi.
 * =========================================================================
 */
import { createServer } from "node:http";
import { readFile, writeFile, appendFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));
const STATE = join(ROOT, "state");
const POSTURE_FILE = join(STATE, "posture.json");
const VERIFICATION_FILE = join(STATE, "verification.json");
const JOBS_FILE = join(STATE, "jobs.jsonl");
const AUDIT_FILE = join(STATE, "audit.log");

const PORT = Number(process.env.PORT || 8137);
const ADMIN_TOKEN = process.env.SK_ADMIN_TOKEN || "";
const AGENT_TOKEN = process.env.SK_AGENT_TOKEN || "";
const ALLOWED_ORIGIN = process.env.SK_ALLOWED_ORIGIN || `http://127.0.0.1:${PORT}`;

const STATUS_ENUM = new Set(["active", "partial", "open", "optional"]);
const MIME = { ".html":"text/html", ".css":"text/css", ".js":"text/javascript",
  ".mjs":"text/javascript", ".json":"application/json", ".svg":"image/svg+xml",
  ".png":"image/png", ".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".webp":"image/webp" };

const ipOf = req => (req.socket.remoteAddress || "").replace(/^::ffff:/, "");
const isLocal = req => ["127.0.0.1", "::1"].includes(ipOf(req));

async function audit(req, event, extra = {}){
  const line = JSON.stringify({ ts: new Date().toISOString(), ip: ipOf(req), method: req.method,
    path: new URL(req.url, "http://x").pathname, event, ...extra });
  try { await appendFile(AUDIT_FILE, line + "\n"); } catch {}
}

// kind: "admin" | "agent"
function authorized(req, kind){
  const token = kind === "agent" ? AGENT_TOKEN : ADMIN_TOKEN;
  if (!token) return isLocal(req); // dev-open: yalnız localhost
  const h = req.headers.authorization || "";
  return h === `Bearer ${token}`;
}

// çok basit IP rate-limit (dev koruması): 120 istek / dk
const hits = new Map();
function rateOk(req){
  const ip = ipOf(req), now = Date.now(), w = 60_000, cap = 120;
  const e = hits.get(ip) || { c: 0, r: now + w };
  if (now > e.r){ e.c = 0; e.r = now + w; }
  e.c++; hits.set(ip, e);
  return e.c <= cap;
}

const json = (res, code, obj) => {
  res.writeHead(code, { "content-type":"application/json", "cache-control":"no-store",
    "access-control-allow-origin": ALLOWED_ORIGIN, "access-control-allow-credentials":"true",
    "access-control-allow-headers":"content-type, authorization", "access-control-allow-methods":"GET,POST,OPTIONS",
    "vary":"origin" });
  res.end(JSON.stringify(obj));
};

async function readPosture(){
  try { return JSON.parse(await readFile(POSTURE_FILE, "utf8")); } catch { return { statuses:{}, metrics:{} }; }
}
async function readVerification(){
  try { return JSON.parse(await readFile(VERIFICATION_FILE, "utf8")); } catch { return { results:{} }; }
}
async function body(req){
  const chunks = []; for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { return {}; }
}

const server = createServer(async (req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  if (req.method === "OPTIONS") return json(res, 204, {});
  if (!rateOk(req)){ await audit(req, "rate_limited"); return json(res, 429, { error:"çok fazla istek" }); }

  // -------- API (auth zorunlu) --------
  if (path.startsWith("/api/")){
    const agentEndpoint = path === "/api/security/status"
      || (path === "/api/security/verification" && req.method === "POST");
    if (!authorized(req, agentEndpoint ? "agent" : "admin")){
      await audit(req, "auth_denied", { target: path });
      return json(res, 401, { error:"yetkisiz" });
    }
    const posture = await readPosture();

    if (path === "/api/security/posture"){
      // Ölçülen duruş (#1): posture + doğrulama sonuçları tek yanıtta.
      return json(res, 200, { ...posture, verification: await readVerification() });
    }
    if (path === "/api/security/verification") return json(res, 200, await readVerification());
    if (path === "/api/security/metrics") return json(res, 200, posture.metrics || {});
    if (path === "/api/security/jobs"){
      let jobs = [];
      try { jobs = (await readFile(JOBS_FILE,"utf8")).trim().split("\n").filter(Boolean).map(l=>JSON.parse(l)); } catch {}
      return json(res, 200, { jobs });
    }
    if (path === "/api/security/equip" && req.method === "POST"){
      const { key } = await body(req);
      if (!key || !(key in (posture.statuses||{}))) return json(res, 400, { error:"geçersiz key" });
      if (posture.statuses[key] === "active") return json(res, 200, { queued:false, message:"zaten aktif" });
      const job = { id:`job_${Date.now()}_${key}`, key, requestedAt:new Date().toISOString(), state:"queued",
        note:"Ajan işleyecek: düzeltmeyi uygula → saldırı testini koş → posture'u güncelle." };
      await appendFile(JOBS_FILE, JSON.stringify(job) + "\n");
      await audit(req, "equip_queued", { key, job: job.id });
      return json(res, 202, { queued:true, job });
    }
    if (path === "/api/security/verify" && req.method === "POST"){
      const { key } = await body(req);
      if (!key || !(key in (posture.statuses||{}))) return json(res, 400, { error:"geçersiz key" });
      const job = { id:`vrf_${Date.now()}_${key}`, key, kind:"verify", requestedAt:new Date().toISOString(), state:"queued",
        note:"Ajan doğrulama döngüsünü koşacak: self-check + saldırı testi → verification güncelle." };
      await appendFile(JOBS_FILE, JSON.stringify(job) + "\n");
      await audit(req, "verify_queued", { key, job: job.id });
      return json(res, 202, { queued:true, job });
    }
    // Ajan doğrulama sonuçlarını yazar (verify-cycle.mjs bunu çağırır). Auth üst kapıda (agent).
    if (path === "/api/security/verification" && req.method === "POST"){
      const { results } = await body(req);
      if (!results || typeof results !== "object") return json(res, 400, { error:"results gerekli" });
      await writeFile(VERIFICATION_FILE, JSON.stringify({ generatedAt:new Date().toISOString(), results }, null, 2));
      await audit(req, "verification_written", { keys: Object.keys(results) });
      return json(res, 200, { ok:true });
    }
    if (path === "/api/security/status" && req.method === "POST"){
      const { key, status } = await body(req);
      if (!key || !(key in (posture.statuses||{}))) return json(res, 400, { error:"geçersiz key" });
      if (!STATUS_ENUM.has(status)) return json(res, 400, { error:"geçersiz status" });
      posture.statuses[key] = status;
      await writeFile(POSTURE_FILE, JSON.stringify(posture, null, 2));
      await audit(req, "status_updated", { key, status });
      return json(res, 200, { ok:true, statuses: posture.statuses });
    }
    return json(res, 404, { error:"api yok" });
  }

  // -------- statik panel (dev; prod'da uygulaman sunar) --------
  let rel = normalize(path === "/" ? "/index.html" : path).replace(/^(\.\.[/\\])+/, "");
  const file = join(ROOT, rel.replace(/^\/security-knight/, "").replace(/^\//, ""));
  if (existsSync(file) && !file.includes(`${normalize("/state/")}`) && file.startsWith(ROOT)){
    try { const data = await readFile(file);
      res.writeHead(200, { "content-type": MIME[extname(file)] || "application/octet-stream" });
      return res.end(data);
    } catch {}
  }
  json(res, 404, { error:"bulunamadı", path });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Güvenlik Şövalyesi (DEV) → http://127.0.0.1:${PORT}/index.html`);
  if (!ADMIN_TOKEN) console.warn("⚠  SK_ADMIN_TOKEN yok → DEV-OPEN mod (yalnız 127.0.0.1). Üretimde Next.js route'larını + admin auth kullan.");
  if (!AGENT_TOKEN) console.warn("⚠  SK_AGENT_TOKEN yok → /status yalnız localhost'tan yazılabilir.");
});
