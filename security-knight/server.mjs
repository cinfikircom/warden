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
 *   • CORS wildcard YOK — yalnız SK_ALLOWED_ORIGIN.
 *   • Basit IP rate-limit, girdi doğrulama, ve state/audit.log denetim izi.
 *
 * Zırh durumu (statuses) yalnızca `warden-bridge.mjs`'in gerçek bir Warden taramasından ürettiği
 * state/warden-posture.json'dan gelir — bu sunucuda onu doğrudan değiştiren hiçbir uç YOKTUR
 * (bir zırhın "active" olması sahte/iddia edilen değil, gerçek bir yeniden-taramanın sonucudur).
 * =========================================================================
 */
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { readFile, appendFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));
const STATE = join(ROOT, "state");
const WARDEN_POSTURE_FILE = join(STATE, "warden-posture.json"); // warden-bridge.mjs'in çıktısı
const JOBS_FILE = join(STATE, "jobs.jsonl");
const AUDIT_FILE = join(STATE, "audit.log");
const GAPS_DIR = join(STATE, "warden-gaps"); // warden-equip.mjs'in yazdığı gerçek eksik listeleri

const PORT = Number(process.env.PORT || 8137);
const ADMIN_TOKEN = process.env.SK_ADMIN_TOKEN || "";
const ALLOWED_ORIGIN = process.env.SK_ALLOWED_ORIGIN || `http://127.0.0.1:${PORT}`;

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

function authorized(req){
  if (!ADMIN_TOKEN) return isLocal(req); // dev-open: yalnız localhost
  const h = req.headers.authorization || "";
  return h === `Bearer ${ADMIN_TOKEN}`;
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

async function body(req){
  const chunks = []; for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { return {}; }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const path = url.pathname;
  if (req.method === "OPTIONS") return json(res, 204, {});
  if (!rateOk(req)){ await audit(req, "rate_limited"); return json(res, 429, { error:"çok fazla istek" }); }

  // -------- API (auth zorunlu) --------
  if (path.startsWith("/api/")){
    if (!authorized(req)){
      await audit(req, "auth_denied", { target: path });
      return json(res, 401, { error:"yetkisiz" });
    }

    // Warden Scan → Knight posture (whole-codebase security as armor). Tek gerçek kaynak.
    if (path === "/api/warden/posture"){
      try { return json(res, 200, JSON.parse(await readFile(WARDEN_POSTURE_FILE, "utf8"))); }
      catch { return json(res, 200, { statuses:{}, verification:{results:{}}, metrics:{}, note:"warden-bridge.mjs koşulmadı" }); }
    }
    if (path === "/api/warden/jobs"){
      let jobs = [];
      try { jobs = (await readFile(JOBS_FILE,"utf8")).trim().split("\n").filter(Boolean).map(l=>JSON.parse(l)); } catch {}
      return json(res, 200, { jobs });
    }
    // Tam döngü (Warden taraması → köprü). Detached; panel posture'ı yoklar.
    if (path === "/api/loop/run" && req.method === "POST"){
      try {
        const child = spawn("node", ["loop.mjs"], { cwd: ROOT, detached: true, stdio: "ignore" });
        child.unref();
        await audit(req, "loop_started");
        return json(res, 202, { started: true, note: "Warden taraması → köprü çalışıyor." });
      } catch (e){ return json(res, 500, { error: String(e.message) }); }
    }
    // Gerçek-taramaya-dayalı "Kuşan" akışı: bir zırha basınca tam tarama + bu modülün GERÇEK
    // bulgularını üretir. Detached; panel /api/warden/gaps'i yoklar.
    if (path === "/api/warden/scan" && req.method === "POST"){
      const { module } = await body(req);
      if (!module) return json(res, 400, { error:"module gerekli" });
      try {
        const child = spawn("node", ["warden-equip.mjs", "--module", module], { cwd: ROOT, detached: true, stdio: "ignore" });
        child.unref();
        await audit(req, "warden_scan_started", { module });
        return json(res, 202, { started:true, note:`${module} için gerçek tarama başladı.` });
      } catch (e){ return json(res, 500, { error: String(e.message) }); }
    }
    // O modülün en son taramadan gelen gerçek bulguları — çekmece bunu gösterir (şablon değil).
    if (path === "/api/warden/gaps" && req.method === "GET"){
      const module = url.searchParams.get("module");
      if (!module) return json(res, 400, { error:"module gerekli" });
      try { return json(res, 200, JSON.parse(await readFile(join(GAPS_DIR, `${module}.json`), "utf8"))); }
      catch { return json(res, 200, { module, findings:[], note:"henüz taranmadı — önce /api/warden/scan çalıştır" }); }
    }
    // "Ajana kuyruğa al": zengin bir warden-fix görevi ekler (SKILL.md prosedürü işler).
    if (path === "/api/warden/fix-queue" && req.method === "POST"){
      const { module } = await body(req);
      if (!module) return json(res, 400, { error:"module gerekli" });
      try {
        const child = spawn("node", ["warden-equip.mjs", "--module", module, "--queue"], { cwd: ROOT, detached: true, stdio: "ignore" });
        child.unref();
        await audit(req, "warden_fix_queued", { module });
        return json(res, 202, { queued:true, note:`${module} için düzeltme kuyruğa alınıyor (taze tarama + prompt).` });
      } catch (e){ return json(res, 500, { error: String(e.message) }); }
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

// Sunucu ayağa kalkınca paneli tarayıcıda kendiliğinden aç — kullanıcının bundan sonraki
// tüm adımları (Kuşan, döngüyü çalıştır) terminale dönmeden panelden yürütebilmesi için.
// CI/headless ortamlarda SK_NO_OPEN=1 ile kapatılabilir.
function openBrowser(url){
  if (process.env.SK_NO_OPEN) return;
  const cmd = process.platform === "darwin" ? "open"
    : process.platform === "win32" ? "cmd"
    : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try { spawn(cmd, args, { stdio: "ignore", detached: true }).unref(); }
  catch { /* tarayıcı açılamadı — URL zaten konsolda yazılı, elle açılabilir */ }
}

server.listen(PORT, "127.0.0.1", () => {
  const url = `http://127.0.0.1:${PORT}/`;
  console.log(`Güvenlik Şövalyesi (DEV) → ${url}`);
  if (!ADMIN_TOKEN) console.warn("⚠  SK_ADMIN_TOKEN yok → DEV-OPEN mod (yalnız 127.0.0.1). Üretimde Next.js route'larını + admin auth kullan.");
  openBrowser(url);
});
