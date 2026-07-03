/**
 * Güvenlik Şövalyesi — Doğrulama Döngüsü (#1: ölçülen duruş)
 * =========================================================================
 * Her AKTİF savunmanın GERÇEKTEN çalıştığını ölçer ve verification.json üretir:
 *   • self-check : uygulama runtime sinyali (savunma gerçekten bağlı mı) — state/selfcheck.json
 *                  veya SK_SELFCHECK_URL (GET → { key: true/false })
 *   • attack     : saldırı-motoru sonucu (opsiyonel) — --attack results.json ({ key: "pass"|"fail" })
 * Kural:  self-check true VEYA attack pass → verified · false/fail → failed · ikisi de yok → claimed (hayalet)
 *
 * Çıktı: state/verification.json (varsayılan) veya --post ile backend'e (SK_AGENT_TOKEN gerekir).
 * Bu, ajan koşucusunun "kuşan → uygula → DOĞRULA → posture güncelle" halkasının doğrulama adımıdır.
 *
 * Çalıştır:  node verify-cycle.mjs
 *            node verify-cycle.mjs --attack ./attack-results.json --post http://127.0.0.1:8137
 * =========================================================================
 */
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));
const STATE = join(ROOT, "state");

function args(){ const a={}; const v=process.argv.slice(2);
  for(let i=0;i<v.length;i++){ if(!v[i].startsWith("--")) continue; const k=v[i].slice(2);
    const n=v[i+1]; if(n===undefined||n.startsWith("--")) a[k]=true; else { a[k]=n; i++; } } return a; }

async function readJson(p, fb){ try { return JSON.parse(await readFile(p,"utf8")); } catch { return fb; } }

async function selfChecks(){
  const url = process.env.SK_SELFCHECK_URL;
  if (url){ try { return await (await fetch(url)).json(); } catch { /* düş */ } }
  return await readJson(join(STATE, "selfcheck.json"), {});
}

function deriveState(sc, at){
  if (sc === true || at === "pass") return { state:"verified", method: sc===true ? "self-check" : "attack",
    detail: sc===true ? "Runtime sinyali: savunma bağlı." : "Saldırı testi geçti." };
  if (sc === false || at === "fail") return { state:"failed", method: sc===false ? "self-check" : "attack",
    detail: "Savunma çalışmıyor görünüyor — ZIRH DÜŞTÜ." };
  return { state:"claimed", method:"-", detail:"Kanıt yok (self-check/attack) → hayalet zırh." };
}

async function main(){
  const a = args();
  const posture = await readJson(join(STATE, "posture.json"), { statuses:{} });
  const sc = await selfChecks();
  const attack = a.attack ? await readJson(a.attack, {}) : {};
  const activeKeys = Object.entries(posture.statuses).filter(([,v])=>v==="active").map(([k])=>k);

  const results = {};
  for (const key of activeKeys) results[key] = deriveState(sc[key], attack[key]);

  const verified = Object.values(results).filter(r=>r.state==="verified").length;
  const failed = Object.values(results).filter(r=>r.state==="failed").length;
  const claimed = Object.values(results).filter(r=>r.state==="claimed").length;
  console.log(`Doğrulama: ${verified} verified · ${claimed} claimed (hayalet) · ${failed} failed (düştü)`);
  for (const [k,r] of Object.entries(results)) console.log(`  ${r.state==="verified"?"✅":r.state==="failed"?"💥":"◐"} ${k} — ${r.detail}`);

  const payload = { generatedAt: new Date().toISOString(), results };
  if (a.post){
    const token = process.env.SK_AGENT_TOKEN;
    const r = await fetch(`${a.post}/api/security/verification`, { method:"POST",
      headers:{ "content-type":"application/json", ...(token?{authorization:`Bearer ${token}`}:{}) },
      body: JSON.stringify({ results }) });
    console.log(`→ backend'e yazıldı: HTTP ${r.status}`);
  } else {
    await writeFile(join(STATE, "verification.json"), JSON.stringify(payload, null, 2));
    console.log("→ state/verification.json güncellendi.");
  }
  if (failed) process.exit(1);
}
main().catch(e=>{ console.error("verify-cycle hata:", e); process.exit(2); });
