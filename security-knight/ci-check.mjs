/**
 * Güvenlik Şövalyesi — CI Regresyon Muhafızı (#3)
 * =========================================================================
 * Bir zamanlar DOĞRULANMIŞ bir savunma "failed" (düştü) olduysa CI'ı kır.
 * Böylece bir savunma prod'da ASLA sessizce regresyona uğramaz — zırh sessizce düşemez.
 *
 * CI akışı:  verify-cycle.mjs (self-check + saldırı testi staging'e) → verification.json → ci-check.mjs
 * Çıkış kodu: 0 = temiz · 1 = regresyon (düşmüş zırh) · 2 = beklenen dosya yok
 *
 * Çalıştır:  node ci-check.mjs           (state/verification.json'a bakar)
 *            node ci-check.mjs --file path/to/verification.json --require honeypot,hmac,rlip
 * =========================================================================
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));
function args(){ const a={}; const v=process.argv.slice(2);
  for(let i=0;i<v.length;i++){ if(!v[i].startsWith("--")) continue; const k=v[i].slice(2);
    const n=v[i+1]; if(n===undefined||n.startsWith("--")) a[k]=true; else { a[k]=n; i++; } } return a; }

async function main(){
  const a = args();
  const file = a.file || join(ROOT, "state", "verification.json");
  let doc;
  try { doc = JSON.parse(await readFile(file, "utf8")); }
  catch { console.error(`❌ doğrulama dosyası okunamadı: ${file}`); process.exit(2); }

  const results = doc.results || {};
  const failed = Object.entries(results).filter(([, r]) => r.state === "failed").map(([k]) => k);
  // --require: bu savunmalar 'verified' OLMALI (yoksa/claimed/failed ise CI kırılır).
  const required = a.require ? String(a.require).split(",").map(s => s.trim()) : [];
  const notVerified = required.filter(k => (results[k]?.state) !== "verified");

  console.log("Güvenlik Şövalyesi — CI regresyon kontrolü");
  for (const [k, r] of Object.entries(results))
    console.log(`  ${r.state === "verified" ? "✅" : r.state === "failed" ? "💥" : "◐"} ${k} — ${r.state}`);

  if (failed.length){
    console.error(`\n❌ REGRESYON: düşmüş (failed) zırh → ${failed.join(", ")}. Savunma bozulmuş; deploy engellendi.`);
    process.exit(1);
  }
  if (notVerified.length){
    console.error(`\n❌ Zorunlu savunmalar 'verified' değil → ${notVerified.join(", ")}. Kanıtlanmadan deploy edilemez.`);
    process.exit(1);
  }
  console.log("\n✅ Regresyon yok — doğrulanmış zırhlar yerinde.");
}
main().catch(e => { console.error("ci-check hata:", e); process.exit(2); });
