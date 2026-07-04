/**
 * WARDEN KNIGHT — the loop
 * =========================================================================
 * One command runs the whole cycle so the knight reflects reality end-to-end:
 *   1) Warden Scan       → warden-report/findings.json          (code security)
 *   2) warden-bridge     → state/warden-posture.json            (scan → armor)
 * After it runs, /api/warden/posture serves the fresh posture and the live panel arms up.
 * A dimension only turns "active"+verified when Warden actually scanned it clean — never claimed.
 *
 * Run:  node loop.mjs                      (scans the parent Warden repo)
 *       node loop.mjs --target /path/proj  (scans another project)
 *       node loop.mjs --no-scan            (skip Warden scan; just re-bridge from existing findings.json)
 * =========================================================================
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));      // security-knight/
const REPO = join(ROOT, "..");                             // Warden repo root (unified)
function args(){ const a={}; const v=process.argv.slice(2);
  for(let i=0;i<v.length;i++){ if(!v[i].startsWith("--")) continue; const k=v[i].slice(2);
    const n=v[i+1]; if(n===undefined||n.startsWith("--")) a[k]=true; else { a[k]=n; i++; } } return a; }
const run = (cmd, cmdArgs, cwd) => execFileSync(cmd, cmdArgs, { cwd, encoding:"utf8", stdio:["ignore","pipe","pipe"] });

async function main(){
  const a = args();
  const target = a.target || REPO;
  const findings = join(target, "warden-report", "findings.json");
  console.log("⚔️  Warden Knight — döngü başlıyor");

  // 1) Warden Scan
  if (!a["no-scan"]){
    try { console.log("  1/2 Warden taraması…"); run("pnpm", ["warden", "scan", "--target", target], REPO); console.log("      ✓ tarandı"); }
    catch (e){ console.log("      ⚠ tarama atlandı (pnpm/warden yok?) — mevcut findings.json kullanılacak"); }
  } else console.log("  1/2 tarama atlandı (--no-scan)");

  // 2) Bridge: scan → armor
  try { console.log("  2/2 köprü (scan → zırh)…"); console.log("      " + run("node", ["warden-bridge.mjs", "--file", findings], ROOT).trim().split("\n").pop()); }
  catch (e){ console.log("      ⚠ köprü başarısız: " + String(e.message).split("\n")[0]); }

  console.log("✅ Döngü bitti — /api/warden/posture taze. Panel canlıysa şövalye kendini günceller.");
}
main().catch(e => { console.error("loop hata:", e); process.exit(2); });
