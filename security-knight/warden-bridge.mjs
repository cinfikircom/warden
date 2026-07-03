/**
 * WARDEN BRIDGE (Phase 2) — Warden Scan → Warden Knight posture
 * =========================================================================
 * Reads a Warden `findings.json` (its scoreboard + summary) and writes a Knight posture
 * (`state/warden-posture.json`) so the Knight visualizes the ENTIRE Warden scan as armor:
 *   • a dimension Warden scanned clean  → armor `active` + `verified`  (solid)
 *   • a dimension with P0 findings       → armor `open`     (critical gap → quest)
 *   • a dimension with P1 / low score    → armor `partial`  (damaged)
 *   • a dimension not evaluated (n/d)    → armor `optional`
 * Measured knight score ≈ Warden's overall posture. Same widget, same knight art.
 *
 * Run:  node warden-bridge.mjs --file ../warden-report/findings.json
 *       node warden-bridge.mjs --target /path/to/project     (reads <target>/warden-report/findings.json)
 * =========================================================================
 */
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { WARDEN_POSTURE } from "./posture-warden.js";

const ROOT = dirname(fileURLToPath(import.meta.url));
function args(){ const a={}; const v=process.argv.slice(2);
  for(let i=0;i<v.length;i++){ if(!v[i].startsWith("--")) continue; const k=v[i].slice(2);
    const n=v[i+1]; if(n===undefined||n.startsWith("--")) a[k]=true; else { a[k]=n; i++; } } return a; }

/** One scoreboard row → { status, verification? }. Pure. */
export function mapDimension(row){
  if (!row || row.score === null || row.score === undefined) return { status: "optional" };
  if ((row.p0 ?? 0) > 0) return { status: "open" };
  if ((row.p1 ?? 0) > 0 || row.score < 8) return { status: "partial" };
  return { status: "active", verification: { state: "verified", method: "warden-scan",
    detail: `Warden scanned this dimension clean (score ${row.score}/10).` } };
}

/** findings.json object → Knight posture ({statuses, verification, metrics}). Pure. */
export function bridge(findings){
  const board = Array.isArray(findings.scoreboard) ? findings.scoreboard : [];
  const byModule = new Map(board.map(r => [r.module, r]));
  const statuses = {}, results = {}, breakdown = {};

  for (const layer of WARDEN_POSTURE.layers){
    const row = byModule.get(layer.key);
    const m = mapDimension(row);
    statuses[layer.key] = m.status;
    if (m.verification) results[layer.key] = m.verification;
    if (row) breakdown[layer.realName || layer.key] = row.findings ?? 0;
  }

  const s = findings.summary || {};
  const bySev = s.bySeverity || {};
  const metrics = {
    "Findings": s.total ?? Object.values(breakdown).reduce((a,b)=>a+b,0),
    "P0": bySev.P0 ?? 0,
    "P1": bySev.P1 ?? 0,
    "Max CVSS": s.maxCvss ?? "–",
    "Aktif tehdit": (bySev.P0 ?? 0) > 0 ? `${bySev.P0} P0` : "Yok",
    breakdown,
  };
  return { generatedAt: findings.generatedAt || null, statuses, verification: { results }, metrics };
}

async function main(){
  const a = args();
  const file = a.file
    || (a.target ? join(a.target, "warden-report", "findings.json") : join(ROOT, "..", "warden-report", "findings.json"));
  let findings;
  try { findings = JSON.parse(await readFile(file, "utf8")); }
  catch { console.error(`❌ findings.json okunamadı: ${file}\n   Önce Warden taraması koş: pnpm warden scan --target <proje>`); process.exit(2); }

  const posture = bridge(findings);
  const out = join(ROOT, "state", "warden-posture.json");
  await writeFile(out, JSON.stringify(posture, null, 2));

  const on = Object.values(posture.statuses).filter(s => s === "active").length;
  const open = Object.values(posture.statuses).filter(s => s === "open").length;
  console.log(`Warden → Knight köprüsü: ${on} boyut sağlam (verified) · ${open} kritik açık · toplam bulgu ${posture.metrics.Findings}`);
  for (const l of WARDEN_POSTURE.layers)
    console.log(`  ${({active:"✅",partial:"◐",open:"💥",optional:"·"})[posture.statuses[l.key]]} ${l.realName} → ${posture.statuses[l.key]}`);
  console.log(`→ ${out}`);
}
main().catch(e => { console.error("warden-bridge hata:", e); process.exit(2); });
