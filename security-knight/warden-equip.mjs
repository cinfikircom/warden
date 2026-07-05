/**
 * WARDEN EQUIP — "Kuşan" tıklamasının arkasındaki gerçek iş (bkz. plan: gerçek-taramaya-dayalı akış).
 * =========================================================================
 * İki ayrı yol vardır (bilerek ayrılmıştır — bkz. aşağıdaki yarış-durumu notu):
 *
 *   node warden-equip.mjs --module B [--target <repo>]
 *     Panel bir zırha basılır basılmaz (drawer açılışında) tetiklenir:
 *       1) Tam `pnpm warden scan` (asla --module — findings.json/history/bridge'in doğruluğu için;
 *          bkz. packages/warden-cli/src/index.ts'teki resolveModules yorumu).
 *       2) warden-bridge.mjs ile tüm tahtayı tazele (state/warden-posture.json).
 *       3) O modülün GERÇEK bulgularını state/warden-gaps/<module>.json'a yaz — çekmece bunu
 *          okuyup şablon metin değil gerçek eksikleri gösterecek.
 *
 *   node warden-equip.mjs --module B --queue
 *     "Ajana kuyruğa al" butonuyla tetiklenir. BİLEREK yeniden taramaz (drawer zaten az önce
 *     yukarıdaki akışla taze bir tarama yaptı) — sadece `warden prompts` ile (mevcut
 *     findings.json'dan, taramasız) taze fingerprint alır ve HEMEN jobs.jsonl'e yazar.
 *     Neden ayrı: panel, kuyruğa alınca "İŞLENİYOR" durumunu iyimser (optimistic) gösterir;
 *     eğer bu yol da tam taramayı tekrarlasaydı (birkaç saniye sürer), o sırada gelen periyodik
 *     poll sunucuda henüz yazılmamış görevi görüp iyimser durumu ezerdi (yanıp-sönme hatası).
 *     Kuyruğa yazmak saniyenin çok altında sürmeli.
 * =========================================================================
 */
import { execFileSync } from "node:child_process";
import { readFile, writeFile, appendFile, mkdir } from "node:fs/promises";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url)); // security-knight/
const REPO = join(ROOT, ".."); // panelin bir üstü (kurulu projede = hedef proje)
// `pnpm warden` yalnız Warden monoreposunda tanımlı. Kurulu projede `.warden-home` (init'in yazdığı)
// Warden repo kökünü verir → `pnpm --dir <home> warden`; yoksa monorepo içindeyiz → REPO.
const HOME_FILE = join(ROOT, ".warden-home");
const WARDEN_HOME = existsSync(HOME_FILE) ? readFileSync(HOME_FILE, "utf8").trim() : REPO;
const STATE = join(ROOT, "state");
const GAPS_DIR = join(STATE, "warden-gaps");
const JOBS_FILE = join(STATE, "jobs.jsonl");

function args() {
  const a = {};
  const v = process.argv.slice(2);
  for (let i = 0; i < v.length; i++) {
    if (!v[i].startsWith("--")) continue;
    const k = v[i].slice(2);
    const n = v[i + 1];
    if (n === undefined || n.startsWith("--")) a[k] = true;
    else { a[k] = n; i++; }
  }
  return a;
}
const run = (cmd, cmdArgs, cwd) => execFileSync(cmd, cmdArgs, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

async function queueOnly(module, target) {
  // Hızlı yol — YENİDEN TARAMAZ. Mevcut findings.json'dan (drawer'ın scan-on-open'ı zaten
  // tazelemiştir) prompts okur ve hemen kuyruğa yazar (bkz. dosya başındaki yarış-durumu notu).
  let fingerprints = [];
  try {
    const out = run("pnpm", ["--dir", WARDEN_HOME, "warden", "prompts", "--target", target, "--module", module], WARDEN_HOME);
    const jsonStart = out.indexOf("{");
    fingerprints = (JSON.parse(out.slice(jsonStart)).prompts ?? []).map((p) => p.fingerprint);
  } catch (e) { console.log("⚠ prompts alınamadı (önce /api/warden/scan gerekebilir): " + String(e.message).split("\n")[0]); }
  const job = {
    id: `wjob_${Date.now()}_${module}`,
    module,
    kind: "warden-fix",
    requestedAt: new Date().toISOString(),
    state: "queued",
    fingerprints,
    note: "Ajan: SKILL.md → 'Otomatik Düzeltme Prosedürü'nü işlet (kuyruğu oku → taze prompt al → paralel düzelt → doğrula → PR aç).",
  };
  await appendFile(JOBS_FILE, JSON.stringify(job) + "\n");
  console.log(`✓ görev kuyruğa alındı: ${job.id} (${fingerprints.length} bulgu)`);
}

async function scanAndWriteGaps(module, target) {
  const findingsPath = join(target, "warden-report", "findings.json");
  console.log(`⚔️  Warden Equip — ${module} zırhı için gerçek tarama başlıyor`);

  // 1) Tam tarama — asla --module (diğer boyutların doğruluğunu bozmasın).
  try { console.log("  1/3 Warden taraması…"); run("pnpm", ["--dir", WARDEN_HOME, "warden", "scan", "--target", target], WARDEN_HOME); console.log("      ✓ tarandı"); }
  catch { console.log("      ⚠ tarama başarısız/atlandı — mevcut findings.json kullanılacak"); }

  // 2) Köprü: scan → tüm tahta (her modül, yalnız bu değil).
  try { console.log("  2/3 köprü (scan → zırh)…"); console.log("      " + run("node", ["warden-bridge.mjs", "--file", findingsPath], ROOT).trim().split("\n").pop()); }
  catch (e) { console.log("      ⚠ köprü başarısız: " + String(e.message).split("\n")[0]); }

  // 3) Bu modülün gerçek bulgularını çekmece için yaz.
  let findings = [];
  try {
    const parsed = JSON.parse(await readFile(findingsPath, "utf8"));
    findings = (parsed.findings ?? []).filter((f) => f.module === module);
  } catch { /* findings.json okunamadı — boş liste yazılır */ }
  await mkdir(GAPS_DIR, { recursive: true });
  const gapsFile = join(GAPS_DIR, `${module}.json`);
  await writeFile(gapsFile, JSON.stringify({ module, generatedAt: new Date().toISOString(), findings }, null, 2));
  console.log(`  3/3 gerçek eksikler yazıldı: ${gapsFile} (${findings.length} bulgu)`);
  console.log(`✅ ${module} için tarama tamam. /api/warden/gaps?module=${module} taze.`);
}

async function main() {
  const a = args();
  const module = a.module;
  if (!module) { console.error("❌ --module gerekli (ör. --module B)"); process.exit(2); }
  const target = a.target || REPO;
  if (a.queue) await queueOnly(module, target);
  else await scanAndWriteGaps(module, target);
}
main().catch((e) => { console.error("warden-equip hata:", e); process.exit(2); });
