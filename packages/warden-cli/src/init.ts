import { mkdirSync, writeFileSync, existsSync, copyFileSync } from "node:fs";
import { cp } from "node:fs/promises";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createServer } from "node:net";

/**
 * `warden init` — Warden'i bir projeye Claude Code SKILL'i olarak kurar.
 * Hedefte `.claude/skills/warden/` altına SKILL.md + yetki şablonu + kısa kullanım kılavuzu yazar,
 * `security-knight/` oyunlaştırılmış paneli kopyalar ve (aksi belirtilmezse) paneli hemen başlatıp
 * tarayıcıda açar. Hiçbir şeyi ezmeden (varsa atlar) çalışır; aktif yetenek varsayılan kapalıdır (§2).
 */

const AUTHZ_TEMPLATE = `# Warden Yetki Kapısı — bu dosyayı doldurursanız AKTİF (DAST) testler açılır.
# Boş/eksikse Warden yalnızca PASİF (read-only) koşar. Allow-list dışına ASLA istek gitmez.
owner_attestation: false
authorized_targets:
  - "localhost"
authorized_by: ""
date: ""
limits:
  max_requests_per_second: 2
  max_total_requests: 500
`;

const USAGE = `# Warden (kurulu skill)

Bu proje Warden güvenlik & production-readiness denetimine kuruldu.

## Çalıştırma
- Pasif (varsayılan, read-only):   warden scan --target .
- Aktif (DAST, yetki kapılı):      warden pentest --target .

## Güvenlik (bağlayıcı)
- Varsayılan tamamen PASİF. Aktif testler yalnızca \`warden.authz.yml\` doldurulunca,
  yalnızca allow-list host'lara, rate-limited, non-destructive çalışır.
- Çıktılar: warden-report/ (report.md · findings.json · remediation-playbook.md ·
  parity-report.md · compliance-report.md · findings.sarif · history.jsonl · warden-run.log)

## Akış
1) warden scan  2) report.md + remediation-playbook.md'yi oku  3) P0/P1 prompt'larını bir
ajana ver, düzelt  4) tekrar çalıştır → öncesi/sonrası delta neyin düzeldiğini gösterir.

## Warden Knight paneli
\`security-knight/\` bu projeye kopyalandı ve (aksi belirtilmediyse) otomatik başlatılıp
tarayıcıda açıldı — bkz. \`security-knight/README.md\`. "Ajana kuyruğa al" ile kuyruğa düşen
görevleri işlemek için SKILL.md'deki "Otomatik Düzeltme Prosedürü" bölümüne bak (paralel
alt-ajan + fingerprint doğrulama + PR kapısı).
`;

function writeIfAbsent(path: string, content: string): "yazıldı" | "atlandı" {
  if (existsSync(path)) return "atlandı";
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
  return "yazıldı";
}

/** `security-knight/`'ı hedef projeye kopyalar. Kaynak durumunu (state/) asla taşımaz — hedef temiz başlar. */
async function copyPanel(targetRoot: string): Promise<"yazıldı" | "atlandı" | "kaynak-yok"> {
  const panelDest = join(targetRoot, "security-knight");
  if (existsSync(panelDest)) return "atlandı";
  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = join(here, "..", "..", ".."); // Warden monorepo kökü — `pnpm warden` yalnız burada tanımlı
  const panelSrc = join(repoRoot, "security-knight");
  if (!existsSync(panelSrc)) return "kaynak-yok"; // paketlenmiş dağıtımda panel yoksa sessizce geç
  await cp(panelSrc, panelDest, {
    recursive: true,
    filter: (src) => {
      const rel = relative(panelSrc, src);
      if (rel === "") return true;
      const top = rel.split(sep)[0];
      return top !== "state" && top !== "node_modules";
    },
  });
  mkdirSync(join(panelDest, "state"), { recursive: true }); // hedef kendi (boş) state'iyle başlar
  // Kurulu panelin tarama scriptleri (loop.mjs / warden-equip.mjs) `pnpm warden`'ı yalnız Warden
  // reposundan bulabilir (hedef projede tanımlı değil). Repo kökünü yaz → `pnpm --dir <home> warden`.
  writeFileSync(join(panelDest, ".warden-home"), repoRoot + "\n", "utf8");
  return "yazıldı";
}

/** 8137'den başlayarak boş bir port arar (dev sunucusu için). Bulamazsa 8137'yi döner. */
async function findFreePort(start: number, tries = 20): Promise<number> {
  for (let port = start; port < start + tries; port++) {
    const free = await new Promise<boolean>((resolvePort) => {
      const srv = createServer();
      srv.once("error", () => resolvePort(false));
      srv.listen(port, "127.0.0.1", () => srv.close(() => resolvePort(true)));
    });
    if (free) return port;
  }
  return start;
}

/** Kopyalanan paneli arka planda başlatır — server.mjs kendi açılışında tarayıcıyı otomatik açar. */
async function launchPanel(targetRoot: string): Promise<void> {
  const panelDir = join(targetRoot, "security-knight");
  if (!existsSync(join(panelDir, "server.mjs"))) return;
  const port = await findFreePort(8137);
  const child = spawn("node", ["server.mjs"], {
    cwd: panelDir,
    env: { ...process.env, PORT: String(port) },
    detached: true,
    stdio: "ignore",
  });
  child.unref();
  process.stdout.write(`\n⚔️  Warden Knight paneli başlatıldı → http://127.0.0.1:${port}/ (tarayıcıda açılıyor)\n`);
  process.stdout.write(`   Durdurmak için: lsof -ti:${port} | xargs kill\n`);
}

export interface RunInitOptions {
  /** Panel dosyalarını hiç kopyalama (yalnızca skill kurulur — eski davranış). */
  noPanel?: boolean;
  /** Panel dosyalarını kopyala ama başlatma/tarayıcıyı açma (ör. testlerde, CI'da). */
  noLaunch?: boolean;
}

export async function runInit(targetRoot: string, opts: RunInitOptions = {}): Promise<void> {
  const skillDir = join(targetRoot, ".claude", "skills", "warden");
  mkdirSync(skillDir, { recursive: true });

  // Paketlenmiş SKILL.md'yi kopyala (warden-skill paketinden).
  const here = dirname(fileURLToPath(import.meta.url));
  const skillSrc = join(here, "..", "..", "warden-skill", "SKILL.md");
  let skillStatus = "atlandı";
  const skillDest = join(skillDir, "SKILL.md");
  if (!existsSync(skillDest) && existsSync(skillSrc)) {
    copyFileSync(skillSrc, skillDest);
    skillStatus = "yazıldı";
  }

  const usageStatus = writeIfAbsent(join(skillDir, "README.md"), USAGE);
  const authzStatus = writeIfAbsent(join(targetRoot, "warden.authz.example.yml"), AUTHZ_TEMPLATE);
  const panelStatus = opts.noPanel ? "atlandı (--no-panel)" : await copyPanel(targetRoot);

  process.stdout.write(`Warden kuruldu → ${skillDir}\n`);
  process.stdout.write(`  SKILL.md: ${skillStatus}\n`);
  process.stdout.write(`  README.md: ${usageStatus}\n`);
  process.stdout.write(`  warden.authz.example.yml: ${authzStatus}\n`);
  process.stdout.write(`  security-knight/: ${panelStatus}\n`);
  process.stdout.write(`\nPasif denetim için: warden scan --target ${targetRoot}\n`);
  process.stdout.write(`Aktif (DAST) için önce: cp warden.authz.example.yml warden.authz.yml ve doldur.\n`);

  if (!opts.noPanel && !opts.noLaunch) await launchPanel(targetRoot);
}
