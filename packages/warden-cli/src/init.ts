import { mkdirSync, writeFileSync, existsSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * `warden init` — Warden'i bir projeye Claude Code SKILL'i olarak kurar.
 * Hedefte `.claude/skills/warden/` altına SKILL.md + yetki şablonu + kısa kullanım kılavuzu yazar.
 * Hiçbir şeyi ezmeden (varsa atlar) çalışır; aktif yetenek varsayılan kapalıdır (§2).
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
`;

function writeIfAbsent(path: string, content: string): "yazıldı" | "atlandı" {
  if (existsSync(path)) return "atlandı";
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
  return "yazıldı";
}

export function runInit(targetRoot: string): void {
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

  process.stdout.write(`Warden kuruldu → ${skillDir}\n`);
  process.stdout.write(`  SKILL.md: ${skillStatus}\n`);
  process.stdout.write(`  README.md: ${usageStatus}\n`);
  process.stdout.write(`  warden.authz.example.yml: ${authzStatus}\n`);
  process.stdout.write(`\nPasif denetim için: warden scan --target ${targetRoot}\n`);
  process.stdout.write(`Aktif (DAST) için önce: cp warden.authz.example.yml warden.authz.yml ve doldur.\n`);
}
