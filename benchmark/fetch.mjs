#!/usr/bin/env node
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Benchmark korpusunu indirir.
 *
 * AYRI BİR ADIM olması bilinçli: Warden offline-first'tür ve `pnpm bench` ağ istemez.
 * İndirme yalnızca burada, açık bir komutla olur. Korpus indirilmemişse benchmark
 * "ölçemedim" der — sessizce boş sonuç dönmez.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGETS = join(HERE, "targets");
// Nokta öneki zorunlu: korpus Warden'ın kendi taramasına karışmamalı (bkz. run.ts).
const CORPUS = join(HERE, ".corpus");

function specs() {
  if (!existsSync(TARGETS)) return [];
  return readdirSync(TARGETS)
    .filter((f) => /\.ya?ml$/i.test(f))
    .map((f) => {
      const text = readFileSync(join(TARGETS, f), "utf8");
      const get = (k) => text.match(new RegExp(`^${k}:\\s*(.+)$`, "m"))?.[1]?.trim() ?? null;
      return { file: f, target: get("target"), repo: get("repo"), ref: get("ref"), root: get("root") };
    });
}

mkdirSync(CORPUS, { recursive: true });

for (const s of specs()) {
  if (!s.repo || !s.ref || !s.root) {
    console.error(`✗ ${s.file}: repo/ref/root eksik, atlandı.`);
    continue;
  }
  const dest = join(CORPUS, s.root);
  if (existsSync(dest)) {
    console.log(`• ${s.target}: zaten var (${s.root})`);
    continue;
  }
  const slug = s.repo.replace(/^https?:\/\/github\.com\//, "").replace(/\.git$/, "");
  const url = `https://codeload.github.com/${slug}/tar.gz/refs/heads/${s.ref}`;
  const tmp = join(CORPUS, `${s.target}.tar.gz`);
  console.log(`↓ ${s.target}: ${url}`);
  try {
    execFileSync("curl", ["-sSL", "--max-time", "180", url, "-o", tmp], { stdio: "inherit" });
    execFileSync("tar", ["xzf", tmp, "-C", CORPUS], { stdio: "inherit" });
    rmSync(tmp, { force: true });
    console.log(`✓ ${s.target} → ${s.root}`);
  } catch (err) {
    rmSync(tmp, { force: true });
    console.error(`✗ ${s.target}: indirilemedi — ${String(err)}`);
    console.error("  Ağ yoksa bu beklenen bir sonuç; benchmark o hedefi 'ölçülemedi' sayacak.");
  }
}
