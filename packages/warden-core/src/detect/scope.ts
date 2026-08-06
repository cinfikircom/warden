import { execFileSync } from "node:child_process";
import type { AuditLog } from "../audit/log.ts";

/**
 * Diff-scope tarama: taramayı bir git referansından bu yana DEĞİŞEN dosyalara daraltır.
 * (Strix devralma §1.1 — bkz. docs/STRIX-ADOPTION.md.)
 *
 * Amaç CI maliyetini düşürmek: bir PR'da 12 dosya değiştiyse 4000 dosyanın tamamını taramak
 * gereksiz. Yerel git dışında hiçbir şeye ihtiyaç duymaz — offline-first kısıtını (K1) korur.
 */
export interface ScanScope {
  /** Karşılaştırma referansı (kullanıcının verdiği ham değer, ör. "HEAD~1", "origin/main"). */
  readonly since: string;
  /** Kapsamdaki dosyalar; proje köküne göre `/` ayraçlı göreli yollar. */
  readonly paths: ReadonlySet<string>;
}

function git(root: string, args: string[], audit?: AuditLog): string | null {
  try {
    audit?.command(`git ${args.join(" ")}`, root);
    return execFileSync("git", ["-C", root, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 10_000,
    }).trim();
  } catch {
    return null;
  }
}

export interface ScopeResult {
  readonly scope: ScanScope | null;
  /** Kapsam çözülemediyse insan-okur sebep (CLI + audit log'a yazılır). */
  readonly error: string | null;
}

/**
 * `since` referansından bu yana değişen dosyaları toplar.
 *
 * İki kaynağın birleşimi:
 *   1. `git diff --name-only <since>` — referanstan ÇALIŞMA AĞACINA kadarki fark.
 *      (İki/üç nokta sözdizimi bilerek kullanılmadı: düz biçim commit edilmemiş
 *      düzenlemeleri de kapsar, ki denetim aracında istenen davranış budur — "değişen"
 *      demek "commit edilmiş" demek değil.)
 *   2. `git ls-files --others --exclude-standard` — henüz izlenmeyen YENİ dosyalar.
 *      Yeni eklenen bir dosya diff'te görünmez ama en riskli kategoridir.
 *
 * Silinen dosyalar da listeye girer; zararsızdır, çünkü tarayıcı okuyamadığı yolu atlar.
 */
export function resolveGitScope(root: string, since: string, audit?: AuditLog): ScopeResult {
  if (git(root, ["rev-parse", "--is-inside-work-tree"], audit) !== "true") {
    return { scope: null, error: `--since verildi ama ${root} bir git deposu değil.` };
  }
  if (git(root, ["rev-parse", "--verify", "--quiet", `${since}^{commit}`], audit) === null) {
    return { scope: null, error: `--since referansı çözülemedi: "${since}".` };
  }

  const changed = git(root, ["diff", "--name-only", since], audit);
  if (changed === null) {
    return { scope: null, error: `git diff başarısız (--since "${since}").` };
  }
  const untracked = git(root, ["ls-files", "--others", "--exclude-standard"], audit) ?? "";

  const paths = new Set<string>();
  for (const line of `${changed}\n${untracked}`.split(/\r?\n/)) {
    const p = line.trim();
    if (p !== "") paths.add(p);
  }
  return { scope: { since, paths }, error: null };
}
