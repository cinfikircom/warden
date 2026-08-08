import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { DetectContext } from "./types.ts";
import type { CoverageCollector } from "../report/coverage.ts";
import { TEST_PATH } from "../util/paths.ts";

const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".turbo",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
  "warden-report",
]);

/**
 * Nokta ile başlayan dizinler varsayılan olarak atlanır (.vscode/.idea/.cache gürültüsü).
 * Ama bazıları güvenlik/CI açısından önemli config taşır — bunlara izin ver.
 * (Örn. D5 CI/CD dedektörü `.github/workflows`'u görebilsin.)
 */
const ALLOW_DOT_DIRS = new Set([".github", ".circleci", ".gitlab"]);

/**
 * Varsayılan dizin derinliği sınırı.
 *
 * 4'tü ve TÜM modülleri etkileyen sessiz bir kör noktaydı: derinlik `walk(root, 0)`'dan
 * sayıldığı için `packages/<pkg>/src/modules/<mod>/x.ts` (= 5) hiç taranmıyordu. Yani Warden
 * kendi `src/modules/` ağacını bile göremiyordu; yalnızca FE modülü yerel olarak 6 geçtiği
 * için oradan bulgu üretebiliyordu.
 *
 * 6, yaygın monorepo yerleşimlerini kapsar (`apps/web/src/components/ui/X.tsx`,
 * `packages/<pkg>/src/<katman>/<alan>/x.ts`). Sınırın asıl amacı patolojik ağaçlara karşı
 * korumaydı; onu zaten `limit` yapıyor (bkz. aşağıdaki `out.length >= limit` kesmesi) ve
 * `IGNORE_DIRS` en büyük alt ağaçları (node_modules/dist/.next…) baştan eliyor.
 */
export const DEFAULT_MAX_DEPTH = 6;

/**
 * Ağaç yürüyüşünde varsayılan dosya tavanı. Bundan KÜÇÜK bir `limit` geçmek, çağıranın
 * kasıtlı bir "var mı?" sondajı yaptığı anlamına gelir (bkz. `find()` içindeki gerekçe).
 */
export const DEFAULT_FILE_LIMIT = 2000;

/**
 * READ-ONLY dosya bağlamı — dedektörler ve modüller bunu kullanır.
 *
 * `scopePaths` verilirse (diff-scope tarama, bkz. detect/scope.ts) YALNIZCA `find()`
 * daraltılır; `exists()` ve `readFile()` bilerek tam ağaca bakmaya devam eder.
 *
 * Bu ayrım kritik: modüllerin çoğu bir korumanın VARLIĞINI `exists()`/`readFile()` ile
 * yoklar ("helmet kurulu mu", "backup script'i var mı"). Onları da kapsama daraltmak,
 * kapsam dışında kaldığı için görülemeyen her korumayı "yok" saydırır ve kısmi tarama
 * bir yokluk-temelli yanlış pozitif fabrikasına dönerdi. Daralan şey "neyi TARIYORUZ",
 * "proje neye SAHİP" değil.
 */
export interface FsContextOptions {
  /** Diff-scope tarama kapsamı (bkz. detect/scope.ts). */
  readonly scopePaths?: ReadonlySet<string> | undefined;
  /**
   * Kapsam toplayıcı. Verilirse derinlik ve dosya-sayısı kesmeleri KAYDEDİLİR ve rapordaki
   * Kapsam Beyanı'nda görünür. Verilmezse davranış eskisiyle birebir aynıdır (sessiz kesme) —
   * geriye dönük uyum için.
   */
  readonly coverage?: CoverageCollector | undefined;
  /** Varsayılan derinlik sınırını geçersiz kıl (CLI: `--max-depth`). */
  readonly maxDepth?: number | undefined;
  /** Varsayılan dosya-sayısı tavanını geçersiz kıl (CLI: `--max-files`). */
  readonly maxFiles?: number | undefined;
}

export function createFsContext(projectRoot: string, options: FsContextOptions = {}): DetectContext {
  const { scopePaths, coverage } = options;

  const readFile = (relPath: string): string | null => {
    try {
      return readFileSync(join(projectRoot, relPath), "utf8");
    } catch {
      return null;
    }
  };
  const exists = (relPath: string): boolean => existsSync(join(projectRoot, relPath));

  const find: DetectContext["find"] = (predicate, opts) => {
    // Öncelik: çağıran modülün açık isteği > kullanıcının CLI ayarı > yerleşik varsayılan.
    // Modül kendi derinliğini geçtiğinde (ör. FE: 6) kullanıcının daha YÜKSEK ayarı kazanır —
    // aksi halde `--max-depth 9` bazı modüllerde sessizce yok sayılırdı.
    const requested = opts?.maxDepth ?? DEFAULT_MAX_DEPTH;
    const maxDepth = options.maxDepth !== undefined ? Math.max(options.maxDepth, requested) : requested;
    const limit = options.maxFiles ?? opts?.limit ?? DEFAULT_FILE_LIMIT;
    const out: string[] = [];

    /*
     * Tavana ulaşmak HER ZAMAN kapsam kaybı değildir.
     *
     * Modüllerin çoğu "bu projede X var mı?" diye sorarken `{ limit: 1 }` geçer — bir tane
     * bulmak yeterlidir ve döngü kasıtlı olarak orada durur. Bunu "kalan dosyalar hiç
     * listelenmedi" diye raporlamak, kapsam beyanının kendisini yanlış alarm üreten bir
     * gürültü kaynağına çevirirdi. Beyanın değeri doğruluğundan geliyor: kaybı gizlemek kadar
     * olmayan kaybı bildirmek de onu güvenilmez kılar.
     *
     * Bu yüzden yalnızca GERÇEK bir tavan (yerleşik varsayılan ya da kullanıcının --max-files
     * ayarı) aşıldığında rapor edilir.
     */
    const limitIsRealCeiling = options.maxFiles !== undefined || limit >= DEFAULT_FILE_LIMIT;

    const walk = (dir: string, depth: number): void => {
      if (out.length >= limit) return;
      if (depth > maxDepth) {
        // SESSİZ DEĞİL: bu alt ağaç hiç görülmedi ve bu, rapora yazılması gereken bir kayıptır.
        //
        // Tek istisna test/fixture ağaçları: oradaki dosyalar kural katmanında zaten
        // eleniyor (util/paths.ts TEST_PATH), dolayısıyla kesilmeleri gerçek bir denetim
        // kaybı değil. Onları listelemek beyanı gerçek kayıpların görünmediği bir listeye
        // çevirirdi.
        const rel = relative(projectRoot, dir).split(sep).join("/");
        if (!TEST_PATH.test(`${rel}/`)) {
          coverage?.limit(
            "depth",
            "depth",
            `Dizin derinliği sınırı (${maxDepth}) aşıldığı için bu dizinlerin altı hiç taranmadı. \`--max-depth\` ile yükseltilebilir.`,
            rel,
          );
        }
        return;
      }
      let entries: import("node:fs").Dirent[];
      try {
        entries = readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        if (out.length >= limit) {
          if (limitIsRealCeiling) {
            coverage?.limit(
              "file-count",
              "file-count",
              `Dosya sayısı tavanına (${limit}) ulaşıldı; kalan dosyalar hiç listelenmedi. \`--max-files\` ile yükseltilebilir.`,
            );
          }
          return;
        }
        const full = join(dir, e.name);
        if (e.isDirectory()) {
          if (IGNORE_DIRS.has(e.name)) continue;
          if (e.name.startsWith(".") && !ALLOW_DOT_DIRS.has(e.name)) continue;
          walk(full, depth + 1);
        } else if (e.isFile()) {
          const rel = relative(projectRoot, full).split(sep).join("/");
          if (scopePaths && !scopePaths.has(rel)) continue;
          if (predicate(rel)) out.push(rel);
        }
      }
    };

    try {
      if (statSync(projectRoot).isDirectory()) walk(projectRoot, 0);
    } catch {
      /* yok say */
    }
    return out;
  };

  return { projectRoot, readFile, exists, find };
}
