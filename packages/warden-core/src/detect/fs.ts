import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { DetectContext } from "./types.ts";

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

/** READ-ONLY dosya bağlamı — dedektörler ve modüller bunu kullanır. */
export function createFsContext(projectRoot: string): DetectContext {
  const readFile = (relPath: string): string | null => {
    try {
      return readFileSync(join(projectRoot, relPath), "utf8");
    } catch {
      return null;
    }
  };
  const exists = (relPath: string): boolean => existsSync(join(projectRoot, relPath));

  const find: DetectContext["find"] = (predicate, opts) => {
    const maxDepth = opts?.maxDepth ?? 4;
    const limit = opts?.limit ?? 2000;
    const out: string[] = [];

    const walk = (dir: string, depth: number): void => {
      if (depth > maxDepth || out.length >= limit) return;
      let entries: import("node:fs").Dirent[];
      try {
        entries = readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        if (out.length >= limit) return;
        const full = join(dir, e.name);
        if (e.isDirectory()) {
          if (IGNORE_DIRS.has(e.name)) continue;
          if (e.name.startsWith(".") && !ALLOW_DOT_DIRS.has(e.name)) continue;
          walk(full, depth + 1);
        } else if (e.isFile()) {
          const rel = relative(projectRoot, full).split(sep).join("/");
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
