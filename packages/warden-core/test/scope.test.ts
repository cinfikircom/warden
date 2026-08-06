import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveGitScope } from "../src/detect/scope.ts";
import { createFsContext } from "../src/detect/fs.ts";

/**
 * Diff-scope tarama (Strix devralma §1.1). Gerçek bir git deposu kurup davranışı uçtan uca
 * doğrular — git çıktısını taklit etmek, tam da burada yanılmak istemediğimiz yeri taklit
 * etmek olurdu.
 */

let repo: string;

function git(...args: string[]): string {
  return execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
}

beforeAll(() => {
  repo = mkdtempSync(join(tmpdir(), "warden-scope-"));
  git("init", "-q");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "T");
  git("config", "commit.gpgsign", "false");

  mkdirSync(join(repo, "src"), { recursive: true });
  writeFileSync(join(repo, "src", "eski.ts"), "export const a = 1;\n");
  writeFileSync(join(repo, "src", "degismeyen.ts"), "export const b = 2;\n");
  git("add", "-A");
  git("commit", "-q", "-m", "ilk");

  // HEAD~1 → HEAD arasında: bir dosya değişti, bir dosya eklendi.
  writeFileSync(join(repo, "src", "eski.ts"), "export const a = 99;\n");
  writeFileSync(join(repo, "src", "yeni.ts"), "export const c = 3;\n");
  git("add", "-A");
  git("commit", "-q", "-m", "ikinci");
});

afterAll(() => {
  rmSync(repo, { recursive: true, force: true });
});

describe("resolveGitScope", () => {
  it("commit'lenmiş değişiklikleri kapsama alır, değişmeyeni almaz", () => {
    const r = resolveGitScope(repo, "HEAD~1");
    expect(r.error).toBeNull();
    expect(r.scope?.paths.has("src/eski.ts")).toBe(true);
    expect(r.scope?.paths.has("src/yeni.ts")).toBe(true);
    expect(r.scope?.paths.has("src/degismeyen.ts")).toBe(false);
  });

  it("commit EDİLMEMİŞ düzenlemeler de kapsama girer", () => {
    writeFileSync(join(repo, "src", "degismeyen.ts"), "export const b = 42; // elle düzenlendi\n");
    try {
      const r = resolveGitScope(repo, "HEAD");
      expect(r.scope?.paths.has("src/degismeyen.ts")).toBe(true);
    } finally {
      git("checkout", "--", "src/degismeyen.ts");
    }
  });

  it("izlenmeyen (untracked) yeni dosyalar kapsama girer — en riskli kategori", () => {
    writeFileSync(join(repo, "src", "izlenmeyen.ts"), "export const d = 4;\n");
    try {
      const r = resolveGitScope(repo, "HEAD");
      expect(r.scope?.paths.has("src/izlenmeyen.ts")).toBe(true);
    } finally {
      rmSync(join(repo, "src", "izlenmeyen.ts"));
    }
  });

  it("çözülemeyen referans → scope null + gerekçe (sessiz başarısızlık yok)", () => {
    const r = resolveGitScope(repo, "boyle-bir-ref-yok");
    expect(r.scope).toBeNull();
    expect(r.error).toContain("çözülemedi");
  });

  it("git deposu olmayan dizin → scope null + gerekçe", () => {
    const bos = mkdtempSync(join(tmpdir(), "warden-nogit-"));
    try {
      const r = resolveGitScope(bos, "HEAD");
      expect(r.scope).toBeNull();
      expect(r.error).toContain("git deposu değil");
    } finally {
      rmSync(bos, { recursive: true, force: true });
    }
  });
});

describe("createFsContext — kapsam filtresi", () => {
  it("find() yalnızca kapsamdaki dosyaları döndürür", () => {
    const scope = resolveGitScope(repo, "HEAD~1").scope;
    const fs = createFsContext(repo, scope?.paths);
    const bulunan = fs.find((p) => p.endsWith(".ts"));
    expect(bulunan).toContain("src/eski.ts");
    expect(bulunan).toContain("src/yeni.ts");
    expect(bulunan).not.toContain("src/degismeyen.ts");
  });

  it("kapsam verilmezse find() tüm ağacı görür", () => {
    const fs = createFsContext(repo);
    expect(fs.find((p) => p.endsWith(".ts"))).toContain("src/degismeyen.ts");
  });

  /**
   * Kritik ayrım: kapsam yalnızca "neyi tarıyoruz"u daraltır, "proje neye sahip"i değil.
   * exists/readFile de daraltılsaydı, kapsam dışında kalan her koruma (helmet, backup
   * script'i, CI dosyası) "yok" sayılır ve kısmi tarama yokluk-temelli FP üretirdi.
   */
  it("exists() ve readFile() kapsamdan ETKİLENMEZ", () => {
    const scope = resolveGitScope(repo, "HEAD~1").scope;
    const fs = createFsContext(repo, scope?.paths);
    expect(scope?.paths.has("src/degismeyen.ts")).toBe(false);
    expect(fs.exists("src/degismeyen.ts")).toBe(true);
    expect(fs.readFile("src/degismeyen.ts")).toContain("export const b");
  });

  it("boş kapsam → find() hiçbir şey bulmaz", () => {
    const fs = createFsContext(repo, new Set<string>());
    expect(fs.find(() => true)).toHaveLength(0);
  });
});
