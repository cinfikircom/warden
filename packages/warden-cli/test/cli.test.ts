import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * CLI uçtan-uca smoke test'i. index.ts import edildiğinde main()'i çalıştırıp
 * process.exit çağırdığı için in-process import edilemez; bu yüzden gerçek bir
 * tsx alt süreci olarak koşuyoruz. Amaç: temel komutların exit kodu + çıktı
 * sözleşmesini sabitlemek (pnpm -r test artık temiz exit 0 döner).
 */

const exec = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "src", "index.ts");

/** CLI'yi tsx ile çalıştırır; exit≠0 da reject etmez, kodu yakalar. */
async function runCli(
  args: readonly string[],
  cwd?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await exec("tsx", [CLI, ...args], {
      cwd: cwd ?? here,
      timeout: 30_000,
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

describe("Warden CLI smoke", () => {
  it("--version yalnızca sürümü yazar, exit 0", async () => {
    const { code, stdout } = await runCli(["--version"]);
    expect(code).toBe(0);
    expect(stdout.trim()).toBe("0.9.0");
  });

  it("--help kullanım metnini gösterir, exit 0", async () => {
    const { code, stdout } = await runCli(["--help"]);
    expect(code).toBe(0);
    expect(stdout).toContain("Kullanım:");
    expect(stdout).toContain("warden scan");
    expect(stdout).toContain("warden pentest");
  });

  it("bilinmeyen komut → exit 2 + stderr uyarısı", async () => {
    const { code, stderr } = await runCli(["frobnicate"]);
    expect(code).toBe(2);
    expect(stderr).toContain("Bilinmeyen komut: frobnicate");
  });

  it("init hedef projeye skill iskeletini yazar, exit 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "warden-cli-test-"));
    try {
      const { code, stdout } = await runCli(["init", "--target", dir], dir);
      expect(code).toBe(0);
      expect(stdout).toContain("Warden kuruldu");
      expect(existsSync(join(dir, ".claude", "skills", "warden", "README.md"))).toBe(true);
      expect(existsSync(join(dir, "warden.authz.example.yml"))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
