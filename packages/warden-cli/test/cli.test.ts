import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, existsSync, rmSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
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

  it("init hedef projeye skill iskeletini + paneli yazar (--no-launch, sunucu başlatmaz), exit 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "warden-cli-test-"));
    try {
      const { code, stdout } = await runCli(["init", "--target", dir, "--no-launch"], dir);
      expect(code).toBe(0);
      expect(stdout).toContain("Warden kuruldu");
      expect(existsSync(join(dir, ".claude", "skills", "warden", "README.md"))).toBe(true);
      expect(existsSync(join(dir, "warden.authz.example.yml"))).toBe(true);
      expect(existsSync(join(dir, "security-knight", "server.mjs"))).toBe(true);
      expect(existsSync(join(dir, "security-knight", "knight.js"))).toBe(true);
      // kaynak reponun kendi çalışma-zamanı durumu (jobs/gaps/vb.) asla taşınmaz — hedef temiz başlar.
      expect(existsSync(join(dir, "security-knight", "state", "jobs.jsonl"))).toBe(false);
      // .warden-home Warden repo kökünü göstermeli → kurulu panel `pnpm --dir <home> warden` ile tarar.
      const homeFile = join(dir, "security-knight", ".warden-home");
      expect(existsSync(homeFile)).toBe(true);
      const home = readFileSync(homeFile, "utf8").trim();
      expect(existsSync(join(home, "package.json"))).toBe(true);
      expect(existsSync(join(home, "packages", "warden-cli"))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("init --no-panel paneli hiç kopyalamaz", async () => {
    const dir = mkdtempSync(join(tmpdir(), "warden-cli-test-"));
    try {
      const { code } = await runCli(["init", "--target", dir, "--no-panel"], dir);
      expect(code).toBe(0);
      expect(existsSync(join(dir, ".claude", "skills", "warden", "SKILL.md"))).toBe(true);
      expect(existsSync(join(dir, "security-knight"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  describe("--module + prompts", () => {
    function makeFixture(): string {
      const dir = mkdtempSync(join(tmpdir(), "warden-cli-module-test-"));
      mkdirSync(join(dir, "src"), { recursive: true });
      writeFileSync(
        join(dir, "src", "app.js"),
        'const crypto = require("crypto");\n' +
          'function hash(x) { return crypto.createHash("md5").update(x).digest("hex"); }\n' +
          "module.exports = { hash };\n",
      );
      writeFileSync(join(dir, "package.json"), "{}\n");
      return dir;
    }

    it("--module B yalnızca B'yi tarar, diğer modüller n/d kalır", async () => {
      const dir = makeFixture();
      try {
        const { code, stdout } = await runCli(["scan", "--target", dir, "--module", "B"], dir);
        expect(code).toBe(0);
        expect(stdout).toContain("Çalışan modül: B");
        const findingsJson = JSON.parse(readFileSync(join(dir, "warden-report", "findings.json"), "utf8"));
        const board = findingsJson.scoreboard as Array<{ module: string; score: number | null }>;
        expect(board.find((r) => r.module === "B")?.score).not.toBeNull();
        expect(board.find((r) => r.module === "A")?.score).toBeNull();
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("prompts --module B --json, taramadan sonra bulgu prompt'unu basar", async () => {
      const dir = makeFixture();
      try {
        await runCli(["scan", "--target", dir, "--module", "B"], dir);
        const { code, stdout } = await runCli(["prompts", "--target", dir, "--module", "B"], dir);
        expect(code).toBe(0);
        const out = JSON.parse(stdout);
        expect(out.module).toBe("B");
        expect(out.count).toBe(1);
        expect(out.prompts[0].fingerprint).toBe(
          JSON.parse(readFileSync(join(dir, "warden-report", "findings.json"), "utf8")).findings[0].fingerprint,
        );
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("prompts, önceden tarama yokken exit 2 + yardımcı mesaj verir", async () => {
      const dir = mkdtempSync(join(tmpdir(), "warden-cli-module-test-"));
      try {
        const { code, stderr } = await runCli(["prompts", "--target", dir, "--module", "B"], dir);
        expect(code).toBe(2);
        expect(stderr).toContain("önce");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
