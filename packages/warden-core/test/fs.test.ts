import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFsContext } from "../src/detect/fs.ts";

/**
 * fs.find() gezgini — nokta-dizin politikasının regresyon testi.
 * Bug: `.github` dahil TÜM nokta-dizinler atlanıyordu, bu yüzden D5 CI/CD
 * dedektörü `.github/workflows/*.yml`'i hiç göremiyordu (kendi reposunda bile).
 */
describe("createFsContext().find — nokta-dizin politikası", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "warden-fs-"));
    mkdirSync(join(root, ".github", "workflows"), { recursive: true });
    writeFileSync(join(root, ".github", "workflows", "ci.yml"), "name: CI\n", "utf8");
    mkdirSync(join(root, ".circleci"), { recursive: true });
    writeFileSync(join(root, ".circleci", "config.yml"), "version: 2.1\n", "utf8");
    mkdirSync(join(root, ".vscode"), { recursive: true });
    writeFileSync(join(root, ".vscode", "settings.json"), "{}", "utf8");
    mkdirSync(join(root, "node_modules", "pkg"), { recursive: true });
    writeFileSync(join(root, "node_modules", "pkg", "index.js"), "x", "utf8");
    writeFileSync(join(root, "app.ts"), "export const x = 1;\n", "utf8");
  });

  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("izin verilen nokta-dizinleri (.github/.circleci) tarar", () => {
    const all = createFsContext(root).find(() => true, { limit: 1000 });
    expect(all).toContain(".github/workflows/ci.yml");
    expect(all).toContain(".circleci/config.yml");
  });

  it("gürültülü nokta-dizinleri (.vscode) ve node_modules'ü atlar", () => {
    const all = createFsContext(root).find(() => true, { limit: 1000 });
    expect(all).not.toContain(".vscode/settings.json");
    expect(all.some((p) => p.startsWith("node_modules/"))).toBe(false);
  });

  it("normal kaynak dosyaları bulur", () => {
    const all = createFsContext(root).find(() => true, { limit: 1000 });
    expect(all).toContain("app.ts");
  });

  it("predicate ve limit'e uyar", () => {
    const yml = createFsContext(root).find((p) => p.endsWith(".yml"), { limit: 1 });
    expect(yml).toHaveLength(1);
    expect(yml[0]?.endsWith(".yml")).toBe(true);
  });
});
