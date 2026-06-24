import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluateAuthz, isTargetAuthorized } from "../src/authz/gate.ts";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "warden-authz-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("yetki kapısı (authorization gate)", () => {
  it("dosya yoksa PASİF", () => {
    const r = evaluateAuthz(dir);
    expect(r.mode).toBe("passive");
    expect(r.fileFound).toBe(false);
  });

  it("dosya var ama eksikse PASİF", () => {
    writeFileSync(join(dir, "warden.authz.yml"), "owner_attestation: false\nauthorized_targets: []\n");
    const r = evaluateAuthz(dir);
    expect(r.mode).toBe("passive");
    expect(r.fileFound).toBe(true);
  });

  it("tüm alanlar doluysa AKTİF", () => {
    writeFileSync(
      join(dir, "warden.authz.yml"),
      [
        "owner_attestation: true",
        "authorized_targets:",
        '  - "staging.ornek.com"',
        '  - "127.0.0.1"',
        'authorized_by: "Ali Veli <ali@ornek.com>"',
        'date: "2026-06-24"',
      ].join("\n"),
    );
    const r = evaluateAuthz(dir);
    expect(r.mode).toBe("active");
    expect(r.authorizedTargets).toContain("staging.ornek.com");
    expect(r.authorizedBy).toContain("Ali Veli");
  });

  it("allow-list dışı hedef reddedilir", () => {
    writeFileSync(
      join(dir, "warden.authz.yml"),
      [
        "owner_attestation: true",
        "authorized_targets:",
        '  - "staging.ornek.com"',
        'authorized_by: "x"',
        'date: "2026-06-24"',
      ].join("\n"),
    );
    const r = evaluateAuthz(dir);
    expect(isTargetAuthorized(r, "staging.ornek.com")).toBe(true);
    expect(isTargetAuthorized(r, "api.staging.ornek.com")).toBe(true);
    expect(isTargetAuthorized(r, "baska-site.com")).toBe(false);
  });

  it("pasif sonuçta hiçbir hedef yetkili değildir", () => {
    const r = evaluateAuthz(dir);
    expect(isTargetAuthorized(r, "localhost")).toBe(false);
  });
});
