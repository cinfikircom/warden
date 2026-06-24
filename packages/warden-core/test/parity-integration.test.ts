import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFsContext } from "../src/detect/fs.ts";
import { detectStack, defaultDetectors } from "../src/detect/registry.ts";
import { evaluateAuthz } from "../src/authz/gate.ts";
import { AuditLog } from "../src/audit/log.ts";
import { parityModule } from "../src/modules/parity/index.ts";
import type { ScanContext } from "../src/model/module.ts";
import type { ParityResult } from "../src/model/parity.ts";
import type { Finding } from "../src/model/finding.ts";

const FIXTURE = fileURLToPath(new URL("./fixtures/vuln-prisma-docker", import.meta.url));

async function runFixture(): Promise<{ findings: readonly Finding[]; artifact: ParityResult }> {
  const fs = createFsContext(FIXTURE);
  const stack = await detectStack(FIXTURE, defaultDetectors());
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "warden-it-")), "run.log"));
  const ctx: ScanContext = { projectRoot: FIXTURE, authz: evaluateAuthz(FIXTURE), audit, stack, fs };
  const res = await parityModule.run(ctx);
  return { findings: res.findings, artifact: res.artifact as ParityResult };
}

describe("detection engine (fixture)", () => {
  it("Prisma + Docker + Cloudflare tespit eder", async () => {
    const stack = await detectStack(FIXTURE, defaultDetectors());
    expect(stack.orm).toContain("prisma");
    expect(stack.containerized).toBe(true);
    expect(stack.cloud).toContain("cloudflare");
    expect(stack.languages).toContain("typescript");
  });
});

describe("Modül A entegrasyon (fixture) — bilinen açıkları yakalar", () => {
  it("A2 yıkıcı migration (P0)", async () => {
    const { findings } = await runFixture();
    const f = findings.find((x) => x.id.startsWith("A2-destructive-migration"));
    expect(f?.severity).toBe("P0");
    expect(f?.title).toMatch(/DROP/);
  });

  it("A2 db push (P1)", async () => {
    const { findings } = await runFixture();
    expect(findings.find((x) => x.id === "A2-db-push")?.severity).toBe("P1");
  });

  it("A4 volume mismatch (P1)", async () => {
    const { findings } = await runFixture();
    const f = findings.find((x) => x.id.startsWith("A4-volume-mismatch"));
    expect(f?.severity).toBe("P1");
  });

  it("A4 eksik env DATABASE_URL (P1)", async () => {
    const { findings } = await runFixture();
    const f = findings.find((x) => x.id === "A4-missing-env");
    expect(f?.severity).toBe("P1");
    expect(f?.title).toMatch(/DATABASE_URL/);
  });

  it("A5 backup var restore yok (P2)", async () => {
    const { findings } = await runFixture();
    expect(findings.find((x) => x.id === "A5-backup-no-restore")?.severity).toBe("P2");
  });

  it("Parity artifact: katmanlar + Overall Parity Score üretir", async () => {
    const { artifact } = await runFixture();
    expect(artifact.layers.length).toBe(6);
    expect(artifact.overall).not.toBeNull();
    // Her bulgunun kanıtı olmalı (false-positive disiplini, iş emri §8).
    const { findings } = await runFixture();
    for (const f of findings) expect(f.evidence.length).toBeGreaterThan(0);
  });
});
