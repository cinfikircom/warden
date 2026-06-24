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
import { sastModule } from "../src/modules/sast/index.ts";
import { complianceModule } from "../src/modules/compliance/index.ts";
import type { ScanContext } from "../src/model/module.ts";

const FIXTURE = fileURLToPath(new URL("./fixtures/vuln-django", import.meta.url));

async function ctxFor(): Promise<ScanContext> {
  const fs = createFsContext(FIXTURE);
  const stack = await detectStack(FIXTURE, defaultDetectors());
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "warden-dj-")), "run.log"));
  return { projectRoot: FIXTURE, authz: evaluateAuthz(FIXTURE), audit, stack, fs };
}

describe("İkinci stack: Django — A+B+D çalışır", () => {
  it("stack tespiti: python + django", async () => {
    const stack = await detectStack(FIXTURE, defaultDetectors());
    expect(stack.languages).toContain("python");
    expect(stack.frameworks).toContain("django");
  });

  it("Modül A: Django yıkıcı migration (RemoveField/DeleteModel) → P0", async () => {
    const ctx = await ctxFor();
    const res = await parityModule.run(ctx);
    const f = res.findings.find((x) => x.id.startsWith("A2-django-destructive"));
    expect(f?.severity).toBe("P0");
    expect(f?.title).toMatch(/RemoveField|DeleteModel/);
  });

  it("Modül B: Python/Django kuralları (md5, shell=True, DEBUG, SECRET_KEY, ALLOWED_HOSTS)", async () => {
    const ctx = await ctxFor();
    const res = await sastModule.run(ctx);
    const ids = res.findings.map((f) => f.id.split(":")[0]);
    expect(ids).toContain("B3-py-weak-hash");
    expect(ids).toContain("B6-py-shell-true");
    expect(ids).toContain("B9-django-debug");
    expect(ids).toContain("B1-django-secret-key");
    expect(ids).toContain("B7-django-allowed-hosts");
  });

  it("Modül D: CVV(P0)/PAN(P1) + kişisel veri + Python deps (Sentry yok → D2)", async () => {
    const ctx = await ctxFor();
    const res = await complianceModule.run(ctx);
    const ids = res.findings.map((f) => f.id.split(":")[0]);
    expect(res.findings.find((f) => f.id.startsWith("D7-cvv-storage"))?.severity).toBe("P0");
    expect(res.findings.find((f) => f.id.startsWith("D7-pan-storage"))?.severity).toBe("P1");
    expect(ids).toContain("D2-no-error-tracking");
    expect(ids).toContain("D4-no-soft-delete"); // kişisel veri + soft-delete yok
  });
});
