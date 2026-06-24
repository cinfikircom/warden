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

function fix(name: string): string {
  return fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
}
async function ctxFor(dir: string): Promise<ScanContext> {
  const fs = createFsContext(dir);
  const stack = await detectStack(dir, defaultDetectors());
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "warden-ad-")), "run.log"));
  return { projectRoot: dir, authz: evaluateAuthz(dir), audit, stack, fs };
}
const ids = (fs: readonly { id: string }[]): string[] => fs.map((f) => f.id.split(":")[0] ?? "");

describe("Laravel adaptörü", () => {
  it("tespit: php + laravel", async () => {
    const s = await detectStack(fix("vuln-laravel"), defaultDetectors());
    expect(s.languages).toContain("php");
    expect(s.frameworks).toContain("laravel");
  });

  it("A2: Laravel yıkıcı migration (dropColumn/dropIfExists) → P0", async () => {
    const res = await parityModule.run(await ctxFor(fix("vuln-laravel")));
    expect(res.findings.find((f) => f.id.startsWith("A2-laravel-destructive"))?.severity).toBe("P0");
  });

  it("B: PHP/Laravel kuralları (md5, shell, raw SQL, withoutGlobalScopes, mass-assign)", async () => {
    const res = await sastModule.run(await ctxFor(fix("vuln-laravel")));
    const got = ids(res.findings);
    expect(got).toContain("B3-php-weak-hash");
    expect(got).toContain("B6-php-command");
    expect(got).toContain("B6-laravel-raw-sql");
    expect(got).toContain("B5-laravel-tenant-escape");
    expect(got).toContain("B5-laravel-mass-assign");
  });

  it("D: PCI kart verisi (CVV P0) + composer deps (Sentry yok → D2)", async () => {
    const res = await complianceModule.run(await ctxFor(fix("vuln-laravel")));
    expect(res.findings.find((f) => f.id.startsWith("D7-cvv-storage"))?.severity).toBe("P0");
    expect(ids(res.findings)).toContain("D2-no-error-tracking");
  });
});

describe(".NET (ASP.NET) adaptörü", () => {
  it("tespit: csharp + aspnet + ef-core", async () => {
    const s = await detectStack(fix("vuln-dotnet"), defaultDetectors());
    expect(s.languages).toContain("csharp");
    expect(s.frameworks).toContain("aspnet");
    expect(s.orm).toContain("ef-core");
  });

  it("A2: EF Core yıkıcı migration (DropColumn/DropTable) → P0", async () => {
    const res = await parityModule.run(await ctxFor(fix("vuln-dotnet")));
    expect(res.findings.find((f) => f.id.startsWith("A2-efcore-destructive"))?.severity).toBe("P0");
  });

  it("B: C#/.NET kuralları (MD5, FromSqlRaw, Process.Start, DeveloperExceptionPage)", async () => {
    const res = await sastModule.run(await ctxFor(fix("vuln-dotnet")));
    const got = ids(res.findings);
    expect(got).toContain("B3-dotnet-weak-hash");
    expect(got).toContain("B6-dotnet-sql");
    expect(got).toContain("B6-dotnet-process");
    expect(got).toContain("B9-dotnet-dev-exception");
  });
});
