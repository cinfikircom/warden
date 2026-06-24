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
import { analyzeCloud, collectIacFiles } from "../src/modules/cloud/index.ts";
import { buildCisChecklist, buildIsoChecklist } from "../src/risk/standards.ts";
import { makeFinding } from "../src/util/finding.ts";
import type { ScanContext } from "../src/model/module.ts";
import type { Finding } from "../src/model/finding.ts";

const fix = (n: string): string => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));
const ids = (fs: readonly { id: string }[]): string[] => fs.map((f) => f.id.split(":")[0] ?? "");
async function ctxFor(dir: string): Promise<ScanContext> {
  const fs = createFsContext(dir);
  const stack = await detectStack(dir, defaultDetectors());
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "warden-sg-")), "run.log"));
  return { projectRoot: dir, authz: evaluateAuthz(dir), audit, stack, fs };
}
function f(id: string, check: string, module: Finding["module"], category = "x"): Finding {
  return makeFinding({
    id, title: id, severity: "P1", module, check, category, confidence: "high",
    evidence: [{ type: "file", source: "x", location: "1" }], impact: "i", recommendation: "r", effort: "S", autoFixable: false,
  });
}

describe("Go adaptörü", () => {
  it("tespit: go", async () => {
    expect((await detectStack(fix("vuln-go"), defaultDetectors())).languages).toContain("go");
  });
  it("A2: Go yıkıcı up migration → P0 (down.sql sayılmaz)", async () => {
    const res = await parityModule.run(await ctxFor(fix("vuln-go")));
    expect(res.findings.find((x) => x.id.startsWith("A2-go-destructive"))?.severity).toBe("P0");
  });
  it("B: Go SAST (md5, Sprintf SQL, exec.Command)", async () => {
    const got = ids((await sastModule.run(await ctxFor(fix("vuln-go")))).findings);
    expect(got).toContain("B3-go-weak-hash");
    expect(got).toContain("B6-go-sql");
    expect(got).toContain("B6-go-command");
  });
});

describe("GCP cloud kuralları", () => {
  const got = ids(analyzeCloud(collectIacFiles(createFsContext(fix("vuln-gcp")))));
  it("public bucket (allUsers) → P0", () => {
    const fs = analyzeCloud(collectIacFiles(createFsContext(fix("vuln-gcp"))));
    expect(fs.find((x) => x.id.startsWith("CLOUD-GCP-bucket-public"))?.severity).toBe("P0");
  });
  it("Cloud SQL public + firewall açık", () => {
    expect(got).toContain("CLOUD-GCP-sql-public");
    expect(got).toContain("CLOUD-GCP-fw-open");
  });
});

describe("CIS & ISO 27001 eşleştirme", () => {
  const findings = [
    f("B3-weak-hash:a:1", "B3", "B"),     // ISO A.8.24
    f("B6-sql:a:1", "B6", "B"),           // ISO A.8.28
    f("K8S-privileged:a", "K8S-1", "K8S"), // CIS K8s + ISO A.5.15
    f("CLOUD-AWS-s3:a:1", "CLOUD-AWS", "CLOUD"), // CIS AWS + ISO A.8.9
  ];
  it("ISO: kripto (A.8.24) ve güvenli kodlama (A.8.28) ✖", () => {
    const iso = buildIsoChecklist(findings);
    expect(iso.items.find((i) => i.control === "A.8.24")?.status).toBe("fail");
    expect(iso.items.find((i) => i.control === "A.8.28")?.status).toBe("fail");
  });
  it("CIS: Kubernetes ve AWS ✖, Docker unknown", () => {
    const cis = buildCisChecklist(findings);
    expect(cis.items.find((i) => i.control === "CIS Kubernetes")?.status).toBe("fail");
    expect(cis.items.find((i) => i.control === "CIS AWS")?.status).toBe("fail");
    expect(cis.items.find((i) => i.control === "CIS Docker")?.status).toBe("unknown");
  });
  it("ilgili bulgu yoksa unknown (uyumlu iddia edilmez)", () => {
    const iso = buildIsoChecklist([]);
    expect(iso.items.every((i) => i.status === "unknown")).toBe(true);
  });
});
