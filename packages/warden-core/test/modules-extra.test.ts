import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { createFsContext } from "../src/detect/fs.ts";
import { collectK8sDocs, analyzeK8s } from "../src/modules/k8s/index.ts";
import { collectIacFiles, analyzeCloud } from "../src/modules/cloud/index.ts";
import { collectAiData, analyzeAi } from "../src/modules/ai/index.ts";

const fix = (n: string): string => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));
const ids = (fs: readonly { id: string }[]): string[] => fs.map((f) => f.id.split(":")[0] ?? "");

describe("Modül K8S", () => {
  const findings = analyzeK8s(collectK8sDocs(createFsContext(fix("vuln-k8s"))));
  const got = ids(findings);
  it("privileged container → P0", () => {
    expect(findings.find((f) => f.id.startsWith("K8S-privileged"))?.severity).toBe("P0");
  });
  it("düz secret env → P1", () => { expect(got).toContain("K8S-plain-secret"); });
  it("latest image → bulgu", () => { expect(got).toContain("K8S-image-tag"); });
  it("root çalışabilir → bulgu", () => { expect(got).toContain("K8S-root"); });
});

describe("Modül CLOUD (Terraform)", () => {
  const findings = analyzeCloud(collectIacFiles(createFsContext(fix("vuln-iac"))));
  const got = ids(findings);
  it("public S3 → P0", () => {
    expect(findings.find((f) => f.id.startsWith("CLOUD-AWS-s3-public"))?.severity).toBe("P0");
  });
  it("açık security group (0.0.0.0/0)", () => { expect(got).toContain("CLOUD-AWS-sg-open"); });
  it("public RDS", () => { expect(got).toContain("CLOUD-AWS-rds-public"); });
  it("IAM wildcard", () => { expect(got).toContain("CLOUD-AWS-iam-wildcard"); });
});

describe("Modül AI", () => {
  const data = collectAiData(createFsContext(fix("vuln-ai")));
  const findings = analyzeAi(data);
  const got = ids(findings);
  it("AI SDK tespit edilir", () => { expect(data.usesAi).toBe(true); });
  it("gömülü OpenAI key → P0 (maskeli)", () => {
    const f = findings.find((x) => x.id.startsWith("AI-3-key"));
    expect(f?.severity).toBe("P0");
    expect(f?.evidence[0]?.excerpt).not.toContain("abcdefghij1234567890ABCD");
  });
  it("prompt injection yüzeyi → bulgu", () => { expect(got).toContain("AI-1-prompt-injection"); });
  it("AI SDK yoksa hiç bulgu yok", () => {
    expect(analyzeAi({ usesAi: false, files: [{ path: "x.ts", content: 'const p = "a" + req.body.q' }] })).toHaveLength(0);
  });
});
