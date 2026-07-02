import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { createFsContext } from "../src/detect/fs.ts";
import { buildImportGraph, packageOfFinding, enrichReachability } from "../src/risk/reachability.ts";
import { makeFinding } from "../src/util/finding.ts";
import type { Finding } from "../src/model/finding.ts";

const SAFE = fileURLToPath(new URL("./fixtures/safe-app", import.meta.url));

function dep(name: string, kev = false): Finding {
  return makeFinding({
    id: `B2-vuln:${name}`,
    title: `Zafiyetli bağımlılık: ${name}`,
    severity: "P1",
    module: "B",
    check: "B2",
    category: "Vulnerable Component",
    confidence: "high",
    evidence: [{ type: "command", source: "audit", excerpt: name }],
    impact: "x",
    recommendation: "y",
    effort: "S",
    autoFixable: true,
    ...(kev ? {} : {}),
  });
}

describe("buildImportGraph", () => {
  const graph = buildImportGraph(createFsContext(SAFE));
  it("JS/TS import'larından paket adı çıkarır (yerel modüller hariç)", () => {
    expect(graph.has("axios")).toBe(true);
    expect(graph.has("node:fs")).toBe(true);
    // yerel './config' vb. dahil edilmez
    expect([...graph].some((p) => p.startsWith("."))).toBe(false);
  });
});

describe("packageOfFinding", () => {
  it("B2-vuln:<ad> ve B2-osv:<ad>:<id>'den paket adı", () => {
    expect(packageOfFinding(dep("lodash"))).toBe("lodash");
    expect(packageOfFinding(dep("@babel/core"))).toBe("@babel/core");
    const osv = makeFinding({ ...dep("django"), id: "B2-osv:django:GHSA-x" } as any);
    expect(packageOfFinding(osv)).toBe("django");
  });
  it("bağımlılık olmayan bulgu → null", () => {
    const f = makeFinding({ ...dep("x"), id: "B6-eval:src/a.ts:1" } as any);
    expect(packageOfFinding(f)).toBeNull();
  });
});

describe("enrichReachability", () => {
  const imported = new Set(["axios", "lodash"]);
  it("import edilen paket → reachable=true, öncelik korunur", () => {
    const [f] = enrichReachability([dep("axios")], imported);
    expect(f?.reachable).toBe(true);
    expect(f?.references?.some((r) => r.includes("reachable"))).toBe(true);
  });
  it("import edilmeyen paket → reachable=false + exploitability low", () => {
    const [f] = enrichReachability([dep("left-pad")], imported);
    expect(f?.reachable).toBe(false);
    expect(f?.exploitability).toBe("low");
  });
  it("KEV bulgusu unreachable olsa bile exploitability düşürülmez", () => {
    const kevDep: Finding = { ...dep("left-pad"), kev: true };
    const [f] = enrichReachability([kevDep], imported);
    expect(f?.reachable).toBe(false);
    expect(f?.exploitability).not.toBe("low");
  });
  it("import grafı boşsa bulgular değişmez (bilinmiyor)", () => {
    const [f] = enrichReachability([dep("axios")], new Set());
    expect(f?.reachable).toBeUndefined();
  });
});
