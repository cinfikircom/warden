import { describe, it, expect } from "vitest";
import { nucleiJsonlToFindings, enabledTools, PASSIVE_TOOLS, ACTIVE_TOOLS } from "../src/adapters/native-tools.ts";
import { inferModule } from "../src/adapters/sarif.ts";

describe("inferModule — araç adından boyut", () => {
  it("IaC araçları → CLOUD", () => {
    expect(inferModule("checkov")).toBe("CLOUD");
    expect(inferModule("tfsec")).toBe("CLOUD");
  });
  it("K8s araçları → K8S", () => {
    expect(inferModule("kubescape")).toBe("K8S");
  });
  it("DAST araçları → C", () => {
    expect(inferModule("nuclei")).toBe("C");
    expect(inferModule("ZAP")).toBe("C");
  });
  it("SAST/secret/SCA → B (varsayılan)", () => {
    expect(inferModule("semgrep")).toBe("B");
    expect(inferModule("gitleaks")).toBe("B");
    expect(inferModule("trivy")).toBe("B");
    expect(inferModule("bilinmeyen")).toBe("B");
  });
});

describe("enabledTools — WARDEN_TOOLS ayrıştırma", () => {
  it("boş → boş küme", () => {
    expect(enabledTools({})).toEqual(new Set());
  });
  it("'all' → 'all'", () => {
    expect(enabledTools({ WARDEN_TOOLS: "all" })).toBe("all");
  });
  it("virgüllü liste → küme", () => {
    const s = enabledTools({ WARDEN_TOOLS: "opengrep, gitleaks ,trivy" });
    expect(s).toEqual(new Set(["opengrep", "gitleaks", "trivy"]));
  });
});

describe("nucleiJsonlToFindings", () => {
  const jsonl = [
    JSON.stringify({ "template-id": "exposed-git", info: { name: "Exposed .git", severity: "high" }, "matched-at": "https://h/.git/config" }),
    "not json",
    JSON.stringify({ "template-id": "info-panel", info: { name: "Login panel", severity: "info" }, host: "https://h" }),
  ].join("\n");

  const findings = nucleiJsonlToFindings(jsonl);
  it("JSONL satırlarını Finding'e çevirir, module C", () => {
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.module === "C")).toBe(true);
  });
  it("severity eşler (high→P1, info→P3)", () => {
    expect(findings.find((f) => f.check === "exposed-git")?.severity).toBe("P1");
    expect(findings.find((f) => f.check === "info-panel")?.severity).toBe("P3");
  });
});

describe("araç kayıtları tutarlı", () => {
  it("pasif araçlar active değil; aktif araçlar active", () => {
    expect(PASSIVE_TOOLS.every((t) => !t.active)).toBe(true);
    expect(ACTIVE_TOOLS.every((t) => t.active)).toBe(true);
    expect(ACTIVE_TOOLS.map((t) => t.id)).toContain("nuclei");
  });
  // Gerçek-CLI sözleşmesi (canlı entegrasyonla doğrulandı) — regresyon kilidi.
  it("gitleaks ≥8.19 CLI: `dir` + stdout `-` (eski `detect`/`/dev/stdout` DEĞİL)", () => {
    const gl = PASSIVE_TOOLS.find((t) => t.id === "gitleaks")!;
    const args = gl.args({ root: "." });
    expect(args[0]).toBe("dir");
    expect(args).not.toContain("detect");
    expect(args).not.toContain("/dev/stdout");
    expect(args).toContain("-"); // --report-path -
  });
  it("trivy fs SARIF + misconfig/vuln/secret tarayıcıları", () => {
    const tv = PASSIVE_TOOLS.find((t) => t.id === "trivy")!;
    const args = tv.args({ root: "." });
    expect(args).toContain("sarif");
    expect(args.join(" ")).toContain("vuln,secret,misconfig");
  });
  it("checkov dosya-tabanlı runOverride kullanır (stdout'a akıtmaz, read-only)", () => {
    const ck = PASSIVE_TOOLS.find((t) => t.id === "checkov")!;
    expect(typeof ck.runOverride).toBe("function");
    expect(ck.args({ root: "." })).toEqual([]); // args kullanılmaz
  });
});
