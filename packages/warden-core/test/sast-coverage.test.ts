import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { createFsContext } from "../src/detect/fs.ts";
import { scanSource } from "../src/modules/sast/scanner.ts";
import { SAST_RULES } from "../src/modules/sast/rules.ts";

const COVERAGE = fileURLToPath(new URL("./fixtures/vuln-coverage", import.meta.url));
const SAFE = fileURLToPath(new URL("./fixtures/safe-app", import.meta.url));

const cov = scanSource(createFsContext(COVERAGE), SAST_RULES, { maxFiles: 100 });
const covIds = new Set(cov.map((f) => f.id.split(":")[0]));

describe("Kapsam-genişletme kuralları — yeni açık sınıflarını yakalar", () => {
  it("SSRF (Node axios + req girdisi)", () => {
    expect(covIds.has("B6-ssrf-node")).toBe(true);
  });
  it("SSRF (Python requests + request.args)", () => {
    expect(covIds.has("B6-ssrf-py")).toBe(true);
  });
  it("SSTI (Python render_template_string)", () => {
    expect(covIds.has("B6-ssti-py")).toBe(true);
  });
  it("Path traversal (Node readFileSync + req)", () => {
    expect(covIds.has("B6-path-traversal-node")).toBe(true);
  });
  it("Path traversal (Python open + request)", () => {
    expect(covIds.has("B6-path-traversal-py")).toBe(true);
  });
  it("Güvensiz deserialization (Node node-serialize) → P0", () => {
    const f = cov.find((x) => x.id.startsWith("B8-deserialize-node"));
    expect(f?.severity).toBe("P0");
  });
  it("Güvensiz deserialization (Python pickle) → P0", () => {
    expect(covIds.has("B8-pickle-py")).toBe(true);
  });
  it("Güvensiz deserialization (PHP unserialize)", () => {
    expect(covIds.has("B8-unserialize-php")).toBe(true);
  });
  it("JWT algorithm none → P0", () => {
    const f = cov.find((x) => x.id.startsWith("B4-jwt-alg-none"));
    expect(f?.severity).toBe("P0");
  });
  it("Open redirect", () => {
    expect(covIds.has("B7-open-redirect")).toBe(true);
  });
  it("Sağlayıcı anahtarı (Stripe sk_live_) → P0", () => {
    const f = cov.find((x) => x.id.startsWith("B1-provider-token"));
    expect(f?.severity).toBe("P0");
  });
  it("Yüksek-entropili secret", () => {
    expect(covIds.has("B1-high-entropy-secret")).toBe(true);
  });
  it("CSP unsafe-inline", () => {
    expect(covIds.has("FE-csp-unsafe")).toBe(true);
  });
  it("Üretimde source map açık", () => {
    expect(covIds.has("FE-source-map-prod")).toBe(true);
  });
  it("secret kanıtı maskeli (Stripe anahtarı tam sızmaz)", () => {
    const f = cov.find((x) => x.id.startsWith("B1-provider-token"));
    expect(f?.evidence[0]?.excerpt ?? "").not.toContain("sk_live_4eC39HqLyjWDarjtT1zdp7dcAbCdEf00");
  });
});

describe("FP muhafızı — güvenli kod bulgu üretmez", () => {
  const safe = scanSource(createFsContext(SAFE), SAST_RULES, { maxFiles: 100 });
  it("safe-app hiç bulgu üretmemeli (0)", () => {
    expect(safe.map((f) => f.id)).toEqual([]);
  });
});
