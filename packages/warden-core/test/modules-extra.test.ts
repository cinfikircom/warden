import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { createFsContext } from "../src/detect/fs.ts";
import { collectK8sDocs, analyzeK8s } from "../src/modules/k8s/index.ts";
import { collectIacFiles, analyzeCloud } from "../src/modules/cloud/index.ts";
import { collectAiData, analyzeAi } from "../src/modules/ai/index.ts";
import { collectPayData, analyzePay } from "../src/modules/pay/index.ts";
import { collectAccessData, analyzeAccess } from "../src/modules/access/index.ts";
import { collectAuthData, analyzeAuth } from "../src/modules/auth/index.ts";

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

describe("Modül PAY (ödeme güvenliği & güvenilirliği)", () => {
  const data = collectPayData(createFsContext(fix("vuln-pay")));
  const findings = analyzePay(data);
  const got = ids(findings);

  it("ödeme entegrasyonu (Stripe) tespit edilir", () => {
    expect(data.usesPayments).toBe(true);
    expect(data.providers).toContain("stripe");
  });
  it("ödeme secret anahtarı client bundle'da → P0 (maskeli)", () => {
    const f = findings.find((x) => x.id.startsWith("PAY-1-key"));
    expect(f?.severity).toBe("P0");
    // Değer maskelenmiş olmalı — ham secret asla serialize edilmez.
    expect(f?.evidence[0]?.excerpt).not.toContain("never_put_a_real_secret_here");
  });
  it("webhook imza doğrulaması yok → P0", () => {
    expect(findings.find((f) => f.id.startsWith("PAY-2"))?.severity).toBe("P0");
  });
  it("tutar istemciden (price tampering) → P0", () => {
    expect(findings.find((f) => f.id.startsWith("PAY-3"))?.severity).toBe("P0");
  });
  it("idempotency anahtarı yok → bulgu", () => { expect(got).toContain("PAY-4-no-idempotency"); });
  it("kart verisi loglanıyor → bulgu", () => { expect(got).toContain("PAY-5-card-data"); });
  it("mutabakat (reconciliation) yok → bulgu", () => { expect(got).toContain("PAY-7-no-reconciliation"); });
  it("webhook dedup yok → bulgu", () => { expect(got).toContain("PAY-8-webhook-no-dedup"); });
  it("kesinti/orphan ödeme koruması yok → bulgu", () => { expect(got).toContain("PAY-9-orphan-payment"); });
  it("başarısız/asenkron olay işlenmiyor → bulgu", () => { expect(got).toContain("PAY-10-webhook-no-failure"); });
  it("abonelik var ama dunning yok → bulgu", () => {
    expect(data.usesSubscriptions).toBe(true);
    expect(got).toContain("PAY-11-no-dunning");
  });
  it("3DS/SCA desteklemeyen legacy Charges API → bulgu", () => { expect(got).toContain("PAY-12-no-sca"); });
  it("iade tutarı istemciden (over-refund) → bulgu", () => { expect(got).toContain("PAY-13-refund-amount"); });
  it("ödeme entegrasyonu yoksa HİÇ bulgu yok (gürültü guard'ı)", () => {
    expect(analyzePay({
      usesPayments: false, providers: [], files: [], hasReconciliation: false, hasSweep: false,
      hasPendingState: false, usesSubscriptions: false, hasDunning: false,
    })).toHaveLength(0);
  });
});

describe("Modül ACCESS (erişim kontrolü & kiracı izolasyonu)", () => {
  const data = collectAccessData(createFsContext(fix("vuln-access")));
  const findings = analyzeAccess(data);
  const got = ids(findings);

  it("web/API + kiracı + auth yüzeyi tespit edilir", () => {
    expect(data.usesWeb).toBe(true);
    expect(data.usesTenancy).toBe(true);
    expect(data.usesAuth).toBe(true);
  });
  it("kiracı filtresi olmadan id sorgusu → ACC-1 P0", () => {
    expect(findings.find((f) => f.id.startsWith("ACC-1"))?.severity).toBe("P0");
  });
  it("auth'suz state-değiştiren endpoint → ACC-2", () => { expect(got).toContain("ACC-2-route-no-auth"); });
  it("mass assignment (req.body → model) → ACC-3", () => { expect(got).toContain("ACC-3-mass-assignment"); });
  it("tek-alan erişimi (req.body.text) ACC-3 tetiklemez (false-positive guard)", () => {
    const comments = findings.filter((f) => f.id.startsWith("ACC-3") && f.evidence[0]?.source.includes("public-routes"));
    expect(comments).toHaveLength(0);
  });
  it("rol kontrolsüz admin aksiyonu → ACC-4", () => { expect(got).toContain("ACC-4-privileged-no-role"); });
  it("web yüzeyi yoksa HİÇ bulgu yok (gürültü guard'ı)", () => {
    expect(analyzeAccess({ usesWeb: false, usesTenancy: false, usesAuth: false, files: [] })).toHaveLength(0);
  });
});

describe("Modül AUTH (kimlik & oturum sertleştirme)", () => {
  const data = collectAuthData(createFsContext(fix("vuln-auth")));
  const findings = analyzeAuth(data);
  const got = ids(findings);

  it("kimlik yüzeyi tespit edilir", () => {
    expect(data.usesAuth).toBe(true);
    expect(data.hasLogin).toBe(true);
    expect(data.hasPasswordHash).toBe(true);
  });
  it("MFA yok → AUTH-1", () => { expect(got).toContain("AUTH-1-no-mfa"); });
  it("tahmin edilebilir reset token → AUTH-2", () => { expect(got).toContain("AUTH-2-weak-reset-token"); });
  it("güvensiz oturum çerezi → AUTH-3", () => { expect(got).toContain("AUTH-3-insecure-cookie"); });
  it("süresiz JWT → AUTH-4", () => { expect(got).toContain("AUTH-4-jwt-no-expiry"); });
  it("brute-force koruması yok → AUTH-5", () => { expect(got).toContain("AUTH-5-no-brute-force"); });
  it("zayıf parola politikası → AUTH-6", () => { expect(got).toContain("AUTH-6-weak-password-policy"); });
  it("kimlik yüzeyi yoksa HİÇ bulgu yok (gürültü guard'ı)", () => {
    expect(analyzeAuth({ usesAuth: false, hasLogin: false, hasMfa: false, hasBruteForce: false, hasPasswordHash: false, hasPasswordStrength: false, files: [] })).toHaveLength(0);
  });
});
