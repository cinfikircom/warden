import { describe, it, expect } from "vitest";
import { scanDiffForSecrets, historyHitsToFindings } from "../src/modules/sast/git-history.ts";

const SAMPLE = `commit a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
Author: Dev <dev@example.com>
Date:   Mon Jan 1 00:00:00 2026 +0000

    add config

diff --git a/config.js b/config.js
index 000..111 100644
--- a/config.js
+++ b/config.js
@@ -0,0 +1,2 @@
+const awsKey = "AKIAZ7QH4NBGX2LPVWRT";
+const safe = "just a normal line";

commit b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1
Author: Dev <dev@example.com>
Date:   Tue Jan 2 00:00:00 2026 +0000

    add stripe

diff --git a/pay.js b/pay.js
+const stripe = "sk_live_51QhTz9Km4RpWnGb7YxLdV3cFtJyU";
-const removed = "AKIAZ7QH4NBGX2LPVWRT";
`;

describe("git geçmişi secret ayrıştırıcı (saf)", () => {
  const hits = scanDiffForSecrets(SAMPLE);

  it("eklenen satırlardaki AWS + Stripe anahtarlarını yakalar", () => {
    const ids = hits.map((h) => h.patternId);
    expect(ids).toContain("aws-key");
    expect(ids).toContain("provider-token");
  });
  it("silinen (-) satırları işaretlemez", () => {
    // Yalnızca bir aws-key (eklenen); silinen kopya sayılmaz.
    expect(hits.filter((h) => h.patternId === "aws-key")).toHaveLength(1);
  });
  it("doğru commit'e bağlar", () => {
    const aws = hits.find((h) => h.patternId === "aws-key");
    expect(aws?.commit).toBe("a1b2c3d4e5f6");
  });
  it("normal satırları işaretlemez", () => {
    expect(hits.every((h) => h.patternId !== undefined)).toBe(true);
    expect(hits.length).toBe(2);
  });
  it("bulgular P0 ve maskeli kanıt taşır", () => {
    const findings = historyHitsToFindings(hits);
    expect(findings.every((f) => f.severity === "P0")).toBe(true);
    const aws = findings.find((f) => f.id.includes("aws-key"));
    expect(aws?.evidence[0]?.excerpt ?? "").not.toContain("AKIAZ7QH4NBGX2LPVWRT");
    expect(aws?.check).toBe("B1");
  });
  it("belirgin yer-tutucu/örnek anahtarları eler (AWS EXAMPLE, 1234567890)", () => {
    const placeholder = `commit c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2\n+const k = "AKIAIOSFODNN7EXAMPLE";\n+const j = "AKIA1234567890ABCDEF";`;
    expect(scanDiffForSecrets(placeholder)).toHaveLength(0);
  });
  it("fingerprint kararlı (aynı girdi → aynı fingerprint)", () => {
    const a = historyHitsToFindings(scanDiffForSecrets(SAMPLE));
    const b = historyHitsToFindings(scanDiffForSecrets(SAMPLE));
    expect(a.map((f) => f.fingerprint)).toEqual(b.map((f) => f.fingerprint));
  });
});
