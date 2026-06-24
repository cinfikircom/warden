import { describe, it, expect } from "vitest";
import { createServer } from "node:net";
import { analyzePorts, checkPort, SENSITIVE_PORTS } from "../src/modules/dast/ports.ts";

describe("C5 port envanteri", () => {
  it("Redis/Mongo gibi açık port → P0", () => {
    const findings = analyzePorts("127.0.0.1", [{ port: 6379, service: "Redis", severity: "P0" }]);
    expect(findings[0]?.severity).toBe("P0");
    expect(findings[0]?.check).toBe("C5");
    expect(findings[0]?.title).toMatch(/6379/);
  });

  it("açık port yoksa bulgu yok", () => {
    expect(analyzePorts("127.0.0.1", [])).toHaveLength(0);
  });

  it("hassas port listesi DB/cache portlarını içerir", () => {
    const ports = SENSITIVE_PORTS.map((p) => p.port);
    expect(ports).toContain(5432);
    expect(ports).toContain(6379);
    expect(ports).toContain(27017);
  });

  it("checkPort: açık portu tespit eder, kapalıya false döner", async () => {
    const srv = createServer();
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const addr = srv.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    expect(await checkPort("127.0.0.1", port, 1000)).toBe(true);
    srv.close();
    // kapalı (rastgele yüksek) port
    expect(await checkPort("127.0.0.1", 1, 500)).toBe(false);
  });
});
