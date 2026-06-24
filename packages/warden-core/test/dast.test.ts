import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GuardedHttpClient } from "../src/modules/dast/client.ts";
import type { FetchLike } from "../src/modules/dast/client.ts";
import { makeDastModule, targetToBaseUrl } from "../src/modules/dast/index.ts";
import { analyzeExposedFile, EXPOSED_PATHS } from "../src/modules/dast/exposed.ts";
import { analyzeSecurityHeaders, analyzeCookies } from "../src/modules/dast/headers.ts";
import { analyzeTls } from "../src/modules/dast/tls.ts";
import { analyzeAdminExposure, analyzeRateLimit } from "../src/modules/dast/active-checks.ts";
import { DEFAULT_LIMITS } from "../src/authz/gate.ts";
import type { AuthzResult } from "../src/authz/gate.ts";
import { AuditLog } from "../src/audit/log.ts";
import { createFsContext } from "../src/detect/fs.ts";
import type { ScanContext } from "../src/model/module.ts";
import { EMPTY_STACK } from "../src/model/module.ts";
import type { ProbeResponse } from "../src/modules/dast/client.ts";

function tmpAudit(): AuditLog {
  return new AuditLog(join(mkdtempSync(join(tmpdir(), "warden-dast-")), "run.log"));
}
function authz(mode: "active" | "passive", targets: string[]): AuthzResult {
  return {
    mode, authorizedTargets: targets, authorizedBy: "t", date: "2026-06-24",
    limits: { ...DEFAULT_LIMITS, maxRequestsPerSecond: 1000 }, reasons: [], fileFound: true,
  };
}
function resp(url: string, status: number, headers: Record<string, string> = {}, body = "", cookies: string[] = []): Response {
  const h = new Headers(headers);
  for (const c of cookies) h.append("set-cookie", c);
  return new Response(body, { status, headers: h });
}
function probe(url: string, status: number, body = "", ct = "text/plain", cookies: string[] = []): ProbeResponse {
  return { url, status, headers: { "content-type": ct }, setCookies: cookies, body };
}

describe("GÜVENLİK: GuardedHttpClient yetki kapısı", () => {
  it("mod PASİF iken HİÇ fetch çağrılmaz", async () => {
    let calls = 0;
    const fake: FetchLike = async (u) => { calls++; return resp(u, 200); };
    const c = new GuardedHttpClient(authz("passive", ["localhost"]), tmpAudit(), fake);
    const r = await c.get("http://localhost/");
    expect(r).toBeNull();
    expect(calls).toBe(0);
  });

  it("allow-list DIŞI host'a HİÇ fetch çağrılmaz", async () => {
    let calls = 0;
    const fake: FetchLike = async (u) => { calls++; return resp(u, 200); };
    const c = new GuardedHttpClient(authz("active", ["staging.ornek.com"]), tmpAudit(), fake);
    const r = await c.get("http://evil.com/");
    expect(r).toBeNull();
    expect(calls).toBe(0);
  });

  it("allow-list İÇİ host'a istek geçer", async () => {
    let calls = 0;
    const fake: FetchLike = async (u) => { calls++; return resp(u, 200, {}, "ok"); };
    const c = new GuardedHttpClient(authz("active", ["staging.ornek.com"]), tmpAudit(), fake);
    const r = await c.get("https://staging.ornek.com/");
    expect(r?.status).toBe(200);
    expect(calls).toBe(1);
  });

  it("toplam istek tavanı aşılınca durur", async () => {
    let calls = 0;
    const fake: FetchLike = async (u) => { calls++; return resp(u, 200); };
    const a = authz("active", ["localhost"]);
    const capped: AuthzResult = { ...a, limits: { ...a.limits, maxTotalRequests: 2 } };
    const c = new GuardedHttpClient(capped, tmpAudit(), fake);
    await c.get("http://localhost/a");
    await c.get("http://localhost/b");
    const third = await c.get("http://localhost/c");
    expect(third).toBeNull();
    expect(calls).toBe(2);
  });

  it("redirect:manual + GET (non-destructive) ile çağrılır", async () => {
    let init: RequestInit | undefined;
    const fake: FetchLike = async (u, i) => { init = i; return resp(u, 200); };
    const c = new GuardedHttpClient(authz("active", ["localhost"]), tmpAudit(), fake);
    await c.get("http://localhost/");
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("manual");
  });
});

describe("GÜVENLİK: Modül C yetki kapısı olmadan istek atmaz", () => {
  it("authz PASİF → 0 fetch, 0 bulgu", async () => {
    let calls = 0;
    const fake: FetchLike = async (u) => { calls++; return resp(u, 200); };
    const dir = mkdtempSync(join(tmpdir(), "warden-c-"));
    const ctx: ScanContext = {
      projectRoot: dir, authz: authz("passive", ["localhost"]), audit: tmpAudit(),
      stack: EMPTY_STACK, fs: createFsContext(dir),
    };
    const res = await makeDastModule(fake).run(ctx);
    expect(res.findings).toHaveLength(0);
    expect(calls).toBe(0);
  });

  it("authz AKTİF → yalnızca allow-list host'a istek; .env (P0) yakalanır", async () => {
    const seen: string[] = [];
    const fake: FetchLike = async (u) => {
      seen.push(u);
      if (u.endsWith("/.env")) return resp(u, 200, { "content-type": "text/plain" }, "SECRET_KEY=abc123\nDB_URL=x");
      if (u.endsWith("/")) return resp(u, 200, {}, "<html>app</html>", ["sid=abc; Path=/"]);
      return resp(u, 404);
    };
    const dir = mkdtempSync(join(tmpdir(), "warden-c2-"));
    const ctx: ScanContext = {
      projectRoot: dir, authz: authz("active", ["localhost"]), audit: tmpAudit(),
      stack: EMPTY_STACK, fs: createFsContext(dir),
    };
    const res = await makeDastModule(fake).run(ctx);
    expect(res.findings.find((f) => f.id === "C1-exposed:/.env")?.severity).toBe("P0");
    // tüm istekler localhost'a gitmiş olmalı
    expect(seen.every((u) => new URL(u).hostname === "localhost")).toBe(true);
  });
});

describe("DAST analizörleri (saf)", () => {
  it("C1: 200 + geçerli .env gövdesi → bulgu; SPA html → null", () => {
    const env = EXPOSED_PATHS.find((p) => p.path === "/.env")!;
    expect(analyzeExposedFile(env, probe("http://h/.env", 200, "KEY=val", "text/plain"))).not.toBeNull();
    expect(analyzeExposedFile(env, probe("http://h/.env", 200, "<!doctype html><html>", "text/html"))).toBeNull();
    expect(analyzeExposedFile(env, probe("http://h/.env", 404, "KEY=val"))).toBeNull();
  });

  it("C2: eksik HSTS/CSP header → bulgu", () => {
    const fs = analyzeSecurityHeaders(probe("http://h/", 200, "", "text/html"));
    const ids = fs.map((f) => f.id);
    expect(ids).toContain("C2-header:strict-transport-security");
    expect(ids).toContain("C2-header:content-security-policy");
  });

  it("C6: oturum çerezi eksik bayrak → P1", () => {
    const fs = analyzeCookies(probe("http://h/", 200, "", "text/html", ["session=x; Path=/"]));
    expect(fs[0]?.severity).toBe("P1");
    expect(fs[0]?.title).toMatch(/HttpOnly/);
  });

  it("C2 TLS: süresi dolmuş → P0, zayıf protokol → P1", () => {
    const now = new Date("2026-06-24T00:00:00Z");
    const expired = analyzeTls({ host: "h", protocol: "TLSv1.3", validTo: new Date("2026-06-01"), authorized: true }, now);
    expect(expired.find((f) => f.id.startsWith("C2-cert-expired"))?.severity).toBe("P0");
    const weak = analyzeTls({ host: "h", protocol: "TLSv1", validTo: new Date("2027-06-24"), authorized: true }, now);
    expect(weak.find((f) => f.id.startsWith("C2-weak-tls"))?.severity).toBe("P1");
  });

  it("C3: login formu olmayan admin 200 → bulgu; login varsa null", () => {
    expect(analyzeAdminExposure(probe("http://h/admin", 200, "Admin Dashboard console", "text/html"))).not.toBeNull();
    expect(analyzeAdminExposure(probe("http://h/admin", 200, "Please login with your password", "text/html"))).toBeNull();
  });

  it("C4: 5+ istek 429 almazsa rate-limit bulgusu", () => {
    expect(analyzeRateLimit("http://h/", [200, 200, 200, 200, 200])).not.toBeNull();
    expect(analyzeRateLimit("http://h/", [200, 429, 200])).toBeNull();
  });

  it("targetToBaseUrl: loopback→http, domain→https, tam URL korunur", () => {
    expect(targetToBaseUrl("localhost")).toBe("http://localhost");
    expect(targetToBaseUrl("staging.ornek.com")).toBe("https://staging.ornek.com");
    expect(targetToBaseUrl("https://x.com:8443/")).toBe("https://x.com:8443");
  });
});
