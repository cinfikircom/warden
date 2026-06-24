import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import { GuardedHttpClient } from "./client.ts";
import type { FetchLike } from "./client.ts";
import { EXPOSED_PATHS, analyzeExposedFile } from "./exposed.ts";
import { analyzeSecurityHeaders, analyzeCookies } from "./headers.ts";
import { collectTls, analyzeTls } from "./tls.ts";
import { ADMIN_PATHS, analyzeAdminExposure, analyzeRateLimit } from "./active-checks.ts";
import { scanPorts } from "./ports.ts";

const LOOPBACK = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$/i;

/** Allow-list host'undan taranacak temel URL üretir. Tam URL verilmişse onu kullanır. */
export function targetToBaseUrl(target: string): string {
  if (/^https?:\/\//i.test(target)) return target.replace(/\/+$/, "");
  const host = target.trim();
  const scheme = LOOPBACK.test(host) ? "http" : "https";
  return `${scheme}://${host}`;
}

/**
 * Modül C — Dinamik / DAST & Pentest (AKTİF, YETKİ KAPILI).
 * ⚠ active:true → orkestratör YALNIZCA mode==="active" iken çağırır. Ek olarak run() içinde
 * modu ve allow-list'i YENİDEN doğrular. Tüm istekler GuardedHttpClient üzerinden:
 * rate-limited, GET-only, non-destructive, audit-loglu, allow-list dışına çıkmaz.
 */
export function makeDastModule(fetchImpl?: FetchLike): WardenModule {
  return {
    id: "C",
    title: "Dinamik / DAST & Pentest (aktif)",
    active: true,
    applicable(ctx: ScanContext) {
      return ctx.authz.mode === "active" && ctx.authz.authorizedTargets.length > 0;
    },
    async run(ctx: ScanContext): Promise<ModuleRunResult> {
      // Belt-and-suspenders: aktif değilse HİÇBİR ŞEY yapma.
      if (ctx.authz.mode !== "active") {
        ctx.audit.warn("Modül C çağrıldı ama mod aktif değil → hiçbir aktif istek atılmadı.");
        return { findings: [] };
      }

      const now = new Date();
      const client = new GuardedHttpClient(ctx.authz, ctx.audit, fetchImpl);
      const findings: Finding[] = [];

      ctx.audit.info(`Modül C (DAST) başlıyor. Yetkili hedefler: ${ctx.authz.authorizedTargets.join(", ")}`);

      for (const target of ctx.authz.authorizedTargets) {
        const base = targetToBaseUrl(target);
        const host = (() => {
          try {
            return new URL(base).hostname;
          } catch {
            return null;
          }
        })();
        if (!host) continue;

        // C1 — açıkta kalan dosyalar
        for (const def of EXPOSED_PATHS) {
          const res = await client.get(base + def.path);
          if (!res) continue;
          const f = analyzeExposedFile(def, res);
          if (f) findings.push(f);
        }

        // C2/C6 — header + cookie (kök istek)
        const root = await client.get(base + "/");
        if (root) {
          findings.push(...analyzeSecurityHeaders(root));
          findings.push(...analyzeCookies(root));
        }

        // C2 — TLS (yalnızca https)
        if (base.startsWith("https://")) {
          const tls = await collectTls(host, ctx.audit);
          findings.push(...analyzeTls(tls, now));
        }

        // C3 — korumasız admin paneli
        for (const p of ADMIN_PATHS) {
          const res = await client.get(base + p);
          if (!res) continue;
          const f = analyzeAdminExposure(res);
          if (f) findings.push(f);
        }

        // C4 — düşük hacimli rate-limit eşik testi (kök yola 5 GET)
        const statuses: number[] = [];
        for (let i = 0; i < 5; i++) {
          const res = await client.get(base + "/");
          if (!res) break;
          statuses.push(res.status);
        }
        const rl = analyzeRateLimit(base + "/", statuses);
        if (rl) findings.push(rl);

        // C5 — port envanteri: YALNIZCA allow_port_scan açıkken (en hassas, ikincil onay).
        if (ctx.authz.limits.allowPortScan) {
          ctx.audit.info(`C5 port taraması açık (allow_port_scan) → ${host}`);
          findings.push(...(await scanPorts(host, ctx.audit)));
        } else {
          ctx.audit.info("C5 port taraması atlandı: allow_port_scan kapalı.");
        }
      }

      ctx.audit.info(`Modül C bitti: ${findings.length} bulgu, toplam ${client.totalRequests} aktif istek.`);
      return { findings };
    },
  };
}

/** Yerleşik DAST modülü (canlı fetch). */
export const dastModule: WardenModule = makeDastModule();
