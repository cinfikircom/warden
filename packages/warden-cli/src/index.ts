#!/usr/bin/env -S tsx
import { resolve } from "node:path";
import { runScan, WARDEN_VERSION, evaluateAuthz, SEVERITIES, severityRank } from "@warden/core";
import type { ScanResult, ParityResult, ComplianceResult, Severity } from "@warden/core";
import { checklistScore } from "@warden/core";
import { runInit } from "./init.ts";

/**
 * Warden CLI. Komutlar:
 *   warden scan    [--target <yol>]   Pasif (read-only) denetim. Varsayılan.
 *   warden pentest [--target <yol>]   Aktif denetim — yalnızca yetki kapısı açıkken.
 *   warden report  [--target <yol>]   Mevcut warden-report/ özetini gösterir.
 *   warden --help | --version
 *
 * Güvenlik (iş emri §2): pentest dahi yetki kapısı kapalıysa yalnızca pasif koşar.
 */

interface Parsed {
  command: string;
  target: string;
  help: boolean;
  version: boolean;
  failOn: Severity | null;
  interval: number;
  once: boolean;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function parseArgs(argv: readonly string[]): Parsed {
  const args = [...argv];
  let command = "scan";
  if (args[0] && !args[0].startsWith("-")) command = args.shift() as string;

  let target = process.cwd();
  let help = false;
  let version = false;
  let failOn: Severity | null = null;
  let interval = 1800;
  let once = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--target" || a === "-t") {
      const v = args[++i];
      if (v) target = resolve(v);
    } else if (a === "--fail-on") {
      const v = (args[++i] ?? "").toUpperCase();
      if ((SEVERITIES as readonly string[]).includes(v)) failOn = v as Severity;
    } else if (a === "--interval") {
      const v = Number.parseInt(args[++i] ?? "", 10);
      if (Number.isFinite(v) && v > 0) interval = v;
    } else if (a === "--once") once = true;
    else if (a === "--help" || a === "-h") help = true;
    else if (a === "--version" || a === "-v") version = true;
  }
  return { command, target, help, version, failOn, interval, once };
}

/** CI gate: eşik şiddetinde/üstünde bulgu varsa true (çıkış kodu 1). */
function shouldFail(res: ScanResult, failOn: Severity | null): boolean {
  if (!failOn) return false;
  const threshold = severityRank(failOn);
  return res.findings.some((f) => severityRank(f.severity) <= threshold);
}

const HELP = `Warden ${WARDEN_VERSION} — production-readiness & güvenlik denetimi (savunma amaçlı)

Kullanım:
  warden init    [--target <yol>]   Warden'i projeye Claude Code skill'i olarak kurar.
  warden scan    [--target <yol>]   Pasif (read-only) denetim. Hiç aktif istek atmaz. [varsayılan]
  warden pentest [--target <yol>]   Aktif/DAST denetim. YALNIZCA warden.authz.yml açıkken çalışır.
  warden report  [--target <yol>]   Son warden-report/ özetini yazdırır.
  warden monitor [--target <yol>]   Sürekli izleme: periyodik tarama + öncesi/sonrası delta.
  warden --help | --version

Seçenekler:
  --target <yol>       Denetlenecek proje kökü (varsayılan: çalışma dizini).
  --fail-on <şiddet>   CI gate: P0|P1|P2|P3 ve üstü bulgu varsa çıkış kodu 1 (SARIF + exit gate).
  --interval <sn>      monitor: taramalar arası saniye (varsayılan 1800).
  --once               monitor: tek tur koş ve çık.

⛔ Güvenlik: Varsayılan read-only. Aktif testler yetki kapısına (warden.authz.yml) bağlıdır;
   yalnızca allow-list host'lara, rate-limited, non-destructive. DoS/brute-force/exploit YOK.`;

function printBanner(): void {
  process.stdout.write(`\nWarden ${WARDEN_VERSION} — savunma amaçlı öz-denetim\n`);
  process.stdout.write("⛔ Varsayılan PASİF/read-only. Aktif test yalnızca yetki kapısı açıkken.\n\n");
}

function printSummary(res: ScanResult): void {
  const counts = { P0: 0, P1: 0, P2: 0, P3: 0 } as Record<string, number>;
  for (const f of res.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  process.stdout.write(`Mod: ${res.mode.toUpperCase()}\n`);
  for (const r of res.authz.reasons) process.stdout.write(`  • ${r}\n`);
  process.stdout.write(
    `\nBulgu: toplam ${res.findings.length} ` +
      `(P0:${counts.P0} P1:${counts.P1} P2:${counts.P2} P3:${counts.P3})\n`,
  );
  process.stdout.write(`Çalışan modül: ${res.ranModules.size === 0 ? "yok" : [...res.ranModules].join(", ")}\n`);
  const maxCvss = res.findings.reduce((m, f) => Math.max(m, f.cvss ?? 0), 0);
  if (maxCvss > 0) process.stdout.write(`En yüksek CVSS v4: ${maxCvss.toFixed(1)}\n`);

  const parity = res.artifacts.get("A") as ParityResult | undefined;
  if (parity) {
    process.stdout.write(`\nPARITY SCORE: ${parity.overall === null ? "n/d" : `${parity.overall.toFixed(1)} / 10`}\n`);
    for (const l of parity.layers) {
      const emoji = { ok: "✅", warn: "🟡", risk: "🔴", unknown: "⏳" }[l.status];
      process.stdout.write(`  ${emoji} ${l.code} ${l.name}: ${l.note}\n`);
    }
  }

  const comp = res.artifacts.get("D") as ComplianceResult | undefined;
  if (comp) {
    process.stdout.write(`\nUyum:\n`);
    for (const list of comp.checklists) {
      const s = checklistScore(list);
      process.stdout.write(`  ${list.name}: ${s.pct === null ? "n/d" : `%${s.pct}`} (✔${s.passed} ⚠${s.partial} ✖${s.failed})\n`);
    }
  }

  if (res.delta && !res.delta.isFirstRun) {
    process.stdout.write(
      `\nDeğişim: ✅ düzeltilen ${res.delta.fixed.length} · 🆕 yeni ${res.delta.introduced.length} · ⏳ kalan ${res.delta.persisting.length}\n`,
    );
  } else if (res.delta?.isFirstRun) {
    process.stdout.write(`\nDeğişim: ilk çalışma — baseline oluşturuldu.\n`);
  }

  process.stdout.write(`\nÇıktılar:\n`);
  process.stdout.write(`  ${res.paths.reportMd}\n`);
  process.stdout.write(`  ${res.paths.findingsJson}\n`);
  process.stdout.write(`  ${res.paths.remediationMd}\n`);
  process.stdout.write(`  ${res.paths.parityMd}\n`);
  process.stdout.write(`  ${res.paths.complianceMd}\n`);
  process.stdout.write(`  ${res.paths.sarif}\n`);
  process.stdout.write(`  ${res.paths.history}\n`);
  process.stdout.write(`  ${res.paths.runLog}\n`);
}

function gateExit(res: ScanResult, failOn: Severity | null): number {
  if (shouldFail(res, failOn)) {
    process.stdout.write(`\n❌ CI gate: ${failOn} ve üstü bulgu var → çıkış kodu 1.\n`);
    return 1;
  }
  return 0;
}

async function main(): Promise<number> {
  const p = parseArgs(process.argv.slice(2));
  if (p.version) {
    process.stdout.write(`${WARDEN_VERSION}\n`);
    return 0;
  }
  if (p.help || p.command === "help") {
    process.stdout.write(`${HELP}\n`);
    return 0;
  }

  printBanner();

  switch (p.command) {
    case "init": {
      runInit(p.target);
      return 0;
    }
    case "scan": {
      const res = await runScan({ projectRoot: p.target, intent: "scan" });
      printSummary(res);
      return gateExit(res, p.failOn);
    }
    case "pentest": {
      const authz = evaluateAuthz(p.target);
      if (authz.mode !== "active") {
        process.stdout.write("⚠ Yetki kapısı kapalı — aktif test yapılmayacak, pasif koşulacak.\n");
        for (const r of authz.reasons) process.stdout.write(`  • ${r}\n`);
        process.stdout.write("\n");
      }
      const res = await runScan({ projectRoot: p.target, intent: "pentest" });
      printSummary(res);
      return gateExit(res, p.failOn);
    }
    case "report": {
      const res = await runScan({ projectRoot: p.target, intent: "scan" });
      printSummary(res);
      return gateExit(res, p.failOn);
    }
    case "monitor": {
      // Continuous monitoring: periyodik pasif tarama + öncesi/sonrası delta.
      let tick = 0;
      for (;;) {
        tick++;
        process.stdout.write(`\n── monitor #${tick} · ${new Date().toISOString()} ──\n`);
        const res = await runScan({ projectRoot: p.target, intent: "scan" });
        printSummary(res);
        if (p.once) return gateExit(res, p.failOn);
        process.stdout.write(`\n(sonraki tarama ${p.interval}s sonra; durdurmak için Ctrl+C)\n`);
        await sleep(p.interval * 1000);
      }
    }
    default:
      process.stderr.write(`Bilinmeyen komut: ${p.command}\n\n${HELP}\n`);
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`Warden hata: ${String(err)}\n`);
    process.exit(1);
  });
