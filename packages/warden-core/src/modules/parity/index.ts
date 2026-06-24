import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { ParityLayer, ParityResult } from "../../model/parity.ts";
import { computeOverallParity } from "../../model/parity.ts";

import { collectGitData, analyzeGitParity } from "./git.ts";
import { collectPrismaData, analyzePrismaSchema } from "./schema-prisma.ts";
import { collectDjangoData, analyzeDjangoMigrations } from "./schema-django.ts";
import { collectLaravelData, analyzeLaravelMigrations } from "./schema-laravel.ts";
import { collectDotnetData, analyzeEfMigrations } from "./schema-dotnet.ts";
import { collectGoMigrations, analyzeGoMigrations } from "./schema-go.ts";
import { collectRuntimeData, analyzeRuntime } from "./runtime.ts";
import { collectStorageData, analyzeStorageParity } from "./storage.ts";
import { collectOperationalData, analyzeOperational } from "./operational.ts";
import { collectExternalData, analyzeExternal } from "./external.ts";

export type { ParityResult, ParityLayer } from "../../model/parity.ts";

/**
 * Modül A — Parity & Deployment Discovery (pasif/read-only).
 * A1 git · A2 şema (Prisma) · A3 runtime · A4 storage+config · A5 operasyonel · A6 dış bağımlılık.
 * artifact olarak ParityResult (katman skorları + Overall Parity Score) döner.
 */
export const parityModule: WardenModule = {
  id: "A",
  title: "Parity & Deployment Discovery",
  active: false,
  applicable() {
    return true; // parity her projede anlamlı (git/compose/env yoksa katmanlar 'unknown' olur).
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const now = new Date();
    const findings: Finding[] = [];
    const layers: ParityLayer[] = [];

    const usePrisma = ctx.stack.orm.includes("prisma");
    const useDjango = ctx.stack.frameworks.includes("django");
    const useLaravel = ctx.stack.frameworks.includes("laravel");
    const useDotnet = ctx.stack.frameworks.includes("aspnet") || ctx.stack.orm.includes("ef-core");
    const useGo = ctx.stack.languages.includes("go");

    const a1 = analyzeGitParity(collectGitData(ctx.projectRoot, ctx.audit));
    findings.push(...a1.findings);
    layers.push(a1.layer);

    if (usePrisma) {
      const a2 = analyzePrismaSchema(collectPrismaData(ctx.fs));
      findings.push(...a2.findings);
      layers.push(a2.layer);
    } else if (useDjango) {
      const a2 = analyzeDjangoMigrations(collectDjangoData(ctx.fs));
      findings.push(...a2.findings);
      layers.push(a2.layer);
    } else if (useLaravel) {
      const a2 = analyzeLaravelMigrations(collectLaravelData(ctx.fs));
      findings.push(...a2.findings);
      layers.push(a2.layer);
    } else if (useDotnet) {
      const a2 = analyzeEfMigrations(collectDotnetData(ctx.fs));
      findings.push(...a2.findings);
      layers.push(a2.layer);
    } else if (useGo) {
      const a2 = analyzeGoMigrations(collectGoMigrations(ctx.fs));
      findings.push(...a2.findings);
      layers.push(a2.layer);
    } else {
      layers.push({ code: "A2", name: "Schema Parity", status: "unknown", score: null, note: "Bilinen ORM/migration tespit edilmedi.", findingIds: [] });
    }

    const a3 = analyzeRuntime(collectRuntimeData(ctx.projectRoot, ctx.audit), now);
    findings.push(...a3.findings);
    layers.push(a3.layer);

    const a4 = analyzeStorageParity(collectStorageData(ctx.fs));
    findings.push(...a4.findings);
    layers.push(a4.layer);

    const a5 = analyzeOperational(collectOperationalData(ctx.fs), now);
    findings.push(...a5.findings);
    layers.push(a5.layer);

    const a6 = analyzeExternal(collectExternalData(ctx.fs));
    findings.push(...a6.findings);
    layers.push(a6.layer);

    const artifact: ParityResult = { layers, overall: computeOverallParity(layers) };
    ctx.audit.info(`Parity: ${layers.length} katman, Overall Parity Score: ${artifact.overall ?? "n/d"}`);

    return { findings, artifact };
  },
};
