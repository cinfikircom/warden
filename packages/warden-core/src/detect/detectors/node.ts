import type { StackDetector, DetectionResult, DetectContext } from "../types.ts";

interface PkgJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

function readPkg(ctx: DetectContext): PkgJson | null {
  const raw = ctx.readFile("package.json");
  if (!raw) return null;
  try {
    return JSON.parse(raw) as PkgJson;
  } catch {
    return null;
  }
}

function allDeps(pkg: PkgJson): Record<string, string> {
  return { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
}

/** Node/TS + Prisma — first-class hedef (iş emri §3). */
export const nodePrismaDetector: StackDetector = {
  id: "node-prisma",
  priority: 100,
  async detect(ctx) {
    const pkg = readPkg(ctx);
    if (!pkg) return null;
    const deps = allDeps(pkg);
    const hasPrisma = "prisma" in deps || "@prisma/client" in deps || ctx.exists("prisma/schema.prisma");
    if (!hasPrisma) return null;

    const frameworks: string[] = [];
    if ("next" in deps) frameworks.push("next");
    if ("express" in deps) frameworks.push("express");
    if ("fastify" in deps) frameworks.push("fastify");
    if ("@nestjs/core" in deps) frameworks.push("nest");

    const languages = "typescript" in deps || ctx.exists("tsconfig.json") ? ["typescript"] : ["javascript"];
    const schemaFiles = ctx.find((p) => p.endsWith("schema.prisma"), { limit: 5 });
    const migrationDirs = ctx.find((p) => /prisma\/migrations\/.+\/migration\.sql$/.test(p), { limit: 500 });

    const result: DetectionResult = {
      languages,
      frameworks,
      orm: ["prisma"],
      signals: {
        schemaFiles,
        migrationCount: migrationDirs.length,
        scripts: pkg.scripts ?? {},
      },
    };
    return result;
  },
};

/** Genel Node + Drizzle. */
export const nodeDrizzleDetector: StackDetector = {
  id: "node-drizzle",
  priority: 90,
  async detect(ctx) {
    const pkg = readPkg(ctx);
    if (!pkg) return null;
    const deps = allDeps(pkg);
    const hasDrizzle = "drizzle-orm" in deps || ctx.exists("drizzle.config.ts") || ctx.exists("drizzle.config.js");
    if (!hasDrizzle) return null;
    const languages = "typescript" in deps || ctx.exists("tsconfig.json") ? ["typescript"] : ["javascript"];
    return { languages, orm: ["drizzle"], signals: { scripts: pkg.scripts ?? {} } };
  },
};

/** Genel Node (ORM tespit edilmese de). Düşük öncelik — fallback. */
export const nodeGenericDetector: StackDetector = {
  id: "node-generic",
  priority: 50,
  async detect(ctx) {
    const pkg = readPkg(ctx);
    if (!pkg) return null;
    const deps = allDeps(pkg);
    const orm: string[] = [];
    if ("typeorm" in deps) orm.push("typeorm");
    if ("knex" in deps) orm.push("knex");
    if ("sequelize" in deps) orm.push("sequelize");
    const languages = "typescript" in deps || ctx.exists("tsconfig.json") ? ["typescript"] : ["javascript"];
    return { languages, orm, signals: { scripts: pkg.scripts ?? {} } };
  },
};
