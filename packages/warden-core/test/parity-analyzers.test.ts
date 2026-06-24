import { describe, it, expect } from "vitest";
import { analyzeGitParity } from "../src/modules/parity/git.ts";
import type { GitData } from "../src/modules/parity/git.ts";
import { analyzePrismaSchema } from "../src/modules/parity/schema-prisma.ts";
import { analyzeVolumeParity, extractMounts, analyzeEnvParity } from "../src/modules/parity/storage.ts";
import { analyzeCertExpiry, analyzeBackupRestore } from "../src/modules/parity/operational.ts";
import { parse as parseYaml } from "yaml";

describe("A1 git parity", () => {
  const base: GitData = {
    isRepo: true, branch: "deploy", mainBranch: "main",
    headSha: "aaaa", mainSha: "bbbb", behind: 0, ahead: 0, dirty: false, dirtyFiles: 0,
  };

  it("HEAD ana daldan geride → P0 production drift", () => {
    const { findings, layer } = analyzeGitParity({ ...base, behind: 8 });
    expect(findings.find((f) => f.id === "A1-production-drift")?.severity).toBe("P0");
    expect(layer.status).toBe("risk");
  });

  it("kirli çalışma ağacı → P1", () => {
    const { findings } = analyzeGitParity({ ...base, dirty: true, dirtyFiles: 3 });
    expect(findings.find((f) => f.id === "A1-dirty-tree")?.severity).toBe("P1");
  });

  it("temiz & güncel → bulgu yok, skor 10", () => {
    const { findings, layer } = analyzeGitParity({ ...base, headSha: "x", mainSha: "x" });
    expect(findings).toHaveLength(0);
    expect(layer.score).toBe(10);
    expect(layer.status).toBe("ok");
  });

  it("git deposu değil → unknown", () => {
    const { layer } = analyzeGitParity({ ...base, isRepo: false });
    expect(layer.status).toBe("unknown");
    expect(layer.score).toBeNull();
  });
});

describe("A2 prisma schema parity", () => {
  it("yıkıcı migration → P0", () => {
    const { findings } = analyzePrismaSchema({
      schemaText: "model User { id String @id }",
      schemaPath: "prisma/schema.prisma",
      migrations: [{ path: "prisma/migrations/x/migration.sql", sql: 'ALTER TABLE "u" DROP COLUMN "phone";\nDROP TABLE "old";' }],
      scripts: {},
    });
    const f = findings.find((x) => x.id.startsWith("A2-destructive-migration"));
    expect(f?.severity).toBe("P0");
    expect(f?.title).toMatch(/DROP COLUMN/);
  });

  it("db push kullanımı → P1", () => {
    const { findings } = analyzePrismaSchema({
      schemaText: "model User { id String @id }",
      schemaPath: "p", migrations: [{ path: "m", sql: "CREATE TABLE x();" }],
      scripts: { "db:push": "prisma db push" },
    });
    expect(findings.find((f) => f.id === "A2-db-push")?.severity).toBe("P1");
  });

  it("model var ama migration yok → P1", () => {
    const { findings } = analyzePrismaSchema({
      schemaText: "model User { id String @id }", schemaPath: "p", migrations: [], scripts: {},
    });
    expect(findings.find((f) => f.id === "A2-no-migrations")?.severity).toBe("P1");
  });
});

describe("A4 volume parity engine (signature-worker)", () => {
  it("aynı 'uploads' verisini farklı kaynağa bağlayan iki servis → P1 mismatch", () => {
    const compose = parseYaml(`
services:
  api:
    volumes:
      - uploads:/data/uploads
  signature-worker:
    volumes:
      - ./local-tmp/uploads:/tmp/uploads
volumes:
  uploads:
`);
    const findings = analyzeVolumeParity(extractMounts(compose), "docker-compose.yml");
    const f = findings.find((x) => x.id.startsWith("A4-volume-mismatch"));
    expect(f?.severity).toBe("P1");
    expect(f?.title).toMatch(/uploads/);
  });

  it("aynı named volume'u paylaşan servisler → bulgu yok", () => {
    const compose = parseYaml(`
services:
  api:
    volumes: [ "uploads:/data/uploads" ]
  worker:
    volumes: [ "uploads:/data/uploads" ]
volumes:
  uploads:
`);
    expect(analyzeVolumeParity(extractMounts(compose), "c.yml")).toHaveLength(0);
  });
});

describe("A4 env parity", () => {
  it(".env.example'da olup .env'de olmayan anahtar → P1", () => {
    const findings = analyzeEnvParity("DATABASE_URL=x\nJWT_SECRET=y", "JWT_SECRET=z", ".env.example");
    expect(findings[0]?.severity).toBe("P1");
    expect(findings[0]?.title).toMatch(/DATABASE_URL/);
  });

  it("tüm anahtarlar mevcut → bulgu yok", () => {
    expect(analyzeEnvParity("A=1\nB=2", "A=x\nB=y", ".env.example")).toHaveLength(0);
  });
});

describe("A5 operational", () => {
  it("yakında süresi dolan sertifika → P1", () => {
    const now = new Date("2026-06-24T00:00:00Z");
    const validTo = new Date("2026-06-30T00:00:00Z"); // 6 gün
    const f = analyzeCertExpiry({ path: "tls/cert.pem", validTo }, now);
    expect(f?.severity).toBe("P1");
  });

  it("süresi dolmuş sertifika → P0", () => {
    const now = new Date("2026-06-24T00:00:00Z");
    const f = analyzeCertExpiry({ path: "c.pem", validTo: new Date("2026-06-01T00:00:00Z") }, now);
    expect(f?.severity).toBe("P0");
  });

  it("uzun geçerli sertifika → bulgu yok", () => {
    const now = new Date("2026-06-24T00:00:00Z");
    expect(analyzeCertExpiry({ path: "c.pem", validTo: new Date("2027-06-24T00:00:00Z") }, now)).toBeNull();
  });

  it("backup var, restore yok → P2", () => {
    const f = analyzeBackupRestore({ hasBackup: true, backupEvidence: "backup.sh", hasRestore: false, certs: [] });
    expect(f?.severity).toBe("P2");
  });

  it("backup + restore var → bulgu yok", () => {
    expect(analyzeBackupRestore({ hasBackup: true, backupEvidence: "b", hasRestore: true, certs: [] })).toBeNull();
  });
});
