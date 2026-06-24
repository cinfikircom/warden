import { parse as parseYaml } from "yaml";
import { basename } from "node:path";
import type { Finding, Evidence } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/** Bir servisin tek bir mount'u. source=null → anonim volume. */
export interface Mount {
  readonly service: string;
  readonly source: string | null;
  readonly target: string;
  readonly raw: string;
}

const DATA_LIKE = /uploads|data|storage|files|media|shared|bucket|documents|assets/i;
const ROLE_HINTS: Array<[RegExp, string]> = [
  [/worker|consumer|processor|signature/i, "worker/consumer"],
  [/producer|publisher/i, "producer"],
  [/scheduler|cron|beat/i, "scheduler"],
  [/api|web|server|app|backend/i, "api"],
];

function roleOf(service: string): string {
  for (const [re, role] of ROLE_HINTS) if (re.test(service)) return role;
  return "service";
}

function parseMountEntry(service: string, entry: unknown): Mount | null {
  if (typeof entry === "string") {
    // "source:target[:mode]" ya da anonim "target"
    const parts = entry.split(":");
    if (parts.length === 1) return { service, source: null, target: parts[0] as string, raw: entry };
    return { service, source: parts[0] as string, target: parts[1] as string, raw: entry };
  }
  if (entry && typeof entry === "object") {
    const o = entry as Record<string, unknown>;
    const target = typeof o["target"] === "string" ? (o["target"] as string) : null;
    const source = typeof o["source"] === "string" ? (o["source"] as string) : null;
    if (target) return { service, source, target, raw: JSON.stringify(o) };
  }
  return null;
}

/** Compose belgesinden tüm mount'ları çıkarır. */
export function extractMounts(compose: unknown): Mount[] {
  const mounts: Mount[] = [];
  if (!compose || typeof compose !== "object") return mounts;
  const services = (compose as Record<string, unknown>)["services"];
  if (!services || typeof services !== "object") return mounts;
  for (const [name, svc] of Object.entries(services as Record<string, unknown>)) {
    if (!svc || typeof svc !== "object") continue;
    const vols = (svc as Record<string, unknown>)["volumes"];
    if (!Array.isArray(vols)) continue;
    for (const v of vols) {
      const m = parseMountEntry(name, v);
      if (m) mounts.push(m);
    }
  }
  return mounts;
}

/**
 * Volume Parity Engine (generic, nokta 4). Veri-benzeri mount'ları hedef adına (basename)
 * göre gruplar; aynı mantıksal veriyi (örn. "uploads") FARKLI kaynağa/yola bağlayan iki+ servis
 * varsa "volume mismatch" üretir. signature-worker vakasını Docker'a özel olmadan yakalar.
 */
export function analyzeVolumeParity(mounts: readonly Mount[], composePath: string): Finding[] {
  const dataMounts = mounts.filter((m) => DATA_LIKE.test(m.target));
  const groups = new Map<string, Mount[]>();
  for (const m of dataMounts) {
    const key = basename(m.target).toLowerCase();
    const arr = groups.get(key) ?? [];
    arr.push(m);
    groups.set(key, arr);
  }

  const findings: Finding[] = [];
  for (const [key, ms] of groups) {
    const services = new Set(ms.map((m) => m.service));
    if (services.size < 2) continue;
    const signatures = new Set(ms.map((m) => `${m.source ?? "<anon>"}→${m.target}`));
    if (signatures.size < 2) continue; // hepsi aynı kaynağı paylaşıyor → sorun yok

    const evidence: Evidence[] = ms.map((m) => ({
      type: "config",
      source: `${composePath} services.${m.service}.volumes`,
      excerpt: `${m.service} (${roleOf(m.service)}): ${m.raw}`,
    }));

    findings.push(
      makeFinding({
        id: `A4-volume-mismatch:${key}`,
        title: `Volume mismatch: "${key}" verisini ${services.size} servis FARKLI kaynağa bağlıyor`,
        severity: "P1",
        module: "A",
        check: "A4",
        category: "Storage Parity",
        confidence: "high",
        evidence,
        impact:
          "Bir servisin yazdığı dosyaları diğeri göremez (üretici/tüketici ayrı depo). " +
          "signature-worker tipi sessiz veri kaybı: işler 'başarılı' görünür ama çıktı kaybolur.",
        recommendation:
          "Veriyi paylaşan tüm servisleri AYNI named volume / mount / bucket'a bağla; " +
          "object storage (S3/R2) kullanıyorsan aynı bucket+prefix.",
        effort: "M",
        autoFixable: false,
      }),
    );
  }
  return findings;
}

/** .env.example ↔ .env parity: sözleşmede olup gerçekte eksik anahtarlar. */
export function analyzeEnvParity(exampleText: string | null, envText: string | null, examplePath: string): Finding[] {
  if (!exampleText) return [];
  const keysOf = (t: string): string[] =>
    t
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
      .map((l) => l.split("=")[0]?.trim())
      .filter((k): k is string => !!k);

  const exampleKeys = keysOf(exampleText);
  const envKeys = new Set(envText ? keysOf(envText) : []);
  const missing = exampleKeys.filter((k) => !envKeys.has(k));
  if (missing.length === 0) return [];

  return [
    makeFinding({
      id: "A4-missing-env",
      title: `Eksik ortam değişkeni: ${missing.slice(0, 8).join(", ")}${missing.length > 8 ? " …" : ""}`,
      severity: "P1",
      module: "A",
      check: "A4",
      category: "Config Parity",
      confidence: envText ? "high" : "medium",
      evidence: [
        { type: "file", source: examplePath, excerpt: `sözleşmede ${exampleKeys.length} anahtar` },
        { type: "config", source: ".env", excerpt: envText ? `${envKeys.size} anahtar tanımlı` : ".env bulunamadı" },
      ],
      impact: "Sözleşmede beklenen değişkenler ortamda yok; üretimde eksik config → çalışma zamanı hatası/yanlış davranış.",
      recommendation: `Eksik anahtarları doldur: ${missing.join(", ")}. Secret manager kullanıyorsan oradan enjekte et.`,
      effort: "S",
      autoFixable: false,
    }),
  ];
}

export interface StorageData {
  readonly composePath: string | null;
  readonly compose: unknown;
  readonly envExample: string | null;
  readonly env: string | null;
}

export function collectStorageData(ctx: DetectContext): StorageData {
  const composePath =
    ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].find((f) => ctx.exists(f)) ?? null;
  let compose: unknown = null;
  if (composePath) {
    const raw = ctx.readFile(composePath);
    if (raw) {
      try {
        compose = parseYaml(raw);
      } catch {
        compose = null;
      }
    }
  }
  return {
    composePath,
    compose,
    envExample: ctx.readFile(".env.example"),
    env: ctx.readFile(".env"),
  };
}

/** A4 — saf analiz birleşimi (volume + env parity). */
export function analyzeStorageParity(data: StorageData): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];
  if (data.composePath && data.compose) {
    findings.push(...analyzeVolumeParity(extractMounts(data.compose), data.composePath));
  }
  findings.push(...analyzeEnvParity(data.envExample, data.env, ".env.example"));

  const canAssess = Boolean(data.composePath) || Boolean(data.envExample);
  if (!canAssess) {
    return {
      findings,
      layer: { code: "A4", name: "Storage / Config Parity", status: "unknown", score: null, note: "Compose veya .env.example yok.", findingIds: [] },
    };
  }

  let score = 10;
  for (const f of findings) score -= f.severity === "P0" ? 6 : f.severity === "P1" ? 2.5 : 1;
  const status = findings.some((f) => f.severity === "P0") ? "risk" : findings.length > 0 ? "warn" : "ok";

  return {
    findings,
    layer: {
      code: "A4",
      name: "Storage / Config Parity",
      status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note: findings.length === 0 ? "Paylaşılan depo ve env tutarlı." : `${findings.length} parity bulgusu.`,
      findingIds: findings.map((f) => f.id),
    },
  };
}
