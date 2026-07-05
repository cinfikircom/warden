import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül API — API Güvenliği (OWASP API Security Top 10, pasif, statik).
 * =========================================================================
 * ACCESS (BOLA/authz) ve B (injection) dışında kalan API-özgü riskler:
 *   API-1  Aşırı veri ifşası: SELECT * / tüm kolonların dönmesi (hassas alanlar sızar)
 *   API-2  API geneli hız sınırı (rate limit) yok → kaynak tüketimi / kötüye kullanım
 *   API-3  Sınırsız sorgu: findMany/findAll limit/pagination olmadan → tüm tablo döner (DoS + ifşa)
 *   API-4  Ayrıntılı hata/stack trace istemciye dönüyor → iç yapı sızıntısı
 *   API-6  GraphQL derinlik/karmaşıklık limiti yok → tek sorguyla DoS
 *
 * Yalnızca bir HTTP/API yüzeyi tespit edilirse koşar. Yokluk-temelli bayraklar YORUMSUZ kodda
 * aranır (yorumdaki söz bastırmasın). Heuristik → düşük/orta güven, `.warden-ignore.yml` ile bastırılır.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|cs|java)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__|migrations?)\//i;

export function stripComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/(^|\s)#[^\n]*/g, "$1");
}

// HTTP/API yüzeyi (uygulanabilirlik).
const API_SURFACE = /\b(app|router)\.(get|post|put|delete|patch)\s*\(|res\.(json|send|status)\s*\(|@(Get|Post|Put|Delete|Patch|Controller)\b|@app\.(get|post|route)|FastAPI|express\(\)|fastify\(\)|ApolloServer|graphql/i;
const RATE_LIMIT_SIG = /\b(rate.?limit|ratelimit|express-rate-limit|rateLimiter|@Throttle|ThrottlerModule|slowapi|rack.?attack|django.?ratelimit|\blimiter\b|bottleneck|throttle)\b/i;
const GRAPHQL_SIG = /\b(ApolloServer|graphql|typeDefs|buildSchema|makeExecutableSchema|GraphQLSchema|mercurius)\b/i;
const GRAPHQL_LIMIT = /\b(depthLimit|graphql-depth-limit|createComplexityRule|queryComplexity|costAnalysis|graphql-cost-analysis|maxDepth|graphql-query-complexity|armor)\b/i;

// API-1: SELECT * (kolon aşırı-getirme).
const SELECT_STAR = /select\s+\*\s+from\b/i;
// API-3: sınırsız sorgu.
const UNBOUNDED = /\.(findMany|findAll)\s*\(/i;
const HAS_LIMIT = /\b(take|limit|first|paginate|pageSize|per_page|cursor|LIMIT)\b/i;
// API-4: ayrıntılı hata istemciye.
const VERBOSE_ERR = /\.(json|send)\s*\([^)]*\b(err|error|exception|e)\.(stack|message)\b|\.(json|send)\s*\(\s*(err|error|exception)\s*\)|\berror\s*:\s*(err|error|e)\.(stack|message)\b/i;

export interface ApiFile {
  readonly path: string;
  readonly content: string;
}
export interface ApiData {
  readonly usesApi: boolean;
  readonly hasRateLimit: boolean;
  readonly usesGraphql: boolean;
  readonly hasGraphqlLimit: boolean;
  readonly files: readonly ApiFile[];
}

export function collectApiData(ctx: DetectContext): ApiData {
  const candidates = ctx.find((p) => CODE_FILE.test(p) && !SKIP.test(p), { limit: 6000 });
  const files: ApiFile[] = [];
  let usesApi = false, hasRateLimit = false, usesGraphql = false, hasGraphqlLimit = false;

  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    const code = stripComments(content);
    if (RATE_LIMIT_SIG.test(code)) hasRateLimit = true;
    if (GRAPHQL_SIG.test(code)) usesGraphql = true;
    if (GRAPHQL_LIMIT.test(code)) hasGraphqlLimit = true;
    if (API_SURFACE.test(content)) {
      usesApi = true;
      files.push({ path: f, content });
    }
  }
  return { usesApi, hasRateLimit, usesGraphql, hasGraphqlLimit, files };
}

export function analyzeApi(data: ApiData): Finding[] {
  if (!data.usesApi) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };
  const anchor = data.files[0]?.path ?? "api-surface";

  // --- Proje düzeyi ---
  if (data.usesApi && !data.hasRateLimit) {
    push(makeFinding({
      id: "API-2-no-rate-limit", title: "API geneli hız sınırı (rate limit) tespit edilemedi",
      severity: "P2", module: "API", check: "API-2", category: "API Resource Limits", confidence: "low",
      evidence: [{ type: "config", source: anchor, excerpt: "HTTP/API yüzeyi var; rate-limit / throttle middleware sinyali bulunamadı" }],
      impact: "Hız sınırı olmadan pahalı endpoint'ler (rapor, arama, export) ve kimlik akışları kötüye kullanılabilir — kaynak tüketimi, maliyet, DoS.",
      recommendation: "Global + endpoint-bazlı rate-limit ekle (express-rate-limit/@Throttle/slowapi); pahalı işlemlere daha sıkı kota; kiracı-bazlı limit uygula.",
      effort: "M", autoFixable: false, references: ["OWASP API4:2023", "CWE-770"],
    }));
  }
  if (data.usesGraphql && !data.hasGraphqlLimit) {
    push(makeFinding({
      id: "API-6-graphql-no-limit", title: "GraphQL derinlik/karmaşıklık limiti yok",
      severity: "P1", module: "API", check: "API-6", category: "API Resource Limits", confidence: "medium",
      evidence: [{ type: "config", source: anchor, excerpt: "GraphQL kullanılıyor; depth/complexity/cost limiti sinyali yok" }],
      impact: "Derinlik/karmaşıklık limiti olmadan iç-içe tek bir sorgu (nested/circular) sunucuyu kilitleyebilir — DoS.",
      recommendation: "graphql-depth-limit + query-complexity/cost analizi ekle; introspection'ı üretimde kapat; kalıcı sorgu (persisted queries) değerlendir.",
      effort: "M", autoFixable: false, references: ["OWASP API4:2023", "CWE-770"],
    }));
  }

  // --- Dosya/satır düzeyi ---
  for (const { path, content } of data.files) {
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      const loc = String(i + 1);

      // API-1 — SELECT * (aşırı kolon ifşası).
      if (SELECT_STAR.test(ln)) {
        push(makeFinding({
          id: `API-1-select-star:${path}:${i + 1}`, title: "Aşırı veri ifşası: SELECT * (tüm kolonlar dönüyor)",
          severity: "P2", module: "API", check: "API-1", category: "Excessive Data Exposure", confidence: "low",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "SELECT * ile yanıta hassas/iç kolonlar (password_hash, token, internal flag) da girebilir; şema değişince sessizce sızar.",
          recommendation: "Yalnızca gereken kolonları seç; yanıtı bir DTO/serializer/allow-list ile şekillendir; hassas alanları asla döndürme.",
          effort: "S", autoFixable: false, references: ["OWASP API3:2023", "CWE-213"],
        }));
      }

      // API-3 — sınırsız sorgu (limit/pagination yok).
      if (UNBOUNDED.test(ln) && !HAS_LIMIT.test(ln)) {
        push(makeFinding({
          id: `API-3-unbounded-query:${path}:${i + 1}`, title: "Sınırsız sorgu: findMany/findAll limit/pagination olmadan",
          severity: "P1", module: "API", check: "API-3", category: "API Resource Limits", confidence: "medium",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "Limit olmadan tüm tablo çekilir; büyük tablolarda bellek/DoS ve gereğinden fazla veri ifşası (CRM/ERP'de kritik).",
          recommendation: "Zorunlu pagination (take/limit + cursor) uygula; varsayılan ve maksimum sayfa boyutu belirle; sıralamayı sabitle.",
          effort: "M", autoFixable: false, references: ["OWASP API4:2023", "CWE-770"],
        }));
      }

      // API-4 — ayrıntılı hata / stack trace istemciye.
      if (VERBOSE_ERR.test(ln)) {
        push(makeFinding({
          id: `API-4-verbose-error:${path}:${i + 1}`, title: "Ayrıntılı hata/stack trace istemciye dönüyor",
          severity: "P2", module: "API", check: "API-4", category: "Information Disclosure", confidence: "medium",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "Stack trace/exception mesajı dosya yolu, kütüphane sürümü, SQL, iç mantık sızdırır; saldırgana keşif kolaylığı.",
          recommendation: "İstemciye jenerik hata + korelasyon id döndür; ayrıntıyı yalnızca sunucu log'una yaz; üretimde debug/verbose kapalı.",
          effort: "S", autoFixable: false, references: ["OWASP API8:2023", "CWE-209"],
        }));
      }
    }
  }
  return findings;
}

export const apiModule: WardenModule = {
  id: "API",
  title: "API Güvenliği (OWASP API Top 10)",
  active: false,
  applicable(ctx: ScanContext) {
    return collectApiData(ctx.fs).usesApi;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings = analyzeApi(collectApiData(ctx.fs));
    ctx.audit.info(`API: ${findings.length} bulgu.`);
    return { findings };
  },
};
