import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül ACCESS — Erişim Kontrolü & Kiracı İzolasyonu (pasif, statik).
 * =========================================================================
 * OWASP #1 (Broken Access Control) — SaaS/CRM/ERP'nin en pahalı ihlal noktası. Kod/altyapı
 * katmanının atladığı iş-mantığı yetkilendirme hatalarını arar:
 *
 *   ACC-1  Kiracı izolasyonu: nesne istemci id'siyle çekiliyor ama tenant/org filtresi yok
 *          → bir müşteri diğerinin verisini görür (multi-tenant sızıntısı)
 *   ACC-2  State-değiştiren endpoint'te yetki (auth) middleware'i yok (projenin geri kalanı
 *          auth kullanıyorken bu route unutulmuş → tutarsız koruma)
 *   ACC-3  Mass assignment / over-posting: req.body doğrudan modele → kullanıcı is_admin=true set eder
 *   ACC-4  Ayrıcalıklı/admin aksiyonu rol/izin kontrolü olmadan (yetki yükseltme)
 *
 * Yalnızca bir web/API + ORM yüzeyi tespit edilirse koşar. Yokluk/heuristik temelli olduğu için
 * düşük/orta güvenle işaretlenir; yanlış-pozitif `.warden-ignore.yml` ile bastırılabilir.
 * =========================================================================
 */

const CODE_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rb|php|cs|java)$/i;
const SKIP = /(^|\/)(node_modules|dist|build|\.next|warden-report|vendor|coverage)\/|\.min\.js$|(^|\/)(test|tests|__tests__|fixtures|__mocks__|migrations?)\//i;

// Kiracı sütunu (ACC-1 kapısı).
const TENANT_COL = /\b(tenant_?id|tenantId|org_?id|orgId|organi[sz]ation_?id|organi[sz]ationId|company_?id|companyId|workspace_?id|workspaceId|account_?id|accountId)\b/i;
// Web/API + ORM yüzeyi (uygulanabilirlik).
const HANDLER_SIG = /\breq\.(body|params|query)\b|\bres\.(json|send|status|render)\b|\b(app|router)\.(get|post|put|delete|patch)\s*\(|@(Get|Post|Put|Delete|Patch|Controller)\b|def\s+\w+\(self,\s*request|ViewSet|params\.(require|permit)|\$request->/;
const ORM_SIG = /\b(prisma|sequelize|typeorm|mongoose|knex|drizzle|getRepository|createQueryBuilder|ActiveRecord)\b|\.(findUnique|findMany|findFirst|findOne|findByPk|findById|objects)\b/i;
// Auth middleware / rol kontrolü sinyalleri.
// `isLoggedIn` / `loggedIn` / `requireSession` yaygın Express adlandırmalarıdır ve listede
// yoktu; eksikliği tüm route-düzeyi auth analizini sessizce devre dışı bırakıyordu.
const AUTH_MW = /\b(requireAuth|isAuthenticated|isLoggedIn|loggedIn|ensureAuth|ensureLoggedIn|requireSession|authenticate|passport\.authenticate|verifyToken|jwtVerify|authGuard|withAuth|protect|checkAuth|requireUser|requireLogin|@UseGuards|before_action\s*:?\s*:?authenticate|login_required|IsAuthenticated)\b/i;
const ROLE_CHECK = /\b(isAdmin|hasRole|requireRole|checkRole|ensureRole|authorize|can\s*\(|cannot\s*\(|ability|@Roles?\b|permission|acl\b|policy\b|IsAdminUser|has_perm|current_user\.admin)\b/i;

// ACC-2: state-değiştiren route kaydı.
const ROUTE_MUT = /\b(router|app)\.(post|put|patch|delete)\s*\(/i;

/* ─── Route envanteri ────────────────────────────────────────────────────────
 *
 * ACC-2'nin ilk hâli DOSYA seviyesinde çalışıyordu: "bu dosyada yazma route'u var ve
 * auth sinyali yok". Gerçek route tablolarında bu yetersizdir — tek bir `routes/index.js`
 * hem korumalı hem korumasız onlarca route içerir ve dosyada bir tane `isLoggedIn` görmek
 * hepsini korunmuş gösterir.
 *
 * Bu ayrıştırıcı her route tanımını tek tek çıkarır: yol, HTTP metodu ve handler'dan
 * önceki middleware zinciri. Böylece bulgu route düzeyinde ve doğru satırda üretilir.
 *
 * Yan kazanç: bu envanter, DAST'ın sabit yol listesi yerine uygulamanın gerçek yüzeyini
 * denemesi için de gereken veridir (bkz. docs/DURUM-VE-GELECEK.md, endpoint envanteri).
 *
 * (Boşluk NodeGoat benchmark'ında ölçülerek bulundu: 6 authz/idor maddesi bu yüzden kaçıyordu.)
 */
const ROUTE_DEF = /\b(?:app|router)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`]+)\2\s*(?:,([^)]*))?\)/gi;
/** Yol parametresi bir KİMLİK mi (`:userId`, `:accountId`, `:id`)? */
const ID_PARAM = /:(\w*(?:id|uuid|guid))\b/i;
/** Kaynak sahipliğini doğrulayan middleware. */
const OWNERSHIP_MW = /\b(checkOwner|isOwner|ensureOwner|verifyOwnership|authorizeResource|canAccess|scopeToUser)\b/i;

interface RouteDef {
  readonly method: string;
  readonly path: string;
  readonly middlewares: string;
  readonly line: number;
  readonly raw: string;
}

/** JS/TS yorumlarını boşlukla değiştirir — konum kayması olmasın diye uzunluk korunur. */
function blankComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, (m, p1: string) => p1 + " ".repeat(m.length - p1.length));
}

/**
 * Bir dosyadaki route tanımlarını çıkarır.
 *
 * Yorumlar ÖNCE temizlenir: düzeltilmiş sürümler kod tabanlarında sıkça yorum içinde bekler
 * (NodeGoat'ta `app.get("/benefits", isLoggedIn, isAdmin, …)` tam olarak öyle durur) ve
 * onları gerçek route sanmak, korumasız bir route'u korunmuş göstererek bulguyu yutardı.
 */
export function extractRoutes(content: string): RouteDef[] {
  const code = blankComments(content);
  const out: RouteDef[] = [];
  ROUTE_DEF.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ROUTE_DEF.exec(code)) !== null) {
    const before = code.slice(0, m.index);
    out.push({
      method: (m[1] ?? "").toLowerCase(),
      path: m[3] ?? "",
      middlewares: m[4] ?? "",
      line: before.split("\n").length,
      raw: m[0].replace(/\s+/g, " ").trim(),
    });
  }
  return out;
}
// ACC-4: ayrıcalıklı/admin route.
const ADMIN_ROUTE = /\.(post|put|patch|delete)\s*\(\s*["'`][^"'`]*(admin|\/role|set[-_]?role|grant|revoke|promote|impersonate|permission)/i;

// ACC-3: mass assignment / over-posting (çok-stack). `req.body` TÜM nesne olarak geçirilmeli
// (req.body.field tek alan değil) → negatif lookahead `(?![.\[\w])` tek-alan erişimini eler.
const MASS_ASSIGN = [
  /\.(create|createMany|update|updateMany|updateOne|save|insert|bulkCreate|findOneAndUpdate|findByIdAndUpdate|set|merge)\s*\([^)]*\breq\.body(?![.\[\w])/i, // JS/TS ORM
  /\bnew\s+[A-Z]\w*\s*\(\s*req\.body(?![.\[\w])/i,                                // new Model(req.body)
  /\bObject\.assign\s*\([^,]+,\s*req\.body(?![.\[\w])/i,                          // Object.assign(x, req.body)
  /\bdata\s*:\s*req\.body(?![.\[\w])/i,                                           // Prisma { data: req.body }
  /::(create|make)\s*\(\s*\$request->all\(\)/i,                                  // Laravel Model::create($request->all())
  /->(fill|forceFill|update)\s*\(\s*\$request->(all|input)\(\)/i,                // Laravel $m->fill($request->all())
  /\.objects\.(create|update)\s*\(\s*\*\*request\.(data|POST|GET)/i,             // Django Model.objects.create(**request.data)
  /\.(new|create|update|update_attributes)\s*\(\s*params\b(?![^)]*\.permit)/i,   // Rails Model.new(params) (strong params yok)
];

// ACC-1: nesne istemci id'siyle çekiliyor.
const QUERY_ID_OBJ = /(findUnique|findFirst|findOne|update|updateOne|delete|deleteOne|findOneAndUpdate|findOneAndDelete)\s*\(\s*\{[^}]*\b(where|_id|id)\b[^}]*\bid\b\s*:\s*(req\.(params|query|body)|params\.|ctx\.params|request\.)/i;
const QUERY_ID_ARG = /\b(findById|findByPk|getById|findByIdAndUpdate|findByIdAndDelete|get_object_or_404)\s*\(\s*[^),]*(req\.(params|query|body)|params\[|ctx\.params|request\.)/i;

export interface AccessFile {
  readonly path: string;
  readonly content: string;
}
export interface AccessData {
  readonly usesWeb: boolean;
  readonly usesTenancy: boolean;
  readonly usesAuth: boolean;
  readonly files: readonly AccessFile[];
}

export function collectAccessData(ctx: DetectContext): AccessData {
  const candidates = ctx.find((p) => (CODE_FILE.test(p) || /\.prisma$|schema\.sql$/i.test(p)) && !SKIP.test(p), { limit: 6000 });
  const files: AccessFile[] = [];
  let usesTenancy = false;
  let usesAuth = false;
  let usesWeb = false;

  for (const f of candidates) {
    const content = ctx.readFile(f);
    if (content === null || content.length > 1_000_000) continue;
    if (TENANT_COL.test(content)) usesTenancy = true;
    if (AUTH_MW.test(content)) usesAuth = true;
    const isHandlerOrOrm = HANDLER_SIG.test(content) || ORM_SIG.test(content);
    if (isHandlerOrOrm) {
      usesWeb = true;
      if (CODE_FILE.test(f)) files.push({ path: f, content });
    }
  }
  return { usesWeb, usesTenancy, usesAuth, files };
}

export function analyzeAccess(data: AccessData): Finding[] {
  if (!data.usesWeb) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding): void => {
    if (seen.has(f.fingerprint)) return;
    seen.add(f.fingerprint);
    findings.push(f);
  };

  /*
   * ACC-4 (proje düzeyi) — kimlik doğrulama var ama ROL/İZİN kontrolü hiç yok.
   *
   * Bu ayrım bilinçli olarak yol adına DEĞİL, kod tabanının bütününe bakar. "Ayrıcalıklı yol"
   * listesi (`/admin`, `/manage` …) tutmak cazip ama yanıltıcıdır: bir uygulamanın en kritik
   * ayrıcalıklı ucu `/benefits` ya da `/payouts` gibi tamamen alana özgü bir ad taşıyabilir.
   * Böyle bir liste yalnızca tahmin ettiğimiz adları yakalar ve ölçüldüğü örneğe göre
   * şişirilmeye açıktır.
   *
   * Ölçülebilir ve genel olan şey şudur: uygulama kullanıcıları ayırt ediyor (auth var) ama
   * hiçbir yerde yetki seviyesi ayırt etmiyor. O zaman giriş yapmış HER kullanıcı, en
   * ayrıcalıklı işlemi de yapabilir.
   */
  /*
   * Ölçüt "kodda `isAdmin` kelimesi geçiyor mu" DEĞİL, "bir route'un middleware zincirinde
   * rol kontrolü UYGULANIYOR mu" olmalı. Fark kritik: NodeGoat'ta `isAdmin` üç dosyada
   * geçiyor ama hepsi VERİ olarak (`user: { isAdmin: true }`) — hiçbir route'ta middleware
   * değil. Kelime aramak, hiç uygulanmayan bir rol modelini uygulanmış gösteriyordu.
   *
   * Bu yüzden yalnızca route tablosu AYRIŞTIRILABİLEN projelerde çalışır; Django/Rails gibi
   * farklı route yapılarında sessizce atlanır (yanlış pozitif üretmektense ölçmemek yeğdir).
   */
  const allRoutes = data.files.flatMap((f) => extractRoutes(f.content));
  const anyRoleInRoutes = allRoutes.some((r) => ROLE_CHECK.test(r.middlewares));
  if (data.usesAuth && allRoutes.length > 0 && !anyRoleInRoutes) {
    const withMut = data.files.find((f) => ROUTE_MUT.test(f.content));
    if (withMut) {
      const li = withMut.content.split(/\r?\n/).findIndex((l) => ROUTE_MUT.test(l));
      push(makeFinding({
        id: "ACC-4-no-role-model", title: "Kimlik doğrulama var ama hiçbir yerde rol/izin kontrolü yok",
        severity: "P1", module: "ACCESS", check: "ACC-4", category: "Privilege Escalation", confidence: "medium",
        evidence: [{
          type: "file", source: withMut.path, ...(li >= 0 ? { location: String(li + 1) } : {}),
          excerpt: "auth middleware kullanılıyor; rol/izin kontrolü (isAdmin/requireRole/@Roles/permission) hiçbir dosyada yok",
        }],
        impact:
          "Uygulama kullanıcıları ayırt ediyor ama yetki seviyelerini ayırt etmiyor: giriş yapmış " +
          "herhangi bir kullanıcı, yönetici işlemleri dâhil her state-değiştiren ucu çağırabilir (OWASP A01).",
        recommendation:
          "Rol/izin modeli tanımla ve ayrıcalıklı route'lara rol middleware'i ekle (isAdmin/requireRole/@Roles). " +
          "Varsayılan-kapalı uygula: yetki gerektirmeyen uçları açıkça işaretle.",
        effort: "L", autoFixable: false, references: ["OWASP A01:2021", "OWASP API5:2023", "CWE-862"],
      }));
    }
  }

  for (const { path, content } of data.files) {
    const lines = content.split(/\r?\n/);
    const fileHasAuth = AUTH_MW.test(content);
    const fileHasRole = ROLE_CHECK.test(content);
    const fileHasMutRoute = ROUTE_MUT.test(content);

    /*
     * Route ENVANTERİ — dosya seviyesi heuristiğin yerine geçer.
     *
     * Route tanımları ayrıştırılabildiyse her biri tek tek değerlendirilir ve bulgu doğru
     * satırda üretilir. Ayrıştırma başarısızsa (farklı framework, dinamik kayıt) aşağıdaki
     * dosya-seviyesi ACC-2 heuristiği devreye girer — yetenek kaybı olmaz.
     */
    const routes = extractRoutes(content);
    for (const r of routes) {
      const mwHasAuth = AUTH_MW.test(r.middlewares);
      const mutating = r.method !== "get" && r.method !== "all";

      if (data.usesAuth && mutating && !mwHasAuth) {
        push(makeFinding({
          id: `ACC-2-route-no-auth:${path}:${r.line}`,
          title: "State-değiştiren route'un middleware zincirinde auth yok",
          severity: "P1", module: "ACCESS", check: "ACC-2", category: "Broken Access Control", confidence: "medium",
          evidence: [{ type: "file", source: path, location: String(r.line), excerpt: r.raw.slice(0, 160) }],
          impact: "Yetki kontrolü olmayan bir yazma endpoint'i, kimliği doğrulanmamış/yetkisiz kullanıcının veri değiştirmesine izin verir (OWASP A01).",
          recommendation: "Bu route'a auth middleware ekle; router seviyesinde varsayılan-kapalı uygula ve istisnaları açıkça işaretle.",
          effort: "M", autoFixable: false, references: ["OWASP A01:2021", "OWASP API5:2023"],
        }));
      }

      // ACC-1 — yol parametresi bir kimlik ve sahiplik doğrulaması yok: klasik IDOR yüzeyi.
      // Kaynak, istemcinin verdiği id ile seçiliyor; sunucu bunun çağıranın kaynağı olduğunu
      // doğrulamıyorsa başka kullanıcının verisi okunabilir/değiştirilebilir.
      if (ID_PARAM.test(r.path) && !OWNERSHIP_MW.test(r.middlewares) && !ROLE_CHECK.test(r.middlewares)) {
        push(makeFinding({
          id: `ACC-1-idor-route:${path}:${r.line}`,
          title: "Route kimlik parametresi alıyor ama sahiplik doğrulaması yok (IDOR)",
          severity: "P1", module: "ACCESS", check: "ACC-1", category: "Broken Access Control", confidence: "medium",
          evidence: [{ type: "file", source: path, location: String(r.line), excerpt: r.raw.slice(0, 160) }],
          impact:
            "Kaynak, istemcinin verdiği kimlikle seçiliyor. Sunucu bu kimliğin çağırana ait olduğunu " +
            "doğrulamazsa, id'yi değiştiren herkes başkasının verisini okuyabilir veya değiştirebilir (IDOR).",
          recommendation:
            "Kaynağı oturumdaki kullanıcıya göre filtrele (`where: { id, userId: session.userId }`) ya da " +
            "sahiplik middleware'i ekle. Mümkünse tahmin edilemez kimlik (UUID) kullan — ama bu tek başına yeterli değildir.",
          effort: "M", autoFixable: false, references: ["OWASP A01:2021", "OWASP API1:2023", "CWE-639"],
        }));
      }
    }

    // ACC-2 (dosya seviyesi) — yalnızca route ayrıştırılamadığında. Aksi halde yukarıdaki
    // route-düzeyi bulgularla aynı sorunu ikinci kez, daha kaba biçimde raporlardı.
    if (routes.length === 0 && data.usesAuth && fileHasMutRoute && !fileHasAuth) {
      const li = lines.findIndex((l) => ROUTE_MUT.test(l));
      push(makeFinding({
        id: `ACC-2-route-no-auth:${path}`, title: "State-değiştiren endpoint yetki (auth) middleware'i olmadan tanımlı",
        severity: "P1", module: "ACCESS", check: "ACC-2", category: "Broken Access Control", confidence: "low",
        evidence: [{ type: "file", source: path, ...(li >= 0 ? { location: String(li + 1) } : {}), excerpt: "post/put/patch/delete route var; bu dosyada auth middleware sinyali yok (proje geneli auth kullanıyor)" }],
        impact: "Yetki kontrolü olmayan bir yazma endpoint'i, kimliği doğrulanmamış/yetkisiz kullanıcının veri değiştirmesine izin verir (OWASP A01).",
        recommendation: "Route'a auth middleware/guard ekle (requireAuth/@UseGuards vb.); mümkünse router seviyesinde varsayılan-kapalı uygula, istisnaları açıkça işaretle.",
        effort: "M", autoFixable: false, references: ["OWASP A01:2021", "OWASP API5:2023"],
      }));
    }

    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] as string;
      const loc = String(i + 1);

      // ACC-3 — mass assignment / over-posting.
      if (MASS_ASSIGN.some((re) => re.test(ln))) {
        push(makeFinding({
          id: `ACC-3-mass-assignment:${path}:${i + 1}`, title: "Mass assignment: istek gövdesi doğrudan modele bağlanıyor (over-posting)",
          severity: "P1", module: "ACCESS", check: "ACC-3", category: "Mass Assignment", confidence: "medium",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "İstek gövdesi filtresiz modele yazılırsa saldırgan beklenmeyen alanları (is_admin, role, balance, tenant_id) set edip yetki yükseltebilir.",
          recommendation: "Yalnızca izin verilen alanları allow-list ile seç (pick/permit/DTO/zod schema); is_admin/role/tenant gibi alanları sunucuda sabitle. Rails: strong params; Laravel: $fillable/$guarded; Prisma: açık alan map'i.",
          effort: "M", autoFixable: false, references: ["OWASP A04:2021", "OWASP API6:2023", "CWE-915"],
        }));
      }

      // ACC-1 — kiracı izolasyonu: istemci id'siyle sorgu, tenant filtresi yok.
      if (data.usesTenancy && (QUERY_ID_OBJ.test(ln) || QUERY_ID_ARG.test(ln)) && !TENANT_COL.test(ln)) {
        push(makeFinding({
          id: `ACC-1-tenant-scope:${path}:${i + 1}`, title: "Nesne istemci id'siyle çekiliyor ama kiracı (tenant/org) filtresi yok",
          severity: "P0", module: "ACCESS", check: "ACC-1", category: "Multi-Tenant Isolation", confidence: "low",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "Sorgu yalnızca id ile filtreleniyorsa bir kiracının kullanıcısı, id'yi değiştirerek BAŞKA kiracının kaydına erişebilir (cross-tenant veri sızıntısı) — SaaS'ın en pahalı ihlali.",
          recommendation: "Her sorguya kiracı filtresini (tenant_id/org_id = oturumdaki kiracı) ekle; tercihen ORM'de zorunlu-tenant scope/middleware ya da RLS (row-level security) kullan. Sahiplik/erişim kontrolünü de doğrula.",
          effort: "M", autoFixable: false, references: ["OWASP A01:2021", "OWASP API1:2023 (BOLA)", "CWE-639"],
        }));
      }

      // ACC-4 — ayrıcalıklı/admin aksiyonu rol kontrolü olmadan.
      if (ADMIN_ROUTE.test(ln) && !fileHasRole) {
        push(makeFinding({
          id: `ACC-4-privileged-no-role:${path}:${i + 1}`, title: "Ayrıcalıklı/admin aksiyonu rol/izin kontrolü olmadan",
          severity: "P1", module: "ACCESS", check: "ACC-4", category: "Privilege Escalation", confidence: "low",
          evidence: [{ type: "file", source: path, location: loc, excerpt: ln.trim().slice(0, 160) }],
          impact: "admin/role/grant gibi ayrıcalıklı bir endpoint rol kontrolü olmadan çalışırsa sıradan kullanıcı yetki yükseltebilir.",
          recommendation: "Ayrıcalıklı aksiyonlara açık rol/izin kontrolü ekle (requireRole('admin')/policy/can). Yetkiyi sunucuda doğrula; istemciden gelen role/izin alanına asla güvenme.",
          effort: "M", autoFixable: false, references: ["OWASP A01:2021", "CWE-269"],
        }));
      }
    }
  }
  return findings;
}

export const accessModule: WardenModule = {
  id: "ACCESS",
  title: "Erişim Kontrolü & Kiracı İzolasyonu",
  active: false,
  applicable(ctx: ScanContext) {
    return collectAccessData(ctx.fs).usesWeb;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const data = collectAccessData(ctx.fs);
    const findings = analyzeAccess(data);
    ctx.audit.info(`ACCESS: ${findings.length} bulgu (${data.files.length} yüzey dosyası).`);
    return { findings, surface: data.files.length };
  },
};
