import type { Finding } from "../../model/finding.ts";
import type { Checklist, ComplianceItem, ComplianceResult } from "../../model/compliance.ts";
import { makeFinding } from "../../util/finding.ts";

/** Kart verisi tarama isabeti (D7). */
export interface CardHit {
  readonly file: string;
  readonly line: number;
  readonly kind: "cvv" | "pan";
  readonly excerpt: string;
}

export interface ComplianceData {
  /** Tüm bağımlılıklar (dep + devDep). */
  readonly deps: Readonly<Record<string, string>>;
  readonly hasCI: boolean;
  readonly ciFiles: readonly string[];
  /** CI içeriğinde test/lint adımı görüldü mü. */
  readonly ciHasTestGate: boolean;
  readonly prismaSchema: string | null;
  /** Kişisel veri bağlamı (ör. User/Customer modeli) var mı. */
  readonly hasPersonalData: boolean;
  /** Kart verisi tarama isabetleri. */
  readonly cardHits: readonly CardHit[];
  /** Yedekleme sinyali (A5 ile paylaşımlı). */
  readonly hasBackup: boolean;
  readonly hasRestore: boolean;
}

function has(deps: Readonly<Record<string, string>>, ...names: string[]): boolean {
  return names.some((n) => Object.keys(deps).some((d) => d === n || d.startsWith(n)));
}

const OBSERVABILITY = [
  "@sentry/", "@rollbar", "rollbar", "@datadog/", "dd-trace", "@opentelemetry/", "newrelic", "elastic-apm-node",
  // Python
  "sentry-sdk", "ddtrace", "elastic-apm", "opentelemetry", "scout-apm",
  // PHP / Laravel
  "sentry/sentry-laravel", "sentry/sentry", "bugsnag/bugsnag-laravel",
  // .NET
  "sentry", "serilog", "microsoft.applicationinsights", "opentelemetry",
  // Go
  "github.com/getsentry/sentry-go", "go.opentelemetry.io", "github.com/datadog/dd-trace-go",
];
const LOGGERS = ["pino", "winston", "bunyan", "@nestjs/common", "structlog", "loguru", "monolog/monolog", "serilog"];
const SECRET_MGR = [
  "@aws-sdk/client-secrets-manager", "@azure/keyvault-secrets", "@google-cloud/secret-manager", "node-vault", "@hashicorp/", "dotenv-vault",
  // Python
  "hvac", "azure-keyvault-secrets", "google-cloud-secret-manager",
  // .NET
  "azure.security.keyvault.secrets", "azure.extensions.aspnetcore.configuration.secrets",
];
const COOKIE_CONSENT = ["react-cookie-consent", "vanilla-cookieconsent", "cookieconsent", "@osano/", "klaro", "tarteaucitron"];

/** Modül D — saf analiz: D1–D8 maturity + uyum bulguları + checklist'ler. */
export function analyzeCompliance(data: ComplianceData): { findings: Finding[]; result: ComplianceResult } {
  const findings: Finding[] = [];

  // D2 Gözlemlenebilirlik
  const hasErrorTracking = has(data.deps, ...OBSERVABILITY);
  const hasLogger = has(data.deps, ...LOGGERS);
  if (!hasErrorTracking) {
    findings.push(
      makeFinding({
        id: "D2-no-error-tracking",
        title: "Hata izleme (Sentry/Datadog vb.) tespit edilmedi",
        severity: "P2", module: "D", check: "D2", category: "Observability", confidence: "medium",
        evidence: [{ type: "config", source: "package.json", excerpt: "observability bağımlılığı yok" }],
        impact: "Üretimdeki hatalar görünmez; olay müdahalesi kör ilerler.",
        recommendation: "Sentry/Datadog/OpenTelemetry entegre et; yapılandırılmış log + request korelasyon ID ekle.",
        effort: "M", autoFixable: false, references: ["D2"],
      }),
    );
  }

  // D3 Secret yönetimi
  const hasSecretMgr = has(data.deps, ...SECRET_MGR);
  if (!hasSecretMgr) {
    findings.push(
      makeFinding({
        id: "D3-no-secret-manager",
        title: "Vault/KMS/secret manager tespit edilmedi (muhtemelen düz .env)",
        severity: "P2", module: "D", check: "D3", category: "Secret Management", confidence: "low",
        evidence: [{ type: "config", source: "package.json", excerpt: "secret manager bağımlılığı yok" }],
        impact: "Düz .env secret'ları rotasyon/erişim denetimi olmadan tutar.",
        recommendation: "Vault/AWS Secrets Manager/Azure Key Vault/GCP Secret Manager kullan; rotasyon politikası tanımla.",
        effort: "M", autoFixable: false, references: ["D3", "ISO 27001 A.10"],
      }),
    );
  }

  // D5 CI/CD hijyeni
  if (!data.hasCI) {
    findings.push(
      makeFinding({
        id: "D5-no-ci",
        title: "CI/CD pipeline tespit edilmedi",
        severity: "P2", module: "D", check: "D5", category: "CI/CD", confidence: "high",
        evidence: [{ type: "config", source: ".github/workflows | .gitlab-ci.yml", excerpt: "CI yapılandırması bulunamadı" }],
        impact: "Otomatik test/lint/güvenlik taraması ve dağıtım kapısı yok; regresyon ve insan hatası riski.",
        recommendation: "CI ekle (test + lint + image/dependency tarama + branch koruması).",
        effort: "M", autoFixable: false, references: ["D5", "SLSA"],
      }),
    );
  } else if (!data.ciHasTestGate) {
    findings.push(
      makeFinding({
        id: "D5-ci-no-test-gate",
        title: "CI var ama test/lint kapısı tespit edilmedi",
        severity: "P3", module: "D", check: "D5", category: "CI/CD", confidence: "medium",
        evidence: [{ type: "config", source: data.ciFiles[0] ?? "CI", excerpt: "test/lint adımı görülmedi" }],
        impact: "Pipeline değişiklikleri doğrulamadan geçirebilir.",
        recommendation: "CI'a test + lint + güvenlik taraması adımı ekle; başarısızlıkta merge'i engelle.",
        effort: "S", autoFixable: false, references: ["D5"],
      }),
    );
  }

  // D1 Backup & DR (A5 ile paylaşımlı sinyal)
  if (data.hasBackup && !data.hasRestore) {
    findings.push(
      makeFinding({
        id: "D1-no-restore-drill",
        title: "Yedek var ama test edilmiş restore prosedürü yok (DR)",
        severity: "P2", module: "D", check: "D1", category: "Backup & DR", confidence: "medium",
        evidence: [{ type: "file", source: "backup", excerpt: "restore/drill sinyali yok" }],
        impact: "Test edilmemiş yedek güvenilmezdir; felakette geri dönüş garanti değil.",
        recommendation: "Düzenli restore drill + off-site + retention politikası tanımla ve dokümante et.",
        effort: "M", autoFixable: false, references: ["D1", "ISO 27001 A.12"],
      }),
    );
  }

  // D4 Veri koruma (GDPR/KVKK) + D8 Privacy
  const schema = data.prismaSchema ?? "";
  const hasSoftDelete = /deletedAt|deleted_at|isDeleted|is_deleted/i.test(schema);
  const hasCookieConsent = has(data.deps, ...COOKIE_CONSENT);
  if (data.hasPersonalData && !hasSoftDelete) {
    findings.push(
      makeFinding({
        id: "D4-no-soft-delete",
        title: "Kişisel veri modeli var ama soft-delete/silme izi tespit edilmedi",
        severity: "P2", module: "D", check: "D4", category: "Data Protection", confidence: "low",
        evidence: [{ type: "config", source: "model şeması (prisma/django)", excerpt: "deletedAt/is_deleted yok" }],
        impact: "Silme talebi (GDPR Art.17 / KVKK) ve denetim izi sağlanamayabilir.",
        recommendation: "Soft-delete + sert silme süreci; veri export endpoint'i; retention politikası.",
        effort: "M", autoFixable: false, references: ["GDPR Art.17", "KVKK"],
      }),
    );
  }

  // D7 PCI-DSS — kart verisi tarama bulguları
  for (const hit of data.cardHits) {
    if (hit.kind === "cvv") {
      findings.push(
        makeFinding({
          id: `D7-cvv-storage:${hit.file}:${hit.line}`,
          title: "CVV/CVC saklanıyor olabilir — PCI-DSS KESİNLİKLE YASAK",
          severity: "P0", module: "D", check: "D7", category: "PCI-DSS", confidence: "medium",
          evidence: [{ type: "file", source: hit.file, location: String(hit.line), excerpt: hit.excerpt }],
          impact: "Yetkilendirme sonrası CVV saklamak PCI-DSS req 3.2 ihlali; ağır ceza + kart şeması riski.",
          recommendation: "CVV'yi ASLA saklama; yalnızca işlem anında kullan ve at.",
          effort: "M", autoFixable: false, references: ["PCI-DSS 4.0 req 3.2"],
        }),
      );
    } else {
      findings.push(
        makeFinding({
          id: `D7-pan-storage:${hit.file}:${hit.line}`,
          title: "Kart numarası (PAN) saklanıyor olabilir — maskeleme/tokenizasyon gerekir",
          severity: "P1", module: "D", check: "D7", category: "PCI-DSS", confidence: "low",
          evidence: [{ type: "file", source: hit.file, location: String(hit.line), excerpt: hit.excerpt }],
          impact: "PAN şifresiz/maskesiz saklanırsa PCI-DSS req 3.3/3.4 ihlali.",
          recommendation: "PAN saklama; ödeme sağlayıcı tokenizasyonu kullan. Zorunluysa şifrele + ilk6/son4 dışında maskele.",
          effort: "L", autoFixable: false, references: ["PCI-DSS 4.0 req 3.3/3.4"],
        }),
      );
    }
  }

  const result: ComplianceResult = {
    checklists: [
      buildPciChecklist(data, hasErrorTracking),
      buildPrivacyChecklist(data, hasSoftDelete, hasCookieConsent),
    ],
  };
  return { findings, result };
}

function statusOf(condition: boolean | null): ComplianceItem["status"] {
  if (condition === null) return "unknown";
  return condition ? "pass" : "fail";
}

function buildPciChecklist(data: ComplianceData, hasLogging: boolean): Checklist {
  const storesCvv = data.cardHits.some((h) => h.kind === "cvv");
  const storesPan = data.cardHits.some((h) => h.kind === "pan");
  const cardContext = data.cardHits.length > 0;
  const items: ComplianceItem[] = [
    { control: "PCI 3.2", title: "CVV/CVC saklanmıyor", status: cardContext ? (storesCvv ? "fail" : "pass") : "unknown", note: storesCvv ? "CVV saklama tespiti var" : "tespit yok" },
    { control: "PCI 3.3/3.4", title: "PAN maskeli/tokenize", status: storesPan ? "fail" : cardContext ? "partial" : "unknown", note: storesPan ? "PAN saklama tespiti" : "doğrulanamadı" },
    { control: "PCI 4.x", title: "TLS 1.2+ aktarımda", status: "unknown", note: "canlı TLS doğrulaması Modül C (DAST) ile" },
    { control: "PCI 8.x", title: "MFA + parola politikası", status: "unknown", note: "auth tasarımı Modül B (B4) ile değerlendirilir" },
    { control: "PCI 10.x", title: "Access/Audit logging", status: hasLogging ? "partial" : "fail", note: hasLogging ? "log altyapısı var, kapsam manuel" : "log altyapısı tespit edilmedi" },
  ];
  return { name: "PCI-DSS 4.0", standard: "PCI-DSS 4.0", items };
}

function buildPrivacyChecklist(data: ComplianceData, hasSoftDelete: boolean, hasCookieConsent: boolean): Checklist {
  const pd = data.hasPersonalData;
  const items: ComplianceItem[] = [
    { control: "GDPR Art.17 / KVKK", title: "Veri silme süreci (soft-delete)", status: pd ? statusOf(hasSoftDelete) : "unknown", note: hasSoftDelete ? "deletedAt/isDeleted bulundu" : "tespit edilmedi" },
    { control: "GDPR Art.20", title: "Veri taşınabilirliği / export", status: "unknown", note: "export endpoint'i manuel doğrulanmalı" },
    { control: "GDPR Art.7", title: "Consent management", status: "unknown", note: "rıza yönetimi manuel doğrulanmalı" },
    { control: "ePrivacy", title: "Cookie consent", status: hasCookieConsent ? "pass" : "unknown", note: hasCookieConsent ? "cookie consent kütüphanesi bulundu" : "tespit edilmedi" },
    { control: "Retention", title: "Data retention politikası", status: "unknown", note: "retention kuralı manuel doğrulanmalı" },
  ];
  return { name: "Privacy (KVKK/GDPR)", standard: "GDPR/KVKK", items };
}
