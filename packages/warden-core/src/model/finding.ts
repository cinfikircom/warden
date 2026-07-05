import type { Severity } from "./severity.ts";

/**
 * Denetim modülleri (iş emri §4 + genişletmeler). Bir bulgu hangi modülden geldiğini taşır.
 * Detaylı kontrol kataloğu: docs/CHECKS.md
 */
export const MODULES = [
  "A", // Parity & Deployment Discovery (pasif)
  "B", // Statik Uygulama Güvenliği / SAST (pasif)
  "C", // Dinamik / DAST & Pentest (AKTİF — yetki kapılı)
  "D", // Uyum & Operasyonel Olgunluk
  "E", // OWASP Top 10 / ASVS eşleştirme (pasif)
  "CLOUD", // AWS / Azure / GCP / Cloudflare
  "K8S", // Kubernetes
  "API", // OWASP API Top 10
  "FE", // Frontend Security
  "AI", // AI / LLM Security
  "PAY", // Ödeme Güvenliği & Güvenilirliği (webhook/tutar/mutabakat/orphan ödeme)
  "ACCESS", // Erişim Kontrolü & Kiracı İzolasyonu (OWASP #1: multi-tenant/authz/mass-assignment)
  "AUTH", // Kimlik & Oturum Sertleştirme (MFA/reset-token/cookie/JWT/brute-force/parola politikası)
  "PRIV", // Veri Gizliliği & Denetim İzi (PII log/URL, at-rest şifreleme, KVKK/GDPR erasure, audit trail)
  "WEB", // CSRF, Clickjacking & Güvenlik Başlıkları (pasif: csrf yok / helmet yok / yansıtılan CORS+credentials)
  "FLOW", // İş-Akışı & Veri Bütünlüğü (transaction'sız çok-adımlı yazma / atomik olmayan sayaç / idempotent olmayan oluşturma)
  "EMAIL", // E-posta Güvenliği (header injection / HTML gövdeye kaçışsız girdi / TLS'siz SMTP) — SPF/DKIM/DMARC DAST/DNS'te
] as const;

export type ModuleId = (typeof MODULES)[number];

/**
 * Bulgu güven düzeyi. Yüksek = kanıt güçlü, false-positive olasılığı düşük.
 * (İş emri §8: kanıtsız bulgu yok; düşük güvenli bulgular işaretlenir.)
 */
export const CONFIDENCE = ["high", "medium", "low"] as const;
export type Confidence = (typeof CONFIDENCE)[number];

/**
 * Kanıt tipi (Evidence Engine). Tüm modüller (A/B/C/...) bu ortak formatı kullanır;
 * böylece Modül B/C geldiğinde veri modeli büyümez. SARIF'e doğrudan eşlenir:
 *   file → physicalLocation, endpoint → logicalLocation, command/config → properties.
 */
export const EVIDENCE_TYPES = ["file", "command", "endpoint", "config"] as const;
export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

export interface Evidence {
  readonly type: EvidenceType;
  /** Ana konum: dosya yolu · komut metni · URL · config anahtarı. */
  readonly source: string;
  /** İnce konum: satır no/aralık, alan adı, header adı. Örn. "42" ya da "12-15". */
  readonly location?: string;
  /** Kanıt parçası (secret'lar MASKELENMİŞ olmalı — bkz. secret/mask.ts). */
  readonly excerpt?: string;
}

/**
 * Standart bulgu kaydı (iş emri §4).
 * Her bulgu STABİL bir `id` ve içerik-türevli bir `fingerprint` taşır (CI gate, dedup).
 */
export interface Finding {
  /** İnsan-okur stabil tanımlayıcı, örn. "B3-weak-hash". */
  readonly id: string;
  /** Aynı bulgunun çalıştırmalar arası eşlenmesi için içerik özeti. */
  readonly fingerprint: string;
  readonly title: string;
  readonly severity: Severity;
  readonly module: ModuleId;
  /** Modül içi kontrol kodu, örn. "B3", "E2", "API1". */
  readonly check: string;
  readonly category: string;
  readonly confidence: Confidence;
  readonly evidence: readonly Evidence[];
  /** Etki açıklaması: neden önemli. */
  readonly impact: string;
  /** Önerilen düzeltme (özet). Detaylı prompt remediation-playbook'a gider. */
  readonly recommendation: string;
  /** Tahmini efor. */
  readonly effort: "S" | "M" | "L";
  /** Otomatik düzeltilebilir mi (remediation prompt üretilsin mi). */
  readonly autoFixable: boolean;
  /** Uyum/standart eşleştirmeleri, örn. ["OWASP A02:2021", "ASVS 6.2.3", "PCI-DSS 3.4"]. */
  readonly references?: readonly string[];
  /** CVSS v4 temel skoru (0–10), varsa (risk motoru doldurur). */
  readonly cvss?: number;
  /** Sömürülebilirlik (risk motoru): ne kadar kolay/uzaktan sömürülür. */
  readonly exploitability?: "high" | "medium" | "low";
  /** CISA KEV: bilinen-sömürülen zafiyet listesinde mi (varsa risk motoru işaretler). */
  readonly kev?: boolean;
  /** EPSS: 30 gün içinde vahşi-doğada sömürülme olasılığı (0–1), varsa. */
  readonly epss?: number;
  /** İlişkili CVE tanımlayıcıları (KEV/EPSS eşleştirmesi + bağımlılık/import bulguları için). */
  readonly cves?: readonly string[];
  /**
   * Erişilebilirlik (reachability): zafiyetli bağımlılık kaynak kodun içe-aktarım grafında mı.
   * true=doğrudan import ediliyor (öncelik yüksek), false=grafikte yok (öncelik düşük), undefined=bilinmiyor.
   * NOT: import-seviyesi heuristik; tam çağrı-grafı analizi değil.
   */
  readonly reachable?: boolean;
}
