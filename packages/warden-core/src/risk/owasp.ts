import type { Finding } from "../model/finding.ts";
import type { Checklist, ComplianceItem } from "../model/compliance.ts";
import { has, idStarts } from "./standards.ts";
import type { TrackedControl } from "./standards.ts";

/**
 * OWASP Top 10:2021 uyum checklist'i.
 * =========================================================================
 * Modül E ARTIK BİR SKOR BOYUTU DEĞİL (v0.10). OWASP Top 10 bir TAKSONOMİdir, bir tarama
 * boyutu değil: kendi bulgusu olmayan bir eşleştirme modülü skor tablosunda ya kalıcı "n/d"
 * kalır ya da anlamsızca 10/10 alır. Bunun yerine mevcut bulguların ÜZERİNE oturan bir uyum
 * katmanı: A01–A10 kontrolleri, ÇALIŞAN modüllerin ürettiği bulgulardan HİBRİT türetilir.
 *
 *   L1 (referans) — bulgunun `references` dizisindeki "OWASP A0x:2021" kodu.
 *   L2 (türetme)  — `check` / `module` / `id` önekinden çıkarım. GEREKLİDİR: cloud, k8s,
 *                   parity, compliance ve SARIF/OSV içe-aktarımı bulguları OWASP referansı
 *                   TAŞIMAZ; saf referans-ayrıştırma bu modüllere kördür.
 *
 * DÜRÜSTLÜK İLKESİ (asvs.ts ile aynı): status YALNIZCA
 *   "fail"    → bu kategoriyi ihlal eden en az bir aktif bulgu var,
 *   "unknown" → doğrulanamadı (manuel/canlı test gerekir).
 * "pass" ASLA üretilmez — Warden statik analizle "bu kategoriden temizsiniz" iddia etmez.
 * =========================================================================
 */

/**
 * TAM-STRING anchor'lı desen. `asvs.ts`'in gevşek `/ASVS\s*([\d.]+)/` deseninden BİLİNÇLİ
 * olarak ayrılıyoruz, çünkü `references` iki yönlü bir kanaldır ve serbest metin içerir:
 *   · kev.ts        → "CISA KEV (aktif sömürülüyor)", "EPSS 87.3%"
 *   · reachability  → "reachable (import grafında)"
 *   · modüller      → "OWASP API1 (BOLA)", "OWASP API5:2023" (API Top 10 — farklı taksonomi)
 * `^…$` + trim() sayesinde bunların hiçbiri kazara bir kategoriyi tetikleyemez.
 */
const OWASP_RE = /^OWASP\s*A(0[1-9]|10):2021$/i;

/** Bulgunun referanslarındaki OWASP 2021 kategorileri ("A01" biçiminde). */
export function owaspCategoriesOf(f: Finding): Set<string> {
  const out = new Set<string>();
  for (const ref of f.references ?? []) {
    const m = OWASP_RE.exec(ref.trim());
    if (m?.[1]) out.add(`A${m[1]}`);
  }
  return out;
}

/** L1: referans katmanı. */
const ref = (f: Finding, cat: string): boolean => owaspCategoriesOf(f).has(cat);

/**
 * A03 türetmesi `check === "B6"` üzerinden gider; ama SSRF (A10), path traversal (A01) ve
 * XXE (A05) de B6 ailesindedir. Çifte sayımı önlemek için negatif filtre.
 */
const B6_ELSEWHERE = (f: Finding): boolean => idStarts(f, "B6-ssrf", "B6-path-traversal", "B6-xxe");

const CONTROLS: readonly TrackedControl[] = [
  {
    control: "A01:2021",
    title: "Broken Access Control",
    // Public veri deposu / IAM wildcard → A01 (CWE-284: veriye erişim kontrolü),
    // açık ağ/SSL modu → A05 (altyapı yanlış yapılandırma). Bkz. A05.
    match: (f) =>
      ref(f, "A01") ||
      has(f, "B5", "ACC-1", "ACC-2", "ACC-3", "ACC-4", "C3", "WEB-1", "UPLOAD-2") ||
      idStarts(
        f,
        "B6-path-traversal",
        "B7-open-redirect",
        "CLOUD-AWS-s3-public",
        "CLOUD-AWS-s3-no-block",
        "CLOUD-AWS-iam-wildcard",
        "CLOUD-AWS-rds-public",
        "CLOUD-AZ-storage-public",
        "CLOUD-GCP-bucket-public",
        "CLOUD-GCP-sql-public",
      ),
  },
  {
    control: "A02:2021",
    title: "Cryptographic Failures",
    match: (f) => ref(f, "A02") || has(f, "B3", "PRIV-3") || idStarts(f, "B3-go-insecure-tls", "A5-cert-expiry", "AI-3"),
  },
  {
    control: "A03:2021",
    title: "Injection (SQL · NoSQL · Command · LDAP · SSTI · XSS)",
    match: (f) => ref(f, "A03") || (has(f, "B6") && !B6_ELSEWHERE(f)) || has(f, "FE-3", "EMAIL-1", "EMAIL-2"),
  },
  {
    control: "A04:2021",
    title: "Insecure Design",
    match: (f) => ref(f, "A04") || has(f, "FLOW-1", "FLOW-2", "FLOW-3", "UPLOAD-1", "UPLOAD-3") || f.module === "PAY",
  },
  {
    control: "A05:2021",
    title: "Security Misconfiguration",
    // XXE, OWASP 2021'de A05'e birleştirildi (kuralın kendi referansı da A05).
    match: (f) =>
      ref(f, "A05") ||
      has(f, "B7", "B9", "FE-2", "FE-4", "FE-6", "FE-7", "C1", "C2", "C5", "C6", "WEB-2", "WEB-3", "API-4") ||
      f.module === "K8S" ||
      idStarts(f, "B6-xxe", "CLOUD-AWS-sg-open", "CLOUD-GCP-fw-open", "CLOUD-CF-ssl-flexible"),
  },
  {
    control: "A06:2021",
    title: "Vulnerable and Outdated Components",
    // SARIF içe-aktarımında `check` araç kural-id'sidir (adapters/sarif.ts) → CVE varlığı
    // en güvenilir sinyal (trivy/grype/snyk/osv).
    match: (f) => ref(f, "A06") || has(f, "B2") || (f.cves?.length ?? 0) > 0,
  },
  {
    control: "A07:2021",
    title: "Identification and Authentication Failures",
    // K8S-plain-secret → A07 (B1 hardcoded-secret ile tutarlı); diğer tüm K8S → A05.
    match: (f) =>
      ref(f, "A07") ||
      has(f, "B1", "B4", "FE-1", "AUTH-1", "AUTH-2", "AUTH-3", "AUTH-4", "AUTH-5", "AUTH-6", "D3") ||
      idStarts(f, "K8S-plain-secret"),
  },
  {
    control: "A08:2021",
    title: "Software and Data Integrity Failures",
    match: (f) => ref(f, "A08") || has(f, "D5") || idStarts(f, "B8-"),
  },
  {
    control: "A09:2021",
    title: "Security Logging and Monitoring Failures",
    // NOT: D4 (soft-delete yok) BİLEREK dahil DEĞİL — o bir veri-koruma (GDPR/KVKK) konusu,
    // loglama/izleme değil. A09'a bağlamak eşleştirmeyi savunulamaz kılardı.
    match: (f) => ref(f, "A09") || has(f, "D2", "PRIV-1", "PRIV-2", "PRIV-5"),
  },
  {
    control: "A10:2021",
    title: "Server-Side Request Forgery (SSRF)",
    match: (f) => ref(f, "A10") || idStarts(f, "B6-ssrf"),
  },
];

/**
 * OWASP Top 10:2021 checklist'i (✖ ihlal var · – doğrulanamadı).
 * `active` (waiver sonrası) bulgulardan kurulmalıdır — bkz. orchestrator.ts.
 */
export function buildOwaspChecklist(findings: readonly Finding[]): Checklist {
  const items: ComplianceItem[] = CONTROLS.map((c) => {
    const hits = findings.filter((f) => c.match(f));
    if (hits.length === 0) {
      return { control: c.control, title: c.title, status: "unknown" as const, note: "doğrulanamadı (manuel)" };
    }
    // İzlenebilirlik: hangi kural ailesi tetikledi (satır/dosya eki atılır).
    const kinds = [...new Set(hits.map((f) => f.id.split(":")[0] ?? f.id))].sort();
    const shown = kinds.slice(0, 3).join(", ");
    const more = kinds.length > 3 ? ` +${kinds.length - 3}` : "";
    const p0 = hits.filter((f) => f.severity === "P0").length;
    return {
      control: c.control,
      title: c.title,
      status: "fail" as const,
      note: `${hits.length} bulgu${p0 > 0 ? ` (P0: ${p0})` : ""} — ${shown}${more}`,
    };
  });
  return { name: "OWASP Top 10:2021", standard: "OWASP Top 10", items };
}
