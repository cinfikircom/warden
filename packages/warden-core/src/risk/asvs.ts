import type { Finding } from "../model/finding.ts";
import type { Checklist, ComplianceItem } from "../model/compliance.ts";

/**
 * OWASP ASVS eşleştirmesi. Bulgu referanslarındaki "ASVS x.y" kodları, izlenen ASVS
 * kontrol kümesine eşlenir. Bir kontrolü ihlal eden bulgu varsa ✖ Failed; yoksa – Unknown
 * (Warden statik olarak "geçti" iddia etmez — dürüst raporlama, iş emri §8).
 */

interface AsvsControl {
  readonly code: string; // "2.1" gibi
  readonly title: string;
}

const TRACKED: readonly AsvsControl[] = [
  { code: "2.1", title: "Parola gücü gereksinimleri" },
  { code: "3.3", title: "Oturum/token zaman aşımı" },
  { code: "3.4", title: "Çerez güvenliği (Secure/HttpOnly/SameSite)" },
  { code: "4.2", title: "Nesne düzeyi erişim kontrolü (IDOR/BOLA)" },
  { code: "5.3", title: "Çıktı kodlama / injection savunması" },
  { code: "6.2", title: "Kriptografik algoritma sağlamlığı" },
  { code: "6.3", title: "Rastgelelik (güvenli RNG)" },
  { code: "6.4", title: "Secret yönetimi" },
];

const ASVS_RE = /ASVS\s*([\d]+(?:\.[\d]+)*)/i;

/** Bulgu referanslarından ihlal edilen ASVS kodlarını toplar. */
export function violatedAsvsCodes(findings: readonly Finding[]): Set<string> {
  const codes = new Set<string>();
  for (const f of findings) {
    for (const ref of f.references ?? []) {
      const m = ASVS_RE.exec(ref);
      if (m && m[1]) codes.add(m[1]);
    }
  }
  return codes;
}

/** ASVS checklist'i üretir (✖ ihlal var · – doğrulanamadı). */
export function buildAsvsChecklist(findings: readonly Finding[]): Checklist {
  const violated = violatedAsvsCodes(findings);
  const items: ComplianceItem[] = TRACKED.map((c) => {
    // "4.2" izlenen kontrol; bulgu "4.2.1" gibi alt kodu referans verebilir → ön-ek eşleşmesi.
    const hit = [...violated].some((v) => v === c.code || v.startsWith(`${c.code}.`));
    return {
      control: `ASVS ${c.code}`,
      title: c.title,
      status: hit ? ("fail" as const) : ("unknown" as const),
      note: hit ? "ilgili bulgu var" : "doğrulanamadı (manuel)",
    };
  });
  return { name: "OWASP ASVS", standard: "OWASP ASVS", items };
}
