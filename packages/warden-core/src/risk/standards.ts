import type { Finding } from "../model/finding.ts";
import type { Checklist, ComplianceItem } from "../model/compliance.ts";

/**
 * CIS Benchmark ve ISO 27001:2022 Annex A eşleştirmesi. Bulgular check/module/kategoriden
 * ilgili kontrollere TÜRETİLİR (her bulguya referans eklemeye gerek kalmadan). İlgili bulgu
 * varsa kontrol ✖ Failed; yoksa – Unknown (Warden statik olarak "uyumlu" iddia etmez).
 */

interface TrackedControl {
  readonly control: string;
  readonly title: string;
  match(f: Finding): boolean;
}

function build(name: string, standard: string, controls: readonly TrackedControl[], findings: readonly Finding[]): Checklist {
  const items: ComplianceItem[] = controls.map((c) => {
    const hits = findings.filter((f) => c.match(f));
    return {
      control: c.control,
      title: c.title,
      status: hits.length > 0 ? ("fail" as const) : ("unknown" as const),
      note: hits.length > 0 ? `${hits.length} ilgili bulgu` : "doğrulanamadı (manuel)",
    };
  });
  return { name, standard, items };
}

const has = (f: Finding, ...checks: string[]): boolean => checks.includes(f.check);
const idStarts = (f: Finding, ...prefixes: string[]): boolean => prefixes.some((p) => f.id.startsWith(p));

/** ISO 27001:2022 Annex A (seçili kontroller). */
export function buildIsoChecklist(findings: readonly Finding[]): Checklist {
  const controls: TrackedControl[] = [
    { control: "A.5.15", title: "Erişim kontrolü", match: (f) => has(f, "B5", "E1", "C3") || idStarts(f, "K8S-privileged") },
    { control: "A.8.8", title: "Teknik zafiyet yönetimi", match: (f) => has(f, "B2") },
    { control: "A.8.9", title: "Yapılandırma yönetimi", match: (f) => has(f, "B7", "B9", "E5") || f.module === "CLOUD" || f.module === "K8S" },
    { control: "A.8.13", title: "Bilgi yedekleme", match: (f) => idStarts(f, "D1", "A5-backup") },
    { control: "A.8.15", title: "Loglama", match: (f) => has(f, "D2") },
    { control: "A.8.24", title: "Kriptografi kullanımı", match: (f) => has(f, "B3", "E2", "B1", "D3") || idStarts(f, "AI-3") },
    { control: "A.8.25", title: "Güvenli geliştirme yaşam döngüsü", match: (f) => has(f, "D5") },
    { control: "A.8.28", title: "Güvenli kodlama", match: (f) => has(f, "B6") },
  ];
  return build("ISO 27001:2022", "ISO 27001", controls, findings);
}

/** CIS Benchmark domain eşleştirmesi. */
export function buildCisChecklist(findings: readonly Finding[]): Checklist {
  const controls: TrackedControl[] = [
    { control: "CIS Kubernetes", title: "Kubernetes Benchmark", match: (f) => f.module === "K8S" },
    { control: "CIS AWS", title: "AWS Foundations Benchmark", match: (f) => has(f, "CLOUD-AWS") },
    { control: "CIS Azure", title: "Azure Foundations Benchmark", match: (f) => has(f, "CLOUD-AZ") },
    { control: "CIS GCP", title: "GCP Foundations Benchmark", match: (f) => has(f, "CLOUD-GCP") },
    { control: "CIS Docker", title: "Docker Benchmark", match: (f) => idStarts(f, "A3-") || /docker/i.test(f.category) },
  ];
  return build("CIS Benchmark", "CIS", controls, findings);
}
