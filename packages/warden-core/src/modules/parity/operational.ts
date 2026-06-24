import { X509Certificate } from "node:crypto";
import type { Finding } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

export interface CertInfo {
  readonly path: string;
  readonly validTo: Date;
}

export interface OperationalData {
  readonly hasBackup: boolean;
  readonly backupEvidence: string | null;
  readonly hasRestore: boolean;
  readonly certs: readonly CertInfo[];
}

const BACKUP_RE = /backup|pg_dump|mysqldump|mongodump|dump\.sql/i;
const RESTORE_RE = /restore|pg_restore|mongorestore|mysql\s*<|drill/i;

/** TLS sertifika geçerlilik analizi — saf. days<0 süresi dolmuş, days<14 yakında. */
export function analyzeCertExpiry(cert: CertInfo, now: Date): Finding | null {
  const days = Math.floor((cert.validTo.getTime() - now.getTime()) / 86_400_000);
  if (days >= 14) return null;
  const expired = days < 0;
  return makeFinding({
    id: `A5-cert-expiry:${cert.path}`,
    title: expired
      ? `TLS sertifikası SÜRESİ DOLMUŞ (${Math.abs(days)} gün önce)`
      : `TLS sertifikası ${days} gün içinde sona eriyor`,
    severity: expired ? "P0" : "P1",
    module: "A",
    check: "A5",
    category: "Operational Health",
    confidence: "high",
    evidence: [{ type: "file", source: cert.path, excerpt: `notAfter=${cert.validTo.toISOString()}` }],
    impact: expired
      ? "Sertifika geçersiz; TLS el sıkışması başarısız, servis erişilemez/insecure."
      : "Yenilenmezse yakında kesinti. Otomatik yenileme yoksa risk yüksek.",
    recommendation: "Otomatik yenileme kur (ACME/Let's Encrypt, cert-manager) ve expiry alarmı ekle.",
    effort: "S",
    autoFixable: false,
    references: ["A5 Operational Health"],
  });
}

/** Backup var ama restore prosedürü/drill yok → P2. */
export function analyzeBackupRestore(data: OperationalData): Finding | null {
  if (!data.hasBackup || data.hasRestore) return null;
  return makeFinding({
    id: "A5-backup-no-restore",
    title: "Backup alınıyor ama restore prosedürü/drill bulunamadı",
    severity: "P2",
    module: "A",
    check: "A5",
    category: "Operational Health",
    confidence: "medium",
    evidence: [{ type: "file", source: data.backupEvidence ?? "backup", excerpt: "backup sinyali var, restore sinyali yok" }],
    impact: "Test edilmemiş yedek = yedek yok sayılır. Felakette geri dönüş garanti değil (iş emri A5/D1).",
    recommendation: "Düzenli RESTORE drill ekle (yedeği boş ortama geri yükleyip doğrula); prosedürü dokümante et.",
    effort: "M",
    autoFixable: false,
    references: ["D1 Backup & DR", "ISO 27001 A.12"],
  });
}

export function collectOperationalData(ctx: DetectContext): OperationalData {
  const files = ctx.find(() => true, { limit: 2000 });
  const scripts = (() => {
    const raw = ctx.readFile("package.json");
    if (!raw) return "";
    try {
      return JSON.stringify((JSON.parse(raw) as { scripts?: unknown }).scripts ?? {});
    } catch {
      return "";
    }
  })();

  const backupFile = files.find((p) => BACKUP_RE.test(p)) ?? null;
  const hasBackup = backupFile !== null || BACKUP_RE.test(scripts);
  const hasRestore = files.some((p) => RESTORE_RE.test(p)) || RESTORE_RE.test(scripts);

  const certPaths = files.filter((p) => /\.(pem|crt|cert)$/i.test(p)).slice(0, 20);
  const certs: CertInfo[] = [];
  for (const p of certPaths) {
    const raw = ctx.readFile(p);
    if (!raw || !raw.includes("BEGIN CERTIFICATE")) continue;
    try {
      const x = new X509Certificate(raw);
      certs.push({ path: p, validTo: new Date(x.validTo) });
    } catch {
      /* sertifika değil */
    }
  }

  return { hasBackup, backupEvidence: backupFile, hasRestore, certs };
}

/** A5 — saf analiz birleşimi. */
export function analyzeOperational(data: OperationalData, now: Date): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];
  const backup = analyzeBackupRestore(data);
  if (backup) findings.push(backup);
  for (const c of data.certs) {
    const f = analyzeCertExpiry(c, now);
    if (f) findings.push(f);
  }

  // Hiç sinyal yoksa (ne backup ne cert) → doğrulanamadı.
  const assessed = data.hasBackup || data.certs.length > 0;
  if (!assessed) {
    return {
      findings,
      layer: {
        code: "A5",
        name: "Operational Health",
        status: "unknown",
        score: null,
        note: "Backup/cert sinyali statik olarak bulunamadı (canlı sağlık için runtime gerekir).",
        findingIds: [],
      },
    };
  }

  let score = 10;
  for (const f of findings) score -= f.severity === "P0" ? 6 : f.severity === "P1" ? 2.5 : 1;
  const status = findings.some((f) => f.severity === "P0") ? "risk" : findings.length > 0 ? "warn" : "ok";
  return {
    findings,
    layer: {
      code: "A5",
      name: "Operational Health",
      status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note: findings.length === 0 ? "Yedek + sertifika sinyalleri sağlıklı." : `${findings.length} operasyonel bulgu.`,
      findingIds: findings.map((f) => f.id),
    },
  };
}
