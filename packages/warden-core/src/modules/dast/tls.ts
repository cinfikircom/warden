import { connect } from "node:tls";
import type { Finding } from "../../model/finding.ts";
import { makeFinding } from "../../util/finding.ts";
import type { AuditLog } from "../../audit/log.ts";

/** C2 — canlı TLS bilgisi. */
export interface TlsInfo {
  readonly host: string;
  readonly protocol: string | null; // örn. "TLSv1.3"
  readonly validTo: Date | null;
  readonly authorized: boolean; // zincir geçerli mi
}

const WEAK_PROTOCOLS = new Set(["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]);

/** TLS bilgisini READ-ONLY toplar (yalnızca el sıkışma; veri göndermez). */
export function collectTls(host: string, audit?: AuditLog, port = 443): Promise<TlsInfo> {
  return new Promise((resolve) => {
    audit?.command(`tls handshake ${host}:${port}`, host);
    const socket = connect({ host, port, servername: host, timeout: 8000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const authorized = socket.authorized;
      const validTo = cert && cert.valid_to ? new Date(cert.valid_to) : null;
      socket.end();
      resolve({ host, protocol, validTo, authorized });
    });
    socket.on("error", () => resolve({ host, protocol: null, validTo: null, authorized: false }));
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ host, protocol: null, validTo: null, authorized: false });
    });
  });
}

/** TLS analizi — saf. Süresi dolmuş cert, yakında bitiş, zayıf protokol. */
export function analyzeTls(info: TlsInfo, now: Date): Finding[] {
  if (info.protocol === null && info.validTo === null) return []; // erişilemedi
  const findings: Finding[] = [];

  if (info.protocol && WEAK_PROTOCOLS.has(info.protocol)) {
    findings.push(
      makeFinding({
        id: `C2-weak-tls:${info.host}`,
        title: `Zayıf TLS protokolü: ${info.protocol}`,
        severity: "P1", module: "C", check: "C2", category: "TLS", confidence: "high",
        evidence: [{ type: "endpoint", source: `${info.host}:443`, excerpt: info.protocol }],
        impact: "Eski TLS sürümü bilinen saldırılara açık.",
        recommendation: "TLS 1.2+ zorunlu kıl; 1.0/1.1'i kapat.",
        effort: "M", autoFixable: false, references: ["PCI-DSS 4.0 req 4", "OWASP A02:2021"],
      }),
    );
  }

  if (info.validTo) {
    const days = Math.floor((info.validTo.getTime() - now.getTime()) / 86_400_000);
    if (days < 0) {
      findings.push(
        makeFinding({
          id: `C2-cert-expired:${info.host}`,
          title: `TLS sertifikası SÜRESİ DOLMUŞ (${Math.abs(days)} gün önce)`,
          severity: "P0", module: "C", check: "C2", category: "TLS", confidence: "high",
          evidence: [{ type: "endpoint", source: `${info.host}:443`, excerpt: `notAfter=${info.validTo.toISOString()}` }],
          impact: "Geçersiz sertifika; TLS başarısız, servis erişilemez/insecure.",
          recommendation: "Sertifikayı yenile; otomatik yenileme (ACME) + expiry alarmı kur.",
          effort: "S", autoFixable: false, references: ["PCI-DSS 4.0 req 4"],
        }),
      );
    } else if (days < 14) {
      findings.push(
        makeFinding({
          id: `C2-cert-soon:${info.host}`,
          title: `TLS sertifikası ${days} gün içinde sona eriyor`,
          severity: "P1", module: "C", check: "C2", category: "TLS", confidence: "high",
          evidence: [{ type: "endpoint", source: `${info.host}:443`, excerpt: `notAfter=${info.validTo.toISOString()}` }],
          impact: "Yenilenmezse yakında kesinti.",
          recommendation: "Otomatik yenileme kur; expiry alarmı ekle.",
          effort: "S", autoFixable: false, references: ["A5", "PCI-DSS 4.0 req 4"],
        }),
      );
    }
  }

  return findings;
}
