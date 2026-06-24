import { connect } from "node:net";
import type { Finding } from "../../model/finding.ts";
import type { Severity } from "../../model/severity.ts";
import { makeFinding } from "../../util/finding.ts";
import type { AuditLog } from "../../audit/log.ts";

/**
 * C5 — hafif port/servis envanteri. EN HASSAS kontrol: yalnızca yetki kapısı açık VE
 * `allow_port_scan: true` iken çalışır. Tam nmap DEĞİL — kısa, sabit, hassas-port listesi.
 * Sadece TCP connect (banner grab/exploit yok).
 */

interface PortDef {
  readonly port: number;
  readonly service: string;
  readonly severity: Severity;
}

/** İnternete açık olmaması gereken hassas servis portları. */
export const SENSITIVE_PORTS: readonly PortDef[] = [
  { port: 22, service: "SSH", severity: "P2" },
  { port: 3389, service: "RDP", severity: "P1" },
  { port: 3306, service: "MySQL", severity: "P1" },
  { port: 5432, service: "PostgreSQL", severity: "P1" },
  { port: 6379, service: "Redis", severity: "P0" },
  { port: 27017, service: "MongoDB", severity: "P0" },
  { port: 9200, service: "Elasticsearch", severity: "P0" },
  { port: 5984, service: "CouchDB", severity: "P1" },
  { port: 11211, service: "Memcached", severity: "P1" },
  { port: 2375, service: "Docker API (TLS yok)", severity: "P0" },
];

/** Tek bir portun açık olup olmadığını TCP connect ile sınar (read-only). */
export function checkPort(host: string, port: number, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host, port, timeout: timeoutMs });
    let done = false;
    const finish = (open: boolean): void => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open);
    };
    socket.on("connect", () => finish(true));
    socket.on("timeout", () => finish(false));
    socket.on("error", () => finish(false));
  });
}

/** Açık portlardan bulgu üretir (saf). */
export function analyzePorts(host: string, openPorts: ReadonlyArray<{ port: number; service: string; severity: Severity }>): Finding[] {
  return openPorts.map((p) =>
    makeFinding({
      id: `C5-open-port:${host}:${p.port}`,
      title: `Hassas port açık: ${p.port}/${p.service} (${host})`,
      severity: p.severity,
      module: "C",
      check: "C5",
      category: "Open Port / Service",
      confidence: "high",
      evidence: [{ type: "endpoint", source: `${host}:${p.port}`, excerpt: `${p.service} TCP connect başarılı` }],
      impact: "Hassas servis internetten erişilebilir; doğrudan saldırı/veri sızıntısı yüzeyi.",
      recommendation: "Portu firewall/security group ile kapat; yalnızca özel ağdan eriş; auth + TLS zorunlu kıl.",
      effort: "M",
      autoFixable: false,
      references: ["CIS Benchmark", "OWASP A05:2021"],
    }),
  );
}

/** Allow-list host'ta hassas portları tarar (yalnızca C modülü gated bağlamında çağrılır). */
export async function scanPorts(host: string, audit?: AuditLog): Promise<Finding[]> {
  const open: Array<{ port: number; service: string; severity: Severity }> = [];
  for (const def of SENSITIVE_PORTS) {
    audit?.command(`tcp connect ${host}:${def.port}`, host);
    if (await checkPort(host, def.port)) open.push(def);
  }
  return analyzePorts(host, open);
}
