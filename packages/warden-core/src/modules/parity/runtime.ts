import { execFileSync } from "node:child_process";
import type { Finding } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { AuditLog } from "../../audit/log.ts";
import { makeFinding } from "../../util/finding.ts";

export interface ContainerInfo {
  readonly name: string;
  readonly state: string; // running | exited | restarting ...
  readonly health: string | null; // healthy | unhealthy | starting | null
  readonly createdAt: Date | null;
  readonly restartCount: number;
}

export interface RuntimeData {
  readonly dockerAvailable: boolean;
  readonly containers: readonly ContainerInfo[];
}

function dockerAvailable(audit?: AuditLog): boolean {
  try {
    audit?.command("docker version --format {{.Server.Version}}");
    execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], { stdio: ["ignore", "ignore", "ignore"], timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/** Best-effort, READ-ONLY container envanteri. Docker yoksa boş döner. */
export function collectRuntimeData(root: string, audit?: AuditLog): RuntimeData {
  if (!dockerAvailable(audit)) return { dockerAvailable: false, containers: [] };
  try {
    audit?.command("docker compose ps --format json", root);
    const out = execFileSync("docker", ["compose", "ps", "--format", "json"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 10_000,
    });
    const containers: ContainerInfo[] = [];
    for (const line of out.split(/\r?\n/).filter((l) => l.trim())) {
      try {
        const o = JSON.parse(line) as Record<string, unknown>;
        containers.push({
          name: String(o["Name"] ?? o["Service"] ?? "?"),
          state: String(o["State"] ?? "?"),
          health: o["Health"] ? String(o["Health"]) : null,
          createdAt: o["CreatedAt"] ? new Date(String(o["CreatedAt"])) : null,
          restartCount: Number(o["ExitCode"] ?? 0),
        });
      } catch {
        /* satır JSON değil */
      }
    }
    return { dockerAvailable: true, containers };
  } catch {
    return { dockerAvailable: true, containers: [] };
  }
}

/** A3 — saf analiz. Crash-loop / unhealthy / bayat imaj. */
export function analyzeRuntime(data: RuntimeData, now: Date): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];

  if (!data.dockerAvailable || data.containers.length === 0) {
    return {
      findings,
      layer: {
        code: "A3",
        name: "Runtime Freshness",
        status: "unknown",
        score: null,
        note: data.dockerAvailable ? "Çalışan container bulunamadı." : "Docker erişilemedi — runtime doğrulanamadı.",
        findingIds: [],
      },
    };
  }

  let score = 10;
  for (const c of data.containers) {
    if (c.state === "restarting" || c.health === "unhealthy") {
      findings.push(
        makeFinding({
          id: `A3-unhealthy:${c.name}`,
          title: `Container sağlıksız/crash-loop: ${c.name} (${c.state}${c.health ? `, ${c.health}` : ""})`,
          severity: "P1",
          module: "A",
          check: "A3",
          category: "Runtime Freshness",
          confidence: "high",
          evidence: [{ type: "command", source: "docker compose ps", excerpt: `${c.name}: ${c.state}/${c.health}` }],
          impact: "Servis kararsız; istekler düşebilir veya iş kuyruğu işlenmeyebilir.",
          recommendation: "Logları incele (docker logs), healthcheck ve restart policy'yi düzelt; kök nedeni gider.",
          effort: "M",
          autoFixable: false,
        }),
      );
      score -= 2.5;
    }
    if (c.createdAt) {
      const ageDays = Math.floor((now.getTime() - c.createdAt.getTime()) / 86_400_000);
      if (ageDays > 14) {
        findings.push(
          makeFinding({
            id: `A3-stale-image:${c.name}`,
            title: `Container ${ageDays} gün önce build/başlatılmış: ${c.name} (güncel koddan olmayabilir)`,
            severity: "P2",
            module: "A",
            check: "A3",
            category: "Runtime Freshness",
            confidence: "medium",
            evidence: [{ type: "command", source: "docker compose ps", excerpt: `${c.name} created ${c.createdAt.toISOString()}` }],
            impact: "Çalışan imaj son commit'ten eski olabilir; deploy edilmemiş değişiklikler var.",
            recommendation: "Yeniden build & deploy; CI/CD ile imaj tazeliğini otomatikleştir.",
            effort: "S",
            autoFixable: false,
          }),
        );
        score -= 1;
      }
    }
  }

  const status = findings.some((f) => f.severity === "P0" || f.severity === "P1") ? "risk" : findings.length > 0 ? "warn" : "ok";
  return {
    findings,
    layer: {
      code: "A3",
      name: "Runtime Freshness",
      status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note: findings.length === 0 ? `${data.containers.length} container sağlıklı ve güncel.` : `${findings.length} runtime bulgusu.`,
      findingIds: findings.map((f) => f.id),
    },
  };
}
