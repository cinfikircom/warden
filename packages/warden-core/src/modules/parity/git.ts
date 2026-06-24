import { execFileSync } from "node:child_process";
import type { Finding } from "../../model/finding.ts";
import type { ParityLayer } from "../../model/parity.ts";
import type { AuditLog } from "../../audit/log.ts";
import { makeFinding } from "../../util/finding.ts";

export interface GitData {
  readonly isRepo: boolean;
  readonly branch: string | null;
  readonly mainBranch: string | null;
  readonly headSha: string | null;
  readonly mainSha: string | null;
  /** HEAD, ana daldan kaç commit geride. */
  readonly behind: number;
  /** HEAD, ana dalın kaç commit önünde. */
  readonly ahead: number;
  readonly dirty: boolean;
  readonly dirtyFiles: number;
}

function git(root: string, args: string[], audit?: AuditLog): string | null {
  try {
    audit?.command(`git ${args.join(" ")}`, root);
    return execFileSync("git", ["-C", root, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 10_000,
    }).trim();
  } catch {
    return null;
  }
}

/** READ-ONLY git komutlarıyla parity verisini toplar. */
export function collectGitData(root: string, audit?: AuditLog): GitData {
  const inside = git(root, ["rev-parse", "--is-inside-work-tree"], audit);
  if (inside !== "true") {
    return { isRepo: false, branch: null, mainBranch: null, headSha: null, mainSha: null, behind: 0, ahead: 0, dirty: false, dirtyFiles: 0 };
  }
  const branch = git(root, ["rev-parse", "--abbrev-ref", "HEAD"], audit);
  const headSha = git(root, ["rev-parse", "HEAD"], audit);

  // Ana dalı belirle: origin/HEAD → main → master.
  let mainBranch: string | null = null;
  const originHead = git(root, ["rev-parse", "--abbrev-ref", "origin/HEAD"], audit);
  if (originHead && originHead !== "origin/HEAD") mainBranch = originHead;
  else if (git(root, ["rev-parse", "--verify", "main"], audit)) mainBranch = "main";
  else if (git(root, ["rev-parse", "--verify", "master"], audit)) mainBranch = "master";

  const mainSha = mainBranch ? git(root, ["rev-parse", mainBranch], audit) : null;

  let behind = 0;
  let ahead = 0;
  if (mainBranch) {
    const counts = git(root, ["rev-list", "--left-right", "--count", `HEAD...${mainBranch}`], audit);
    if (counts) {
      const [a, b] = counts.split(/\s+/).map((n) => Number.parseInt(n, 10));
      ahead = Number.isFinite(a) ? (a as number) : 0;
      behind = Number.isFinite(b) ? (b as number) : 0;
    }
  }

  const status = git(root, ["status", "--porcelain"], audit) ?? "";
  const dirtyFiles = status === "" ? 0 : status.split("\n").filter((l) => l.trim() !== "").length;

  return {
    isRepo: true,
    branch,
    mainBranch,
    headSha,
    mainSha,
    behind,
    ahead,
    dirty: dirtyFiles > 0,
    dirtyFiles,
  };
}

/** A1 — saf analiz. Verilen git verisinden bulgu + katman skoru üretir. */
export function analyzeGitParity(data: GitData): { findings: Finding[]; layer: ParityLayer } {
  const findings: Finding[] = [];

  if (!data.isRepo) {
    return {
      findings,
      layer: { code: "A1", name: "Git Parity", status: "unknown", score: null, note: "Git deposu değil — doğrulanamadı.", findingIds: [] },
    };
  }

  let score = 10;

  if (data.behind > 0 && data.headSha !== data.mainSha) {
    const f = makeFinding({
      id: "A1-production-drift",
      title: `Production drift: HEAD ana daldan ${data.behind} commit geride`,
      severity: "P0",
      module: "A",
      check: "A1",
      category: "Deployment Parity",
      confidence: "high",
      evidence: [
        {
          type: "command",
          source: `git rev-list --left-right --count HEAD...${data.mainBranch ?? "main"}`,
          excerpt: `HEAD=${data.headSha?.slice(0, 8)} ${data.mainBranch}=${data.mainSha?.slice(0, 8)} (ahead ${data.ahead} / behind ${data.behind})`,
        },
      ],
      impact: "Çalışan kod ana daldan eski. Yapılan düzeltmeler/güvenlik yamaları henüz canlıda olmayabilir.",
      recommendation: `Deploy'u ana dala hizala (${data.mainBranch}); CI/CD ile otomatik dağıtım kur.`,
      effort: "M",
      autoFixable: false,
    });
    findings.push(f);
    score -= 6;
  }

  if (data.dirty) {
    const f = makeFinding({
      id: "A1-dirty-tree",
      title: `Çalışma ağacı kirli: ${data.dirtyFiles} dosya commit edilmemiş (elle düzenleme = drift)`,
      severity: "P1",
      module: "A",
      check: "A1",
      category: "Deployment Parity",
      confidence: "high",
      evidence: [{ type: "command", source: "git status --porcelain", excerpt: `${data.dirtyFiles} değişiklik` }],
      impact: "Çalışan ortam kaynak kontrolünde olmayan elle değişiklikler içeriyor; tekrar üretilemez.",
      recommendation: "Değişiklikleri commit'le veya geri al; ortamı git ile yeniden oluşturulabilir tut.",
      effort: "S",
      autoFixable: false,
    });
    findings.push(f);
    score -= 2.5;
  }

  const status = score >= 9.5 ? "ok" : score >= 6 ? "warn" : "risk";
  const note =
    findings.length === 0
      ? `Temiz ve güncel (${data.branch} = ${data.mainBranch}).`
      : `${data.behind} commit geride, ${data.dirtyFiles} kirli dosya.`;

  return {
    findings,
    layer: {
      code: "A1",
      name: "Git Parity",
      status,
      score: Math.max(0, Math.round(score * 10) / 10),
      note,
      findingIds: findings.map((f) => f.id),
    },
  };
}
