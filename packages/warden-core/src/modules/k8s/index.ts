import { parseAllDocuments } from "yaml";
import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import type { DetectContext } from "../../detect/types.ts";
import { makeFinding } from "../../util/finding.ts";

/**
 * Modül K8S — Kubernetes manifest güvenliği (pasif, statik).
 * privileged · root container · latest/imagePullPolicy · açık env secret · ingress TLS yok.
 */

const WORKLOAD_KINDS = new Set(["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"]);
const SECRET_ENV = /(password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key)/i;

export interface K8sDoc {
  readonly path: string;
  readonly doc: Record<string, unknown>;
}

function getContainers(doc: Record<string, unknown>): Array<Record<string, unknown>> {
  // Pod: spec.containers · Deployment/...: spec.template.spec.containers · CronJob: spec.jobTemplate.spec.template.spec.containers
  const spec = doc["spec"] as Record<string, unknown> | undefined;
  if (!spec) return [];
  const direct = spec["containers"];
  if (Array.isArray(direct)) return direct as Array<Record<string, unknown>>;
  const tmpl = (spec["template"] as Record<string, unknown> | undefined)?.["spec"] as Record<string, unknown> | undefined;
  if (tmpl && Array.isArray(tmpl["containers"])) return tmpl["containers"] as Array<Record<string, unknown>>;
  const jobT = (spec["jobTemplate"] as Record<string, unknown> | undefined)?.["spec"] as Record<string, unknown> | undefined;
  const jobTmpl = (jobT?.["template"] as Record<string, unknown> | undefined)?.["spec"] as Record<string, unknown> | undefined;
  if (jobTmpl && Array.isArray(jobTmpl["containers"])) return jobTmpl["containers"] as Array<Record<string, unknown>>;
  return [];
}

function podSecurityContext(doc: Record<string, unknown>): Record<string, unknown> {
  const spec = doc["spec"] as Record<string, unknown> | undefined;
  const tmplSpec = (spec?.["template"] as Record<string, unknown> | undefined)?.["spec"] as Record<string, unknown> | undefined;
  return ((tmplSpec ?? spec)?.["securityContext"] as Record<string, unknown>) ?? {};
}

/** K8S — saf analiz: parse edilmiş manifest'lerden bulgu üretir. */
export function analyzeK8s(docs: readonly K8sDoc[]): Finding[] {
  const findings: Finding[] = [];

  for (const { path, doc } of docs) {
    const kind = String(doc["kind"] ?? "");
    const name = String((doc["metadata"] as Record<string, unknown> | undefined)?.["name"] ?? "?");

    if (kind === "Ingress") {
      const spec = (doc["spec"] as Record<string, unknown>) ?? {};
      if (!spec["tls"]) {
        findings.push(mk(path, `K8S-ingress-no-tls:${name}`, "K8S-5", "Ingress TLS tanımsız (düz HTTP)", "P2",
          "Ingress TLS olmadan trafiği şifresiz taşır.", "spec.tls ekle; cert-manager ile otomatik sertifika.", "Ingress Misconfig"));
      }
      continue;
    }

    if (!WORKLOAD_KINDS.has(kind)) continue;

    const podSec = podSecurityContext(doc);
    const podNonRoot = podSec["runAsNonRoot"] === true;

    for (const c of getContainers(doc)) {
      const cname = String(c["name"] ?? "container");
      const sec = (c["securityContext"] as Record<string, unknown>) ?? {};

      if (sec["privileged"] === true) {
        findings.push(mk(path, `K8S-privileged:${name}/${cname}`, "K8S-1", `Privileged container: ${name}/${cname}`, "P0",
          "Privileged container host'a tam erişir; kaçış = node ele geçirme.", "privileged: false; gerekli capability'leri tek tek ver.", "Privileged Container"));
      }

      const cNonRoot = sec["runAsNonRoot"] === true;
      const runsAsRoot = sec["runAsUser"] === 0;
      if (runsAsRoot || (!podNonRoot && !cNonRoot)) {
        findings.push(mk(path, `K8S-root:${name}/${cname}`, "K8S-2", `Container root çalışabilir: ${name}/${cname}`, "P1",
          "runAsNonRoot ayarlı değil; container root olarak çalışabilir.", "securityContext.runAsNonRoot: true (+ runAsUser>0).", "Root Container"));
      }

      const image = String(c["image"] ?? "");
      const pull = String(c["imagePullPolicy"] ?? "");
      if (image && (!image.includes(":") || image.endsWith(":latest") || pull === "Always" && image.endsWith(":latest"))) {
        findings.push(mk(path, `K8S-image-tag:${name}/${cname}`, "K8S-3", `Belirsiz image etiketi (latest/tagsız): ${image || cname}`, "P2",
          "latest/tagsız image tekrar-üretilemez dağıtım + beklenmedik güncelleme.", "Sabit sürüm etiketi (digest) kullan.", "Image Policy"));
      }

      const env = c["env"];
      if (Array.isArray(env)) {
        for (const e of env as Array<Record<string, unknown>>) {
          const en = String(e["name"] ?? "");
          if (SECRET_ENV.test(en) && typeof e["value"] === "string" && e["value"] !== "") {
            findings.push(mk(path, `K8S-plain-secret:${name}/${cname}/${en}`, "K8S-4", `Manifest'te düz secret env: ${en}`, "P1",
              "Secret düz metin env olarak manifest'te; sızıntı/repo riski.", "Secret/secretKeyRef veya harici secret store kullan.", "Exposed Secret"));
          }
        }
      }
    }
  }
  return findings;
}

function mk(path: string, id: string, check: string, title: string, severity: "P0" | "P1" | "P2", impact: string, rec: string, category: string): Finding {
  return makeFinding({
    id, title, severity, module: "K8S", check, category, confidence: "high",
    evidence: [{ type: "config", source: path, excerpt: title }],
    impact, recommendation: rec, effort: "M", autoFixable: false, references: ["CIS Kubernetes Benchmark"],
  });
}

const YAML_FILE = /\.ya?ml$/i;
const SKIP = /(^|\/)(node_modules|dist|build|warden-report|vendor)\//;

export function collectK8sDocs(ctx: DetectContext): K8sDoc[] {
  const files = ctx.find((p) => YAML_FILE.test(p) && !SKIP.test(p), { limit: 2000 });
  const out: K8sDoc[] = [];
  for (const f of files) {
    const text = ctx.readFile(f);
    if (!text || !/\bkind\s*:/.test(text) || !/\bapiVersion\s*:/.test(text)) continue;
    let docs: ReturnType<typeof parseAllDocuments>;
    try {
      docs = parseAllDocuments(text);
    } catch {
      continue;
    }
    for (const d of docs) {
      const js = d.toJS() as unknown;
      if (js && typeof js === "object" && "kind" in js && "apiVersion" in js) {
        out.push({ path: f, doc: js as Record<string, unknown> });
      }
    }
  }
  return out;
}

export const k8sModule: WardenModule = {
  id: "K8S",
  title: "Kubernetes Manifest Güvenliği",
  active: false,
  applicable(ctx: ScanContext) {
    return collectK8sDocs(ctx.fs).length > 0;
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const docs = collectK8sDocs(ctx.fs);
    const findings = analyzeK8s(docs);
    ctx.audit.info(`K8S: ${docs.length} manifest, ${findings.length} bulgu.`);
    return { findings };
  },
};
