import type { StackDetector, DetectionResult } from "./types.ts";
import type { StackInfo } from "../model/module.ts";
import { createFsContext } from "./fs.ts";
import { nodePrismaDetector, nodeDrizzleDetector, nodeGenericDetector } from "./detectors/node.ts";
import { djangoDetector, laravelDetector, aspnetDetector, goDetector } from "./detectors/other-stacks.ts";
import { dockerDetector, cloudflareDetector } from "./detectors/infra.ts";

/** Yerleşik dedektör seti. Yeni stack = bu listeye bir satır. */
export function defaultDetectors(): StackDetector[] {
  return [
    nodePrismaDetector,
    nodeDrizzleDetector,
    djangoDetector,
    laravelDetector,
    aspnetDetector,
    goDetector,
    dockerDetector,
    cloudflareDetector,
    nodeGenericDetector,
  ];
}

function uniq(arr: readonly string[]): string[] {
  return [...new Set(arr)];
}

/**
 * Tüm dedektörleri öncelik sırasıyla koşar ve sonuçları tek StackInfo'da birleştir.
 * Dedektörler READ-ONLY; biri hata verirse atlanır (denetim hiç çökmemeli).
 */
export async function detectStack(
  projectRoot: string,
  detectors: readonly StackDetector[],
  onLog?: (msg: string) => void,
): Promise<StackInfo> {
  const ctx = createFsContext(projectRoot);
  const ordered = [...detectors].sort((a, b) => b.priority - a.priority);

  const languages: string[] = [];
  const frameworks: string[] = [];
  const orm: string[] = [];
  const cloud: string[] = [];
  let containerized = false;
  const raw: Record<string, unknown> = {};

  for (const d of ordered) {
    let res: DetectionResult | null = null;
    try {
      res = await d.detect(ctx);
    } catch (err) {
      onLog?.(`Dedektör ${d.id} hata verdi, atlandı: ${String(err)}`);
      continue;
    }
    if (!res) continue;
    onLog?.(`Dedektör eşleşti: ${d.id}`);
    if (res.languages) languages.push(...res.languages);
    if (res.frameworks) frameworks.push(...res.frameworks);
    if (res.orm) orm.push(...res.orm);
    if (res.cloud) cloud.push(...res.cloud);
    if (res.containerized) containerized = true;
    raw[d.id] = res.signals ?? {};
  }

  return {
    languages: uniq(languages),
    frameworks: uniq(frameworks),
    orm: uniq(orm),
    cloud: uniq(cloud),
    containerized,
    raw,
  };
}
