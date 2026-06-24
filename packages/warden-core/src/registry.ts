import type { WardenModule } from "./model/module.ts";
import { parityModule } from "./modules/parity/index.ts";
import { sastModule } from "./modules/sast/index.ts";
import { complianceModule } from "./modules/compliance/index.ts";
import { dastModule } from "./modules/dast/index.ts";
import { k8sModule } from "./modules/k8s/index.ts";
import { cloudModule } from "./modules/cloud/index.ts";
import { aiModule } from "./modules/ai/index.ts";

/**
 * Yerleşik denetim modülleri.
 * A (parity) · B (SAST) · D (uyum + PCI/Privacy) · CLOUD (IaC) · K8S (manifest) · AI (LLM) · C (DAST, yetki kapılı).
 * CLOUD/K8S/AI yalnızca ilgili dosyalar (IaC/manifest/AI SDK) varsa koşar. C active:true → yalnızca yetki kapısı açıkken.
 */
export function defaultModules(): WardenModule[] {
  return [parityModule, sastModule, complianceModule, cloudModule, k8sModule, aiModule, dastModule];
}
