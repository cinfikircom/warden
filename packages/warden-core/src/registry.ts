import type { WardenModule } from "./model/module.ts";
import { parityModule } from "./modules/parity/index.ts";
import { sastModule } from "./modules/sast/index.ts";
import { importsModule } from "./modules/imports/index.ts";
import { complianceModule } from "./modules/compliance/index.ts";
import { dastModule } from "./modules/dast/index.ts";
import { k8sModule } from "./modules/k8s/index.ts";
import { cloudModule } from "./modules/cloud/index.ts";
import { aiModule } from "./modules/ai/index.ts";
import { payModule } from "./modules/pay/index.ts";
import { accessModule } from "./modules/access/index.ts";
import { authModule } from "./modules/auth/index.ts";
import { apiModule } from "./modules/api/index.ts";
import { privModule } from "./modules/priv/index.ts";
import { webModule } from "./modules/web/index.ts";
import { flowModule } from "./modules/flow/index.ts";
import { emailModule } from "./modules/email/index.ts";
import { uploadModule } from "./modules/upload/index.ts";

/**
 * Yerleşik denetim modülleri.
 * A (parity) · B (SAST) · D (uyum + PCI/Privacy) · CLOUD (IaC) · K8S (manifest) · AI (LLM) ·
 * PAY (ödeme güvenliği & güvenilirliği) · C (DAST, yetki kapılı).
 * CLOUD/K8S/AI/PAY yalnızca ilgili dosyalar (IaC/manifest/AI SDK/ödeme entegrasyonu) varsa koşar.
 * C active:true → yalnızca yetki kapısı açıkken.
 */
export function defaultModules(): WardenModule[] {
  return [parityModule, sastModule, importsModule, complianceModule, cloudModule, k8sModule, aiModule, payModule, accessModule, authModule, apiModule, privModule, webModule, flowModule, emailModule, uploadModule, dastModule];
}
