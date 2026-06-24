import type { Finding, ModuleId } from "./finding.ts";
import type { AuthzResult } from "../authz/gate.ts";
import type { AuditLog } from "../audit/log.ts";
import type { DetectContext } from "../detect/types.ts";

/**
 * Bir denetim modülünün çalışması için verilen bağlam.
 * Modüller bu bağlamı OKUR; hedefe kalıcı değişiklik yapmaz (iş emri §2.6).
 */
export interface ScanContext {
  /** Denetlenen projenin kök dizini. */
  readonly projectRoot: string;
  /** Yetki kapısı sonucu. Aktif modüller bunu kontrol eder. */
  readonly authz: AuthzResult;
  /** Audit log — çalıştırılan her komut buraya yazılır. */
  readonly audit: AuditLog;
  /** Tespit edilen stack ipuçları. */
  readonly stack: StackInfo;
  /** READ-ONLY dosya erişimi. */
  readonly fs: DetectContext;
}

export interface StackInfo {
  readonly languages: readonly string[];
  readonly frameworks: readonly string[];
  readonly orm: readonly string[];
  readonly containerized: boolean;
  readonly cloud: readonly string[];
  readonly raw: Readonly<Record<string, unknown>>;
}

export const EMPTY_STACK: StackInfo = {
  languages: [],
  frameworks: [],
  orm: [],
  containerized: false,
  cloud: [],
  raw: {},
};

/**
 * Bir modülün çıktısı: bulgular + isteğe bağlı yapısal artifact (ör. parity katman skorları).
 * artifact, modüle özeldir ve rapor üreticiye iletilir (ModuleId ile anahtarlanır).
 */
export interface ModuleRunResult {
  readonly findings: readonly Finding[];
  readonly artifact?: unknown;
}

/**
 * Tüm denetim modüllerinin (A/B/C/D/E/CLOUD/...) uyacağı sözleşme.
 * Her modül bulgu üretir; aktif olanlar yetki kapısını kendi içinde doğrular.
 */
export interface WardenModule {
  readonly id: ModuleId;
  readonly title: string;
  /** Aktif (DAST) modül mü — yalnızca yetki kapısı açıkken koşar. */
  readonly active: boolean;
  /** Bu modül verilen projede çalışmalı mı (stack uyumu). */
  applicable(ctx: ScanContext): boolean;
  /** Bulguları üret. Hata fırlatmamalı; üretemezse boş sonuç + audit.warn. */
  run(ctx: ScanContext): Promise<ModuleRunResult>;
}
