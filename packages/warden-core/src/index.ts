// Warden çekirdek API'si — cli ve skill bu yüzeyi kullanır.

export { runScan, WARDEN_VERSION } from "./orchestrator.ts";
export type { ScanOptions, ScanResult } from "./orchestrator.ts";

export { evaluateAuthz, isTargetAuthorized, DEFAULT_LIMITS } from "./authz/gate.ts";
export type { AuthzResult, AuthzLimits, WardenMode } from "./authz/gate.ts";

export { maskSecrets, maskValue, looksLikeSecret } from "./secret/mask.ts";
export { AuditLog } from "./audit/log.ts";

export { reportPaths, writeReport } from "./report/generator.ts";
export type { ReportMeta, ReportPaths } from "./report/generator.ts";
export { buildScoreboard, overallScore, DIMENSIONS } from "./report/scoreboard.ts";
export type { ScoreRow } from "./report/scoreboard.ts";
export { toSarif } from "./report/sarif.ts";
export { computeDelta, renderDeltaSection } from "./report/delta.ts";
export type { Delta, PreviousRun } from "./report/delta.ts";
export { enrichRisk, scoreOf } from "./risk/score.ts";
export type { Exploitability } from "./risk/score.ts";
export { buildAsvsChecklist, violatedAsvsCodes } from "./risk/asvs.ts";
export { buildCisChecklist, buildIsoChecklist } from "./risk/standards.ts";
export { analyzeGoMigrations, collectGoMigrations } from "./modules/parity/schema-go.ts";

export { SEVERITIES, SEVERITY_LABEL, SEVERITY_EMOJI, severityRank } from "./model/severity.ts";
export type { Severity } from "./model/severity.ts";
export { MODULES, CONFIDENCE, EVIDENCE_TYPES } from "./model/finding.ts";
export type { Finding, ModuleId, Evidence, EvidenceType, Confidence } from "./model/finding.ts";
export { EMPTY_STACK } from "./model/module.ts";
export type { WardenModule, ScanContext, StackInfo, ModuleRunResult } from "./model/module.ts";
export { makeFinding, fingerprintOf } from "./util/finding.ts";

export { PARITY_EMOJI, computeOverallParity } from "./model/parity.ts";
export type { ParityResult, ParityLayer, ParityStatus } from "./model/parity.ts";

export { analyzeDjangoMigrations, collectDjangoData } from "./modules/parity/schema-django.ts";
export { analyzeLaravelMigrations, collectLaravelData } from "./modules/parity/schema-laravel.ts";
export { analyzeEfMigrations, collectDotnetData } from "./modules/parity/schema-dotnet.ts";

export { defaultDetectors, detectStack } from "./detect/registry.ts";
export type { StackDetector, DetectionResult, DetectContext } from "./detect/types.ts";
export { defaultModules } from "./registry.ts";
export { parityModule } from "./modules/parity/index.ts";
export { sastModule } from "./modules/sast/index.ts";
export { scanSource } from "./modules/sast/scanner.ts";
export type { SourceRule } from "./modules/sast/scanner.ts";
export { SAST_RULES } from "./modules/sast/rules.ts";
export { parseAudit, vulnsToFindings } from "./modules/sast/dependency.ts";

export { k8sModule, analyzeK8s, collectK8sDocs } from "./modules/k8s/index.ts";
export { cloudModule, analyzeCloud, collectIacFiles } from "./modules/cloud/index.ts";
export { aiModule, analyzeAi, collectAiData } from "./modules/ai/index.ts";

export { dastModule, makeDastModule, targetToBaseUrl } from "./modules/dast/index.ts";
export { GuardedHttpClient } from "./modules/dast/client.ts";
export type { ProbeResponse, FetchLike } from "./modules/dast/client.ts";
export { EXPOSED_PATHS, analyzeExposedFile } from "./modules/dast/exposed.ts";
export { analyzeSecurityHeaders, analyzeCookies } from "./modules/dast/headers.ts";
export { collectTls, analyzeTls } from "./modules/dast/tls.ts";
export { analyzeAdminExposure, analyzeRateLimit } from "./modules/dast/active-checks.ts";
export { analyzePorts, scanPorts, checkPort, SENSITIVE_PORTS } from "./modules/dast/ports.ts";

export { complianceModule, collectComplianceData } from "./modules/compliance/index.ts";
export { analyzeCompliance } from "./modules/compliance/checks.ts";
export type { ComplianceData, CardHit } from "./modules/compliance/checks.ts";
export { COMPLIANCE_EMOJI, checklistScore } from "./model/compliance.ts";
export type { ComplianceResult, Checklist, ComplianceItem, ComplianceStatus } from "./model/compliance.ts";
