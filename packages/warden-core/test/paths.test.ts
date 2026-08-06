import { describe, it, expect } from "vitest";
import { VENDOR_PATH, TEST_PATH, MINIFIED_PATH, isRealSourcePath } from "../src/util/paths.ts";
import { SKIP_PATH } from "../src/modules/sast/scanner.ts";
import { DEFAULT_MAX_DEPTH } from "../src/detect/fs.ts";

/**
 * Bu testler iki regresyonu bekler:
 *
 * 1. `ctx.find()` varsayılan derinliği 4'ken `packages/<pkg>/src/modules/<mod>/x.ts` (= 5)
 *    hiç taranmıyordu — TÜM modülleri etkileyen sessiz bir kör nokta.
 * 2. Derinlik açılınca CLOUD/K8S/parity, `test/fixtures/vuln-*` altındaki KASITLI zafiyetli
 *    örnekleri gerçek altyapı sanıp P0 üretti. Test/fixture eleme bilgisi dört ayrı yerde
 *    farklı biçimde durduğu için ikisi eliyor, ikisi elemiyordu.
 */

describe("Yol filtreleri (util/paths.ts) — tek kaynak", () => {
  it("DEFAULT_MAX_DEPTH monorepo derinliğini kapsar (packages/x/src/modules/y = 5)", () => {
    expect(DEFAULT_MAX_DEPTH).toBeGreaterThanOrEqual(5);
  });

  it("TEST_PATH: kasıtlı zafiyetli fixture yollarını eler", () => {
    for (const p of [
      "packages/warden-core/test/fixtures/vuln-k8s/deployment.yaml",
      "packages/warden-core/test/fixtures/vuln-iac/main.tf",
      "packages/warden-core/test/fixtures/vuln-gcp/gcp.tf",
      "packages/warden-core/test/fixtures/vuln-dotnet/Migrations/20240101_Drop.cs",
      "test/foo.ts",
      "tests/foo.ts",
      "src/__tests__/foo.ts",
      "src/app.test.ts",
      "src/app.spec.tsx",
    ]) {
      expect(TEST_PATH.test(p), p).toBe(true);
    }
  });

  it("TEST_PATH: gerçek kaynak yollarını ELEMEZ", () => {
    for (const p of [
      "src/app.ts",
      "packages/warden-core/src/modules/fe/index.ts",
      "apps/web/src/components/ui/Button.tsx",
      "infra/k8s/deployment.yaml",
      // "latest" gibi kelime içinde geçen "test" yakalanmamalı
      "src/latest-config.ts",
      "src/contest/index.ts",
    ]) {
      expect(TEST_PATH.test(p), p).toBe(false);
    }
  });

  it("VENDOR_PATH: build/vendor çıktılarını eler, kaynağı elemez", () => {
    expect(VENDOR_PATH.test("node_modules/x/index.js")).toBe(true);
    expect(VENDOR_PATH.test("apps/web/.next/static/x.js")).toBe(true);
    expect(VENDOR_PATH.test("dist/bundle.js")).toBe(true);
    expect(VENDOR_PATH.test("src/dist-helper.ts")).toBe(false);
  });

  it("MINIFIED_PATH: küçültülmüş bundle'ları eler", () => {
    expect(MINIFIED_PATH.test("public/vendor.min.js")).toBe(true);
    expect(MINIFIED_PATH.test("public/app.min.css")).toBe(true);
    expect(MINIFIED_PATH.test("src/admin.js")).toBe(false);
  });

  it("isRealSourcePath: üç filtreyi birleştirir", () => {
    expect(isRealSourcePath("packages/warden-core/src/modules/fe/index.ts")).toBe(true);
    expect(isRealSourcePath("packages/warden-core/test/fixtures/vuln-fe/src/App.tsx")).toBe(false);
    expect(isRealSourcePath("node_modules/react/index.js")).toBe(false);
    expect(isRealSourcePath("public/vendor.min.js")).toBe(false);
  });

  /**
   * SKIP_PATH artık ortak parçalardan türetiliyor. Bu test, refactor'ın SAST'ın eski
   * davranışını birebir koruduğunu sabitler: bir bulgu kaybı ya da yeni gürültü,
   * fingerprint/delta zincirini kırardı.
   */
  it("SKIP_PATH: refactor öncesi davranışı birebir korur", () => {
    const eski =
      /(^|\/)(node_modules|dist|build|\.next|coverage|warden-report|vendor)\/|\.min\.js$|\.(test|spec)\.[a-z]+$|(^|\/)(test|tests|__tests__|fixtures)\//i;
    const ornekler = [
      "src/app.ts",
      "node_modules/x/i.js",
      "dist/b.js",
      "build/b.js",
      ".next/s.js",
      "coverage/lcov.info",
      "warden-report/report.md",
      "vendor/lib.php",
      "p/vendor.min.js",
      "src/a.test.ts",
      "src/a.spec.tsx",
      "test/x.ts",
      "tests/x.ts",
      "src/__tests__/x.ts",
      "packages/core/test/fixtures/vuln-k8s/d.yaml",
      "src/modules/fe/index.ts",
      "apps/web/src/components/ui/Button.tsx",
    ];
    for (const p of ornekler) {
      expect(SKIP_PATH.test(p), p).toBe(eski.test(p));
    }
  });
});
