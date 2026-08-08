#!/usr/bin/env -S tsx
import { readFileSync, existsSync, readdirSync, rmSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { runScan } from "../packages/warden-core/src/index.ts";
import type { Finding } from "../packages/warden-core/src/index.ts";

/**
 * RECALL BENCHMARK — "kaçırıyor muyum?"
 *
 * Warden'ın test paketi kuralların çalıştığını kanıtlar; bu harness kaçırmadığını ölçer.
 * Bağımsız, bilinen-zafiyetli bir kod tabanına karşı koşar ve iki sayı üretir: konum recall'u
 * (doğru yerde bir şey gördük mü) ve sınıf recall'u (gördüğümüzün ne olduğunu bildik mi).
 *
 * Bkz. benchmark/README.md
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGETS_DIR = join(HERE, "targets");
/*
 * Korpus dizini NOKTA ile başlar: `benchmark/.corpus`.
 *
 * Bu bir stil tercihi değil, zorunluluk. `detect/fs.ts` nokta-dizinlerini varsayılan olarak
 * atlar; normal bir `corpus/` klasörü ise Warden'ın KENDİ self-scan'ine karışıyordu.
 * Waiver yetmiyordu: üçüncü taraf korpustaki bir sinyal (ör. bir CI workflow'u) proje-düzeyi
 * bir kontrolü tetikleyip bulguyu WARDEN'ın kendi dosyasına bağlıyordu — yol waiver'ının
 * göremediği bir sızıntı. Nokta öneki korpusu tarama ağacının tamamen dışında tutar.
 */
const CORPUS_DIR = process.env["WARDEN_BENCH_CORPUS"] ?? join(HERE, ".corpus");

/**
 * Bir ground-truth zafiyet sınıfının hangi Warden check kodlarına karşılık geldiği.
 *
 * ⚠ Bu tablo recall'un doğruluğunu belirler ve onu **skoru yükseltmek için** genişletmek
 * kendi kendini kandırmaktır. Tek ölçüt şudur: *bu check gerçekten aynı zafiyeti mi
 * gösteriyor?* Örnek: `PRIV-1` (log'a PII yazılması) gerçekten bir bilgi sızıntısıdır, o
 * yüzden `info-disclosure`'a eklenmiştir — ama `PRIV-2` (URL'de PII) aynı satırdaki başka
 * bir sorundur ve eklenmemiştir.
 */
const CLASS_TO_CHECKS: Record<string, readonly string[]> = {
  "sql-injection": ["B6"],
  "nosql-injection": ["B6"],
  "command-injection": ["B6"],
  "code-injection-eval": ["B6"],
  "ssrf": ["B6"],
  "path-traversal": ["B6"],
  // XXE, ground truth'ta bu sınıfa eşlendi (sabit sözlükte ayrı `xxe` yok);
  // Warden XXE'yi B6-xxe olarak raporlar, o yüzden ikisi de kabul edilir.
  "insecure-deserialization": ["B8", "B6-xxe"],
  "xss": ["FE-3", "B6", "FE-1", "FE-2", "FE-8"],
  "idor": ["B5", "ACC-1", "ACC-4"],
  "missing-authz": ["ACC-2", "ACC-4", "API-1"],
  "mass-assignment": ["ACC-3", "B5"],
  "csrf": ["WEB-1"],
  "open-redirect": ["B7"],
  "weak-crypto": ["B3", "AUTH-2", "AUTH-7"],
  "hardcoded-secret": ["B1"],
  "weak-password-policy": ["AUTH-6", "AUTH-1"],
  "session-misconfig": ["AUTH-3", "AUTH-4", "AUTH-5", "AUTH-8", "WEB-2", "FE-1"],
  // PRIV-1/3/4/5 gerçekten bilgi sızıntısı sınıfıdır (log'da PII, şifresiz hassas alan,
  // silme hakkı yok, denetim izi yok) — hepsi "hassas veri korunmuyor" ailesinden.
  "info-disclosure": ["B9", "API-4", "API-2", "AUTH-9", "PRIV-1", "PRIV-3", "PRIV-4", "PRIV-5", "D3"],
  "regex-dos": ["B6", "API-3"],
  "unrestricted-file-upload": ["UPLOAD-1", "UPLOAD-4", "UPLOAD-2"],
  "vulnerable-dependency": ["B2"],
};

/** Bulgunun konumu ground-truth satırının bu kadar yakınındaysa aynı yer sayılır. */
const LINE_TOLERANCE = 4;

interface GroundTruthVuln {
  readonly file: string;
  readonly line: number;
  readonly class: string;
  readonly evidence?: string;
  readonly note?: string;
  readonly confidence?: string;
  /**
   * Eşleştirme kapsamı.
   *
   * `file` (varsayılan): bulgu aynı dosyada ve satır toleransı içinde olmalı.
   *
   * `project`: bulgu **konum taşımaz**, çünkü zafiyet bir yokluktur — "projede CSRF koruması
   * yok", "helmet yüklü değil", "şu paket zafiyetli". Warden bunları tek bir proje-düzeyi
   * bulgu olarak üretir ve hangi satıra bağlayacağı keyfidir. Bu maddeleri satır eşleşmesi
   * beklemek, bulunan bir zafiyeti "kaçırıldı" saymaktı — ölçümü yanlış yapardı.
   *
   * Bu bir gevşetme değil, doğru birimde ölçüm: yokluk bulgusunun birimi proje, satır değil.
   */
  readonly scope?: "file" | "project";
}
interface TargetSpec {
  readonly target: string;
  readonly repo: string;
  readonly ref: string;
  readonly root: string;
  /** Dil/stack etiketi — özet tablosunda recall'u DİL bazında görmek için. */
  readonly language?: string;
  readonly vulnerabilities: readonly GroundTruthVuln[];
}

function loadTargets(only: string | null): TargetSpec[] {
  if (!existsSync(TARGETS_DIR)) return [];
  const out: TargetSpec[] = [];
  for (const f of readdirSync(TARGETS_DIR)) {
    if (!/\.ya?ml$/i.test(f)) continue;
    const spec = parse(readFileSync(join(TARGETS_DIR, f), "utf8")) as TargetSpec;
    if (only && spec.target !== only) continue;
    // Eşlenemeyen bir sınıf recall'u SESSİZCE yükseltirdi (hiçbir check'e bağlanmadığı için
    // asla eşleşmez ve "kaçırdık" sayılır) — ya da tam tersi bir refactor'da sessizce
    // eşleşir hâle gelirdi. İkisi de kabul edilemez: erken ve gürültülü patla.
    for (const v of spec.vulnerabilities) {
      if (!CLASS_TO_CHECKS[v.class]) {
        throw new Error(
          `${f}: bilinmeyen zafiyet sınıfı "${v.class}" (${v.file}:${v.line}). ` +
            `run.ts içindeki CLASS_TO_CHECKS sözlüğüne ekleyin.`,
        );
      }
    }
    out.push(spec);
  }
  return out;
}

/** Bir bulgunun dokunduğu (dosya, satır) çiftleri. */
function locationsOf(f: Finding): Array<{ file: string; line: number | null }> {
  return f.evidence.map((e) => ({
    file: e.source.replace(/\\/g, "/"),
    line: e.location !== undefined && /^\d+$/.test(e.location) ? Number(e.location) : null,
  }));
}

function checkMatches(f: Finding, cls: string): boolean {
  const prefixes = CLASS_TO_CHECKS[cls] ?? [];
  return prefixes.some((p) => f.check === p || f.check.startsWith(p) || f.id.startsWith(p));
}

interface Outcome {
  readonly vuln: GroundTruthVuln;
  readonly located: boolean;
  readonly classified: boolean;
  readonly matchedBy: string | null;
}

function evaluate(spec: TargetSpec, findings: readonly Finding[]): { outcomes: Outcome[]; unmatched: number } {
  const usedFingerprints = new Set<string>();
  const outcomes: Outcome[] = [];

  for (const v of spec.vulnerabilities) {
    const want = v.file.replace(/\\/g, "/");
    const projectScoped = v.scope === "project";
    let located = false;
    let classified = false;
    let matchedBy: string | null = null;

    for (const f of findings) {
      // Proje-kapsamlı maddede konum aranmaz — birim proje, satır değil.
      const here =
        projectScoped ||
        locationsOf(f).some(
          (l) => l.file === want && (l.line === null || Math.abs(l.line - v.line) <= LINE_TOLERANCE),
        );
      if (!here) continue;
      const right = checkMatches(f, v.class);
      // Proje kapsamında "yeri gördüm" ancak doğru sınıfla anlamlıdır: konum sinyali yok,
      // dolayısıyla sınıf eşleşmeyen bir bulgu bu madde hakkında hiçbir şey söylemez.
      if (projectScoped && !right) continue;
      located = true;
      usedFingerprints.add(f.fingerprint);
      if (right) {
        classified = true;
        matchedBy = f.id;
        break; // doğru sınıfta eşleşme bulundu; daha iyisi yok
      }
      matchedBy ??= f.id;
    }
    outcomes.push({ vuln: v, located, classified, matchedBy });
  }

  // Ground truth'ta karşılığı olmayan bulgular. precision HESAPLANMAZ — bunlar yanlış pozitif
  // de olabilir, ground truth'un eksiği de. İkisini ayırmak elle inceleme ister.
  const unmatched = findings.filter((f) => !usedFingerprints.has(f.fingerprint)).length;
  return { outcomes, unmatched };
}

function pct(n: number, d: number): string {
  return d === 0 ? "n/d" : `%${((n / d) * 100).toFixed(1)}`;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const only = argv.includes("--target") ? (argv[argv.indexOf("--target") + 1] ?? null) : null;
  const verbose = argv.includes("--verbose");

  const specs = loadTargets(only);
  if (specs.length === 0) {
    process.stderr.write("⚠ Hedef tanımı yok (benchmark/targets/*.yml).\n");
    process.exit(2);
  }

  let grandLocated = 0, grandClassified = 0, grandTotal = 0;
  const missingCorpus: string[] = [];
  const rows: Array<{ target: string; lang: string; located: number; classified: number; total: number }> = [];

  for (const spec of specs) {
    const root = resolve(CORPUS_DIR, spec.root);
    if (!existsSync(root)) {
      // SESSİZ ATLAMA YOK: ölçemediğini ölçmüş gibi göstermek bu projenin karşı olduğu şey.
      missingCorpus.push(spec.target);
      process.stdout.write(`\n▪ ${spec.target}: ⚠ ÇALIŞMADI — korpus indirilmemiş (${root}).\n`);
      process.stdout.write(`  \`pnpm bench:fetch\` çalıştırın.\n`);
      continue;
    }

    process.stdout.write(`\n▪ ${spec.target} — ${spec.vulnerabilities.length} bilinen zafiyet\n`);
    const started = Date.now();
    const res = await runScan({ projectRoot: root, intent: "scan", maxDepth: 12, maxFiles: 8000 });
    const { outcomes, unmatched } = evaluate(spec, res.findings);

    const located = outcomes.filter((o) => o.located).length;
    const classified = outcomes.filter((o) => o.classified).length;
    grandLocated += located;
    grandClassified += classified;
    grandTotal += spec.vulnerabilities.length;
    rows.push({
      target: spec.target,
      lang: spec.language ?? "?",
      located,
      classified,
      total: spec.vulnerabilities.length,
    });

    process.stdout.write(
      `  Konum recall'u:  ${located}/${spec.vulnerabilities.length}  ${pct(located, spec.vulnerabilities.length)}\n` +
        `  Sınıf recall'u:  ${classified}/${spec.vulnerabilities.length}  ${pct(classified, spec.vulnerabilities.length)}\n` +
        `  Toplam bulgu: ${res.findings.length} · eşleşmeyen: ${unmatched} (FP değil — bkz. README)\n` +
        `  Kapsam: ${res.coverage.filesScanned} dosya · ${res.coverage.modules.filter((m) => m.status === "audited").length} modül denetlendi` +
        ` · süre ${((Date.now() - started) / 1000).toFixed(1)}s\n`,
    );

    // Kapsam kaybı recall'u doğrudan etkiler: göremediğin yerde bulamazsın.
    for (const l of res.coverage.limits) {
      process.stdout.write(`  ⚠ kapsam: ${l.detail.split(".")[0]} (${l.count})\n`);
    }

    const missed = outcomes.filter((o) => !o.classified);
    if (missed.length > 0) {
      process.stdout.write(`  Kaçanlar (${missed.length}):\n`);
      for (const m of verbose ? missed : missed.slice(0, 8)) {
        const tag = m.located ? "yeri görüldü, sınıf yanlış" : "hiç görülmedi";
        process.stdout.write(`    · ${m.vuln.class} @ ${m.vuln.file}:${m.vuln.line} — ${tag}\n`);
        if (verbose && m.vuln.note) process.stdout.write(`        ${m.vuln.note}\n`);
      }
      if (!verbose && missed.length > 8) {
        process.stdout.write(`    … ve ${missed.length - 8} tane daha (--verbose ile tümü)\n`);
      }
    }

    // Benchmark hedef dizinine rapor yazar (Warden'ın normal davranışı); korpusu kirletmeyelim.
    rmSync(join(root, "warden-report"), { recursive: true, force: true });
  }

  if (rows.length > 0) {
    /*
     * DİL BAZLI TABLO — tek bir toplam sayı yanıltıcıdır.
     *
     * "Recall %79,7" cümlesi, ölçümün hangi dilde/framework'te yapıldığını söylemediği sürece
     * kapsamı beyan edilmemiş bir iddiadır: bir dilde %80, başkasında %0 olabiliriz. Bu tablo
     * tam olarak o beyanı yapar ve bir sonraki yatırımın nereye gideceğini gösterir.
     */
    process.stdout.write(`\n${"═".repeat(66)}\nRECALL HARİTASI\n\n`);
    process.stdout.write(`  ${"hedef".padEnd(12)}${"dil".padEnd(16)}${"konum".padEnd(16)}sınıf\n`);
    process.stdout.write(`  ${"─".repeat(62)}\n`);
    for (const r of [...rows].sort((a, b) => b.classified / b.total - a.classified / a.total)) {
      const loc = `${r.located}/${r.total} ${pct(r.located, r.total)}`;
      const cls = `${r.classified}/${r.total} ${pct(r.classified, r.total)}`;
      process.stdout.write(`  ${r.target.padEnd(12)}${r.lang.padEnd(16)}${loc.padEnd(16)}${cls}\n`);
    }
    process.stdout.write(`  ${"─".repeat(62)}\n`);
    process.stdout.write(
      `  ${"TOPLAM".padEnd(28)}` +
        `${`${grandLocated}/${grandTotal} ${pct(grandLocated, grandTotal)}`.padEnd(16)}` +
        `${grandClassified}/${grandTotal} ${pct(grandClassified, grandTotal)}\n`,
    );
    // Toplam, hedeflerin zafiyet sayısıyla AĞIRLIKLI ortalamadır — büyük ground truth'lu bir
    // hedef sonucu baskılar. Dil bazlı satırlar bu yüzden toplamdan daha bilgilendiricidir.
    process.stdout.write(`\n  Not: toplam, zafiyet sayısıyla ağırlıklıdır; dil satırları daha bilgilendirici.\n`);
  }
  if (missingCorpus.length > 0) {
    process.stdout.write(`\n⚠ Ölçülemeyen hedef: ${missingCorpus.join(", ")} — bu sayı eksiktir.\n`);
    process.exit(3);
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`benchmark hatası: ${String(err)}\n`);
  process.exit(1);
});
