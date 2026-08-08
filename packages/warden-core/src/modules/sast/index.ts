import type { WardenModule, ScanContext, ModuleRunResult } from "../../model/module.ts";
import type { Finding } from "../../model/finding.ts";
import { scanSource, SKIP_PATH } from "./scanner.ts";
import { SAST_RULES } from "./rules.ts";
import { loadRulePacks, RULE_PACK_DIR } from "./rule-packs.ts";
import { collectAuditFindings } from "./dependency.ts";
import { collectGitHistorySecrets, GIT_HISTORY_MAX_COMMITS } from "./git-history.ts";
import { makeFinding } from "../../util/finding.ts";
import { looksLikeSecret } from "../../secret/mask.ts";

/**
 * Modül B — Statik Uygulama Güvenliği (SAST, pasif/read-only).
 * B1 secret · B2 bağımlılık · B3 kripto · B4 auth · B5 authz · B6 injection · B7/B9 sertleştirme.
 * (Frontend kontrolleri v0.10'da ayrıldı → Modül FE, modules/fe/.)
 * Çoğu kontrol bildirimsel kural setinden (rules.ts) gelir; B2 canlı audit'i sarmalar.
 */
export const sastModule: WardenModule = {
  id: "B",
  title: "Statik Uygulama Güvenliği (SAST)",
  active: false,
  applicable() {
    return true; // kaynak kodu olan her projede anlamlı.
  },
  async run(ctx: ScanContext): Promise<ModuleRunResult> {
    const findings: Finding[] = [];

    /*
     * Bildirimsel kaynak kuralları (B1/B3/B4/B5/B6/B7/B9) + varsa kullanıcı kural paketleri.
     *
     * Harici kurallar yerleşiklerin YANINA eklenir, yerine geçmez: bir kural paketi
     * yükleyerek Warden'ın kendi kontrollerini devre dışı bırakmak mümkün olmamalı.
     */
    const packs = loadRulePacks(ctx.fs);
    for (const w of packs.warnings) ctx.audit.warn(`Rule pack: ${w}`);
    if (packs.rules.length > 0) {
      ctx.audit.info(`${RULE_PACK_DIR}/: ${packs.rules.length} harici kural yüklendi (${packs.files.length} dosya).`);
    } else if (packs.files.length > 0) {
      // Dosya var ama tek kural yüklenmedi: sessiz kalmak "kurallarım çalışıyor" sanılmasına
      // yol açardı — kapsam beyanıyla aynı ilke.
      ctx.coverage?.limit(
        "rule-pack-empty",
        "tool-missing",
        `${RULE_PACK_DIR}/ altında kural dosyası var ama hiçbiri yüklenemedi — o kontroller ÇALIŞMADI.`,
        packs.files[0] ?? RULE_PACK_DIR,
      );
    }
    findings.push(...scanSource(ctx.fs, [...SAST_RULES, ...packs.rules], { coverage: ctx.coverage }));

    // Commit'lenmiş .env içinde gerçek secret (B1).
    const envText = ctx.fs.readFile(".env");
    if (envText && looksLikeSecret(envText)) {
      findings.push(
        makeFinding({
          id: "B1-committed-dotenv",
          title: "Depoda .env dosyası gerçek secret içeriyor olabilir",
          severity: "P1",
          module: "B",
          check: "B1",
          category: "Secret",
          confidence: "medium",
          evidence: [{ type: "file", source: ".env", excerpt: "secret-benzeri değer tespit edildi (maskeli)" }],
          impact: ".env repoda ise secret'lar paylaşılır/sızar.",
          recommendation: ".env'i .gitignore'a al; geçmişten temizle; değerleri rotasyon yap.",
          effort: "S",
          autoFixable: false,
          references: ["OWASP A07:2021"],
        }),
      );
    }

    /*
     * B1 — depoya commit edilmiş ANAHTAR DOSYALARI.
     *
     * Kural motoru yalnızca `CODE_FILE` uzantılarını tarar; `.key`, `.pem`, `.p12` gibi
     * dosyalar o listede olmadığı için bir TLS özel anahtarı repoya eklendiğinde Warden
     * tamamen sessiz kalıyordu. Kaynak kodda gömülü bir anahtar yakalanıp, dosya olarak
     * duran anahtarın kaçırılması tutarsızdı — ve ikincisi genelde daha ağırdır.
     *
     * İçerik doğrulaması zorunlu: `.key` uzantısı tek başına yeterli değildir (bazı projeler
     * onu i18n/lisans anahtarı için kullanır). PEM/PKCS başlığı aranır.
     */
    const KEY_FILE = /\.(key|pem|p12|pfx|jks|keystore|ppk)$/i;
    const KEY_BY_NAME = /(^|\/)(id_(rsa|dsa|ecdsa|ed25519)|server\.key|private\.key)$/i;
    const PEM_HEADER = /-----BEGIN (?:[A-Z ]*)?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----|PuTTY-User-Key-File/;
    // Vendor ve test/fixture yolları elenir — kural motorunun SKIP_PATH'i burada otomatik
    // uygulanmıyor, çünkü bu tarama `scanSource` dışında kendi `find()` çağrısını yapıyor.
    // Elemeden, kasıtlı test anahtarları gerçek bir P0 maruziyet gibi raporlanıyordu.
    for (const p of ctx.fs.find((x) => (KEY_FILE.test(x) || KEY_BY_NAME.test(x)) && !SKIP_PATH.test(x), { limit: 200 })) {
      const body = ctx.fs.readFile(p);
      if (body === null || !PEM_HEADER.test(body)) continue;
      findings.push(
        makeFinding({
          id: `B1-committed-key-file:${p}`,
          title: "Depoda özel anahtar dosyası",
          severity: "P0",
          module: "B",
          check: "B1",
          category: "Secret",
          confidence: "high",
          evidence: [{ type: "file", source: p, excerpt: "PEM/PKCS özel anahtar başlığı tespit edildi (içerik maskeli)" }],
          impact:
            "Özel anahtar depoya girmiş: klonlayan herkes TLS trafiğini çözebilir, sunucuya SSH ile " +
            "bağlanabilir ya da imza üretebilir. Depodan silmek yetmez — anahtar geçmişte kalır.",
          recommendation:
            "Anahtarı DERHAL iptal et ve yenisini üret. Dosyayı .gitignore'a al ve git geçmişinden temizle " +
            "(git-filter-repo / BFG). Anahtarları secret manager'dan (Vault/KMS) ya da dağıtım ortamından ver.",
          effort: "M",
          autoFixable: false,
          references: ["OWASP A07:2021", "CWE-798", "ASVS 6.4"],
        }),
      );
    }

    // B2 bağımlılık zafiyetleri (best-effort, ağ gerektirir).
    const dep = collectAuditFindings(ctx.projectRoot, ctx.fs, ctx.audit);
    findings.push(...dep.findings);
    if (!dep.ran) {
      // Bu, kapsam beyanının en kritik satırlarından biri: bağımlılık CVE taraması
      // HİÇ YAPILMADI. Yalnızca audit log'a yazmak, raporu okuyan kişiye "bağımlılıklar
      // temiz" izlenimi verirdi — oysa hiç bakılmadı.
      ctx.audit.info("B2 dependency audit atlandı (lockfile yok ya da ağ erişimi yok).");
      ctx.coverage?.limit(
        "npm-audit",
        "tool-missing",
        "Bağımlılık CVE taraması (`npm/pnpm audit`) çalışmadı — lockfile yok ya da ağ erişimi yok. " +
          "**Bağımlılıklarda zafiyet olmadığı anlamına GELMEZ**; bu kontrol hiç yapılmadı.",
        "npm/pnpm audit",
      );
    }

    // B1 git geçmişi secret taraması (read-only, .git varsa).
    const gitSecrets = collectGitHistorySecrets(ctx.projectRoot, ctx.fs, ctx.audit);
    findings.push(...gitSecrets.findings);
    if (gitSecrets.ran) {
      ctx.audit.info(`B1 git geçmişi: ${gitSecrets.findings.length} tarihsel secret bulgusu.`);
      // Tarama gerçekleşse bile pencere sınırlı: daha eski commit'lere gömülüp sonradan
      // silinmiş bir secret görülmez. Merge commit'leri de bilerek atlanır.
      ctx.coverage?.limit(
        "git-window",
        "git-history",
        `Git geçmişi secret taraması son ${GIT_HISTORY_MAX_COMMITS} commit ile sınırlı ve merge ` +
          "commit'leri hariç — daha eski geçmişe gömülmüş secret'lar görülmedi.",
        `son ${GIT_HISTORY_MAX_COMMITS} commit`,
      );
    } else if (ctx.fs.exists(".git")) {
      ctx.coverage?.limit(
        "git-history-skip",
        "tool-missing",
        "Git geçmişi secret taraması çalışmadı (git erişilemedi) — tarihsel secret'lar denetlenmedi.",
        "git log",
      );
    }

    ctx.audit.info(`SAST: ${findings.length} bulgu (kural seti + ${dep.ran ? "audit" : "audit yok"}).`);
    return { findings };
  },
};
