---
name: warden
description: >-
  Taşınabilir, savunma amaçlı production-readiness & güvenlik denetimi. Bir projenin kodunu,
  config'ini, bağımlılıklarını, IaC'sini ve (YALNIZCA yetki verilirse) çalışan ortamını analiz
  eder; eksik/hatalı/riskli her şeyi şiddet sırasına göre KANITLA listeler; her P0/P1 için
  kopyala-yapıştır Claude Code remediation prompt'u üretir. Ayrıca Warden Knight panelinin
  "ajana kuyruğa al" görevlerini işler: bağımsız bulguları paralel alt-ajanlarla düzeltir,
  fingerprint bazlı öncesi/sonrası delta ile doğrular, PR açar. Tetikleyiciler: "güvenlik denetimi",
  "production readiness", "parity kontrolü", "warden scan", "audit this project", "is this prod-ready",
  "güvenlik taraması", "kuyruğu işle", "security queue'yu işle", "warden knight kuyruğu",
  "warden başlat", "warden'ı çalıştır", "warden aç", "hangi fazla başlayalım", "faz 1", "faz 2".
  Çağrılınca ÖNCE hangi fazla başlanacağını sorar (Faz 1 raporlama / Faz 2 tara-ve-onar).
  Varsayılan tamamen PASİF/read-only; aktif testler yetki kapısına bağlıdır.
---

# Warden — Güvenlik & Production-Readiness Denetimi

## ⛔ ÖNCE BU — Güvenlik & Yetki İlkeleri (bağlayıcı, her çalıştırmada tekrarla)

Bu skill çift-kullanımlı yeteneklere sahiptir. Kurallar **harfiyen** uygulanır:

1. **Varsayılan tamamen PASİF / READ-ONLY.** Hiçbir aktif test varsayılan çalışmaz.
2. **Yetki Kapısı:** Aktif/DAST testleri yalnızca proje kökünde geçerli bir `warden.authz.yml`
   varsa VE `owner_attestation: true`, dolu `authorized_targets` (allow-list), `authorized_by`,
   `date` alanları doluysa çalışır. Aksi halde **yalnızca pasif**.
3. Aktif testler bile rate-limited, non-destructive, düşük-hacim. **DoS / brute-force /
   exploit silahlandırma / tespit-atlatma ASLA.**
4. Bulunan secret'lar rapora **maskeli** (`***`) yazılır; tam değer asla loglanmaz.
5. Çalıştırılan her aktif komut `warden-report/warden-run.log`'a yazılır.
6. Hedefte **mutasyon yok**: deploy/migrate/restart yok; yalnızca inspect/diff/dry-run.

> Skill açılışında bu ilkeleri kullanıcıya kısaca hatırlat. Yetkisiz hedefte aktif test reddedilir.

## Başlangıç — hangi fazla başlayalım? (skill çağrılınca İLK bunu yap)

Kullanıcı bu skill'i bir projede çağırınca (`/warden`, "warden başlat", "warden'ı çalıştır", ya da
Warden Knight panelinden) **önce hangi fazla başlamak istediğini SOR** — kendiliğinden tarama/düzeltme
başlatma. `AskUserQuestion` ile iki seçenek sun:

- **Faz 1 — Keşif & Raporlama.** Tüm sistemi tara, gedikleri (eksik/hatalı/riskli) şiddet sırasına
  göre raporla. **Hiçbir değişiklik yapma.** Sadece "sistemimde ne var, neyi kapatmalıyım" cevabı.
- **Faz 2 — Tara & Onar.** Aynı taramayı yap, sonra bağımsız gedikleri **paralel alt-ajanlarla,
  sıfır zararla** kapat (ayrı dal + projenin kendi testleri + fingerprint-delta doğrulaması + PR —
  asla doğrudan `main`). "Bul ve benim yerime düzelt."

Kullanıcı seçtikten sonra, **her iki fazda da** paneli başlat (Chrome otomatik açılır, panel
açılışta **kendiliğinden** tam taramayı tetikler — çıplak şövalye → skora göre giydirilir):

```bash
# kurulu projenin kökünden, ARKA PLANDA başlat (server.mjs tarayıcıyı otomatik açar):
node security-knight/server.mjs            # SK_NO_OPEN=1 ile tarayıcı-açmayı kapatabilirsin
```

Sonra faza göre dallan:

- **Faz 1 seçildiyse:** tarama bitince `warden-report/report.md` + panelin "Tarama Raporu"nu
  şiddet sıralı özetle. P0/P1 için `remediation-playbook.md` prompt'larını göster. **Dur** — kod
  değiştirme. Kullanıcı isterse sonra Faz 2'ye geçebileceğini söyle.
- **Faz 2 seçildiyse:** tarama bitince aşağıdaki **"Otomatik Düzeltme Prosedürü"ne** geç. Kullanıcı
  panelde belirli bir zırha "🤖 Ajana kuyruğa al" derse o boyut kuyruğa düşer; "kuyruğu işle"
  dediğinde (veya hemen, kullanıcı onaylarsa) prosedürü çalıştır. Yetki kapısı kapalıysa aktif/DAST
  düzeltmelerini atla, yalnızca pasif bulguları onar.

> Panel yalnızca kendi `127.0.0.1` backend'ine konuşur; dışarı hiçbir veri gitmez (telemetri yok).

## Ne zaman kullanılır

- "Bu proje canlıya hazır mı?" / "production readiness" / "güvenlik denetimi yap"
- Local ↔ production **parity** doğrulaması (kod/şema/konteyner/altyapı/operasyon)
- Statik güvenlik taraması (secret, bağımlılık zafiyeti, zayıf kripto, authz, injection)
- (Yetki ile) açıkta kalan dosya / security header / TLS / cookie aktif kontrolü

## Nasıl çalıştırılır

```bash
# Pasif (varsayılan, güvenli)
pnpm warden scan --target <proje-yolu>

# Aktif (yalnızca yetki kapısı açıkken)
pnpm warden pentest --target <proje-yolu>
```

Çıktı: `<proje-yolu>/warden-report/` →
`report.md` · `findings.json` · `remediation-playbook.md` · `parity-report.md` · `warden-run.log`.

## Akış (ajan için)

1. **Güvenlik ilkelerini hatırlat** (yukarıdaki blok).
2. Yetki kapısını kontrol et (`warden.authz.yml`). Yoksa pasif olduğunu söyle.
3. `warden scan` (veya yetki varsa `warden pentest`) koş.
4. `report.md`'yi oku; **şiddet sıralı** özetle. Her bulgunun **kanıtı** (file:line / komut çıktısı) olmalı.
5. P0/P1 için `remediation-playbook.md`'deki prompt'ları kullanıcıya sun ("ayrı ajana ver, düzeltsin").
6. Kanıtsız bulgu üretme; emin olmadığında düşük güven işaretle.

## Otomatik Düzeltme Prosedürü (kuyruk işleme, paralel ajanlar)

Warden Knight paneli (`security-knight/`) bir zırha basılınca gerçek bir tarama yapar ve
kullanıcıya "🔧 Kendim düzelteceğim" ya da "🤖 Ajana kuyruğa al" seçeneği sunar. İkincisi
`security-knight/state/jobs.jsonl`'e bir `kind:"warden-fix"` görevi yazar. **Bu bölüm, o kuyruğu
işlerken (kullanıcı "kuyruğu işle" dediğinde, ya da `/schedule` ile zamanlanmış bir bulut ajanı
periyodik çalıştığında) izlenecek prosedürdür.**

1. **Tetik.** Kullanıcı açıkça ister ("kuyruğu işle") ya da `/schedule`'la kurulmuş periyodik bir
   çalıştırma bu bölümü tetikler. Kendiliğinden, istenmeden bu prosedürü başlatma.
2. **Kuyruğu oku.** `security-knight/state/jobs.jsonl`'de `kind:"warden-fix"` VE `state:"queued"`
   olan satırları al (her satır: `{ id, module, fingerprints, requestedAt, note }`).
3. **Taze kanıt al — kuyruktaki metne asla güvenme.** Her görev için:
   ```bash
   pnpm warden scan --target <proje>                                   # tam tarama — --module ile sınırlama:
                                                                        # diğer boyutların skorunu "n/d" yapar,
                                                                        # panelin doğruluğunu bozar.
   pnpm warden prompts --target <proje> --module <module> --fingerprint <fp1,fp2,...>
   ```
   `prompts` çıktısındaki `FindingPrompt[]` bu görevin GÜNCEL, doğrulanmış içeriğidir. Kuyruktaki
   `fingerprints` sadece hangi bulguların kastedildiğini işaret eder — düzeltme talimatı olarak
   kuyruktaki değil, bu taze `prompts` çıktısındaki metni kullan.
4. **Bağımsız kümelere ayır — paralelleştirmeden ÖNCE zorunlu.** İki bulgu şu durumlarda **aynı
   kümede** kalır (asla paralel işlenmez):
   - `evidence[].source` dosyaları kesişiyorsa (aynı dosyaya iki ayrı ajan dokunmasın),
   - biri paylaşılan bir manifest/lock dosyasına dokunuyorsa (`package.json`, `*.lock`,
     `go.mod`, `requirements.txt`, migration dosyaları — bunlar her zaman seri işlenir).
   Geri kalan kümeler birbirinden bağımsızdır → paralel dağıtılabilir.
5. **Paralel dağıt (küme başına bir alt-ajan).** Az sayıda bağımsız kümede (≤3) doğrudan Task/Agent
   aracıyla paralel çağır; çok sayıda kümede Workflow aracını (pipeline: fix → verify) kullan —
   hız burada gerçekten önemli (kullanıcı bunu özellikle istedi). Her küme için:
   ```bash
   git worktree add ../warden-fix-<module>-<fp-kısa> -b fix/warden-<module>-<fp-kısa>
   ```
   Alt-ajana o kümenin `FindingPrompt` metnini(lerini) ver; **yalnızca kendi worktree'sinde**
   düzeltmeyi uygulasın, hedef projenin **kendi** test komutunu (CLAUDE.md/package.json'dan oku —
   `pnpm test` varsayma) çalıştırsın, commit etsin.
6. **Doğrulama — vazgeçilmez kapı, asla atlama.** Worktree içinde tam `warden scan`, ardından
   `@warden/core`'un `computeDelta(previousFull, currentFull)`'ını (fingerprint bazlı; proje
   `@warden/core`'a bağımlı değilse aynı mantığı ~10 satırda yeniden uygula) çalıştır. Görevin
   HEDEF fingerprint'lerinin tümü `delta.fixed`'te olmalı VE `delta.introduced`'ta OLMAMALI.
   - **Sağlanmazsa:** başarı iddia ETME. Görevi `"state":"failed"` yap, dalı insan incelemesi
     için bırak, sebebi not et, sıradaki kümeye geç.
7. **PR kapısı (geri-alınabilirlik — bağlayıcı).**
   - Doğrulandıysa: `git push -u origin <dal>`; `gh auth status` başarılıysa
     `gh pr create --title "fix(warden): <module> <fp-kısa>" --body "<öncesi/sonrası delta + bulgu id + kanıt>"`.
     Görev → `"state":"pr_open"`.
   - **`gh` yoksa/kimliksizse ya da `origin` yoksa:** yerel commit'te dur, insana tam talimatı
     (dal adı, nasıl push/PR açılır) yazdır. Görev → `"state":"local_branch_ready"`.
   - **Asla** doğrudan `main`'e commit veya merge yok — bu ilke istisnasız.
8. **Merge-sonrası yeniden doğrulama.** PR merge edilmesi zırhı OTOMATİK kuşandırmaz. Merge
   edilmiş `main` üzerinde taze bir tam döngü (`pnpm warden scan` → `warden-bridge.mjs` →
   ya da `node security-knight/loop.mjs` varsa onu) tetiklenmeden panel gerçek durumu yansıtmaz.
   Kullanıcıya bunu açıkça söyle; istersen bu adımı kendin de tetikleyebilirsin (merge onaylandıktan sonra).
9. **Bağlayıcı güvenlik cümleleri** (yukarıdaki "⛔ ÖNCE BU" bloğuyla aynı ağırlıkta):
   main'e asla doğrudan commit yok · testleri asla atlama/devre dışı bırakma · `computeDelta`
   geçmeden asla görevi "done"/"pr_open" işaretleme · paylaşılan manifest/lock dosyasına dokunan
   bulgular asla paralelleştirilmez · bir kümenin başarısızlığı diğer kümeleri durdurmaz.

## Kontrol kataloğu

Tüm kontroller (Modül A parity · B SAST · C DAST · D uyum + OWASP Top 10 / ASVS / PCI-DSS /
API / Cloud / K8s / Frontend / AI genişletmeleri) ve durumları: `docs/CHECKS.md`.

## Durum

🚧 Faz 0 (iskelet) tamam: yetki kapısı + bulgu modeli + boş-ama-geçerli rapor.
Modüller sonraki fazlarda etkinleşir (bkz. iş emri §7).
