<div align="center">

# ⚔️ Warden

### Kodunu bir realm gibi savun.

**Warden tüm sistemindeki *eksik, bozuk veya riskli* her şeyi tarar — sonra yalnızca gerçek bir
yeniden tarama gediğin kapandığını kanıtlayınca zırhlanan bir şövalyeyi kuşandırır.**
Hak etmediği hiçbir yeşil tik yok. Kodunu bozan hiçbir düzeltme yok. Karanlıkta atılan hiçbir adım yok.

🇬🇧 [English README](../README.md) · 📚 [Check kataloğu](CHECKS.md) · ⚔️ [Warden Knight paneli](../security-knight/README.md)

<img src="../security-knight/assets/panel-combined.png" width="820" alt="Warden Knight paneli"/>

</div>

---

## 📜 Warden'ın Yemini

Bir güvenlik aracı, ona duyabildiğin güven kadar değerlidir. Warden **üç söz verir — ve üçünü de
README'de değil, kodda uygular:**

| Yemin | Anlamı | Nasıl uygulanır |
|---|---|---|
| **Kanıtı görmeden zafer ilan etmem.** | Duruş *ölçülür*, iddia edilmez. Bir zırh yalnızca gerçek, temiz bir yeniden tarama kanıtlayınca katılaşır — hiçbir buton/uç/bayrak "active" yazmaz. | içerik-tabanlı `fingerprint` + `computeDelta` öncesi/sonrası; Knight köprüsü durumu yalnızca gerçek bulgulardan türetir |
| **Ustanın kodunu bozmadan onarırım.** | Otomatik düzeltmeler **sıfır zararla** iner: ayrı dal, projenin kendi testleri, fingerprint-delta doğrulaması ve PR — *asla* doğrudan `main`'e commit. | `packages/warden-skill/SKILL.md` düzeltme prosedürü (git worktree izolasyonu, delta kapısı, PR kapısı) |
| **Karanlıkta değil, herkesin gözü önünde çalışırım.** | Varsayılan pasif/read-only; her komut ve istek loglanır; aktif/DAST testleri **yalnızca** yetki kapısı açıkken koşar. | `warden.authz.yml` kapısı · `warden-report/warden-run.log` denetim izi · kaynakta secret maskeleme |

> Bunlar slogan değil — test paketinin koruduğu değişmezlerdir. Birini bozarsan CI kırmızıya döner.

---

## ⛔ ÖNCE OKU — Güvenlik & Yetkilendirme İlkeleri (bağlayıcı)

Warden çift-kullanımlı yeteneklere sahiptir (aktif/DAST testleri). Bu yüzden kuralları **harfiyen** uygulanır:

1. **Varsayılan tamamen PASİF / READ-ONLY.** Hiçbir aktif test varsayılan çalışmaz.
2. **Yetki Kapısı (Authorization Gate):** Aktif testler **yalnızca** proje kökünde geçerli bir
   `warden.authz.yml` dosyası varsa VE içinde şunlar doluysa çalışır:
   - `owner_attestation: true` — "bu varlıklar bana ait / yetkiliyim" beyanı
   - `authorized_targets:` — allow-list; **yalnızca** bu host/domain/IP'lere aktif test yapılır
   - `authorized_by:` ve `date:` — denetim izi

   Dosya yoksa veya eksikse Warden **yalnızca pasif** koşar. Allow-list dışı hiçbir hedefe aktif istek gitmez.
3. **Intrusive değil:** Aktif testler bile rate-limited, non-destructive, düşük-hacimdir.
   **DoS yok, brute-force yok, exploit silahlandırma yok, tespit-atlatma yok.**
4. **Secret maskeleme:** Bulunan token/parola/URL rapora `***` ile yazılır; tam değer asla loglanmaz.
5. **Audit log:** Çalıştırılan her aktif komut `warden-report/warden-run.log`'a yazılır (şeffaflık).
6. **Üretimde mutasyon yok:** Komutlar `--dry-run`/diff/inspect seviyesinde kalır; deploy/migrate/restart **YOK**.

> Bu araç yetkili öz-denetim, CTF, eğitim ve savunma içindir. Yetkisiz hedefe kullanımı yasaktır ve
> kullanıcının sorumluluğundadır.

---

## Mimari (3 katman)

Warden bir **pnpm monorepo**'dur:

| Paket | Sorumluluk |
|-------|-----------|
| **`packages/warden-core`** | Stack-agnostik analiz motoru: bulgu modeli, yetki kapısı, modül orkestrasyonu, rapor üretici, secret maskeleme, audit log. |
| **`packages/warden-cli`** | `warden scan` · `warden report` · `warden pentest` komut satırı arayüzü. |
| **`packages/warden-skill`** | Claude Code Skill köprüsü (`SKILL.md` + script'ler). Cursor / Windsurf / VSCode / GitHub Action da core'u kullanabilir. |

## Hızlı başlangıç

```bash
# Bağımlılıkları kur
pnpm install

# Pasif denetim (varsayılan; hiç aktif istek atmaz)
pnpm warden scan --target <proje-yolu>

# Çıktılar
ls warden-report/
#   report.md · findings.json · remediation-playbook.md · parity-report.md · warden-run.log
```

Aktif (DAST) testler için önce yetki kapısını açın:

```bash
cp warden.authz.example.yml warden.authz.yml   # düzenleyin: owner_attestation, authorized_targets, authorized_by, date
pnpm warden pentest --target <proje-yolu>       # yalnızca allow-list host'lara, rate-limited
```

## Çıktı formatı

`warden-report/` altında: `report.md` (yönetici özeti + şiddet sıralı bulgular + skor tablosu),
`findings.json` (makine-okur, CI gate'i), `remediation-playbook.md` (her P0/P1 için Claude prompt'u),
`parity-report.md` (Modül A katman tablosu), `warden-run.log` (denetim izi).

Şiddet ölçeği: **P0** (production blocker / aktif sömürülebilir) · **P1** (ilk müşteri öncesi) ·
**P2** (mimari borç) · **P3** (ölçek/iyileştirme).

## Kontrol kataloğu

Tüm kontrollerin (orijinal Modül A/B/C/D + OWASP Top 10 / ASVS / PCI-DSS / API / Cloud / K8s /
Frontend / AI Security genişletmeleri) ID, şiddet, faz ve durumu için bkz. [`docs/CHECKS.md`](docs/CHECKS.md).

## Durum

🚧 Geliştirme aşamalı ilerliyor (bkz. iş emri §7).
- **Faz 0** ✅ iskelet, yetki kapısı, bulgu modeli, boş-ama-geçerli rapor üretici.
- **Faz 1** ✅ Stack tespiti (plugin dedektörler) + Modül A parity (A1 git · A2 Prisma derin · A3 runtime · A4 generic volume + env · A5 backup/TLS · A6 webhook) + Evidence Engine + **SARIF export** + Parity Risk Score.
- **Faz 2** ✅ Modül B (SAST: B1 secret · B2 bağımlılık · B3 kripto · B4/FE auth · B5 IDOR · B6 injection · B7/B9 sertleştirme) + OWASP/ASVS eşleştirme + **run-to-run delta (öncesi/sonrası puanlama)** + `history.jsonl` trend.
- **Faz 3** ✅ Modül D (uyum & operasyonel olgunluk: D1 backup/DR · D2 observability · D3 secret mgmt · D4 veri koruma · D5 CI/CD) + **D7 PCI-DSS 4.0** (CVV/PAN + checklist) + **D8 Privacy/KVKK-GDPR** (checklist) → `compliance-report.md` (✔/⚠/✖).
- **Faz 4** ✅ Modül C (DAST/**aktif, yetki kapılı**): C1 açıkta dosya · C2 header/TLS · C3 açık admin · C4 rate-limit · C6 cookie. Korumalı HTTP istemcisi (allow-list + rate-limit + GET-only + audit). Secret maskeleme artık **kaynakta** (tüm çıktılar maskeli).
- **Faz 5** ✅ Risk motoru: **CVSS v4 taban skoru + exploitability** her bulguda; **OWASP ASVS checklist** (✔/⚠/✖); zenginleştirilmiş **remediation playbook** (risk + standart + konumlar + adımlar + test/kabul + delta geri-besleme).
- **Faz 6** ✅ Paketleme (`warden init` → `.claude/skills/warden/`) + **ikinci stack: Django** (A2 Django yıkıcı migration + Python/Django SAST kuralları + D Python deps). Laravel/.NET/Go: tespit hazır, derin kontroller sonraki.

**Tüm iş emri fazları (0–6) tamamlandı.** İş emri §9 Definition of Done karşılanıyor.

### Eklentiler (iş emri sonrası)
- **GitHub Action + SARIF upload** ✅ — CI'da pasif tarama + `--fail-on P0` gate + `findings.sarif` → GitHub Code Scanning (bkz. aşağıdaki bölüm).
- **Laravel & .NET adaptörleri (derin)** ✅ — A2 yıkıcı migration (Laravel `dropColumn`, EF Core `DropColumn/DropTable`), PHP/C# SAST kuralları, D composer/.csproj bağımlılık tespiti.

- **Cloud / Kubernetes / AI Security modülleri** ✅ — CLOUD (Terraform: public S3 / IAM wildcard / açık SG / public RDS / Azure storage / Cloudflare SSL), K8S (privileged/root container, latest image, manifest düz secret, ingress TLS), AI (gömülü LLM key, prompt injection yüzeyi, sistem-prompt sızıntısı). Hepsi yalnızca ilgili dosya varsa koşar.

- **GCP cloud + Go adaptörü + CIS/ISO eşleştirme** ✅ — GCP (public bucket / Cloud SQL public / firewall 0.0.0.0/0), Go (golang-migrate yıkıcı migration + Go SAST + go.mod deps), **CIS Benchmark** ve **ISO 27001:2022 Annex A** checklist'leri (bulgulardan türetilir, ✖/–).

112 test geçiyor; 10 stack/senaryo fixture (Node/Prisma, Django, Laravel, .NET, Go, K8s, Terraform-AWS, Terraform-GCP, AI + DAST).

## GitHub Action (SARIF upload + CI gate)

Başka bir projede kullanım (`.github/workflows/security.yml`):

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload için
jobs:
  warden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: <org>/warden@v1          # bu repo (composite action.yml)
        with:
          target: "."
          fail-on: "P0"                 # P0 bulguda job'ı düşür
          upload-sarif: "true"          # findings.sarif → Code Scanning
```

CI gate yereldeki karşılığı: `warden scan --fail-on P0` (P0 bulguda çıkış kodu 1).
