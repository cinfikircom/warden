---
name: warden
description: >-
  Taşınabilir, savunma amaçlı production-readiness & güvenlik denetimi. Bir projenin kodunu,
  config'ini, bağımlılıklarını, IaC'sini ve (YALNIZCA yetki verilirse) çalışan ortamını analiz
  eder; eksik/hatalı/riskli her şeyi şiddet sırasına göre KANITLA listeler; her P0/P1 için
  kopyala-yapıştır Claude Code remediation prompt'u üretir. Tetikleyiciler: "güvenlik denetimi",
  "production readiness", "parity kontrolü", "warden scan", "audit this project", "is this prod-ready",
  "güvenlik taraması". Varsayılan tamamen PASİF/read-only; aktif testler yetki kapısına bağlıdır.
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

## Kontrol kataloğu

Tüm kontroller (Modül A parity · B SAST · C DAST · D uyum + OWASP Top 10 / ASVS / PCI-DSS /
API / Cloud / K8s / Frontend / AI genişletmeleri) ve durumları: `docs/CHECKS.md`.

## Durum

🚧 Faz 0 (iskelet) tamam: yetki kapısı + bulgu modeli + boş-ama-geçerli rapor.
Modüller sonraki fazlarda etkinleşir (bkz. iş emri §7).
