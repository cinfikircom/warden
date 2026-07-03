# 🤖 Ajan Koşucu — "Kuşan"ı otonom hale getirme

Amaç: kullanıcı panelde **Kuşan**'a bastığında arka planda ajan (ben) o savunmayı
**uygular → gerçek saldırıyla test eder → posture'u günceller**; panel kendiliğinden yükselir.
Kullanıcıya mümkün olduğunca az manuel kontrol.

## Akış

```
[Panel "Kuşan"]  →  POST /api/security/equip  →  state/jobs.jsonl'e görev
                                                        │
                                          [Ajan koşucu kuyruğu izler]
                                                        ▼
      1) Düzeltmeyi hedef repoda uygula (görev.key → değişiklik)
      2) attack-harness.mjs ile GERÇEK saldırı/testi koş (yetkili hedefe)
      3) Test geçtiyse: POST /api/security/status { key, status:"active" }  (posture.json güncellenir)
         Geçmediyse: job'ı "failed" işaretle, sebebi yaz, düzeltmeyi tekrarla
                                                        ▼
                                   [Panel posture'u okur → zırh kalıcı belirir]
```

## Görev kaydı (`state/jobs.jsonl`)
Her satır bir JSON: `{ id, key, requestedAt, state:"queued", note }`.

## key → düzeltme eşlemesi (hedef repoda ne yapılır)
| key | Uygulanacak düzeltme | Test (harness) |
|---|---|---|
| `token1x` | HMAC damgasına nonce ekle, tek-kullanımlık (Redis/DB TTL), e-posta+IP'ye bağla, süre 10–15dk | replay testi (testHook) |
| `consttime` | E-posta gönderimini kuyruğa al; bot/insan yolu aynı sürede dönsün | timing testi |
| `observ` | Bot-yakalama sayaçları + `/api/security/metrics` + ani-artış alarmı | metrik ucu 200 döner |
| `enum` | Kayıtlı/kayıtsız e-posta aynı gövde+süre | enum-parity timing |
| `a11y` | Honeypot'a `tabindex=-1 aria-hidden autocomplete=off` | manuel/gözle |

## Koşucuyu çalıştırma (ben = ajan)

**Yarı-otonom (önerilen başlangıç):** kullanıcı panelde Kuşan'a basar; sonra bana der ki
"kuyruğu işle" → ben `state/jobs.jsonl`'deki bekleyen görevleri okur, yukarıdaki eşlemeye göre
hedef repoda düzeltmeyi uygular, `attack-harness.mjs`'i yetkili hedefe koşar, geçerse
`POST /api/security/status`'la `active` yaparım. Panel yenilenince zırh belirir.

**Tam otonom (sıfır-dokunuş):** `/loop` becerisiyle beni kuyruğu periyodik işleyecek şekilde
kur — ör. `"/loop 2m güvenlik kuyruğunu işle: security-knight/state/jobs.jsonl'deki queued
görevleri uygula+test et+posture'u güncelle"`. Ya da `/schedule` ile zamanlanmış ajan.
Token maliyeti oluşur; yalnızca yetkili hedeflere saldırı koşar.

## ⚠ Güvenlik / yetki (bağlayıcı)
- Saldırı motoru **yalnızca sana ait / yetkili** hedeflere koşulur (staging/localhost). Warden'ın
  yetki-kapısı ilkesiyle aynı: allow-list dışına istek yok, non-destructive, düşük hacim, DoS yok.
- Düzeltmeler **kod değişikliğidir** → önce dalda/PR olarak; üretime elle onayla gidebilir
  (ya da senin belirlediğin otomasyon eşiğiyle).
- Backend uçları (`/api/security/*`) **admin kimlik doğrulaması** arkasında olmalı.

## Bana bağlanmak için gerekenler
1. **Hedef proje yolu/repo** — düzeltmeleri nerede uygulayayım (formun/honeypot/HMAC kodu).
2. **Form URL'i + endpoint şekli** — `attack-harness.mjs`'i buna göre yapılandırayım
   (request/verify yolu, alan adları, honeypot alan adı, token alan adı).
3. (Opsiyonel ama güçlü) Backend **test-modu kancası** — son isteğin bot mu sayıldığını ve
   e-posta gidip gitmediğini dönen bir uç; oracle-free honeypot/replay'i kara-kutu doğrulamak için.
