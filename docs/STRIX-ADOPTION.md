# Strix Yetenek Devralma — Karar Kaydı

> Bu doküman, Strix (AI-ajan tabanlı pentest aracı) incelemesinden sonra Warden'a **nelerin
> alındığını**, **nelerin bilerek alınmadığını** ve **neden** olduğunu kaydeder. Amaç: aynı
> tartışmayı tekrar açmamak ve ileride koşullar değişirse kararın hangi varsayıma dayandığını
> görebilmek.
>
> Bağlam: Warden bir AI pentest aracı değil; **internet bağlantısı olmadan çalışan, kanıt üreten,
> deterministik bir güvenlik doğrulama sistemi**. Strix'in avantajı AI; Warden'ın avantajı
> **güven, denetlenebilirlik ve veri egemenliği**. Devralma kararları bu eksende verilir.

Durum: ✅ yapıldı · 🔨 yapılıyor · ⏳ planlı · ❌ bilerek alınmadı

---

## 0. Devralmanın değişmez kısıtları

Her devralma kararı bu dört kısıta karşı sınanır. Bir yetenek kısıtlardan birini ihlal ediyorsa
alınmaz — ne kadar değerli olursa olsun.

| # | Kısıt | Neden |
|---|-------|-------|
| K1 | **Ağ erişimi varsayılan kapalı** | Offline-first manifestosu. Tarama, hedef sistem hakkında dışarıya tek bayt sızdırmamalı. |
| K2 | **Tek runtime bağımlılığı (`yaml`), build adımı yok** | `npx warden` ile sıfır kurulum. Native binary / platform-özel derleme bu vaadi bozar. |
| K3 | **Read-only** | Warden hedef projeye asla yazmaz (rapor klasörü hariç). Strix'in writable mount + agent'ın gerçek dosyaları değiştirmesi modeli reddedilir. |
| K4 | **Deterministik** | Aynı girdi → aynı çıktı → aynı fingerprint. LLM-merkezli karar mekanizması bunu ihlal eder. |

### K5 — Fingerprint kararlılığı (uygulama kuralı)

`util/finding.ts:26` gereği fingerprint şu dörtlüden türer:

```
module | check | title | evidence(source + normalize(excerpt))
```

Bundan çıkan **kritik sonuç**: `confidence`, `severity`, `cvss`, `reachable`, `epss` alanları
fingerprint'e **girmez**. Yani:

- ✅ **Güvenli:** taint/bağlam analiziyle `confidence` veya `severity` ayarlamak. Waiver'lar
  tutmaya devam eder, delta geçmişi bozulmaz, `history.jsonl` trendi kırılmaz.
- ⚠️ **Kaydırıcı:** kural `title`'ını veya `check` kodunu değiştirmek, `excerpt`'in kırpma
  sınırını/normalizasyonunu oynatmak, bir bulgunun evidence `source`'unu değiştirmek.

v0.10'da `E3/E8/E10 → B6/B8` normalizasyonu tam da bu yüzden tek seferlik bir "fixed + new"
dalgası yarattı. **Strix devralma turunda ikinci bir fingerprint dalgası çıkarılmayacak** —
bu yüzden aşağıdaki sıralama fingerprint-nötr işlerden başlar.

---

## 1. ALINANLAR

### 1.1 Diff-scope tarama ✅ · risk: düşük

**Strix'te:** yalnızca değişen kodu analiz ederek PR başına maliyeti düşürme.

**Warden'da:** `warden scan --since <git-ref>` — `git diff --name-only <ref>...HEAD` ile değişen
dosya kümesi çıkarılır, `DetectContext.find()` sonucu bu kümeye daraltılır.

Neden alındı: K1–K4'ün hiçbirini ihlal etmiyor (git zaten yerel), bağımlılık gerektirmiyor,
CI'da en büyük hız kazancı bu.

**Tasarım şartı — delta zehirlenmesi:** kısmi tarama sonucu tam taramayla karşılaştırılırsa,
taranmayan dosyalardaki bulgular yanlışlıkla **"düzeltildi"** görünür. Bu sessiz bir yanlış
güven kaynağıdır. Bu yüzden `--since` modunda:
- delta hesabı **kapsam-farkındalı** olur; taranmamış dosyalardaki önceki bulgular `fixed`
  değil **`out-of-scope`** sayılır,
- `findings.json` önceki tam tarama sonucunun **üzerine yazılmaz** (aksi halde bir sonraki tam
  tarama sahte "yeni bulgu" dalgası üretir),
- raporun başında kapsamın daraltıldığı açıkça yazılır.

### 1.2 Taint / veri-akışı analizi (dosya-içi) ✅ · risk: orta · **en yüksek değerli madde**

**Strix'te:** kaynaktan (kullanıcı girdisi) sink'e (tehlikeli çağrı) veri akışını izleyerek
"bu gerçekten sömürülebilir mi" sorusunu yanıtlama.

**Warden'da:** `SourceRule` motorunun yanına — **yerine değil** — bir `taint.ts` katmanı.
Dosya içinde, kaynak belirteçlerinden (`req.body`, `req.query`, `req.params`, `searchParams`,
`process.argv`, `location.hash` …) türeyen değişkenleri izler ve mevcut sink kurallarıyla
kesiştirir.

Neden alındı: Warden'ın en büyük zayıflığı regex'in bağlam körlüğü — sabit string ile çağrılan
`exec()` ile kullanıcı girdisi taşıyan `exec()` aynı bulguyu üretiyor. Taint bunu ayırır.
Bağımlılık gerektirmez, tamamen deterministiktir.

**Kapsam sınırı (bilerek):** dosya-içi ve fonksiyon-içi. Fonksiyonlar arası / dosyalar arası
taint tam AST + çağrı grafı ister — bkz. §2.1. Bu sınır rapora **açıkça** yazılır; "taint var"
demek "tam veri akışı analizi var" anlamına gelmemeli.

**Fingerprint güvencesi (K5):** taint sonucu yeni bulgu **üretmez** ve mevcut bulgunun
`title`/`check`/`evidence`'ını **değiştirmez**. Yalnızca `confidence`'ı ayarlar ve bulguya
taint kanıtı (kaynak satırı) ekler. Böylece tüm mevcut waiver'lar ve delta geçmişi aynen tutar.

### 1.3 Opsiyonel AST katmanı (yerleşik TypeScript ile) ⏳ · risk: orta

**Strix'te:** `ast-grep` / tree-sitter ile yapısal analiz.

**Warden'da:** `typescript` paketi **opsiyonel peer** olarak ele alınır — kuruluysa
`ts.createSourceFile()` ile gerçek AST üzerinden çalışılır, kurulu değilse regex+taint yoluna
**graceful düşülür**. Bu, `adapters/native-tools.ts`'te zaten kullanılan desenin (araç
kuruluysa çalıştır, değilse atla) aynısıdır.

Neden bu yol: `ast-grep` napi binary'si ve tree-sitter'ın native derlemesi **K2'yi doğrudan
ihlal ediyor**. TypeScript ise saf JS, native derleme istemez ve zaten devDependency olarak
mevcut. Böylece AST kazancı K2'yi kırmadan elde edilir.

Neden §1.2'den sonra: taint katmanı AST varsa AST'den, yoksa regex'ten beslenecek şekilde
arkasına gizlenir. Önce arayüz, sonra motor.

### 1.4 Rule Packs (harici kural paketleri) ✅ · risk: düşük · v0.12 — uygulama: §1.9

**Strix'te:** skill/kural sistemi ile kapsam genişletme.

**Warden'da:** `warden-rules/*.yml` — `SourceRule` şemasının bildirimsel YAML karşılığı.
`yaml` zaten tek runtime bağımlılığı, ek maliyet yok.

**Tasarım şartı:** harici kurallar **kod çalıştıramaz** (`validate` fonksiyonu YAML'dan
gelemez) — aksi halde kural dosyası bir uzaktan kod çalıştırma yüzeyine dönüşür. Yalnızca
bildirimsel alanlar (pattern, severity, pathInclude …) desteklenir.

### 1.5 Çok katmanlı doğrulama (LLM'siz) ✅ · risk: düşük

**Strix'te:** birden fazla AI ajanının birbirinin bulgusunu doğrulaması.

**Warden'da:** deterministik karşılığı — bir bulgunun güveni, **bağımsız sinyallerin
birleşiminden** türer: kural eşleşmesi + taint erişimi + reachability + KEV/EPSS. İki bağımsız
sinyal onaylıyorsa `confidence: high`, yalnız kural eşleşmesi varsa `low`.

Bu zaten §1.2 ile geliyor; ayrı bir iş kalemi değil, taint'in raporlamaya yansıması.

---

### 1.6 DAST yol kataloğu — 11 → 43 yol ✅ · risk: düşük · v0.12

**Strix'te:** `skills/vulnerabilities/information_disclosure.md` ve `path_traversal_lfi_rfi.md`
içinde "High-Value Surfaces" başlığı altında toplanmış açıkta-kalan-dosya yüzeyleri.

**Warden'da:** `modules/dast/exposed.ts` içindeki `EXPOSED_PATHS` kataloğu genişletildi.
Eklenen sınıflar: ortam dosyası varyantları (`.env.local/.production/.bak`), özel anahtarlar
(SSH/TLS/GCP service-account), sürüm kontrolü ağaçları (`.git/index`, `.svn/wc.db`,
`.hg/requires`), uygulama yapılandırması (`web.config`, `appsettings.json`, `settings.py`,
`config.php`, `wp-config.php.bak`, `docker-compose.yml`, `.htaccess`), veritabanı dökümleri,
ve debug yüzeyleri (`actuator/env`, `debug/pprof/`, `metrics`, `_profiler`, `phpinfo.php`,
`server-status`).

**Lisans:** Strix Apache-2.0. Alınanlar **olgusal veri** (standart dosya yolları) — telif
kapsamında değil, dolayısıyla attribution yükümlülüğü doğmuyor. Yine de kaynak burada
kaydedilir: Strix, OmniSecure Inc., Apache-2.0.

**İki değişmez kural** (kod yorumunda da yazılı, testle korunuyor):

1. **Her yolun içerik doğrulayıcısı olmalı.** SPA'lar ve catch-all router'lar her yola 200
   döner; "200 döndü" hiçbir zaman tek başına bulgu değildir. `test/dast-exposed-paths.test.ts`
   43 yolun tamamını SPA gövdesine, boş gövdeye ve 404'e karşı sınar.
2. **Büyük/binary dump yolları katalogda yok** (`/actuator/heapdump`, `/debug/pprof/heap`,
   `/actuator/threaddump`). Yüzlerce MB indirmek yetki kapısının "non-intrusive, düşük hacim"
   vaadini bozardı. Bu, testle de zorlanıyor.

**Maliyet:** hedef başına 43 GET; saniyede 2 istek sınırıyla ~17 saniye. Bilinçli denge.

### 1.7 CWE eşlemesi ✅ · risk: düşük · v0.12

**Strix'te:** `tools/reporting/tool.py` içinde küratörlü bir CWE listesi ve onunla gelen kural:
*"en spesifik child CWE'yi kullan, parent'ı değil"* — yasaklı parent'lar 74, 20, 200, 284, 693.

**Warden'da:** `risk/cwe.ts`. `Finding.cwe` alanı eklendi, `enrichCwe` zincire girdi ve SARIF
çıktısı artık **CWE taksonomisi** bildiriyor (`taxonomies` + kural başına `relationships`) —
GitHub Code Scanning ve Azure DevOps bulguları CWE kategorisinde gruplayabiliyor.

Asıl değer parent yasağında: `CWE-74` ("Injection") SQL ile komut enjeksiyonunu aynı kutuya
koyar ve düzeltmeyi yönlendirmez. Bu yüzden `FORBIDDEN_PARENTS` bir testle zorlanıyor — tabloya
yanlışlıkla bir parent girerse test kırılır. Eşleşme bulunamazsa CWE **uydurulmaz**, boş kalır.

Fingerprint'e girmez (K5): sonradan eklenmesi mevcut waiver ve delta geçmişini bozmaz.

### 1.8 Doğrulama notları — "False Positives" ✅ · risk: düşük · v0.12

**Strix'te:** her zafiyet dosyasında bir `## False Positives` bölümü; LLM'e "acele karar verme"
demek için yazılmış.

**Warden'da:** `risk/false-positives.ts` — deterministik karşılığı, bulguyu **sunarken sınırını
da söylemek**. Remediation playbook'ta her bulgunun 1. adımının altına düşüyor:

```
  1) Yukarıdaki konum(lar)ı aç ve sorunu doğrula.
     ÖNCE DOĞRULA — bu bulgu şu durumlarda GEÇERSİZDİR:
       · Sorgu parametreli API ile çalışıyorsa (`?`, `$1`) enjeksiyon yoktur.
       · Değer sabit bir allow-list'ten geliyorsa risk yoktur.
     Yukarıdakilerden biri geçerliyse düzeltme YAPMA; gerekçeli waiver yaz.
```

Neden değerli: Warden'ın en büyük zaafı satır-bazlı regex'in bağlam körlüğü. Onu tamamen
kapatmak AST + çağrı grafı ister (Faz B). Ama körlüğü **beyan etmek** bugün mümkün ve kullanıcıyı
körlemesine düzeltmeden kurtarıyor — Kapsam Beyanı'nın bulgu düzeyindeki hâli. Notlar bulguyu
bastırmaz, güveni düşürmez, fingerprint'e girmez.

### 1.9 Rule Packs ✅ · risk: düşük · v0.12

**Warden'da:** `warden-rules/*.yml`. Bildirimsel kurallar yerleşiklerin **yanına** eklenir,
yerine geçmez — bir kural paketi yükleyerek Warden'ın kendi kontrollerini kapatmak mümkün değil.

Dört güvenlik kısıtı, hepsi testle zorlanıyor:

| Kısıt | Neden |
|---|---|
| `validate` YAML'dan **gelemez** | Fonksiyon olsaydı kural dosyası indirmek uzaktan kod çalıştırma yüzeyi olurdu — üstelik bir güvenlik aracında |
| İç içe niceleyici içeren desen **reddedilir** | Kendi motorunu kilitleyebilen bir kural paketi kabul edilemez (ReDoS) |
| `g`/`y` bayrakları **çıkarılır** | `test()` stateful olur ve dosyaları rastgele atlar (scanner.ts'te belgelenmiş tuzak) |
| Harici kuralın güveni varsayılan **`low`** | Doğrulanmamış bir kuralın raporun başına çıkması yanlış olurdu |

Geçersiz girdi **sessizce atlanmaz**: her ret audit log'a yazılır, ve dosya var ama hiç kural
yüklenemediyse Kapsam Beyanı'na "o kontroller çalışmadı" satırı düşer.

### 1.10 Strix'ten alınmayan kalan kalemler ⏳

Devralma turu tamamlandı. Alınmayanlar ve gerekçeleri §2'de; bunlardan **Playwright** ve
**Proof Engine** "ayrı, opsiyonel paket olarak alınmalı" diye karara bağlandı ama henüz
yapılmadı (bkz. docs/DURUM-VE-GELECEK.md Faz C).

Strix'in **payload katalogları** (XSS polyglot, path traversal, XXE) bilerek alınmadı: Warden
onları gönderemez (K1/K3) ve yalnızca "kaynak kodda bu desen var mı" statik kontrolü olarak
almak, mevcut sink kurallarının üstüne değer katmıyor.

### 1.8 Kapsam Beyanı — Strix'te olmayan, Warden'a özgü ✅ · v0.12

Bu madde devralma değil; incelemenin **yan ürünü**. Strix'in yeteneklerini Warden'ınkilerle
karşılaştırırken asıl farkın kural sayısı değil, **kapsam bilgisi** olduğu görüldü: Warden
neyi göremediğini bilmiyordu ve rapor "bakamadım" ile "baktım, temiz"i aynı gösteriyordu.

Ayrıntı ve tasarım kararları: `docs/DURUM-VE-GELECEK.md` §9.

---

## 2. ALINMAYANLAR

Bunlar "kötü fikir" değil — **Warden'ın kimliğiyle çelişen** ya da maliyeti şu an getirisini
aşan fikirler. Her biri için, kararı tersine çevirecek koşul yazılıdır.

### 2.1 `ast-grep` / tree-sitter ❌ — K2 ihlali

Platform-özel native binary (~10–20 MB) ve/veya derleme adımı gerektirir. `npx warden` ile
sıfır kurulum vaadini ve "1 runtime dep / build yok" etiğini bozar. Ayrıca kurulumun kendisi
ağ erişimi gerektirir (K1 ile gerilim).

**Karşılığı:** §1.3 — yerleşik TypeScript AST'i. TS/JS ekosistemi için kazancın büyük kısmını
native maliyet olmadan verir.

**Kararı değiştirecek koşul:** Warden'ın TS/JS dışı dillerde (Python/Go/PHP/C#) **derin**
yapısal analize ihtiyaç duyması. TypeScript AST'i yalnızca TS/JS'i çözer; diğer diller regex
seviyesinde kalır. Çok-dilli derin analiz gerçek bir ürün gereksinimi haline gelirse
`ast-grep` **opsiyonel peer** olarak yeniden değerlendirilmeli.

### 2.2 Playwright Security Engine ❌ — K1/K2 ihlali

~300 MB tarayıcı binary'si indirir. K2'yi (sıfır kurulum) ve kurulum anında K1'i (ağ) ihlal
eder. Opsiyonel peer yapılsa bile, "login/logout/cookie/CSRF senaryolarını tarayıcıda koştur"
yeteneği tanım gereği **aktif testtir** — yetki kapısının ciddi biçimde genişletilmesini
gerektirir.

**Kararı değiştirecek koşul:** Faz 3 (Proof Engine) hayata geçer ve kullanıcılar oturum-tabanlı
senaryo doğrulaması (yalnızca statik analizle imkânsız olan şey) talep ederse. O noktada
`warden-browser` **ayrı ve tamamen opsiyonel bir paket** olarak düşünülmeli — çekirdeğe asla
girmemeli.

### 2.3 Proof Engine / Module X (PoC üretimi) ⏳ değil ❌ — ertelendi, reddedilmedi

"Bulgu" yerine "kanıt" üretme (ör. IDOR için `GET /user/1` + `GET /user/2` → 200 → doğrulandı)
Warden'ın vizyonuyla **tamamen uyumlu** — hatta altyapısı kısmen hazır: korumalı HTTP istemcisi
(allow-list + rate-limit + GET-only + audit) DAST modülünde zaten var.

Şimdi yapılmama nedeni **kapsam**, ilke değil: aktif sömürü doğrulaması `warden.authz.yml`
kapısının genişletilmesini, hukuki/etik yüzeyin yeniden çizilmesini ve PoC'lerin
non-destructive olduğunun ispatını gerektirir. Bu, devralma turuna sığmayacak müstakil bir faz.

**Sırası:** §1.2 (taint) tamamlandıktan sonra. Taint, hangi bulguların PoC'ye değeceğini
belirleyen ön eleme katmanıdır — sırası tesadüf değil.

### 2.4 Graph-of-Agents / LLM-merkezli karar ❌ — K4 ihlali

Warden'ın tüm değer önerisi determinizm ve denetlenebilirlik. Bir bulgunun varlığı bir dil
modelinin o günkü çıktısına bağlıysa; fingerprint kararsızlaşır, delta anlamını yitirir, CI
gate güvenilmez olur ve "kanıt üreten sistem" iddiası düşer.

**Kararı değiştirecek koşul:** Yok — bu kimlik kararı. Yalnızca **yerel** LLM (Ollama/llama.cpp),
**yalnızca açıklama/özetleme** için ve **asla bulgu üretme/eleme kararında değil**, uzak gelecekte
opsiyonel olarak düşünülebilir (vizyon Faz 5).

### 2.5 Writable mount / agent'ın dosya değiştirmesi ❌ — K3 ihlali

Strix ajanları hedef repoda gerçek değişiklik yapar. Warden read-only'dir ve düzeltmeyi
`remediation-playbook.md` + skill üzerinden **kullanıcının onayıyla** yapar. Denetim aracının
denetlediği sistemi sessizce değiştirmesi, denetimin kendisini geçersiz kılar.

**Kararı değiştirecek koşul:** Yok — bu da kimlik kararı.

### 2.6 Docker / Kali bağımlılığı ❌ — K2 ihlali

Strix analiz ortamını konteynerde kurar. Warden'ın hedefi, geliştiricinin makinesinde ek
altyapı olmadan çalışmak. Konteyner zorunluluğu benimseme eşiğini yükseltir.

---

## 3. Uygulama sırası

Sıra risk-artan ve fingerprint-nötr işleri öne alacak biçimde kuruldu.

| # | İş | Fingerprint etkisi | Risk | Durum |
|---|-----|:---:|:---:|:---:|
| 0 | v0.10 turunu commit'le (583 satır commit'siz duruyor) | yok | yok | ✅ |
| 1 | `detect/fs.ts` `maxDepth` kör noktası (13 modülü etkiliyor) | **yeni bulgu dalgası** | orta | ✅ |
| 1b | Waiver `path` selector'ı + Warden self-match'leri | yok | düşük | ✅ |
| 2 | Diff-scope tarama (`--since`) — §1.1 | yok | düşük | ✅ |
| 3 | Taint katmanı (dosya-içi) — §1.2 + §1.5 | yok (yalnız `confidence`) | orta | ✅ |
| 4 | Opsiyonel AST katmanı — §1.3 | yok | orta | ⏳ |
| 5 | Rule Packs — §1.4 | yeni kural = yeni bulgu | düşük | ✅ |
| 6 | DAST yol kataloğu 11→43 — §1.6 | yok (yalnız aktif tarama) | düşük | ✅ |
| 7 | Kapsam Beyanı (Strix'te yok) | yok | düşük | ✅ |
| 8 | CWE eşlemesi + SARIF taksonomisi — §1.7 | yok | düşük | ✅ |
| 9 | Doğrulama notları (False Positives) — §1.8 | yok | düşük | ✅ |
| 10 | Rule Packs — §1.9 | yeni kural = yeni bulgu | düşük | ✅ |

### §1.3 hakkında düzeltme (v0.12)

`ast-grep` reddi (§2.1) "platform-özel native binary" gerekçesine dayanıyordu ve
`@ast-grep/napi` için bu **doğru**. Ancak gerekçe tüm AST seçeneklerine genellenmişti; oysa
**`web-tree-sitter` saf WASM'dır** — 4,5 MB, platform-bağımsız, derleme adımı yok. K2'nin
native-derleme itirazı buna uymuyor.

Sonuç: §1.3'ün "yerleşik TypeScript AST'i" planı, yalnızca TS/JS'i çözdüğü için yetersiz
kalıyor. Yerine `web-tree-sitter` opsiyonel peer olarak değerlendirilmeli — Ruby, Java, Rust,
Kotlin bugün **sıfır dile özgü kurala** sahip ve TypeScript AST'i bunu çözmüyor. §2.1'in
"kararı değiştirecek koşul" satırı (çok-dilli derin analiz gerçek bir gereksinim olursa)
fiilen gerçekleşti.

### Sıra 1'in ortaya çıkardıkları (kayıt)

`maxDepth` 4→6 tek başına bir performans ayarı sanılıyordu; iki gizli kusuru açığa çıkardı:

- **Yedi modül hiç çalışmıyormuş.** Bu repoda çalışan modül sayısı 9 → 16. CLOUD, K8S, PAY,
  WEB, FLOW, EMAIL ve UPLOAD modüllerinin `applicable()` kontrolleri derin dosyaları
  göremediği için sessizce atlanıyorlardı. Rapor bunu "modül uygulanabilir değil" diye
  gösteriyordu — yani eksik denetim, tam denetim gibi görünüyordu.
- **Test fixture'ları gerçek altyapı sanılıyordu.** Derinlik açılınca CLOUD/K8S/parity,
  `test/fixtures/vuln-*` altındaki kasıtlı zafiyetli örneklerden 13 bulgu (4'ü P0) üretti.
  Sebep: "test/fixture gerçek değildir" bilgisinin dört ayrı yerde farklı biçimde durması.
  `util/paths.ts` artık tek kaynak.

Sonuç: self-scan 46 bulgudan (13 fixture FP + 26 self-match) **7 gerçek bulguya** indi.

### Sıra 2'nin tasarım kararı (kayıt)

Diff-scope'ta en kolay hata, kısmi sonucu tam postür kaydıyla karıştırmaktı. Alınan önlemler:

- `find()` daraltılır, **`exists()`/`readFile()` daraltılmaz**. Modüllerin çoğu bir korumanın
  *varlığını* yokluyor ("helmet kurulu mu"); onları da daraltmak, kapsam dışında kaldığı için
  görülemeyen her korumayı "yok" saydırır ve kısmi taramayı bir yokluk-temelli FP fabrikasına
  çevirirdi. Daralan şey "neyi tarıyoruz", "proje neye sahip" değil.
- `findings.json` ve `history.jsonl` kısmi çalışmada **yazılmaz**. İkisi de "bu projenin bilinen
  tüm bulguları" anlamı taşır; kısmi sonucu oraya yazmak, taranmayan dosyalardaki bulguları bir
  sonraki çalışmada "yeni", bu çalışmada "düzeltildi" gösterirdi.
- **Delta hesaplanmaz.** Boş delta, yanlış delta'dan iyidir.
- Kapsam çözülemezse (git yok, ref yok) **tam taramaya düşülür ve gürültülü uyarılır** —
  sessizce eksik tarama yapmaktansa beklenenden yavaş çalışmak yeğdir.

### Sıra 3'ün tasarım kararı (kayıt) — sinyalin asimetrisi

Taint katmanının ilk tasarımında güven iki yönlü ayarlanıyordu: girdi ulaşıyorsa yükselt,
ulaşmıyorsa düşür. **Bu yanlıştı ve uygulanmadan önce düzeltildi.**

Motorun pozitif kararı ("girdi ulaşıyor") güvenilirdir — kaynaktan sink'e giden atama zinciri
fiilen görülmüştür. Negatif kararı ("ulaşmıyor") güvenilir değildir, çünkü analiz dosya-içi ve
düz atamalarla sınırlı: fonksiyonlar arası ya da dosyalar arası akışla gelen gerçek bir zafiyet
motora görünmez. İki yönlü ayar, tam da motorun kör olduğu yerlerde gerçek zafiyetlerin güvenini
düşürür ve onları raporun dibine gömerdi.

Nihai davranış:

| Taint sonucu | Güven |
|---|---|
| ulaşıyor + temizlenmemiş | **yükselir** (low→medium→high) |
| temizlenmiş | bir kademe düşer, `low`'un altına inmez |
| bulunamadı | **hiç dokunulmaz** |

Son satır bu katmanın en önemli güvencesi: **taint eklemek hiçbir mevcut bulgunun görünürlüğünü
azaltamaz.** Katman yalnızca bilgi ekler, asla bilgi gizlemez.

`severity` de bilerek dokunulmadan bırakıldı — severity `--fail-on` CI gate'ini sürüyor ve
heuristik bir sinyalin build kırma kararını değiştirmesi, bu katmanın hak ettiğinden fazla
yetki almasıdır.

23 kural taint-farkındalı işaretlendi (17 B6 injection sink'i + 6 FE DOM-XSS sink'i).

**Sıra 1 hakkında uyarı:** `maxDepth` varsayılanı 4→6 çıkarmak Strix işi değil, mevcut sistemin
kendi borcu. Ama monorepo'larda (`apps/web/src/components/ui/X.tsx` = 5 seviye) **tüm modüller**
kör; taint eklemeden önce kapatılmalı, aksi halde taint de aynı dosyaları göremez. Etkisi
fingerprint kayması değil ama **gerçek yeni bulgu dalgasıdır** — daha önce hiç taranmamış
dosyalar ilk kez görülecek. Bu beklenen ve doğru davranıştır; sürüm notunda duyurulmalı.
