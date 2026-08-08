# Warden — Durum Değerlendirmesi ve Gelişim Önerisi

> Tarih: 2026-08-07 · Değerlendirilen sürüm: **v0.11.0** · Hedef: "her yazılımı, her web
> projesini, en uç noktasına kadar kontrol edebilen bir sistem"
>
> **Güncelleme (v0.12.0):** Faz A'nın çekirdeği uygulandı — Kapsam Beyanı, skor tablosunda
> "kapsam dışı" durumu, sessiz limitlerin raporlanması, modül sağlık tablosu ve
> `--max-depth` / `--max-files` bayrakları. Ayrıntı: §9. Kalan Faz A işi: recall benchmark.
>
> Bu doküman üç soruya cevap verir: **(1)** Bugün gerçekte neyi kontrol ediyoruz? **(2)** Neyi
> kaçırıyoruz ve neden? **(3)** Hedefe ulaşmak için ne eklenmeli? Son bölüm, `STRIX-ADOPTION.md`
> içinde "alınmadı" diye kapatılan maddelerin bugünkü hedef ışığında yeniden değerlendirmesidir.

---

## 0. Tek paragraflık cevap

Warden bugün **çok iyi bir kod denetçisi**. 18 modül, 91 kontrol kodu, 67 desen kuralı, 435 test.
Ama hedeflenen şey — "çalışan bir yazılımın her adımını uç noktasına kadar kontrol etmek" — bugünkü
Warden'ın **yapmadığı** bir şey: Warden kaynak kodu okur, çalışan yazılımı izlemez. Aradaki fark bir
eksik özellik değil, bir **kategori farkı**: röntgen çekmekle hastayı yürürken izlemek arasındaki
fark. İkincisi olmadan "bizden bir şey kaçmadı" denemez.

Bundan da önemli ikinci bir sorun var: **Warden bugün neyi göremediğini bilmiyor ve söylemiyor.**
Aşağıdaki 3. bölüm bunu kendi raporumuzla kanıtlıyor. Bu, kaçırılan zafiyetten daha tehlikelidir,
çünkü kullanıcıya hak etmediği bir güven verir.

---

## 1. Bugün ne durumdayız — sayılarla

| Ölçü | Değer | Not |
|---|---|---|
| Motor kodu | 10.158 satır TypeScript | `packages/warden-core/src` |
| Test | 405 test / 32 dosya | Hepsi kendi fixture'larımıza karşı — bkz. §6 fikir 2 |
| Modül implementasyonu | **18** | 17 farklı modül kodu (`sast` ve `imports` ikisi de `B`) |
| Farklı kontrol kodu (`check`) | **91** | A1–A6, B1–B9, C1–C6, D1–D7, CLOUD-*, K8S-*, API-*, … |
| SAST desen kuralı | **57** | `modules/sast/rules.ts` |
| Frontend desen kuralı | **10 + 4** | 10 satır kuralı + 4 pencere analizi (CSP, postMessage, tabnabbing, SRI) |
| IaC / K8s kuralı | **10 + 5** | Terraform + Kubernetes manifest |
| Stack dedektörü | **9** | Prisma, Drizzle, Django, Laravel, ASP.NET, Go, Docker, Cloudflare, Node-generic |
| Runtime bağımlılığı | **1** (`yaml`) | Build adımı yok, `npx` ile çalışır |
| Standart eşlemesi | OWASP Top 10, ASVS, API Top 10, CIS, ISO 27001, PCI-DSS 4.0 | Hiçbiri "pass" üretmez — yalnızca `fail` / `unknown` |

**Güçlü olduğumuz yerler — bunlar gerçekten sektör üstü:**

1. **Kanıt zorunluluğu.** Hiçbir boyut "temiz" ilan edilemez; skor ölçülür, iddia edilmez.
   Fingerprint + delta motoru bunu kod düzeyinde zorlar.
2. **Dürüst uyum eşlemesi.** ASVS/OWASP/CIS haritaları asla `pass` üretmiyor, yalnızca `fail`
   veya `unknown`. Ticari tarayıcıların çoğu burada yeşil tik basar. Biz basmıyoruz.
3. **Offline çalışma.** KEV/EPSS bile yerel anlık görüntüden okunuyor. Tarama sırasında hedef
   sistem hakkında dışarı tek bayt gitmiyor.
4. **Genişlik.** Ödeme akışı, kiracı izolasyonu, iş-akışı bütünlüğü (transaction/idempotency),
   e-posta başlık enjeksiyonu, dosya yükleme — bunlar çoğu tarayıcıda yok. Modül PAY ve FLOW
   fiilen "CRM/ERP'yi batıran hatalar" kataloğu.
5. **Yetki kapısı.** Aktif test çift kapılı (`intent` + `warden.authz.yml`). Etik yüzey net.

---

## 2. Bir proje geldiğinde tam olarak neye bakıyoruz

Her modülün sorduğu soruyu tek cümleyle:

| Boyut | Sorduğu soru | Ne zaman çalışır |
|---|---|---|
| **A — Parity** | Yazdığın kod ile çalışan sistem aynı mı? Migration veri siler mi? | Her projede |
| **B — SAST** | Kodda gömülü sır, zayıf kripto, enjeksiyon, zafiyetli paket var mı? | Her projede |
| **C — DAST** | Canlı hedefte açıkta dosya, zayıf başlık, açık admin paneli var mı? | Yalnız yetki kapısı açıkken |
| **D — Uyum** | Log/izleme, sır yönetimi, CI/CD, veri koruma, PCI, KVKK var mı? | Her projede |
| **CLOUD** | Terraform'da public bucket, IAM wildcard, açık güvenlik grubu var mı? | `.tf`/`.hcl` varsa |
| **K8S** | Privileged container, `:latest` imaj, düz metin secret var mı? | K8s YAML varsa |
| **API** | Aşırı veri dönüyor mu, rate-limit var mı, sayfalama var mı, hata sızıyor mu? | HTTP/API yüzeyi varsa |
| **ACCESS** | Kiracı izolasyonu kırık mı, yetkisiz endpoint var mı, mass-assignment var mı? | Web + ORM varsa |
| **AUTH** | MFA var mı, reset token tahmin edilebilir mi, cookie güvenli mi, brute-force koruması var mı? | Auth yüzeyi varsa |
| **PRIV** | Log'a/URL'e PII sızıyor mu, silme hakkı var mı, denetim izi var mı? | PII alanı varsa |
| **WEB** | CSRF koruması var mı, güvenlik başlıkları var mı, CORS yansıtılıyor mu? | Web yüzeyi varsa |
| **FLOW** | Çok adımlı yazma transaction'sız mı, sayaç atomik mi, sipariş idempotent mi? | Web yüzeyi varsa (yalnız JS/TS) |
| **EMAIL** | Başlık enjeksiyonu, HTML gövdede kaçışsız girdi, TLS'siz SMTP var mı? | Mailer varsa |
| **UPLOAD** | Dosya tipi kısıtı, path traversal, boyut limiti, web-root'a yazma var mı? | Upload kütüphanesi varsa |
| **FE** | DOM-XSS sink'i, storage'da token, zayıf CSP, prod source-map, SRI eksik mi? | Frontend yüzeyi varsa |
| **AI** | Gömülü LLM anahtarı, prompt enjeksiyonu yüzeyi, sistem promptu sızıntısı var mı? | LLM SDK'sı varsa |
| **PAY** | Webhook imzası, istemci-belirlediği tutar, idempotency, 3DS, mutabakat var mı? | Ödeme SDK'sı varsa |

Bu liste gerçekten geniş. Sorun listede değil, **her satırın ne kadar derin baktığında.**

---

## 3. Kanıt: kendi raporumuz neden yanıltıcı

Bugün bu repo üzerinde çalıştırdığımız taramanın (v0.11.0) skor tablosu:

```
Genel skor: 9.4 / 10 · 6 bulgu · P0: 0 · P1: 2

API Security ........................ 10.0 / 10
Payment Security & Reliability ...... 10.0 / 10
Access Control & Tenant Isolation ... 10.0 / 10
Identity & Session Hardening ........ 10.0 / 10
Data Privacy & Audit Trail .......... 10.0 / 10
CSRF, Clickjacking & Headers ........ 10.0 / 10
Workflow & Data Integrity ........... 10.0 / 10
Email Security ...................... 10.0 / 10
File Upload Security ................ 10.0 / 10
```

Warden bir CLI aracıdır. **HTTP API'si yok. Ödeme almıyor. Kullanıcı oturumu yok. Dosya yüklemesi
yok. Kiracı kavramı yok.** Yani bu dokuz "10.0/10", "kontrol ettim ve temiz buldum" değil,
**"kontrol edilecek bir şey yoktu"** demek. Rapor bu iki durumu ayırt etmiyor.

Aynı sorunun daha sinsi biçimleri:

- Bir modül çöker (`orchestrator.ts` her modülü `try/catch` içinde koşar) → hata log'a yazılır,
  rapor bunu "bu boyut denetlenemedi" diye **öne çıkarmaz**.
- `npm audit` ağ olmadığı için çalışmaz → bağımlılık taraması sessizce atlanır, skor değişmez.
- Bir Ruby projesi taranır → `.rb` dosyaları okunur ama **tek bir Ruby'ye özgü kural yoktur** →
  rapor "0 bulgu" der.
- Dosya derinliği 6'yı aşar (`apps/web/src/app/(dashboard)/admin/page.tsx` = 7) → dosya
  **hiç okunmaz**, hiç uyarı çıkmaz.
- Bir dosyada 40 SQL enjeksiyonu vardır → `maxPerFile: 3` yüzünden **3'ü** raporlanır, kalan 37'si
  hiçbir yerde sayılmaz.

**Bu, bu dokümanın en önemli tespitidir.** "Bizden bir şey kaçmasın" hedefinin ilk adımı yeni kural
yazmak değil; **neyi göremediğini bilen ve bunu beyan eden bir sistem** kurmaktır. Şu an bir
kullanıcı 9.4/10 görüp rahatlıyor; oysa doğru cümle "incelenebilen alanda 9.4/10, ancak yüzeyin
%X'i hiç görülmedi" olmalıydı.

---

## 4. Beş yapısal boşluk

### G1 — Çalışan yazılımı hiç görmüyoruz  🔴 en büyük

Hedef "localde çalışan bir yazılımın her adımı" diyor. Bugün bu hedefin karşılığı **sıfıra yakın.**

18 modülün 17'si tamamen statiktir. Tek aktif modül DAST'tır ve bir hedefe yaptığı **her şey**
şudur: 11 sabit yol denemesi (`/.env`, `/.git/config`, `/swagger.json` …), 6 dizin listeleme yolu,
köke 1 istek (başlık + cookie analizi), TLS sertifika kontrolü, 5 sabit admin yolu, rate-limit için
köke 5 istek. Toplam **~25 GET isteği.**

Olmayanlar:

- **Oturum yok.** İstemci yalnızca `user-agent` gönderiyor; cookie/`Authorization` enjekte etmenin
  hiçbir yolu yok. Sonuç: **login arkasındaki her şey — yani uygulamanın gerçek gövdesi — görünmez.**
- **Crawler yok.** Endpoint listesi 11 sabit yoldan ibaret. Uygulamanın kendi 300 endpoint'i
  denenmiyor.
- **GET dışı metod yok.** POST/PUT/DELETE ile tetiklenen her şey (CSRF davranışı, yazma yolu IDOR,
  mass assignment) test edilemiyor.
- **Payload yok.** SQLi, XSS, SSRF, path traversal için tek bir aktif prob yok.
- **Redirect izlenmiyor.** `/admin` → 302 → `/admin/dashboard` senaryosunda kontrol `status !== 200`
  diye erken çıkıyor. Uygulamaların çoğu redirect kullandığı için bu kontrol pratikte ölü.
- **Gövdenin ilk 2 KB'ı okunuyor.** React/Next uygulamasında ilk 2 KB `<head>` boilerplate'idir →
  içerik heuristikleri neredeyse hep yanlış karar veriyor.
- **Rate-limit testi kendi kendini çürütüyor.** 5 istek atıyoruz ama istemci saniyede 2 istek
  sınırıyla ~500 ms bekliyor. 2,5 saniyede 5 istek hiçbir rate-limiter'ı tetiklemez → bu kontrol
  her hedefte yanlış pozitif üretmeye yatkın.

### G2 — Göremediğimizi bilmiyoruz  🔴

Motorun her katmanında **sessiz kırpma** var:

| Sınır | Değer | Uyarı veriliyor mu? |
|---|---|---|
| Dizin derinliği | 6 | ❌ Hayır, CLI bayrağı da yok |
| Dosya sayısı | 2.000 (genel) / 5.000 (SAST) | ❌ Hayır |
| Dosya boyutu | 1 MB | ❌ Hayır |
| Kural başına dosyada bulgu | 3 | ❌ Hayır |
| Git geçmişi | Son 500 commit, merge'ler hariç | ❌ Hayır |
| Harici araç yoksa | Boş sonuç döner | ❌ "Bulgu yok"tan ayırt edilemiyor |
| Modül çökerse | Boş sonuç döner | ⚠️ Yalnız log'a |

Ortak örüntü şu: **"graceful degradation" bir kör nokta fabrikasına dönüşmüş.** Her katman hata
durumunda sessizce boş sonuç dönüyor ve boş sonuç, rapor katmanında "temiz"den ayırt edilemiyor.
Bir güvenlik aracı için *"bakamadım"* ile *"baktım, temiz"* arasındaki farkın kaybolması en kritik
yapısal zaaftır.

Ayrıca **hiç taranmayan büyük dosya sınıfları** var: `Dockerfile` (uzantısız → regex tutmuyor),
`.sh` deploy script'leri, `.sql`, `.json` config'ler (service-account key'leri!), `.env`, lockfile
içerikleri, `dist/` (üretime giden asıl artefakt!), ve `.github` dışındaki **tüm nokta dizinleri**
— yani `.aws/`, `.ssh/`, `.kube/`, `.docker/`, `.husky/` (git hook = supply-chain vektörü),
`.vercel/`, `.terraform/`.

### G3 — Satır satır okuyoruz, kodu anlamıyoruz  🟠

Motorun tamamı `rule.pattern.test(line)` — yani **tek satırlık regex.** Bunun somut bedeli:

```js
// Prettier bunu böldüğü an motor kör:
const cmd = req.body
  .command;
exec(cmd);
```

Taint (veri akışı) katmanı v0.11'de eklendi ve doğru tasarlandı — ama kendi belgelediği sınırları
gerçek kodda çok bağlayıcı: **dosya-içi**, **fonksiyon-içi**, **kontrol akışsız**. Modern kod
neredeyse tamamen `controller → service → repository` şeklinde bölündüğü için taint motoru gerçek
projelerde çoğunlukla "bulunamadı" döner. Ek olarak scope kavramı olmadığından `data`, `id`, `value`
gibi yaygın isimler tainted işaretlendiğinde dosyadaki ilgisiz satırlar da tainted sayılabiliyor;
`escape` sanitizer deseni ise `escapeRegExp`/`escapeShell` gibi tamamen alakasız fonksiyonları da
"temizleyici" sayıyor.

### G4 — Dil kapsamı yanıltıcı  🟠

| Dil | Dile özgü kural | Gerçek durum |
|---|---|---|
| TypeScript / JavaScript | 5 + tüm generic | **Derin** — taint de yalnız burada çalışıyor |
| Python | 11 | Orta |
| PHP | 7 | Sığ |
| C# | 5 | Çok sığ |
| Go | 4 | Çok sığ |
| **Ruby** | **0** | ⚠️ Taranıyor sayılıyor, kural yok |
| **Java** | **0** | ⚠️ Taranıyor sayılıyor, kural yok — Log4Shell sınıfı hiçbir şey yok |
| Rust, Kotlin, Swift, Elixir, C/C++, Dart | — | Dosya bile okunmuyor |

Ruby ve Java tarama listesinde olduğu için rapor bu dillerde "0 bulgu" gösterir. **Denetlenmemişin
temiz gibi sunulması**, kapsam boşluklarının en tehlikeli türüdür.

Aynı yanılsama framework tespitinde de var: Django dışındaki hiçbir Python framework'ü (Flask,
FastAPI), Laravel dışındaki hiçbir PHP framework'ü (Symfony, WordPress), Rails, Spring
tanınmıyor — dolayısıyla bu projelerde **Modül A (parity/şema) hiç çalışmıyor.**

### G5 — Tedarik zinciri yalnızca npm  🟠

CVE taraması sadece `npm/pnpm audit` üzerinden. Yani:

- **Python, PHP, Go, .NET, Ruby, Java için hiçbir CVE kontrolü yok.**
- `yarn.lock` desteklenmiyor → Yarn projesinde bağımlılık taraması sessizce atlanıyor.
- `npm audit` **ağ gerektiriyor** — offline-first bir araçta bu, en kritik kontrolün en kırılgan
  kontrol olması demek. (`osv-scanner` alternatifi var ama harici araç kurulumu istiyor.)
- Monorepo'da manifest'ler yalnızca kökte aranıyor → `apps/api/requirements.txt` hiç görülmüyor.
- KEV/EPSS anlık görüntüsünün **tazeliği kontrol edilmiyor** — 6 ay eski bir KEV listesi, yeni
  sömürülen bir CVE'yi normal önceliğe düşürür ve kimse fark etmez.
- Lockfile **içeriği** okunmuyor: özel registry'ye/GitHub tarball'a işaret eden `resolved` URL'ler,
  eksik integrity hash, tipo-squat isimler — hiçbiri incelenmiyor.

---

## 5. Strix'te "alınmadı" denenler — bugünkü hedefle yeniden değerlendirme

`STRIX-ADOPTION.md` bu kararları **doğru gerekçelerle** verdi. Ama o kararlar "Warden çekirdeği ne
olmalı?" sorusuna cevaptı. Şimdiki soru farklı: **"Her yazılımı uç noktasına kadar kontrol eden bir
sistem ne olmalı?"** Bu soruya aynı cevaplar verilemez.

### Kilit içgörü: kısıtlar çekirdeğe ait, ürüne değil

K1–K4 (ağ kapalı, tek bağımlılık, read-only, deterministik) **korunmalı** — Warden'ın tüm değeri
orada. Ama bu kısıtları *tüm ürüne* dayatmak, hedefi matematiksel olarak imkânsız kılıyor:

> Çalışan bir yazılımı ağ kullanmadan test edemezsiniz. Bir tarayıcıyı 4,5 MB'lık motor olmadan
> sürüklenemezsiniz. Bir oturumu açmadan login arkasını göremezsiniz.

Çözüm kısıtları gevşetmek değil, **katmanı ayırmak**:

```
@warden/core     — K1–K4 mutlak. Değişmez. Varsayılan. npx ile çalışır.     [BUGÜN]
@warden/deep     — Opsiyonel peer. AST + çağrı grafı. Hâlâ offline, hâlâ read-only.
@warden/live     — Opsiyonel paket. Tarayıcı + oturumlu DAST + kanıt üretimi. Yetki kapılı.
@warden/observe  — Opsiyonel. Çalışan sürece bağlanan runtime gözlemci (IAST).
```

Kullanıcı hiçbirini kurmazsa bugünkü Warden'ı aynen alır. Kurarsa **kapsam beyanında** "derin
analiz: aktif" yazar. Kısıt ihlal edilmez, çünkü kısıt çekirdeğin sözüdür — ürünün tamamının değil.

### Madde madde yeni karar

| Strix maddesi | Eski karar | **Yeni öneri** | Gerekçe |
|---|---|---|---|
| **ast-grep / tree-sitter** | ❌ K2 (native binary) | 🔄 **Kısmen evet — ama `web-tree-sitter` ile** | `@ast-grep/napi` gerçekten platform-özel native binary. Ama **`web-tree-sitter` saf WASM'dır** (4,5 MB, platform-bağımsız, derleme adımı yok). Native derleme itirazı buna uymuyor. Ruby, Java, Rust, Kotlin, Swift bir anda açılır. Opsiyonel peer olarak K2 ihlali değil — `native-tools.ts` deseninin aynısı. |
| **Playwright** | ❌ K1/K2 (300 MB, aktif) | ✅ **Evet — ayrı paket olarak** | Ayrı paketse çekirdeği kirletmez. Oturumlu tarama, SPA render'ı ve DOM-XSS'in gerçek doğrulaması **statik analizle mümkün değil.** "Her adımı kontrol et" hedefinin olmazsa olmazı. Yetki kapısı zaten var, genişletilir. |
| **Proof Engine (PoC üretimi)** | ⏳ Ertelendi | ✅ **Evet — vizyonun kalbi** | "Kanıt üreten sistem" iddiasının somutlaşması bu. Taint tamamlandı, sıra geldi. Non-destructive PoC (iki hesapla IDOR doğrulaması gibi) hiçbir kısıtı ihlal etmiyor. |
| **Graph-of-Agents / LLM karar** | ❌ K4 (determinizm) | ❌ **Aynen hayır** | Bu bir kimlik kararı ve doğru. **Ama:** LLM'in *bulgu üretmediği* yerlerde kullanımı K4'ü ihlal etmez — bkz. Fikir 14 (kural derleyici) ve rapor özetleme. Ayrım "kim karar veriyor?" sorusudur, "LLM var mı?" değil. |
| **Writable mount / agent'ın yazması** | ❌ K3 | ❌ **Aynen hayır** — ama bir istisna öneriyorum | Hedef projeye yazmak yanlış. Ancak **izole bir git worktree'de düzeltmeyi deneyip delta ölçmek** (`fix simülasyonu`) hedef projeyi değiştirmez ve "bu düzeltme gerçekten kapatıyor mu?" sorusunu deterministik olarak yanıtlar. |
| **Docker / Kali zorunluluğu** | ❌ K2 | ❌ **Zorunlu olarak hayır** | Ama `@warden/observe` için **opsiyonel** bir sandbox profili mantıklı — kullanıcı isterse. |

---

## 6. Özgür fikirler — hedefe götürecek 14 öneri

Kısıtları bir kenara bırakıp "ne olsaydı bu sistem gerçekten hiçbir şeyi kaçırmazdı" sorusuna
cevaplar. Etki ve zorluk kabaca işaretlendi.

### Katman 1 — Dürüstlük (yeni bulgu üretmez, yalanı keser)

**1. Kapsam Beyanı (Coverage Manifest)** · etki: 🔥🔥🔥 · zorluk: düşük

Her rapora ikinci bir sayı: **kapsam yüzdesi.** Rapor şunu söylemeli:

```
Güvenlik skoru: 9.4/10   ·   Kapsam: %62

Gördüklerim:      412 dosya · 5 dil · 14/18 modül
Göremediklerim:   38 dosya derinlik-6 sınırında kesildi
                  4 dosya 1 MB üstü (atlandı)
                  dist/ hiç taranmadı (build çıktısı)
                  Ruby dosyaları tarandı ama Ruby kuralı yok (0/0)
                  npm audit çalışmadı (ağ yok) → bağımlılık CVE kontrolü YAPILMADI
                  CLOUD, K8S modülleri: bu projede uygulanamaz (dosya yok)
                  DAST: kapalı (yetki kapısı yok)
```

Ve skor tablosunda **"10.0"** ile **"n/d"** arasına üçüncü bir durum: **"kapsam dışı"**. Bugün
uygulanamayan modül 10.0 alıyor; alması gereken şey bir puan değil, bir açıklama.

Bu tek özellik Warden'ı sektörde eşsiz yapar. Hiçbir ticari tarayıcı "şunu göremedim" demiyor —
çünkü satış zorlaşıyor. Warden'ın tüm konumlandırması zaten dürüstlük üzerine kurulu; bu, o
konumlandırmanın en güçlü hâli.

**2. Recall ölçümü — bilinen zafiyetli uygulamalara karşı benchmark** · etki: 🔥🔥🔥 · zorluk: orta

435 test var ama hepsi **kendi yazdığımız fixture'lara** karşı. Bu, "yazdığım kuralın çalıştığını"
kanıtlar; **"kaçırmadığımı" kanıtlamaz.** Ölçülmesi gereken şey *recall* (duyarlılık):

> OWASP Benchmark / Juice Shop / DVWA / WebGoat / Damn Vulnerable GraphQL üzerinde: 
> "Bu uygulamada bilinen 87 zafiyetin kaçını bulduk?"

Sonuç README'ye bir rozet olarak konur ve her sürümde ölçülür. Bu, "bizden bir şey kaçmasın"
hedefinin **tek ölçülebilir cevabıdır.** Bugün bu sayıyı kimse bilmiyor — ne biz, ne kullanıcı.

**3. Sessiz limitleri gürültülü yap** · etki: 🔥🔥 · zorluk: çok düşük

`maxDepth`, `maxFiles`, `maxBytes`, `maxPerFile`, 500-commit sınırı, modül çökmesi, harici araç
yokluğu — hepsi rapora **bir satır** yazsın ve hepsi CLI bayrağıyla açılabilsin (`--max-depth`,
`--no-limits`). "Bu dosyada 3 bulgu gösterildi, **37 tane daha var**" cümlesi tek başına bir
düzeltme turunu kurtarır.

**4. Modül sağlık raporu** · etki: 🔥🔥 · zorluk: düşük

`ScanResult` içinde üç ayrı liste: **çalıştı** / **uygulanamaz (neden)** / **çöktü (hata)**. Bugün
çöken modül ile boş dönen modül aynı görünüyor. Yarısı çökmüş bir tarama temiz rapor gibi
görünebiliyor.

### Katman 2 — Derinlik (kodu gerçekten anlamak)

**5. `web-tree-sitter` ile çok dilli AST** · etki: 🔥🔥🔥 · zorluk: yüksek

Saf WASM, platform-bağımsız, derleme yok, opsiyonel peer. Kazanımlar:

- Çok satırlı ifadeler görünür olur (regex'in en büyük körlüğü)
- Yorum / string literal / ölü kod ayırt edilir → yanlış pozitifler düşer
- **Ruby, Java, Rust, Kotlin, Swift, C/C++ bir anda açılır** — bugün 0 kural olan diller
- Fonksiyon sınırları bilinir → taint scope kazanır

Kurulu değilse bugünkü regex yoluna düşülür. Kullanıcı hiçbir şey kaybetmez.

**6. Fonksiyonlar ve dosyalar arası taint (çağrı grafı)** · etki: 🔥🔥🔥 · zorluk: yüksek

Bugünkü taint gerçek kodda çoğunlukla susuyor, çünkü `controller → service → repository` zincirini
izleyemiyor. AST üstüne kurulan bir çağrı grafı bunu açar. Sırası 5'ten sonra — motor önce yapıyı
görmeli.

Not: `STRIX-ADOPTION.md`'deki **asimetri kuralı korunmalı** — pozitif taint güveni yükseltir,
negatif taint asla düşürmez. Bu, o dokümanın en iyi kararıydı.

**7. Saldırı Yüzeyi Grafı** · etki: 🔥🔥🔥 · zorluk: yüksek · **en özgün fikir**

Bugün 18 modül birbirinden **habersiz** çalışıyor. ACCESS "bu endpoint auth'suz" diyor, PRIV "bu
tablo PII içeriyor" diyor — ama kimse ikisini birleştirmiyor. Tek bir graf kurulsa:

```
endpoint → handler → ORM sorgusu → tablo → alan → PII sınıfı
    ↑                                              ↓
  auth middleware?                          şifreli mi?
```

Bu graf üzerinde **zincir soruları** sorulabilir:

- "Auth'suz bir endpoint, PII içeren bir tabloya sayfalamasız erişiyor" → tek bir P0
- "Kullanıcı girdisi 4 dosya geçip `exec()`'e ulaşıyor" → tam veri akışı zinciri
- "Bu ödeme webhook'u imzasız **ve** idempotent değil **ve** transaction'sız" → para kaybı senaryosu

Bu, **tek tek bulgulardan saldırı senaryosuna** geçiş. Bir güvenlik uzmanının kafasında yaptığı işi
motor yapar. Warden'ı "linter" kategorisinden çıkarıp gerçek bir denetim sistemine taşıyan şey bu.

**8. Endpoint / Route Envanteri** · etki: 🔥🔥🔥 · zorluk: orta · **en iyi maliyet/fayda**

Koddan gerçek endpoint listesini çıkar: Express router'ları, Next.js App Router dosya yolları,
FastAPI dekoratörleri, Django `urls.py`, Laravel `routes/`, Spring `@RequestMapping`. Üç şey aynı
anda kazanılır:

1. Rapora **"Bu uygulamanın 247 endpoint'i var"** envanteri girer — kullanıcı için tek başına
   değerli.
2. Her endpoint **auth / rate-limit / validation / PII** eksenlerinde tek tek işaretlenir.
3. **DAST 11 sabit yol yerine 247 gerçek yolu dener** → aktif tarama tek hamlede 20 kat derinleşir.

7. maddedeki grafın omurgası da bu envanterdir.

### Katman 3 — Canlılık (çalışan yazılımı görmek)

**9. Oturumlu DAST** · etki: 🔥🔥🔥 · zorluk: orta

`warden.authz.yml`'a bir `session:` bloğu:

```yaml
session:
  mode: cookie          # veya: login_flow | bearer
  cookie: "session=..."
  # ya da:
  login_flow:
    url: /login
    method: POST
    body: { email: "test@example.com", password: "..." }
  logged_in_marker: "Çıkış yap"    # oturumun düştüğünü anlamak için
```

Bu tek özellik **uygulamanın gövdesini** açar. Bugün DAST yalnızca kapıya bakıyor; oturumla içeri
girer. Ek olarak POST/PUT/DELETE desteği, redirect takibi ve gövde limitinin 2 KB'dan büyütülmesi.

**10. Runtime Observer — `warden observe`** · etki: 🔥🔥🔥 · zorluk: yüksek · **hedefin tam karşılığı**

Kullanıcı "**localde çalışan bir yazılımın** her adımı" dedi. Bunun tek gerçek cevabı budur:

```bash
warden observe -- npm run dev
warden observe -- python manage.py runserver
```

Node'da `--require` hook'u, Python'da `sitecustomize.py` ile uygulamaya bağlanılır (ikisi de
platform-standart, native derleme yok) ve **çalışırken** kaydedilir:

- Hangi endpoint'ler gerçekten kayıtlı (kodda bulunamayan dinamik route'lar dâhil)
- Hangi ortam değişkenleri okundu, hangileri hiç okunmadı (ölü config)
- Hangi dış host'lara bağlanıldı → **kod okuyarak asla bulunamayacak veri sızıntısı**
- Hangi SQL sorguları çalıştı → parametreli mi, string birleştirme mi (kesin cevap)
- Hangi dosyalar açıldı, hangi komutlar çalıştırıldı
- Hangi kütüphaneler **gerçekten yüklendi** → reachability artık heuristik değil, **ölçüm**

Bu bir **IAST** (interaktif uygulama güvenliği testi) katmanıdır ve statik analizin en zayıf
yerlerini tam olarak kapatır. Determinizm açısından: çıktısı çalıştırmaya bağlı olduğu için ayrı
bir kanıt sınıfı olarak (`evidence.kind: "runtime"`) işaretlenir ve fingerprint'e dâhil edilmez —
K4'e dokunmaz.

**11. Proof Engine — bulgu değil kanıt** · etki: 🔥🔥🔥 · zorluk: yüksek

"Muhtemelen IDOR var" yerine: iki test hesabı, A'nın kaynağını B ile iste, 200 döndü → **doğrulandı.**
Non-destructive PoC sınıfları: IDOR, eksik yetkilendirme, kiracı sızıntısı, açık redirect, CORS
yansıtma, rate-limit yokluğu (gerçek yükle), CSRF (tokensiz POST).

Doğrulanmış bulgu ayrı bir güven sınıfına girer: `confidence: proven`. Bu, kullanıcının playbook'ta
hangi işi önce yapacağını kesin olarak belirler.

**12. Tarayıcı katmanı — `@warden/browser`** · etki: 🔥🔥 · zorluk: orta

Playwright ayrı paket olarak. Kazanımlar: SPA render'ı (bugün ham HTML'in 2 KB'ı okunuyor), gerçek
DOM-XSS doğrulaması, CSP'nin *çalışırken* etkisi, oturum akışının otomasyonu, tarayıcı konsol
hatalarının toplanması, ve bir **ekran görüntülü kanıt** (rapora gömülebilir).

### Katman 4 — Genişlik

**13. Altyapı ve dağıtım katmanı** · etki: 🔥🔥 · zorluk: düşük

Bugün hiç taranmayan, riski yüksek yüzeyler:

- **`Dockerfile`** — root user, `latest` base, `ADD` ile uzak URL, build arg'da secret
- **CI workflow'ları** — `pull_request_target` + checkout (klasik repo ele geçirme), log'a
  yazılan secret, sürüm pinlenmemiş third-party action
- **`.husky/` git hook'ları** — supply-chain vektörü
- **`nginx.conf` / `Caddyfile` / systemd unit** — açık dizin listeleme, zayıf TLS
- **`dist/` bundle taraması** — üretime giden asıl dosya. Next.js'te `NEXT_PUBLIC_` olmayan bir
  env'in bundle'a sızması klasik bir P0 ve bugün **tamamen görünmez** (`dist/` ignore listesinde).
- **Lockfile içeriği** — özel registry URL'leri, eksik integrity, tipo-squat

**14. Rule Packs + doğal dil kural derleyici** · etki: 🔥🔥 · zorluk: orta

`STRIX-ADOPTION.md` §1.4 zaten planlıyor (YAML kural paketleri, kod çalıştıramaz). Üzerine bir
fikir: **kural yazmayı bir LLM'e yaptırmak K4'ü ihlal etmez.**

> "Bu projede her API handler'ı `withTenant()` sarmalayıcısı kullanmalı" 
> → LLM bunu bir YAML kuralına derler → **insan onaylar** → kural artık deterministik çalışır.

Karar LLM'de değil, kuralda. Warden'ın kimliği korunur, kapsam kullanıcı başına genişler. Aynı
mantık raporu sadeleştirmek için de geçerli — özetleyen LLM, bulgu üretmiyor.

### Bonus fikirler (kısa)

- **Filo görünümü.** Warden Knight bugün tek proje. 40 repoyu tek panelde izleyen bir "kale
  görünümü" — hangi repo hangi seviyede, kimin borcu ne kadar.
- **PR yorumu.** GitHub Action var ama PR'a yorum bırakmıyor. `--since` zaten hazır; eksik olan
  sadece yorum adımı.
- **Zaman boyutu.** "Bu bağımlılık 3 yıldır güncellenmedi", "KEV anlık görüntün 6 ay eski",
  "bu bulgu 180 gündür açık" — çürüme sinyalleri bugün ölçülmüyor.
- **Paralel + önbellekli orkestrasyon.** 18 modül **sırayla** çalışıyor ve her biri dosya ağacını
  **baştan** yürüyor; aynı dosya defalarca okunuyor. Tek bir paylaşılan dosya önbelleği + modül
  paralelliği büyük repoda taramayı kat kat hızlandırır. Bu bir güvenlik özelliği değil ama
  "her şeyi tara" hedefinin **ön koşulu**: yavaş tarayıcı, daraltılmış tarayıcıdır.
- **Modül başına zaman aşımı.** Bugün yok. Patolojik bir regex (ReDoS) tüm taramayı süresiz
  kilitleyebilir.

---

## 7. Önerilen sıralama

Sıra, `STRIX-ADOPTION.md`'nin kendi ilkesini izliyor: **önce fingerprint-nötr ve dürüstlük
artıran işler, sonra derinlik, en son yeni yüzey.**

### Faz A — Dürüstlük (2–3 hafta) · yeni bulgu üretmez

| # | İş | Neden önce |
|---|---|---|
| 1 | Kapsam Beyanı + "kapsam dışı" durumu | Bugünkü 9.4/10 yanıltıcı. Önce yalanı kes. |
| 3 | Sessiz limitleri raporla + CLI bayrakları | Tek satırlık değişikliklerle büyük kazanç |
| 4 | Modül sağlık raporu | Çöken modül temiz görünmesin |
| 2 | Recall benchmark (Juice Shop / OWASP Benchmark) | Bundan sonraki her işin ölçüsü bu olacak |

> Faz A'nın sonunda skorumuz muhtemelen **düşecek** ve kapsam yüzdemiz mütevazı çıkacak. Bu bir
> gerileme değil; ilk kez doğru sayıyı görüyor olacağız. Sonraki fazların değeri bu sayıyla ölçülür.

### Faz B — Derinlik (4–6 hafta)

| # | İş |
|---|---|
| 8 | Endpoint envanteri (en iyi maliyet/fayda) |
| 5 | `web-tree-sitter` AST katmanı (opsiyonel peer) |
| 13 | Altyapı katmanı: Dockerfile, CI, hook, bundle, lockfile |
| 6 | Fonksiyonlar/dosyalar arası taint |
| 14 | Rule Packs |

### Faz C — Canlılık (6–8 hafta) · `@warden/live`

| # | İş |
|---|---|
| 9 | Oturumlu DAST + POST/PUT/DELETE + redirect + crawl (8'in envanteriyle) |
| 11 | Proof Engine — `confidence: proven` |
| 10 | `warden observe` — runtime gözlemci (IAST) |
| 12 | `@warden/browser` — Playwright katmanı |

### Faz D — Sentez

| # | İş |
|---|---|
| 7 | Saldırı Yüzeyi Grafı — tüm modüllerin çıktısını tek grafta birleştir, zincir soruları sor |
| — | Filo görünümü, PR yorumu, zaman boyutu, paralel orkestrasyon |

---

## 7b. Bir projeye nasıl bağlanır?

"Tek ürün, farklı modüller" kararının pratik karşılığı budur. Dört soruya net cevap gerekiyor:
**nasıl kurulur, nasıl konuşur, uydular nasıl devreye girer, CI'a nasıl girer.**

### Bugün nasıl bağlanıyor

Zaten çalışan dört yol var ve hiçbiri hedef projeye yazmıyor (rapor klasörü hariç):

```bash
npx warden scan --target /yol/proje       # sıfır kurulum, hiçbir dosya bırakmaz
warden init --target /yol/proje           # Claude Code skill'i + Knight paneli kurar
warden scan --since origin/main           # PR/CI için diff-scope
# .github/workflows/ içinde composite action.yml → SARIF → Code Scanning
```

En düşük sürtünmeli giriş `npx`. Bu korunmalı: **kurulum gerektiren her adım benimseme
eşiğini yükseltir** ve K2'nin varlık sebebi tam olarak budur.

### Öneri 1 — Tek konfigürasyon dosyası

Bugün üç ayrı dosya var: `warden.authz.yml` (yetki), `.warden-ignore.yml` (waiver) ve planlanan
`warden-rules/`. Bir projeye bağlanmak "hangi dosyayı nereye koyacağım" sorusuyla başlamamalı.

```yaml
# warden.config.yml — tek giriş noktası
extends: recommended            # hazır profil: minimal | recommended | strict
scan:
  maxDepth: 8                   # derin monorepo
  include: ["apps/**", "services/**"]
layers:
  deep: auto                    # kuruluysa kullan, değilse regex'e düş
  live: off
authz: ./warden.authz.yml       # yetki kapısı AYRI dosyada kalır — bilerek
waivers: ./.warden-ignore.yml
```

**Yetki kapısı bilerek ayrı bırakılmalı.** `warden.authz.yml`'ın ayrı bir dosya olması bir
tasarım hatası değil, bir güvenlik özelliği: aktif test yetkisi, sıradan bir yapılandırma
anahtarıyla yanlışlıkla açılabilecek bir şey olmamalı. Ayrı dosya + imza alanları, o kararı
bilinçli bir eylem olarak tutuyor.

### Öneri 2 — Uydular opsiyonel peer olarak, otomatik algılamayla

`adapters/native-tools.ts` deseni zaten bunu yapıyor: araç kuruluysa çalıştır, değilse
graceful atla. Aynı desen katmanlara uygulanır:

```bash
npm i -D @warden/deep      # AST + çağrı grafı (offline, read-only kalır)
npm i -D @warden/live      # oturumlu DAST + kanıt üretimi (yetki kapılı)
```

Warden kurulu olanı **kendi algılar**; kullanıcı hiçbir bayrak yazmaz. Kurulu değilse tarama
aynen çalışır — kaybedilen tek şey Kapsam Beyanı'ndaki bir satırdır.

### Öneri 3 — Kapsam Beyanı aynı zamanda kurulum rehberi olsun

Bu, katmanlı mimarinin kendini kullanıcıya açıklama biçimi ve v0.12'nin doğal devamı.
Rapor şunu söyleyebilmeli:

```
Kapsam: 412 dosya · 14/18 modül · dosya kapsamı %91

Kapsamı artırmak için:
  • Ruby dosyalarında kural yok (37 dosya görüldü, denetlenmedi)
      → @warden/deep kurun: tree-sitter ile Ruby/Java/Rust açılır
  • Login arkasındaki 210 endpoint hiç test edilmedi
      → @warden/live + warden.authz.yml içinde session: bloğu
  • 8 dizin derinlik sınırında kesildi
      → --max-depth 9   (ya da warden.config.yml → scan.maxDepth)
```

Kullanıcı böylece "neyi göremediğimi" öğrenmekle kalmaz, **onu nasıl görünür yapacağını** da
öğrenir. Kapsam beyanı bir şikâyet listesi değil, bir yol haritası hâline gelir.

### Öneri 4 — CI'da kapsam da bir kapı olsun

`--fail-on P1` bugün yalnızca bulgu şiddetine bakıyor. Ama kapsam çökerse bulgu da düşer ve
CI yeşile döner — yani **kapsam kaybı, gate'i sessizce atlatmanın yolu.** Bunu kapatmak için:

```bash
warden scan --fail-on P1 --min-coverage 85 --fail-on-module-error
```

`--fail-on-module-error` özellikle önemli: bir modülün çökmesi bugün sadece log satırı. CI
bunu bilmeli, çünkü çöken modül = denetlenmemiş boyut.

### Önerilen bağlanma akışı

1. `npx warden scan --target .` — kurulum yok, ilk resim.
2. Raporun **Kapsam Beyanı** bölümünü oku: neyi göremedim?
3. `warden.config.yml` ile sınırları aç (`maxDepth`, `include`).
4. Kapsam hâlâ dar ise önerilen uydu paketini kur.
5. `warden init` — skill + panel; düzeltme döngüsü başlar.
6. CI'a `--fail-on` + `--min-coverage` ile bağla.

---

## 8. Kapanış: iki ürün mü, bir ürün mü?

Bu dokümanın altında yatan asıl soru şu:

> **Warden "her geliştiricinin `npx` ile çalıştırdığı dürüst bir denetçi" mi olacak, yoksa
> "bir sistemin her katmanını uç noktasına kadar doğrulayan bir platform" mu?**

İkisi aynı anda olabilir — ama yalnızca **katmanlı** bir mimaride:

- **Çekirdek asla değişmez.** K1–K4 aynen durur. `npx warden scan` bugünkü gibi çalışır, tek
  bağımlılık, ağ yok, saniyeler içinde.
- **Uydular opt-in.** Kullanıcı derinlik isterse kurar. Kurmazsa kaybettiği tek şey, kapsam
  beyanında yazan bir satırdır: *"derin analiz: kurulu değil"*.
- **Kapsam Beyanı ikisini birbirine bağlar.** Sistem her zaman ne gördüğünü ve ne göremediğini
  söyler. "Her şeyi kontrol ettim" hiçbir zaman iddia edilmez; onun yerine **kontrol edilenin
  sınırı ölçülür ve gösterilir.**

Bu, "kanıt üreten sistem" vizyonunun doğal devamı. Bugünkü Warden *bulguyu* kanıtlıyor. Bir sonraki
Warden **kapsamı da kanıtlamalı** — çünkü "bizden bir şey kaçmasın" cümlesinin tek dürüst karşılığı,
neyin kaçabileceğini bilmektir.

---

*Bu doküman v0.11.0 kod tabanı okunarak ve bu repo üzerinde canlı bir self-scan çalıştırılarak
hazırlandı. İçindeki her sayı ve her sınır kaynak koddan doğrulanmıştır.*

---

## 9. Uygulama kaydı — v0.12.0 (Faz A çekirdeği)

Bu bölüm, yukarıdaki önerilerden **hangilerinin gerçekten kodlandığını** ve uygularken ortaya
çıkan tasarım kararlarını kaydeder. Amaç, `STRIX-ADOPTION.md`'deki gibi aynı tartışmayı
tekrar açmamak.

### Yapılanlar

| # | İş | Nerede | Fingerprint etkisi |
|---|-----|--------|:---:|
| 1 | Kapsam Beyanı modeli + toplayıcı | `report/coverage.ts` (yeni) | yok |
| 3 | Derinlik / dosya-sayısı kesmeleri raporlanıyor | `detect/fs.ts` | yok |
| 3 | Dosya-boyutu ve kural-tavanı kesmeleri raporlanıyor | `modules/sast/scanner.ts` | yok |
| 4 | Modül sağlık kaydı (denetlendi / kapsam dışı / çalışmadı / hata) | `orchestrator.ts` | yok |
| 1 | Skor tablosunda **"kapsam dışı"** durumu | `report/scoreboard.ts` | yok |
| 1 | Rapora Kapsam Beyanı bölümü + `findings.json`'a `coverage` alanı | `report/generator.ts` | yok |
| 3 | `--max-depth` / `--max-files` bayrakları | `warden-cli/src/index.ts` | yok |
| 1 | 10 modül kendi yüzey sayısını bildiriyor | `modules/{upload,email,pay,ai,access,auth,api,priv,web,flow}` | yok |

17 yeni test (`test/coverage.test.ts`). Toplam 405 test geçiyor.

### Tasarım kararları (kayıt)

**Kapsam katmanı bulgu üretmez, bulgu bastırmaz.** K5 gereği fingerprint yalnızca
`module | check | title | evidence`'tan türer; kapsam bilgisi bunların hiçbirine dokunmaz.
Böylece tüm mevcut waiver'lar, delta geçmişi ve `history.jsonl` trendi kırılmadan korunur.
Bu, taint katmanında verilen kararın aynısıdır: **yeni katman yalnızca bilgi ekler.**

**Yanlış alarm da yanlış beyandır.** İlk uygulama her `{limit: 1}` sondajını "dosya tavanına
ulaşıldı" diye raporluyordu — modüllerin çoğu "bu projede X var mı?" diye sorarken bir tane
bulmakla yetindiği için beyan anında gürültüye boğuldu. Kural düzeltildi: yalnızca **gerçek**
bir tavan (yerleşik varsayılan ya da kullanıcının `--max-files` ayarı) aşıldığında raporlanır.
Aynı gerekçeyle test/fixture ağaçlarındaki derinlik kesmeleri de sayılmaz — oradaki dosyalar
kural katmanında zaten eleniyor, kesilmeleri gerçek bir denetim kaybı değil.

> Bu, katmanın en önemli dengesi: kaybı gizlemek kadar **olmayan kaybı bildirmek** de beyanı
> güvenilmez kılar. Kimse her taramada 40 satır yanlış uyarı okumaz; okunmayan beyan,
> olmayan beyandır.

**Sayım benzersizleştirilir.** `ctx.find()` her modül tarafından yeniden çağrıldığı için aynı
derinlik kesmesi 18 kez tetikleniyordu. Örnek verilen kayıplar örneğe göre tekilleştirilir;
aksi halde rapor "142 dizin kesildi" derdi, gerçek sayı 8 iken. Kapsamı olduğundan **kötü**
göstermek de yanlış beyandır.

**Atlanan dosya sayısı bilinen bir alt sınırdır.** Derinlik sınırında kesilen bir dizinin
altında kaç dosya olduğunu saymıyoruz — saymak için o ağacı yürümek, yani sınırın var oluş
sebebini iptal etmek gerekirdi. Bu belirsizlik raporda "Bu beyanın kendi sınırları"
başlığıyla açıkça yazılır: kapsam katmanı kendi eksiğini de beyan eder.

**Yüzey ölçümü `applicable()`'ın yerine geçmez, onu tamamlar.** `applicable()` gevşek bir ön
elemedir ve öyle kalmalı (dar olsaydı gerçek yüzeyleri kaçırırdı). Modül artık ayrıca kaç
gerçek yüzey öğesi bulduğunu bildirir; 0 ise boyut puan yerine "kapsam dışı" alır. Bulgu
varsa bu kural uygulanmaz — bulgu, yüzeyin var olduğunun kesin kanıtıdır ve başka bir
kaynaktan (SARIF içe-aktarımı) gelmiş olabilir.

**Kademeli geçiş.** `ModuleRunResult.surface` opsiyoneldir. Bildirmeyen modüller (A, B, D, FE,
CLOUD, K8S, C) eski davranışı korur ve raporda yüzey sütununda "—" gösterir. Bu, 18 modülü tek
seferde değiştirmek zorunda kalmadan doğru davranışa geçmeyi sağladı.

### Kullanıcı-görünür değişiklik

Yüzey bulamayan modül artık **10.0/10 yerine "kapsam dışı"** alır ve genel ortalamaya girmez.
Bir projede genel skor bu yüzden değişebilir. Bu bir gerileme değil — ilk kez doğru sayının
görülmesidir. Sürüm notunda duyurulmalı.

Bu repodaki self-scan'de CLOUD ve K8S boyutları "kapsam dışı"na geçti. PAY/UPLOAD/EMAIL gibi
boyutlar hâlâ puanlı görünüyor, çünkü Warden'ın **kendi kural tanımları** (ör. `pay/index.ts`
içindeki "stripe" deseni) yüzey sinyali olarak sayılıyor. Bu self-scan'e özgü bir durumdur ve
`.warden-ignore.yml`'daki self-match waiver'larıyla aynı kök nedene sahiptir; gerçek bir
kullanıcı projesinde PAY yalnızca gerçek bir ödeme entegrasyonu varsa tetiklenir.

### Önceki sanat: kapsam raporlamasında kimse iyi değil

Kapsam Beyanı'nın gerçekten bir boşluğu doldurup doldurmadığını sınamak için yaygın açık
kaynak tarayıcıları incelendi. Bulgular, tezi doğrudan destekliyor:

- **SARIF 2.1.0'ın kendisi kapsam kanıtı taşımıyor.** Yalnızca ihlaller (`results[]`) aktarılır;
  geçen kontroller, ayrıştırılamayan dosyalar ve taranan kaynak sayısı dışarıda kalır. Ölçüm
  (Checkov 3.3.9): 42 kontrol değerlendirilmiş, SARIF'e 17 sonuç yazılmış — **payda kayboluyor.**
  Bu, SARIF tüketen herkesi (Warden dâhil) etkileyen yapısal bir sınırdır.
- **Checkov'da `--skip-check` sessiz.** Atlanan kontrol `passed_checks`, `failed_checks` ve
  `skipped_checks` listelerinin **hiçbirinde** görünmez; yalnızca `failed` sayacı düşer. İnline
  `# checkov:skip=` gerekçesiyle birlikte raporlanırken, CLI ile atlama iz bırakmıyor.
- **KICS'te `files_failed_to_scan` alanı ölü** — her zaman 0 döner (üretim tarama yolunda hiç
  set edilmiyor). Bozuk bir dosya `files_scanned=3, files_parsed=2` verirken hata sayacı 0
  kalıyor ve rapor hangi dosyanın başarısız olduğunu **hiç söylemiyor**.

Yani "kontrol edemedim"i "temiz"den ayırmama sorunu Warden'a özgü değil; sektör genelinde bir
kör nokta. Bu, Kapsam Beyanı'nı bir eksiği kapatma işi olmaktan çıkarıp **farklılaştırıcı** bir
özellik hâline getiriyor.

Warden tarafında somut sonuç: `modules/imports/index.ts` artık harici rapor içe aktardığında
kapsam beyanına bir sınır notu yazıyor — o araçların neyi tarayamadığı bilinemediği için
içe-aktarılan bulgular kapsam yüzdesine dâhil edilmiyor, ama bu belirsizlik gizlenmiyor de.

### Ölü sayaç hatası — kendi kodumuzda bulundu ve kapatıldı

Rakip araç incelemesinin en değerli çıktısı bir kural oldu: **"her zaman sıfır olan bir sayıyı
hiçbir test yakalamaz."** KICS'in `Counters` struct'ı `files_failed_to_scan` alanını tanımlar
ama üretim yolunda hiç doldurmaz — bozuk bir dosya verildiğinde bile 0 döner ve hiçbir test
bunu fark etmez, çünkü "0 hata" geçerli bir sonuç gibi görünür.

Bu kural Warden'a uygulandığında **aynı hatanın burada da olduğu görüldü:** `LimitKind`
birleşiminde tanımlı yedi türden üçü — `git-history`, `tool-missing`, `no-rules-for-language`
— hiçbir yerde üretilmiyordu. Yani Kapsam Beyanı'nın kendisi, olmayan üç güvenceyi varmış gibi
gösteriyordu. Bunlar kapatıldı:

- **`no-rules-for-language`** → `sast/scanner.ts`: bir dosya okundu ama ona uyan hiçbir
  *dile özgü* kural yoksa bildirilir. Ruby ve Java için tam olarak bu geçerli: rapor artık
  *"`.rb` dosyaları okundu ama bu dile özgü kural yok — '0 bulgu', 'denetlendi ve temiz'
  anlamına gelmez"* diyor.
- **`tool-missing`** → `sast/index.ts`: `npm/pnpm audit` çalışmazsa. Bu, beyanın en kritik
  satırlarından biri — bağımlılık CVE taraması hiç yapılmadıysa kullanıcı bunu bilmeli.
- **`git-history`** → `sast/index.ts`: 500 commit penceresi ve merge-hariç taraması artık
  rapora yazılıyor.

Ve kalıcı koruma: `test/coverage.test.ts` içindeki **ölü sayaç testi** her `LimitKind` için en
az bir üretim çağrısı olduğunu zorluyor. Test, listeye sahte bir tür eklenerek doğrulandı —
yakalıyor. Bu, bu turun en kalıcı kazanımı: hata bir kez düzeltilmedi, **tekrar edilemez** hâle
getirildi.

### Rule Packs için kaynak ve lisans kararları (Faz B girdisi)

Kural paketlerinin nereden besleneceği birincil kaynaklardan doğrulandı:

| Kaynak | Lisans | Karar |
|--------|--------|-------|
| **gitleaks** | MIT · 222 kural | ✅ **Alınabilir** — secret desenleri, büyük ölçüde mekanik JS portu. Bugünkü 4 git-history desenimizin yerine geçer |
| **Nosey Parker** | Apache-2.0 · 189 kural | ✅ Alınabilir |
| **ast-grep-essentials** | Apache-2.0 · 554 kural | ✅ Alınabilir (AST katmanı geldiğinde) |
| **semgrep-rules / opengrep-rules** | Commons Clause / dağıtım yasağı | ❌ **Kapalı** — kural setini dağıtamayız |
| **trufflehog** | AGPL | ❌ Kapalı |
| **Snyk** | Apache-2.0 kod, ama ToS §2(n) rakip yasağı | ❌ Kapalı. Tek istisna `snyk/policy-engine` (Apache-2.0) |
| **Checkov** | Apache-2.0 · 1.359 kontrol, 33 framework | ✅ Zaten SARIF ile içe aktarılıyor |
| **KICS** | Apache-2.0 · 1.811 sorgu (v2.1.21) | ✅ İçe aktarılıyor; Rego yolu ayrıca değerlendirilebilir |

Checkov'un **inline suppression** biçimi doğrudan kopyalanmalı: `# checkov:skip=ID:gerekçe`
SARIF'e `"suppressions": [{"kind": "inSource", "justification": "..."}]` olarak düşüyor ve
seviye `error` → `warning`'e iniyor. Warden'ın waiver'ları bugün SARIF export'ta bu standart
alanı kullanmıyor — kullanmalı.

### Recall ilk kez ölçüldü — %42,2

Faz A tamamlandı. `benchmark/` altyapısı kuruldu (`pnpm bench`), ilk hedef **OWASP NodeGoat**
(Apache-2.0) ve ground truth'u kaynak kod okunarak çıkarıldı: **64 zafiyet**, dosya·satır·sınıf
düzeyinde.

| Ölçü | Sonuç | Anlamı |
|---|:---:|---|
| **Konum recall'u** | 33/64 · **%51,6** | Doğru yerde *bir şey* gördük |
| **Sınıf recall'u** | 27/64 · **%42,2** | Gördüğümüzün *ne olduğunu* da bildik |

Aradaki 6 maddelik fark kural kalibrasyonu işidir (yeri görüyoruz, yanlış etiketliyoruz),
kör nokta değil.

**Metodoloji düzeltmesi (kayıt).** İlk ölçüm %12,5 çıktı ve şüpheli derecede düşüktü.
İnceleyince iki ölçüm hatası bulundu — ikisi de recall'u *olduğundan kötü* gösteriyordu:

1. **Yokluk bulguları satır taşımaz.** "Projede CSRF koruması yok", "helmet yüklü değil",
   "şu paket zafiyetli" — bunlar proje-düzeyi bulgulardır ve Warden hangi satıra bağlayacağını
   keyfi seçer. Satır eşleşmesi beklemek, *bulunmuş* bir zafiyeti "kaçırıldı" sayıyordu.
   Ground truth'a `scope: project` alanı eklendi; 17 madde bu birimde ölçülüyor.
2. **`info-disclosure` eşlemesi eksikti** — PRIV-1 (log'da PII), PRIV-3/4/5 gerçekten bu
   ailedendir ve tabloda yoktu.

Eşleme tablosunun **skoru yükseltmek için** genişletilmesi kendi kendini kandırmak olurdu; tek
ölçüt "bu check gerçekten aynı zafiyeti mi gösteriyor" oldu ve bu kural `run.ts` içine yorum
olarak yazıldı.

**Kaçan 37 madde — kör nokta haritası:**

| Sınıf | Kaçan | Kök neden |
|---|:---:|---|
| info-disclosure | 7 | Şifresiz hassas alan / hata sızıntısı kuralları dar |
| xss | 6 | Swig `autoescape: false` ve `.html` şablon bağlamı görülmüyor |
| **hardcoded-secret** | **6** | `config/env/*.js` ve `artifacts/` altındaki sırlar (ZAP anahtarı dahil) kaçtı |
| nosql-injection | 4 | Taint kaynağı satırı bulgu üretmiyor (beklenen), `$where` dışı kalıplar yok |
| missing-authz / idor | 6 | Route tablosundaki eksik middleware görülmüyor |
| weak-crypto | 2 | "Parola düz metin saklanıyor/karşılaştırılıyor" kuralı yok |
| **ssrf** | **2** | `needle.get()` sink listesinde yok — kural axios/fetch'e göre yazılmış |
| regex-dos | 2 | ReDoS kuralı hiç yok |

31'i hiç görülmedi, 6'sının yeri görüldü ama sınıfı yanlıştı. `hardcoded-secret` ve `ssrf`
en çarpıcı olanlar: ikisi de Warden'ın *var olduğunu iddia ettiği* yeteneklerin sınırında.

### İlk kör nokta turu — recall %42,2 → %54,7

Benchmark'ın gösterdiği boşluklardan üçü kapatıldı. Her biri ölçülerek doğrulandı; toplam
kazanç **+12,5 puan** (konum recall'u %51,6 → %64,1).

| Düzeltme | Kök neden | Kazanç |
|---|---|:---:|
| **B1 camelCase secret** | Desen `\bsecret\b` gibi kelime sınırları kullanıyordu; JS/TS'in standart adlandırması olan `cookieSecret`, `cryptoKey`, `zapApiKey`, `dbPassword` hiçbiri eşleşmiyordu | +6 |
| **B6 SSRF değişken üzerinden** | Kural girdiyi sink ile aynı satırda arıyordu; gerçek kodda URL bir değişkenden gelir. Ayrıca `needle` sink listesinde yoktu | +2 |
| **B6 ReDoS** | Kural hiç yoktu | +2 |

**Yeni mekanizma: `requiresTaint`.** SSRF'nin değişken hâli desenle tek başına yakalanamaz —
her `needle.get(x)` bulgu üretirdi. Bu yüzden kural yalnızca taint girdinin sink'e ulaştığını
gösterirse bulgu üretiyor. Güvenli olmasının nedeni `STRIX-ADOPTION.md` §Sıra 3'teki asimetri:
taint motorunun **pozitif** kararı güvenilirdir (atama zinciri fiilen görülmüştür), güvenilmez
olan negatif kararıdır. Bu bayrak yalnızca pozitif karara dayanır ve mevcut hiçbir kuralın
görünürlüğünü azaltmaz.

**Süreç, sonuçtan daha öğreticiydi.** Üç ayrı hata bu turda kendi araçlarımızla yakalandı:

1. **`maxPerFile: 3` gerçek bir sır kaçırdı.** Fixture'daki dördüncü sır (`dbPassword`) sessizce
   kırpılmıştı. Sırlar tek bir config dosyasında kümelenir ve her biri rotasyon gerektiren
   gerçek bir maruziyettir — tavan 12'ye çıkarıldı. Bunu Kapsam Beyanı'nın uyarısı değil,
   *fixture testi* yakaladı; ikisi birbirini tamamlıyor.
2. **ReDoS kuralı yanlış pozitif üretti** — Warden'ın kendi `risk/asvs.ts` dosyasındaki güvenli
   sürüm regex'ini işaretledi. `safe-app` FP muhafızı testi bunu anında yakaladı. Desen iki
   şartla daraltıldı: grup içinde parantez olmamalı ve grup yakalayıcı olmalı (`(?:` elenir).
3. **Benchmark korpusu self-scan'i kirletti.** `benchmark/corpus/` indirilince Warden kendi
   postürüne 32 sahte bulgu ekledi. `.warden-ignore.yml`'a yol waiver'ı eklendi — üçüncü tarafa
   ait kasıtlı zafiyetli kod Warden'ın postürü değildir, ama bulguları benchmark'ta ölçülür.

### İkinci kör nokta turu — recall %54,7 → %79,7

Kalan boşlukların çoğu tek satırlık regex'le çözülmüyordu; eksik olan **katmanlardı**.
Konum ve sınıf recall'u artık eşit (%79,7) — yani gördüğümüz her zafiyeti doğru da
sınıflandırıyoruz.

| Eklenen katman | Kök neden | Kazanç |
|---|---|:---:|
| **FE-8 şablon motoru kaçışı** | Sunucu-tarafı şablon güvenliği hiç analiz edilmiyordu. Kaçış `server.js`'te kapatılır, sonucu `views/*.html`'dedir — ilişki dosyalar arası | +6 |
| **ACCESS route envanteri** | ACC-2 dosya seviyesindeydi: bir dosyada tek `isLoggedIn` görmek tüm route'ları korunmuş gösteriyordu | +6 |
| **AUTH-7/8/9** | Parola hash'inin YOKLUĞU, session fixation ve kullanıcı adı enumeration hiç kontrol edilmiyordu | +5 |
| **PRIV hassas alan listesi** | `dob`, `bankAcc`, `routingNumber` yüksek-hassas sayılmıyordu | +3 |
| **B1 anahtar dosyaları** | `.key`/`.pem`/`.p12` hiç taranmıyordu — koddaki gömülü anahtar yakalanıp dosya olarak duranın kaçırılması tutarsızdı | +1 |

**Beş ayrı "kelime var ama koruma yok" hatası bulundu.** Hepsi aynı sınıftan ve hepsi
ölçülmeden görünmezdi:

- `bcrypt` **import ediliyor** ama tek kullanımı yorumda — "hash var" sanılıyordu.
  Kullanılmayan bir import, uygulanmış bir koruma değildir.
- `isAdmin` üç dosyada geçiyor ama hepsi **veri** olarak (`user: { isAdmin: true }`);
  hiçbir route'ta middleware değil. Rol modeli yokken var sanılıyordu.
- `isLoggedIn` — çok yaygın bir Express middleware adı — auth listesinde **yoktu**;
  eksikliği tüm route-düzeyi auth analizini sessizce devre dışı bırakıyordu.
- Express + Swig/EJS gibi klasik sunucu-render uygulamaları **FE yüzeyi sayılmıyordu**
  (şablonda `<script>` yoksa "frontend değil"), tam da XSS'in en yoğun olduğu sınıf.
- FE-8'in URL-bağlamı kontrolü, ham-çıktı bulgularıyla **aynı dosya tavanını** paylaşıyordu;
  tavan dolunca ayrı bir zafiyet sınıfı sessizce kayboluyordu.

**Bir tasarım kararı, ölçüme rağmen reddedildi.** "Ayrıcalıklı yol" listesi (`/admin`,
`/manage` …) tutmak NodeGoat'ta puan kazandırırdı, ama bir uygulamanın en kritik ucu
`/benefits` ya da `/payouts` gibi tamamen alana özgü bir ad taşıyabilir. Böyle bir liste
yalnızca tahmin ettiğimiz adları yakalar ve ölçüldüğü örneğe göre şişirilmeye açıktır.
Onun yerine genel ve ölçülebilir olan kondu: **auth var ama hiçbir route'ta rol kontrolü
uygulanmıyor** — o zaman giriş yapmış her kullanıcı en ayrıcalıklı işlemi de yapabilir.

Yine iki hata kendi araçlarımızla yakalandı: FE-8'in açıklama yorumu kendi FE-3 kuralımızı
tetikledi (waiver), ve benchmark inceleme dosyam self-scan'e sızdı (temizlendi).

### Sıradaki iş

13 kaçan kaldı. Çoğu handler-içi akış analizi istiyor: `req.params.userId` ile çekilen
kaydın sahiplik doğrulaması (2), `req.body` tip kontrolü olmadan NoSQL sorgusuna geçmesi (3),
uzak yanıtın `res.write` ile istemciye yazılması (1), HTTP Parameter Pollution (1).
Bunlar fonksiyon-içi veri akışı gerektiriyor — yani `web-tree-sitter` AST katmanının
doğal işi.

Ardından Faz B: endpoint envanteri → `web-tree-sitter` → altyapı katmanı. Artık her değişiklik
`pnpm bench` ile sayıyla sınanıyor.

Faz B için not: **Rego/OPA portability doğrulandı.** KICS'in Rego sorguları
`opa build -t wasm` ile derlenip Node'da `@open-policy-agent/opa-wasm` (Apache-2.0) ile
çalıştırılabiliyor — 120/120 terraform/aws sorgusu hatasız derlendi ve doğru bulgu üretti.
Ama bedeli var: build zamanında Go `opa` binary'si gerekiyor (saf JS Rego derleyicisi yok),
KICS sorguları Rego v0 olduğu için `--v0-compatible` zorunlu (deprecation saati işliyor) ve
her sorgu `package Cx` olduğundan naif birleştirme çakışıyor. Son kullanıcı saf JS ve offline
kalır (önceden derlenmiş `.wasm`, sorgu+kütüphane başına ~145 KB). Rule Packs (§1.4) için
bildirimsel YAML'a göre çok daha güçlü ama çok daha ağır bir alternatif — kayda geçiyor.
