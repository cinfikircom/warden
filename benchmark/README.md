# Warden Recall Benchmark

> **Soru:** "Kuralım çalışıyor mu?" değil — **"Kaçırıyor muyum?"**

Warden'ın 431 testinin tamamı kendi yazdığımız fixture'lara karşı koşar. Bu, bir kuralın
çalıştığını kanıtlar; **kaçırmadığını kanıtlamaz**. Bir güvenlik aracı için asıl soru ikincisidir
ve bugüne kadar cevabını ne biz biliyorduk ne kullanıcı.

Bu dizin o cevabı ölçülebilir kılar: **bağımsız, bilinen-zafiyetli** bir kod tabanına karşı
"şuradaki N zafiyetin kaçını buldun?" sorusu.

## Neden kendi fixture'larımız yetmiyor

Kendi fixture'ımızı yazarken kuralı da biz yazıyoruz — ikisi aynı varsayımı paylaşıyor. Fixture
kuralın aynadaki yansımasıdır: hep geçer, çünkü kural tam olarak onu yakalamak için yazıldı.
Bağımsız bir kod tabanı bu döngüyü kırar; oradaki zafiyet bizim hayal ettiğimiz biçimde değil,
gerçek bir geliştiricinin yazdığı biçimde durur.

## Kullanım

```bash
pnpm bench:fetch     # hedefleri indirir (ağ gerektirir, bir kez)
pnpm bench           # taramayı koşar ve recall'u raporlar
pnpm bench -- --target nodegoat --verbose   # tek hedef, kaçanları tek tek listeler
```

Ağ yoksa `bench:fetch` atlanır ve indirilmiş hedeflerle çalışılır — indirilmiş hedef yoksa
benchmark **çalışmadığını söyler**, sessizce boş sonuç dönmez. (Kapsam Beyanı'nın aynı ilkesi:
ölçemediğini ölçmüş gibi göstermek en pahalı hatadır.)

### Korpus neden `.corpus` (nokta ile)

İndirilen hedefler `benchmark/.corpus/` altına iner. Nokta öneki zorunludur: `detect/fs.ts`
nokta-dizinlerini atlar, dolayısıyla korpus Warden'ın **kendi** self-scan'ine karışmaz.

Bu ders pahalıya öğrenildi. Korpus önce düz `corpus/` idi ve waiver ile bastırılıyordu — ama
waiver yetmedi: üçüncü taraf korpustaki bir CI workflow'u, proje-düzeyi bir kontrolü tetikleyip
bulguyu **Warden'ın kendi dosyasına** bağladı. Yol waiver'ı bunu göremez, çünkü bulgunun konumu
korpusta değil. Tek doğru çözüm korpusu tarama ağacının tamamen dışında tutmaktı.

### Tek sayı değil, harita

`pnpm bench` sonunda **dil bazlı bir tablo** basar. Tek bir toplam recall yanıltıcıdır: bir dilde
%80, başkasında %0 olabilirsiniz ve toplam bunu gizler. Toplam satırı ayrıca zafiyet sayısıyla
ağırlıklıdır — büyük ground truth'lu bir hedef sonucu baskılar. **Dil satırları toplamdan daha
bilgilendiricidir** ve bir sonraki yatırımın nereye gideceğini gösterir.

## Ground truth formatı

`targets/<isim>.yml`:

```yaml
target: nodegoat
repo: https://github.com/OWASP/NodeGoat
ref: master
root: NodeGoat-master
vulnerabilities:
  - file: app/data/allocations-dao.js
    line: 62
    class: nosql-injection
    evidence: "$where: \"this.userId == \" + userId"
    note: "Kullanıcı girdisi doğrudan MongoDB $where ifadesine giriyor."
```

`class` sabit bir sözlükten gelir (bkz. `run.ts` içindeki `CLASS_TO_CHECKS`). Sözlükte olmayan
bir sınıf **hata verir** — sessizce yok sayılmaz, çünkü eşlenemeyen bir ground-truth maddesi
recall'u sessizce yükseltirdi.

## İki recall ölçüsü

Tek bir yüzde yanıltıcı olurdu, bu yüzden iki sayı raporlanır:

| Ölçü | Anlamı |
|---|---|
| **Konum recall'u** | Doğru dosya ve satır civarında *herhangi bir* bulgu ürettik mi? "Buraya baktım ve bir şey gördüm." |
| **Sınıf recall'u** | Aynı yerde *doğru sınıfta* bulgu ürettik mi? "Gördüğüm şeyin ne olduğunu da bildim." |

Konum yüksek + sınıf düşük ise: zafiyeti görüyoruz ama yanlış etiketliyoruz — bu bir kural
kalibrasyon işidir. İkisi de düşükse: gerçek bir kör nokta.

## Eşleşmeyen bulgular neden "yanlış pozitif" sayılmaz

Bir bulgu ground truth'ta yoksa, bu iki anlama gelebilir: (a) gerçekten yanlış pozitif, ya da
(b) **ground truth eksik** — NodeGoat'un tutorial'ı OWASP Top 10'a odaklanır, oysa kodda
belgelenmemiş başka zafiyetler de vardır. İkisini ayırmak elle inceleme ister.

Bu yüzden rapor onları `unmatched` diye sayar ve **precision hesaplamaz**. Ölçemediğimiz bir
sayıyı üretmemek, bu projenin baştan beri savunduğu şey.
