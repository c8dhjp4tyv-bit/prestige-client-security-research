# Prestige Client güvenlik araştırması

Bu klasör, `Prestige-Client.exe` ve 16 Ağustos 2026 tarihinde resmi API'den yakalanan `injector.dll` için çalıştırmasız statik analiz paketidir.

## Sonuç

İncelenen zincir, sunucudan aldığı imzasız PE payload'larını kriptografik olarak sabitlemeden bellekte çalıştırıyor ve Minecraft sürecine enjekte ediyor. Anti-debug/anti-VM katmanı ve kararlı donanım parmak izi toplama da doğrulandı. Ele geçirilen iki exact hash üzerinde RAT, browser stealer, keylogger, ekran kaydı, kalıcılık veya fidyeleme kanıtlanmadı; authenticated üçüncü aşama henüz elde edilmedi.

İlk kayıt parolasının düz metin gönderildiği iddiası da exact DLL üzerinde çürütüldü: değer Crypto++ SHA-256/HexEncoder hattından sonra JSON'a giriyor. Resmî gizlilik politikası bu istemci davranışıyla uyumlu. Bu sonuç sunucunun hash'i güvenli sakladığını veya hash'in tekrar kullanılamayacağını kanıtlamaz.

Bu nedenle doğru uyarı şudur: **RAT iddiası henüz kanıtlanmış değildir, fakat doğrulanmamış ve uzaktan değiştirilebilir keyfî kod teslim mimarisi kanıtlanmıştır; yazılım kullanılmamalıdır.**

## Dosyalar

- `Prestige-Client-investigation-TR.md`: yayımlanabilir ana Türkçe araştırma
- `EVIDENCE-LEDGER.md`: her iddia için exact hash, VA/ofset, veri akışı, kanıt düzeyi ve sınırlar
- `Prestige-injector-dll-static-analysis.md`: ikinci aşama teknik analiz
- `Prestige-Client-static-analysis.md`: dış loader teknik özeti
- `iocs.json`: makinece okunabilir IOC ve örnek kimlikleri
- `prestige_chain.yar`: exact-hash ve yapısal aile tespit kuralları
- `capture-third-stage.sh`: token'ı komut satırına koymadan Whonix'te üçüncü aşamayı yalnız dosyaya alan betik
- `SHA256SUMS`: yayımlanan artefaktların bütünlük listesi

Zararlı/şüpheli binary'ler bilerek bu pakete dahil edilmemiştir.

## Kanıt politikası

- Exact sample baytları, disassembly ve kesintisiz veri akışı birincil kanıttır.
- Kamu sandbox/AV etiketleri yalnız korelasyondur.
- Otomatik “keylogging”, “PowerShell” ve “credential theft” etiketleri IDA'da elle doğrulanmış; bağlamı desteklemeyenler suçlama olarak kullanılmamıştır.
- Başka domain/hash kullanan sahte Prestige paketleri bu örneğe atfedilmemiştir.
- Sandbox görev-özeti etiketleri süreç ağacına göre ayrılmıştır; aynı görevdeki Chrome/Windows davranışları Prestige'e mal edilmemiştir.

## Güvenli kullanım

Kurallar savunma ve olay müdahalesi içindir. Örnekleri kişisel/üretim Windows sisteminde çalıştırmayın. IP Cloudflare ortak altyapısı olabileceğinden tek başına IP bazlı engelleme yapmayın; hash, domain, URL ve davranış zincirini birlikte değerlendirin.
