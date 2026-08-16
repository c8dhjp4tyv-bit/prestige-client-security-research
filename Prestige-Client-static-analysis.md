# Prestige-Client.exe statik malware analizi

Tarih: 2026-08-16  
Yöntem: IDA Pro MCP (headless statik tersine mühendislik) ve CAPEv2 MCP (`static` kategori). Örnek yerelde veya CAPE sanal makinesinde yürütülmedi.

## Sonuç

**Risk: Yüksek — çalıştırmayın.** Dosya, sabit bir HTTPS uç noktasından ikinci aşama PE/DLL indiriyor, dosyayı diske bırakmadan belleğe elle eşliyor ve indirilen modülün `JNI_OnLoad` ihracını çağırıyor. Bu tasarım, uzaktaki sunucunun sonradan değiştirebildiği kodun kullanıcı makinesinde çalışmasına izin veren bir stager/loader davranışıdır. Dış EXE üzerinde Authenticode imzası yoktur.

Statik inceleme tek başına indirilen ikinci aşamanın nihai amacını (ör. hile modülü, bilgi hırsızı veya başka bir payload) kanıtlayamaz. Ancak mevcut kabuğun davranışı güvenli kabul etmek için yeterli değildir.

## Dosya kimliği

- Yol: `/home/umutcagand/İndirilenler/Prestige-Client.exe`
- Tür: PE32+, Windows GUI, x86-64
- Boyut: 767.488 bayt
- MD5: `d101c0eeb89ce736928a061f100337de`
- SHA-1: `feb0a5a4280eef41b7fa96be26e4698eb30804a2`
- SHA-256: `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08`
- Import hash: `c48ec9fabbe14329942c8cc66b3ae7bd`
- CAPEv2 ssdeep: `12288:LghUjKHgMt5PsrSuf+v+4o0+W6YLqjlOHnfR7oBmTzipavj/FYi8l5FUnI:vjKHgkKWv+4o0j6YLqjlOHnfR7okTz48`
- PE derleme zaman damgası: 2026-05-26 14:03:24
- Authenticode Security Directory: boş (imzasız)
- Overlay: yok

## IDA Pro kanıtları

1. `WinMain` (`0x1400012D0`) libcurl istemcisini hazırlıyor ve `CURLOPT_RESOLVE` ile `api.prestigeclient.vip:443` alan adını doğrudan `172.67.137.182` adresine sabitliyor.
2. `sub_140001A50` (`0x140001A50`) `https://api.prestigeclient.vip/injectorDownload` URL'sine boş gövdeli bir HTTPS POST isteği yapıyor. Yanıt baytları bellek içi bir vektörde toplanıyor; yalnızca curl hatası yoksa ve HTTP yanıtı 200–299 aralığındaysa tutuluyor.
3. `sub_1400015D0` (`0x1400015D0`) bir PE64 reflective/manual loader:
   - `MZ`, `PE\0\0`, PE32+ ve DLL bayraklarını doğruluyor.
   - `VirtualAlloc` ile imaj belleği ayırıyor.
   - PE bölümlerini kopyalıyor ve relocations uyguluyor.
   - Importları `LoadLibraryA`/`GetProcAddress` ile çözüyor.
   - Bölüm korumalarını `VirtualProtect` ile ayarlıyor.
   - TLS callback'lerini ve DLL giriş noktasını çağırıyor.
4. `WinMain`, yüklenen modülün export tablosunda `JNI_OnLoad` arıyor ve bulduğu adresi `(0, 0)` parametreleriyle çağırıyor.
5. Bağlantı veya payload geçersizse `Prestige failed to start. Please check your connection and try again.` mesajı gösterilip süreç sonlandırılıyor.

Bu akış, ikinci aşamanın diske yazılmadan ağdan alınmasını ve bellekte çalıştırılmasını sağlar. Ağ erişimi veya geçerli payload olmadan program işlev göstermiyor.

## Dikkat çeken diğer bulgular

- Ana PE, libcurl kodunu statik olarak içeriyor; görülen genel HTTP/FTP/SMB/LDAP/TLS dizelerinin çoğu libcurl kaynaklı ve tek başına uygulama davranışı sayılmamalı.
- `IsDebuggerPresent` referansları MSVC runtime hata/teşhis yollarında görünüyor; ana kötü niyet göstergesi bunlar değil.
- Registry importu bulunmadı ve dış kabukta açık kalıcılık mekanizması görülmedi. Kalıcılık veya veri hırsızlığı ikinci aşamada olabilir.
- `.text` entropisi 6.425; ana dosyada belirgin yüksek-entropili packer bölümü veya overlay saptanmadı. Gizleme, ikinci aşamayı uzaktan getirme yoluyla sağlanıyor.

## IOC'ler

- Domain: `api.prestigeclient.vip`
- URL: `https://api.prestigeclient.vip/injectorDownload`
- Sabitlenmiş IP: `172.67.137.182`
- SHA-256: `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08`
- Bellekte aranan export: `JNI_OnLoad`

Not: IP bir CDN/ters proxy adresi olabilir; tek başına IP'yi kötü niyetli olarak etiketlemek ortak altyapıda yanlış pozitif yaratabilir. Domain ve tam URL daha anlamlı IOC'lerdir.

## CAPEv2 durumu

- Önceden mevcut görev: bulunamadı.
- Yeni görev: `6`
- Kategori: `static`
- Timeout: `0`, machine: boş, guest: boş — dinamik yürütme planlanmadı.
- Son gözlenen durum: `pending`; CAPE statik işleyici henüz rapor üretmedi.
- CAPE, dosya türünü ve tüm özetleri doğruladı. Dinamik davranış raporu özellikle oluşturulmadı.

## Öneri

- Dosyayı çalıştırmayın ve kaynağı güvenilir kabul etmeyin.
- SHA-256 ile karantinaya alın; alan adını DNS/proxy/EDR katmanında engelleyin.
- Bu dosya daha önce çalıştırıldıysa `api.prestigeclient.vip` ve `/injectorDownload` erişimleri için DNS, proxy, firewall ve EDR geçmişini arayın. İkinci aşama yalnızca bellekte bulunduğundan process-memory/EDR telemetry, disk taramasından daha değerlidir.
- Dinamik analiz istenirse ayrı bir CAPEv2 `submit_file` görevi payload'ı gerçekten çalıştıracaktır; bu adım bu incelemede yapılmadı.
