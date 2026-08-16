# Prestige `injector.dll` — statik teknik analiz

Tarih: 16 Ağustos 2026  
Yöntem: IDA Pro MCP + yerel PE araçları + CAPEv2 static-only  
Yürütme: Yapılmadı

## Örnek kimliği

| Alan | Değer |
|---|---|
| Kaynak | `POST https://api.prestigeclient.vip/injectorDownload` |
| HTTP dosya adı | `injector.dll` |
| Boyut | 5.105.566 bayt |
| MD5 | `af658bbb582714a733d212e60c0e17c7` |
| SHA-256 | `1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad` |
| Tür | PE32+ x86-64 DLL |
| Timestamp | 2026-08-07 15:45:15 UTC |
| Authenticode | Yok |
| Exportlar | `JNI_OnLoad`, `DllEntryPoint` |
| PDB | `C:\\Users\\vikkn\\Documents\\Prestige Software Development\\Prestige-Injector\\x64\\DLL\\PrestigeInjector.pdb` |

Yakalama arşivi SHA-256: `5ccc313babf89e0efdd9540d8e73e01a66d839cae0b6177d8e73c15cd835108b`.

## PE ve koruma yapısı

İmaj tabanı `0x180000000`, imaj boyutu yaklaşık `0x4e8000`; IDA 5.163 fonksiyon ve 9.225 string tanımladı. Sekiz bölümden özellikle ikisi koruma/sanallaştırma göstergesi:

| Bölüm | Boyut | İzin | Not |
|---|---:|---|---|
| `.text` | `0x148000` | RX | Normal kod |
| `.vm_sec` | `0x0c200` | RW | VM/koruma verisi göstergesi |
| `.vlizer` | `0x2ad99e` | RX | Yaklaşık 2,8 MB sanallaştırılmış kod |

`JNI_OnLoad` başlangıcındaki kısa açık kod iki bağlantı hedefini çözüyor ve ardından `.vlizer` alanına geçiyor:

```text
api.prestigeclient.vip:443:172.67.137.182
api.prestigeclient.vip:80:172.67.137.182
```

## Anti-analiz ve sandbox kaçınma

Dosyada güçlü ve özel amaçlı bir anti-analiz katmanı doğrulandı:

- `CheckRemoteDebuggerPresent` ile debugger kontrolü,
- `CPUID 0x40000000` ile hypervisor vendor kontrolü,
- BIOS registry değerlerinde `SystemManufacturer`, `SystemProductName`, `BaseBoardManufacturer` ve `BaseBoardProduct` taraması,
- VMware, VirtualBox, KVM, QEMU/TCG, Xen, Parallels, bhyve, ACRN, QNX, OpenBSD VMM, HAXM ve Jailhouse vendor dizeleri,
- çalışan süreçler içinde 30 analiz aracının case-insensitive karşılaştırılması.

Doğrulanan süreç kara listesi şunları içeriyor:

```text
HTTPDebuggerUI.exe, HTTP Toolkit.exe
x64dbg.exe, x32dbg.exe, x96dbg.exe, ollydbg.exe
windbg.exe, WinDbgX.exe
idaq.exe, idaq64.exe, ida.exe, ida64.exe
Fiddler.exe, Fiddler Everywhere.exe
charles.exe, mitmproxy.exe, mitmweb.exe, mitmdump.exe
cheatengine-x86_64.exe, cheatengine-i386.exe
Scylla.exe, Scylla_x64.exe, ImportREC.exe, PEiD.exe, die.exe
ghidra.exe, dnSpy.exe, dnSpy64.exe
ApiMonitor-x64.exe, ApiMonitor-x86.exe
```

Algılama halinde `sub_18007C460`, “Prestige - Security compatibility issue” uyarısı çıkarıyor, mevcut host'u `--security-notice` argümanıyla yeniden başlatıyor ve ana süreci `TerminateProcess(..., 0x4EC)` ile kapatıyor. Bu davranış CAPE/VM koşularının payload indirme aşamasına ulaşmadan bitmesine yol açabilir.

Bu düzeyde kaçınma gelişmiş malware ile uyumludur; anti-crack/anti-reversing kullanan ticari hile yazılımlarında da görülebilir. Tek başına RAT veya belirli tehdit aktörü atfı değildir, fakat güven puanını ciddi biçimde düşürür.

## Ağ/API davranışı

Dosya statik bağlı libcurl ve nlohmann/json kullanıyor. Aşağıdaki yollar uygulamaya özgü:

| Yol | Statik olarak görülen JSON alanları |
|---|---|
| `/prestigeDownload` | `token`, `version` |
| `/injectionDownload` | `token` |
| `/login` | `token`, `challenge` |
| `/newModLogin` | `token`, `challenge` |
| `/newFirstLogin` | `email`, `password`, `hwid`, `challenge` |
| `/injectorAccountInfo` | `token`, `challenge` |
| `/injectorBetaToggle` | `token`, `challenge`, `active` |

`sub_180087770` (`/injectionDownload`) akışı:

1. Global/oturum nesnesinden token değerini alır.
2. `{"token": ...}` nlohmann/json nesnesi oluşturur.
3. JSON'u string olarak serialize eder (`sub_180087D20`).
4. libcurl üzerinde URL (`CURLOPT_URL`/10002), POST gövdesi (`CURLOPT_POSTFIELDS`/10015), uzunluk, callback ve `Content-Type: application/json` ayarlar.
5. `sub_180086DA0` callback'i yanıtı değiştirmeden bellek buffer'ında toplar.
6. `sub_180097440` başarılı buffer adresi ve uzunluğunu `qword_1802186E8`/`qword_1802186F0` alanlarına yazar.
7. `sub_18006E0B0` bu iki globali yerel pointer/length çiftine alır ve doğrudan `sub_180052E50` manual mapper'ına verir. `sub_18006EF90` ikinci tüketici yoludur.

Bu zincirde payload hash'i, Authenticode publisher kontrolü veya beklenen public-key signature doğrulaması bulunmadı. Response baytları ile remote mapper arasında arşiv/format dönüşümü de yoktur.

Firejail `--private` içinde dummy token ile yapılan güvenli doğrulama `HTTP/2 400`, boş gövde döndürdü. Gerçek üçüncü aşama geçerli hesap token'ı olmadan alınamadı; brute-force veya hesap oluşturma yapılmadı.

### `/newFirstLogin` parola veri akışı

UI'daki `login_password` buffer'ı (`byte_180218700`) `sub_180084CD0` fonksiyonuna verilir. Fonksiyon Crypto++ `SHA256`, `HashFilter`, `HexEncoder` ve `StringSink<std::string>` nesnelerini zincirler; oluşan değer thread parametresinde `sub_180097950` üzerinden `sub_18008AE20`'ye ulaşır ve yalnız bu değer `/newFirstLogin` JSON nesnesinin `password` alanına yazılır. Ham UI parolasının aynı isteğe giden ikinci bir yolu bulunmadı.

Kritik makine kodu tanıkları:

```text
0x180084D83  48 8D 05 DE 9E 0C 00 48 89 44 24 70 B9 B0 00 00 00 E8
              ^ CryptoPP::SHA256::vftable adresini yükler

0x180084DFF  48 8D 05 42 AD 0C 00 48 89 07 48 8D 05 A8 AE 0C 00
             48 89 47 08 4C 89 77 18 ... E8 6B FC
              ^ StringSink vtable'ları ve HexEncoder kurucu çağrısı

0x180084E4F  45 33 C9 4C 8B C0 48 8D 54 24 70 48 8B CE E8 1E 50 02 00
              ^ HashFilter kurulumu; R9=0
```

HexEncoder parametreleri `uppercase=true`, `groupSize=0`, `separator=":"`, `terminator=""` ile Crypto++ varsayılanlarıdır; sonuç 32 baytlık SHA-256 digest'in ayırıcısız 64 büyük harfli hex karakteridir. Resmî politikanın SHA-256 hash'li parola beyanı istemci koduyla uyumludur. Bu, sunucu tarafında saklama biçimini veya hash'in parola-eşdeğeri olarak tekrar kullanılabilirliğini kanıtlamaz.

Kaynaklar: [Prestige gizlilik politikası](https://www.prestigeclient.vip/tos), [Crypto++ HexEncoder API](https://cryptopp.com/docs/ref/class_hex_encoder.html).

### Resmî özelliklerle bağlam

Resmî 7 Ağustos 2026 changelog'u erken hook, “zero-trace cleanup” ve capture'a görünmeyen streamproof arayüzü; fiyatlandırma ise screenshare bypass'ı tanımlar. Bu, bazı anti-analysis/anti-forensics özelliklerinin ilan edilen ghost-client işleviyle uyumlu olduğunu gösterir; bunları tek başına RAT kanıtı saymak doğru değildir. Kaynak: [Prestige Client resmî sitesi](https://www.prestigeclient.vip/).

## HWID / sistem parmak izi

`sub_180055290` aşağıdaki verileri bir araya getirir:

- `Win32_ComputerSystemProduct.UUID`
- `Win32_BaseBoard.SerialNumber`
- `Win32_BIOS.SerialNumber`
- `Win32_Processor.ProcessorId`
- `Win32_DiskDrive.SerialNumber` (`Index = 0`)
- `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`

Bu, kararlı cihaz parmak izi üretme yeteneğidir ve login/HWID eşleştirme çağrılarında kullanılır. Statik kanıt bunu credential theft olarak değil lisans/hesap bağlama telemetrisi olarak gösteriyor.

## Process injection yetenekleri

İçe aktarımlar ve xref'ler şu zinciri doğruluyor:

```text
OpenProcess
  ├─ VirtualAllocEx
  ├─ WriteProcessMemory / ReadProcessMemory
  └─ CreateRemoteThread
```

- `sub_180052E50`: PE doğrulama, uzakta bellek ayırma, section kopyalama, relocation/import çözümü ve exception-table desteği içeren manual mapper.
- `sub_180044E70`: geçici DLL ve hedef süreçte `LoadLibraryA` kullanan alternatif enjeksiyon yolu.
- UI dizeleri Minecraft süreci açma, manual-map ve payload'ı oyundan silme/temizleme işlevlerini açıkça anlatıyor.

Bu davranış müdahaleci ve EDR tarafından doğal olarak şüpheli görülür; aynı zamanda ürünün beyan edilen injector işleviyle uyumludur. Tek başına RAT sonucu vermez.

## RAT/stealer hipotezi

Bulunmayan doğrudan göstergeler:

- Chromium `Login Data`, `Local State`, browser profile veya LevelDB yolları,
- `CryptUnprotectData`, CredRead veya Vault API'leri,
- `GetAsyncKeyState`, `SetWindowsHookEx` veya benzeri keylogger zinciri,
- `BitBlt`, `PrintWindow`, kamera/mikrofon yakalama,
- Run key, service, scheduled task ya da PowerShell/cmd persistence,
- operatör komut döngüsü veya açık RAT C2 protokolü.

Clipboard okuma/yazma yardımcıları (`sub_18001FBD0`, `sub_18001FD20`) var; keşfedilen çağrı grafiğinde ağ aktarımına bağlanmıyor ve GUI clipboard adaptörü biçiminde.

### capa/FLOSS doğrulaması

`capa 9.4.0` process injection, reflective loading, WMI, process discovery ve anti-VM yeteneklerini bağımsız olarak eşleştirdi. “PowerShell”, “keylogging” ve “clipboard collection” etiketleri IDA'da elle kontrol edildi:

- iki `system()` çağrısı `start <URL>` komutu oluşturuyor;
- `GetKeyState` yalnız UI modifier durumlarına gidiyor; async key state/hook/tuş buffer'ı yok;
- clipboard yardımcıları ImGui kopyala/yapıştır entegrasyonudur;
- GDI kodu 32×32 ikon rasterizasyonu ve DPI hesabıdır, ekran görüntüsü değildir.
- credit-card/Luhn eşleşmeleri MSVC `std::regex` parser fonksiyonlarına, geolocation eşleşmesi yalnız locale API'sine dayanır; uygulama düzeyinde kart veya konum toplama yolu yoktur.

`FLOSS 3.1.1` taraması 7 stack string, 6 tight string ve bir sayısal decoded string çıkardı; yeni IOC veya RAT/stealer dizisi bulmadı. Sanallaştırılmış `.vlizer` kodu nedeniyle bu sonuç eksiksiz string çözümü olarak yorumlanamaz.

Bu nedenle otomatik etiketler tek başına nihai sınıflandırmaya alınmadı.

## Kritik opcode kanıtları

Image base `0x180000000`:

```text
0x180097545  0f8447010000488b4c24204885c90f84310100004889058811180048890d89111800
              response pointer/length -> qword_1802186E8/F0

0x18006E0F2  c744245400000000488b05e7a51a0048894424488b05e4a51a0089442450
              global pointer/length -> local pair

0x18006E1D8  e843acfeff4c8d442448488b17e8664cfeff
              lea r8,[rsp+48h] -> call sub_180052E50
```

Tam uzunluklu bayt kesitleri ana raporun “Ham bayt ve disassembly kanıt eki” bölümündedir.

### Kamuya açık spesifik iddiaların kontrolü

Bir sosyal medya gönderisi Chrome'un `--headless --remote-debugging-port=9222 --incognito` ile açıldığını, `VaultSvc`/`lsass.exe` erişimini ve ZIP exfiltration'ı iddia ediyor. Exact hash üzerinde yapılan kontrol:

- `9222`, `remote-debugging`, `--headless`, `incognito`, `chrome.exe`, `lsass.exe`, `VaultSvc` ve ZIP/archive göstergeleri: **0 eşleşme**.
- `CreateProcessW`: yalnızca `sub_18007C770` tarafından çağrılıyor; `GetModuleFileNameW(NULL, ...)` ile mevcut host'u alıp anti-analiz uyarısı için yeniden başlatıyor. Chrome veya başka browser başlatmıyor.
- `/injectorAccountInfo`: `token` ve üretilen `challenge` içeren JSON gönderiyor; dosya listesi/arşiv gövdesi oluşturmuyor.
- Doğrudan `connect`, `send`, `recv`, `WSAStartup` xref'leri statik bağlı libcurl koduna gidiyor; ayrı uygulama C2 socket döngüsü görülmedi.
- Tanımlı kodda doğrudan syscall talimatı bulunmadı.

Bu sonuçlar başka bir sürümü veya sunucu kontrollü üçüncü payload'ı aklamaz. Yalnızca söz konusu iddiaların bu iki exact hash için mevcut kanıtla doğrulanmadığını gösterir. İnternetteki `prestige-client.live` kaynaklı stealer JAR'ları farklı hash, farklı domain ve farklı dağıtım zinciridir; bu incelemeyle birleştirilmemelidir.

## Hüküm

Bu hash'li ikinci aşama için kanıtlanan sınıflandırma **yoğun korumalı, kapsamlı anti-VM/anti-debug özellikli Minecraft injector/controller**dır. Statik bulgular bu DLL'nin RAT veya browser stealer olduğunu doğrulamıyor. Fakat DLL, `/injectionDownload` yolundan henüz ele geçirilmemiş üçüncü bir payload indiriyor ve onu Minecraft sürecine enjekte ediyor. Nihai güvenlik hükmü bu üçüncü aşama olmadan tamamlanamaz.

Yine de zincir güvenli kabul edilemez: dış loader ve controller imzasızdır, uzaktan değiştirilebilir kod alır ve kullanıcıya doğrulanabilir payload hash'i/imzası sunmaz.

## CAPEv2 durumu

- Static-only görevler: ilk `7`, yeniden zamanlanan `9`
- Son görülen durum: ikisi de `pending`; `machine_id=null`, `analysis_started_on=null`, hata kaydı yok
- CAPE 2.5 host görünümü: 2 pending, 0 running, 5 reported; processing worker bu görevi almamış
- CAPE veritabanı dosya boyutu, tür, MD5/SHA-1/SHA-256/SHA-512 ve ssdeep değerlerini doğruladı
- Dinamik görev açılmadı; örnek çalıştırılmadı.
