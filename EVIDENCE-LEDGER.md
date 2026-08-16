# Prestige Client kanıt defteri

**Tarih:** 16 Ağustos 2026  
**Amaç:** Yayımlanan her teknik hükmün hangi exact örneğe, adrese, dosya ofsetine, çağrı zincirine ve dış kaynağa dayandığını göstermek.  
**Ana rapor:** [`Prestige-Client-investigation-TR.md`](Prestige-Client-investigation-TR.md)

## Son hüküm

İncelenen zincir için kanıtlanan sınıflandırma şudur:

> **İmzasız, uzaktan değiştirilebilir PE payload'larını doğrulamadan bellekte çalıştıran; ikinci aşamasında güçlü anti-analysis, cihaz parmak izi ve iki ayrı Minecraft process-injection yolu bulunan yüksek riskli loader/injector zinciri.**

Exact iki örnekte RAT komut döngüsü, browser credential hırsızlığı, keylogging, ekran yakalama, kalıcılık, fidyeleme veya dosya exfiltration davranışı kanıtlanmadı. Kimlik doğrulamalı üçüncü payload ele geçirilmediği için zincirin nihai aşaması hakkında “temiz” veya “RAT” hükmü verilemez.

## Kanıt düzeyleri

| Düzey | Anlamı | Kullanım |
|---|---|---|
| A | Exact sample baytı, PE yapısı, IDA disassembly/decompile, xref veya kesintisiz veri akışı | Davranışı doğrulamak için yeterli |
| B | Aynı exact hash için bağımsız rapor veya aynı altyapıdaki tarihsel farklı hash | Korelasyon; tek başına davranış/aktör atfı değil |
| C | AV, capa veya sandbox otomatik etiketi | Elle doğrulanmadıkça hüküm değil |
| D | Sosyal medya, video veya doğrulanamayan teknik iddia | Yalnız iddia olarak kaydedilir |

## Artefakt ve gözetim zinciri

| ID | Rol | Boyut | SHA-256 | Kaynak ve doğrulama |
|---|---|---:|---|---|
| S1 | Dış loader | 767.488 | `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08` | Kullanıcının indirdiği `Prestige-Client.exe`; yerel `sha256sum`, PE parser, IDA `prestige_client_static` |
| S2 | Injector/controller DLL | 5.105.566 | `1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad` | 16 Ağustos 2026'da `POST /injectorDownload` yanıtı; HTTP `Content-Disposition: injector.dll`; yerel hash + IDA `prestige_injector_payload` |
| A1 | Yakalama arşivi | — | `5ccc313babf89e0efdd9540d8e73e01a66d839cae0b6177d8e73c15cd835108b` | S2, response headers ve meta verisini içeren kullanıcı arşivi |

S1 ve S2 Authenticode imzası taşımıyor. Şüpheli binary'ler GitHub çıktı paketine eklenmedi; yayımlanan metin, IOC ve YARA dosyaları [`SHA256SUMS`](SHA256SUMS) ile sabitlendi.

## VA → dosya ofseti eşlemesi

Her iki PE'de `.text` section RVA'sı `0x1000`, raw başlangıcı `0x400`dür. Bu nedenle aşağıdaki `.text` adresleri için:

```text
file_offset = VA - image_base - 0x1000 + 0x400
```

| Örnek | VA | Dosya ofseti | İşlev |
|---|---:|---:|---|
| S1 | `0x140001316` | `0x716` | Pinned hostname/IP ve `CURLOPT_RESOLVE` |
| S1 | `0x14000142C` | `0x82C` | Response → manual mapper; export arama |
| S1 | `0x1400014CF` | `0x8CF` | `JNI_OnLoad(0,0)` dolaylı çağrısı |
| S1 | `0x1400015F1` | `0x9F1` | PE/DLL doğrulama başlangıcı |
| S1 | `0x1400017FD` | `0xBFD` | `LoadLibraryA` ile import çözme |
| S1 | `0x140001912` | `0xD12` | `VirtualProtect` ile section izinleri |
| S2 | `0x180052E50` | `0x52250` | Remote manual mapper |
| S2 | `0x180044E70` | `0x44270` | Remote `LoadLibraryA` fallback yolu |
| S2 | `0x1800879A9` | `0x86DA9` | `/injectionDownload` write callback/data kurulumu |
| S2 | `0x180097545` | `0x96945` | Response pointer/length → globaller |
| S2 | `0x18006E0F2` | `0x6D4F2` | Globaller → yerel pointer/length çifti |
| S2 | `0x18006E1D8` | `0x6D5D8` | Çift → remote mapper çağrısı |
| S2 | `0x18007C540` | `0x7B940` | Debugger/analiz aracı kontrolü |
| S2 | `0x180055290` | `0x54690` | HWID/WMI toplama |
| S2 | `0x180084D83` | `0x84183` | Crypto++ SHA-256 parola hattı |

## Doğrulanan iddialar

### C01 — Dış örnek sunucuya sabitlenmiş bir HTTPS isteği yapar

- **Durum:** Doğrulandı — A.
- **Örnek:** S1.
- **Kanıt:** `WinMain` `0x1400012D0`; `0x140001316` adresinde `api.prestigeclient.vip:443:172.67.137.182` dizesi alınır ve option `0x27DB`/10203 (`CURLOPT_RESOLVE`) ayarlanır.
- **URL:** `sub_140001070` temel `https://api.prestigeclient.vip`; `sub_140001A50` `0x140001BA1` civarında `/injectorDownload` ekler.
- **Resmî semantik:** [libcurl CURLOPT_RESOLVE](https://curl.se/libcurl/c/CURLOPT_RESOLVE.html) `HOST:PORT:ADDRESS` biçiminin hostname çözümlemesini belirtilen IP'ye yönlendirdiğini açıklar.

Ham bayt başlangıcı:

```text
0x140001316 / file 0x716
48 8d 15 fb 7f 0a 00 33 c9 e8 9c 10 00 00 48 8b
0d 7d 46 0b 00 4c 8b c0 ba db 27 00 00 48 89 05
76 46 0b 00 e8 41 3e 00 00
```

### C02 — Sunucu yanıtı executable PE/DLL olarak beklenir

- **Durum:** Doğrulandı — A.
- **Örnek:** S1.
- **Kanıt:** `sub_1400015D0` şu kontrolleri reddetme dallarıyla uygular: `MZ` (`0x5A4D`), `PE\0\0` (`0x4550`), PE32+ magic (`0x20B`) ve `IMAGE_FILE_DLL` (`0x2000`).
- **Adres/ofset:** `0x1400015F1` / `0x9F1`.

```text
48 83 fa 40 ... b8 4d 5a 00 00 66 39 01 ...
41 81 3c 0e 50 45 00 00 ... b8 0b 02 00 00 ...
b8 00 20 00 00 66 41 85 44 0e 16
```

### C03 — S1 yanıt DLL'sini kendi belleğine manual-map eder

- **Durum:** Doğrulandı — A.
- **Örnek:** S1.
- **İşlev:** `sub_1400015D0`.
- **Kesintisiz işlemler:** `VirtualAlloc` (`0x140001674/690`) → PE headers/sections `memcpy` → base relocations (`0x14000172D–7BE`) → `LoadLibraryA`/`GetProcAddress` (`0x1400017FD/83C`) → `VirtualProtect` (`0x140001912`) → `RtlAddFunctionTable` → TLS callbacks → DLL entry point.
- **Sınıflandırma:** [MITRE ATT&CK T1620 – Reflective Code Loading](https://attack.mitre.org/techniques/T1620/).

### C04 — Manual-map edilen DLL gerçekten çalıştırılır

- **Durum:** Doğrulandı — A.
- **Örnek:** S1.
- **Kanıt:** `WinMain`, mapped image export tablosunda `JNI_OnLoad` adını arar (`0x140001494–4C2`), RCX ve RDX'yi sıfırlayıp `call rax` yapar (`0x1400014CB–4CF`).

```text
33 d2 33 c9 ff d0
```

Bu, `JNI_OnLoad(0,0)` çağrısıdır; S1 yalnız dosya indiren pasif updater değildir.

### C05 — İndirilen kod için hash veya yayıncı doğrulaması yoktur

- **Durum:** Doğrulandı — A, negatif arama ile destekli.
- **Örnek:** S1 ve S2.
- **Kanıt:** S1'de network buffer `sub_140001A50 → WinMain → sub_1400015D0 → JNI_OnLoad` yolunda yalnız PE yapısı kontrol edilir. S2'de callback buffer'ı `sub_180086DA0 → qword_1802186E8/F0 → sub_180052E50` yolunda hash/imza kapısı olmadan ilerler.
- **Ek kontrol:** Her iki IDB'de `WinVerifyTrust`, `CertGetCertificateChain` ve payload hash allowlist/publisher dizesi bulunmadı; `WinVerifyTrust` importu yok. PE Security Directory'leri boş.
- **Karşılaştırma kaynağı:** Microsoft, [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust) işlevini Authenticode policy provider ile dosya/yayıncı güveni doğrulama mekanizması olarak tanımlar.
- **Sınır:** TLS sunucu bağlantısını korur; sunucunun seçtiği payload'ın sabit, önceden denetlenmiş veya aynı kullanıcılar için aynı olduğunu kanıtlamaz.

### C06 — S2 gerçek Prestige injector/controller örneğidir

- **Durum:** Doğrulandı — A.
- **Kanıt:** Exact HTTP yanıt adı `injector.dll`; PDB `Prestige-Injector\\x64\\DLL\\PrestigeInjector.pdb`; exportlar `JNI_OnLoad`/`DllEntryPoint`; UI dizeleri “Opening Minecraft process” ve “Manual-map injection”; uygulamaya özgü Prestige API yolları.
- **Koruma:** `.vm_sec` RW ve yaklaşık 2,8 MB `.vlizer` RX section'ları; `JNI_OnLoad` sanallaştırılmış bölgeye geçer.

### C07 — S2 authenticated üçüncü payload indirir

- **Durum:** Doğrulandı — A.
- **İşlev:** `sub_180087770`.
- **Kanıt:** nlohmann/json ile `{"token": ...}` oluşturulur; URL `/injectionDownload`; libcurl URL, POST fields, content-length, write callback ve userdata ayarlanır.
- **Callback:** `sub_180086DA0` gelen her chunk'ı değişiklik yapmadan büyüyen buffer'a ekler. libcurl'ın [CURLOPT_WRITEFUNCTION](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html) belgesi callback'in alınan response baytlarını teslim ettiğini; [CURLOPT_WRITEDATA](https://curl.se/libcurl/c/CURLOPT_WRITEDATA.html) belgesi userdata pointer'ının callback'e taşındığını doğrular.

### C08 — Üçüncü payload response'u doğrudan remote mapper'a gider

- **Durum:** Doğrulandı — A; araştırmanın en kritik veri akışı.
- **Örnek:** S2.
- **Zincir:** `sub_180086DA0` → `sub_180097440` → `qword_1802186E8/F0` → `sub_18006E0B0` veya `sub_18006EF90` → `sub_180052E50`.
- **Dönüşüm:** Arada archive çıkarma, decrypt/transform, hash allowlist, Authenticode veya publisher doğrulaması yok; pointer ve uzunluk aynı PE consumer'a verilir.
- **Ham baytlar:** Ana raporun “Ham bayt ve disassembly kanıt eki” bölümü dört ardışık kesiti yayımlar.

### C09 — S2 hedef sürece manual-map enjeksiyonu yapabilir

- **Durum:** Doğrulandı — A.
- **İşlev:** `sub_180052E50`.
- **Pozitif importlar:** `OpenProcess` `0x180149318`, `VirtualAllocEx` `0x180149270`, `WriteProcessMemory` `0x180149228`, `ReadProcessMemory` `0x180149278`, `CreateRemoteThread` `0x180149280`.
- **Semantik:** Fonksiyon PE headers/sections, relocation, import ve exception table yapılarını işler; uzak belleği ayırır/yazar ve remote thread başlatır.
- **Resmî API:** [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory), [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread).
- **Sınıflandırma:** [MITRE ATT&CK T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/).

### C10 — S2'nin ikinci, remote `LoadLibraryA` enjeksiyon yolu vardır

- **Durum:** Doğrulandı — A.
- **İşlev:** `sub_180044E70`.
- **Kanıt:** Geçici DLL yolu hazırlanır; hedef süreçte `LoadLibraryA` adresi çözülür; uzak bellek/remote thread çağrılarıyla DLL yüklenir. Bu, C09'daki manual mapper'dan ayrı fallback yoludur.

### C11 — S2 özel anti-debug ve analiz aracı engellemesi içerir

- **Durum:** Doğrulandı — A.
- **İşlev:** `sub_18007C540`; `CheckRemoteDebuggerPresent` importu `0x180149368`.
- **Kanıt:** Çalışan süreç adları case-insensitive karşılaştırılır; IDA/IDA64, Ghidra, x64dbg/x32dbg, WinDbg, Fiddler, mitmproxy, HTTP Toolkit, dnSpy, Cheat Engine, Scylla, DIE, API Monitor ve diğerleri dahil 30 exact isim kara listededir.
- **Tepki:** Uyarı, mevcut host'u `--security-notice` ile yeniden başlatma ve `TerminateProcess(...,0x4EC)`.
- **Sınır:** Anti-analysis malware ile uyumludur; ticari cheat/anti-crack bağlamında da görülebilir. Tek başına RAT kanıtı değildir.

### C12 — S2 VM/sandbox ortamını tespit etmeye çalışır

- **Durum:** Doğrulandı — A.
- **Kanıt:** CPUID hypervisor vendor; BIOS/baseboard manufacturer/product registry alanları; VMware, VBox, KVM, QEMU/TCG, Xen, Parallels, bhyve, ACRN ve diğer vendor dizeleri.
- **Sınıflandırma:** [MITRE ATT&CK T1497.001](https://attack.mitre.org/techniques/T1497/001/) VM artefaktları, registry/hardware alanları ve VM'e özgü işlemci kontrollerini kapsar.

### C13 — S2 kararlı cihaz/HWID parmak izi toplar

- **Durum:** Doğrulandı — A.
- **İşlev:** `sub_180055290`.
- **Alanlar:** `Win32_ComputerSystemProduct.UUID`, baseboard/BIOS serial, CPU `ProcessorId`, disk 0 serial ve `MachineGuid`.
- **Kullanım bağlamı:** `/newFirstLogin` ve hesap/HWID akışı; resmî şartlar donanım doğrulamasına izin istiyor ve HWID reset için donanım kanıtı talep ediyor.
- **Sınır:** Bu, cihaz parmak izidir; tek başına credential theft değildir.

### C14 — İlk kayıt parolası istemci tarafında SHA-256 hex'e çevrilir

- **Durum:** Doğrulandı — A.
- **Zincir:** `login_password` buffer → `sub_180084CD0` → `CryptoPP::SHA256` → `HashFilter` → `HexEncoder` → `StringSink` → `/newFirstLogin` JSON `password`.
- **Adres:** SHA256 vtable `0x180084D83`; HexEncoder/StringSink `0x180084DFF–E30`; HashFilter `0x180084E5D`.
- **Biçim:** uppercase `true`, group size `0`, separator `":"`, terminator `""`; sonuç ayırıcısız 64 büyük harf hex karakteridir. [Crypto++ HexEncoder API](https://cryptopp.com/docs/ref/class_hex_encoder.html).
- **Sınır:** Sunucunun nasıl sakladığı veya hash'i parola-eşdeğeri kabul edip etmediği istemciden kanıtlanamaz.

### C15 — Resmî ürün beyanları bazı stealth davranışlarını doğrular

- **Durum:** Doğrulandı — B; üreticinin kendi beyanı.
- **Kaynak:** [Resmî site](https://www.prestigeclient.vip/) 7 Ağustos 2026 changelog'u erken hook, “zero-trace cleanup”, capture'a görünmeyen UI ve screenshare bypass'ı pazarlar.
- **Kod korelasyonu:** Aynı tarihli S2'de anti-analysis, bellek temizliği ve injection mantığı vardır.
- **Sınır:** Pazarlama metni teknik güvenlik denetimi değildir; RAT'ı ne kanıtlar ne çürütür.

### C16 — Exact dış loader bağımsız araçlarca yüksek riskli görülür

- **Durum:** Doğrulandı — B/C.
- **Kaynak:** [Manalyzer exact-hash raporu](https://manalyzer.org/report/4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08) aynı SHA-256'yı ve aktarılan 46/68 AV sonucunu gösterir.
- **Sınır:** AV skoru tek başına RAT ailesi veya davranış kanıtı değildir; C01–C12 gibi A-düzeyi bulguların yerine kullanılmadı.

### C17 — Reddit/Triage “stealer/persistence” özeti süreç-atıf hatasına açıktır

- **Durum:** Doğrulandı — B/D denetimi.
- **Kaynak:** [Reddit gönderisi](https://www.reddit.com/r/minecraftclients/comments/1vpfkic/prestige_client_is_so_trash_bro/) ve [exact-hash Triage görevi](https://tria.ge/260623-fqhjgsat5q/behavioral1).
- **Süreç ağacı:** `Explorer.EXE` altında `Prestige-Client.exe` PID 79 ve `chrome.exe` PID 81 aynı derinlikte ayrı kardeş süreçlerdir. Chrome, Prestige'in çocuğu değildir.
- **Atıf:** Triage görev özeti tüm süreçlerden 43 imzayı birleştirir. Prestige satırındaki görünen process-specific imzalar `GetForegroundWindowSpam` ve `SetWindowsHookEx`; browser/persistence etiketlerini üst özetten doğrudan Prestige'e aktarmak geçerli değildir.
- **IDA çapraz kontrolü:** Exact S1/S2'de iddia edilen Chrome profile, servis, RDP, Run key ve COM-hijack uygulama zincirleri bulunmadı.

## Kanıtlanamayan veya çürütülen iddialar

Bu bölüm “işlev kesinlikle hiçbir sürümde yoktur” demez. Sonuçlar yalnız S1 ve S2 exact hash'leri içindir; sanallaştırılmış kod ve eksik üçüncü aşama sınırları açıkça korunur.

| ID | İddia | Exact iki örnekte sonuç | Aranan kanıt ve bulunan bağlam |
|---|---|---|---|
| N01 | Tam özellikli RAT/C2 komut döngüsü | **Kanıtlanmadı** | Operatör command dispatcher, beacon/task döngüsü, komut kimlikleri, uzak shell veya ayrı C2 protokolü bulunmadı; görülen ağ yolu hesap/payload API'sidir |
| N02 | Browser cookie/parola hırsızlığı | **Kanıtlanmadı** | `Login Data`, `Local State`, Chromium profile/LevelDB yolları; `CryptUnprotectData`, CredRead/Vault importları ve bu verileri ağa bağlayan xref yok |
| N03 | Chrome'u headless debug modunda açma | **Çürütüldü (S2)** | `chrome.exe`, `--headless`, `remote-debugging-port`, `9222`, `incognito` 0 uygulama eşleşmesi; tek `CreateProcessW` çağırıcısı mevcut host'u `--security-notice` ile yeniden başlatır |
| N04 | Keylogger | **Kanıtlanmadı** | `GetAsyncKeyState`/`SetWindowsHookEx` importu yok; `GetKeyState` importu `0x180149928` yalnız UI modifier durumlarına gider; tuş buffer'ı/ağ akışı yok |
| N05 | Clipboard hırsızlığı | **Kanıtlanmadı** | `sub_18001FBD0/FD20` ImGui UTF-8/UTF-16 clipboard adaptörüdür; network consumer xref'i yok |
| N06 | Ekran görüntüsü/kamera/mikrofon | **Kanıtlanmadı** | `BitBlt`, `PrintWindow`, capture/camera/mic zinciri yok; GDI eşleşmesi 32×32 ikon rasterizasyonu ve DPI hesabıdır |
| N07 | Kalıcılık | **Kanıtlanmadı** | `RegSetValue*`, `CreateService*`, `OpenSCManager*`, scheduled-task importları yok; Run/RunOnce/service/schtasks startup veri akışı yok |
| N08 | Privilege escalation/driver | **Kanıtlanmadı** | Token privilege → elevated action, service/driver kurma veya UAC bypass zinciri yok; Triage görev-özeti başka süreçleri toplar |
| N09 | Fidyeleme/veri yok etme | **Kanıtlanmadı** | Dosya ağacı şifreleme, ransom note, shadow-copy silme, `vssadmin/wbadmin/bcdedit` zinciri yok |
| N10 | Dosya arşivleme/exfiltration | **Kanıtlanmadı** | Uygulama düzeyinde ZIP/7z/archive oluşturma ve dosya upload akışı yok; libcurl'ın gömülü cookie/multipart/upload dizeleri kütüphane kodudur |
| N11 | `/injectorAccountInfo` ile ZIP/credential gönderme | **Çürütüldü (S2)** | Request JSON yalnız `token` ve `challenge`; dosya/arşiv pointer'ı veya multipart body consumer'ı yok |
| N12 | PowerShell yürütme | **Çürütüldü (S2)** | capa eşleşmesindeki iki `system()` çağrısı `start <URL>` oluşturur; PowerShell/cmd script'i yok |
| N13 | Kredi kartı/Luhn toplama | **Çürütüldü (S2)** | Eşleşmeler MSVC `std::regex` parser (`0x1800A13B0`, `0x1800A3DD0`); kart verisi veya uygulama çağırıcısı yok |
| N14 | Coğrafi konum toplama | **Kanıtlanmadı** | capa etiketi geniş `GetLocaleInfo(A/Ex)` kuralından gelir; şehir/ülke/GeoID ve ağ aktarımı yok |
| N15 | Düz metin kayıt parolası gönderme | **Çürütüldü (S2)** | C14 veri akışı raw UI parolasını SHA-256/HexEncoder'dan sonra request'e verir |
| N16 | Belirli gelişmiş tehdit grubu/RAT ailesi | **Kanıtlanmadı** | Aileye özgü config, C2, mutex, crypto/protokol veya kod benzerliği yok; topluluk söylentisi aktör atfı değildir |
| N17 | Üçüncü aşamanın temiz veya zararlı olması | **Belirlenemedi** | `/injectionDownload` geçerli token gerektiriyor; dummy token HTTP 400/boş gövde; exact payload yok |

### Negatif arama kapsamı

IDA import sorguları S1 ve S2 için şu ailelerde sıfır sonuç verdi:

```text
WinVerifyTrust, CryptUnprotectData, CredRead*, Vault*, GetAsyncKeyState,
SetWindowsHook*, BitBlt, PrintWindow, RegSetValue*, CreateService*,
OpenSCManager*, ChangeServiceConfig*
```

S2 string aramasındaki `cookie`, `.onion`, multipart ve upload metinleri statik bağlı libcurl'ın hata/dokümantasyon dizeleridir. Uygulamaya özgü xref'ler JSON API POST'larına gider. “Bulunmadı” sonucu import/string/xref kapsamını ifade eder; `.vlizer` sanallaştırmasının matematiksel olarak eksiksiz çözümü değildir.

## Dış kaynakların doğru kullanım biçimi

| Kaynak | Desteklediği hüküm | Desteklemediği hüküm |
|---|---|---|
| Manalyzer exact hash | PE kimliği, packer/loader şüphesi, aktarılan çoklu AV sonucu | RAT ailesi, exfiltration |
| Exact-hash Triage | Aynı örneğin sandbox'ta PE indirmesi ve görev düzeyi şüpheli aktivite | Her görev imzasının Prestige PID'sine ait olması |
| ANY.RUN `e88dc…` | Mart 2026'da aynı API'den executable controller indirme sürekliliği | Ağustos 2026 üçüncü aşaması veya RAT |
| Hybrid Analysis tarihsel hash'ler | Aynı domain, anti-VM ve injection soyuna korelasyon | Güncel exact hash davranışının yerine geçme |
| Resmî Prestige site/politika | Ürünün injection, zero-trace, screenshare bypass ve HWID/SHA-256 beyanları | Bağımsız güvenlik sertifikası |
| Reddit/YouTube | Topluluk iddialarının kaynağı | Exact-sample davranış kanıtı |
| MITRE/Microsoft/curl/Crypto++ | API/tekniğin genel teknik semantiği | Örneğin bu semantiği kullandığına dair tek başına kanıt; bunun için IDA gerekir |

## Yeniden üretilebilir güvenli kontroller

Bu komutlar dosyaları çalıştırmaz:

```sh
sha256sum Prestige-Client.exe injectorDownload.bin
file Prestige-Client.exe injectorDownload.bin
objdump -h Prestige-Client.exe
objdump -h injectorDownload.bin
yara prestige_chain.yar Prestige-Client.exe
yara prestige_chain.yar injectorDownload.bin
```

Yayımlanan paket için:

```sh
cd outputs
sha256sum -c SHA256SUMS
jq empty iocs.json
sh -n capture-third-stage.sh
```

`prestige_chain.yar` içindeki exact-hash kuralı yalnız iki yakalanan örneği; yapısal kural ise Prestige controller ailesine özgü PDB/API/section birleşimini hedefler. Yapısal eşleşme tek başına RAT demek değildir.

## Yayında kullanılabilecek ve kullanılamayacak ifadeler

### Kanıtın desteklediği

> Prestige Client'ın incelenen sürümü, sunucudan aldığı imzasız ve kullanıcı tarafından doğrulanamayan PE payload'larını bellekte çalıştıran bir loader zinciridir. İkinci aşama authenticated üçüncü payload'ı doğrudan Minecraft'a enjekte edebilir. Güçlü anti-analysis ve HWID toplaması da doğrulanmıştır. Bu mimari, nihai payload temiz olsa bile kullanıcı açısından doğrulanamaz uzaktan kod çalıştırma riski yaratır; yazılım kullanılmamalıdır.

### Kanıtın desteklemediği

> “Prestige kesin RAT'tır”, “parolaları/cookie'leri kesin çalıyor”, “belirli gelişmiş grup tarafından yazıldı” veya “Triage'teki tüm 43 imza Prestige'e aittir.”

Bu ayrım araştırmayı zayıflatmaz; yanlış pozitifleri ayıklayıp kesin kanıtlanan mimari riski daha savunulabilir hâle getirir.
