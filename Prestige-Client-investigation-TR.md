# Prestige Client Injector incelemesi: genel malware analizi, RAT iddiası ve doğrulanmış risk

**Yayın tarihi:** 16 Ağustos 2026  
**İncelenen dosyalar:** `Prestige-Client.exe` ve 16 Ağustos 2026'da yakalanan `injector.dll`  
**Ana SHA-256:** `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08`

> **Kısa sonuç:** İncelenen zincir güvenli kabul edilemez. Dış EXE'nin sunucudan aldığı imzasız DLL'yi doğrulamadan kendi belleğinde çalıştırdığı; bu DLL'nin de kimliği doğrulanmış hesaba göre aldığı ham üçüncü-aşama PE'yi Minecraft sürecine manual-map ettiği bayt, disassembly ve veri akışı seviyesinde doğrulandı. İkinci aşama ayrıca özel anti-debug/anti-VM kontrollerine sahiptir. Bununla birlikte ele geçirilen iki exact hash üzerinde credential theft, keylogging, ekran kaydı, kalıcılık, fidyeleme veya operatör komut döngüsü kanıtlanmadı. Bu nedenle rapor “RAT kesin” demiyor; **uzaktan değiştirilebilir ve kriptografik olarak sabitlenmemiş keyfî kod teslim zincirinin kesin olarak kanıtlandığını** söylüyor.

## Neden bu araştırma yapıldı?

Minecraft client topluluklarında Prestige Client hakkında uzun süredir birbiriyle çelişen iddialar bulunuyor. Bazı kullanıcılar RAT veya cookie stealer olduğunu söylüyor; diğerleri şüpheli davranışların yalnızca anti-crack/koruma sistemi olduğunu savunuyor. Topluluk yorumları kanıt değildir. Bu araştırmanın amacı tek bir güncel örneği hash ile sabitleyip iddiaları tersine mühendislik kanıtlarıyla değerlendirmektir.

Bu nedenle aşağıdaki kanıt sınıfları birbirinden ayrıldı:

- **A — Doğrudan kanıt:** Exact sample'ın baytları, PE yapısı, IDA disassembly/decompile ve kesintisiz veri akışı.
- **B — Bağımsız korelasyon:** Aynı altyapı/aileye ait başka hash'lerin kamu sandbox raporları.
- **C — Otomatik sezgi:** AV/capa/sandbox etiketi; elle doğrulanmadıkça davranış kanıtı değildir.
- **D — İddia:** Kaynağı gösterilir fakat exact sample üzerinde doğrulanmamıştır.

## Örnek ve yöntem

Dosyalar yerelde çalıştırılmadı. IDA Pro MCP ile iki ayrı IDB üzerinde statik analiz yapıldı. CAPEv2'ye yalnızca `static` kategoride görev açıldı; sanal makine veya guest atanmadı. PE başlıkları, imza dizini, section entropileri, importlar, dizeler, çapraz referanslar, kritik fonksiyonların Hex-Rays çıktıları ve ağdan gelen buffer'ın tüketildiği noktaya kadar veri akışı incelendi. İkinci aşama Whonix'te boş POST isteğiyle ham dosya olarak yakalandı ve aktarım sonrası SHA-256 yeniden doğrulandı. Ek bağımsız tarama `capa 9.4.0` ve `FLOSS 3.1.1` ile yapıldı; capa rule commit'i `801a792c60fb2c8ef79e1b5d61d7e3d2cab4d405` olarak sabitlendi.

“Bayt bayt” burada bütün 5,1 MB dosyanın rapora hex dump edilmesi anlamına gelmez; bunun kanıt değeri yoktur. Bunun yerine her kritik hükmün dayandığı dosya ofseti/sanal adres, ham opcode dizisi, disassembly ve çağrı zinciri birlikte verildi. Binary'nin bütünü SHA-256 ile değişmez biçimde tanımlandı.

Her iddianın exact örnek, VA, dosya ofseti, veri akışı, dış kaynak ve sınırlamasını tek tabloda izlemek için ayrıca [`EVIDENCE-LEDGER.md`](EVIDENCE-LEDGER.md) yayımlandı. Bu defter, olumlu bulgular kadar kanıtlanamayan veya çürütülen iddiaları da ayrı kayıtlar hâlinde gösterir.

| Özellik | Değer |
|---|---|
| Dosya türü | PE32+, Windows GUI, x86-64 |
| Boyut | 767.488 bayt |
| MD5 | `d101c0eeb89ce736928a061f100337de` |
| SHA-1 | `feb0a5a4280eef41b7fa96be26e4698eb30804a2` |
| SHA-256 | `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08` |
| Import hash | `c48ec9fabbe14329942c8cc66b3ae7bd` |
| PE timestamp | 26 Mayıs 2026 11:03:24 UTC |
| Authenticode | Yok; Security Directory boş |
| Overlay | Yok |

Yakalanan ikinci aşamanın kimliği:

| Özellik | Değer |
|---|---|
| Sunucunun dosya adı | `injector.dll` |
| Dosya türü | PE32+ DLL, x86-64 |
| Boyut | 5.105.566 bayt |
| MD5 | `af658bbb582714a733d212e60c0e17c7` |
| SHA-256 | `1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad` |
| PE timestamp | 7 Ağustos 2026 15:45:15 UTC |
| Authenticode | Yok |
| PDB izi | `...Prestige-Injector\\x64\\DLL\\PrestigeInjector.pdb` |
| Koruma izleri | Büyük RX `.vlizer` bölümü; RW `.vm_sec` bölümü |

Bağımsız Manalyzer raporu aynı hash, import hash ve PE özelliklerini doğruluyor. Raporda 4 Temmuz 2026 tarihli VirusTotal sonucu **46/68** olarak aktarılmış; Microsoft, ESET, Fortinet, Bitdefender ve diğer birçok motor örneği Trojan/Agent veya genel malware olarak sınıflandırmış. AV isimleri tek başına RAT ailesini kanıtlamaz, fakat statik bulgularla birlikte ciddi bir bağımsız uyarıdır: [aynı SHA-256 için Manalyzer raporu](https://manalyzer.org/report/4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08).

## Çalışma zinciri

IDA'da doğrulanan yürütme zinciri şöyledir:

```text
Prestige-Client.exe
  └─ HTTPS POST: https://api.prestigeclient.vip/injectorDownload
       └─ Sunucudan ham PE/DLL yanıtı
            └─ VirtualAlloc ile bellek ayırma
                 └─ PE section kopyalama + relocation
                      └─ LoadLibraryA/GetProcAddress ile import çözme
                           └─ VirtualProtect ile section izinlerini ayarlama
                                └─ DLL entry point ve JNI_OnLoad(0, 0) çağrısı
```

### 1. Sunucu ve payload URL'si

`WinMain` (`0x1400012D0`) libcurl istemcisini oluşturuyor. `CURLOPT_RESOLVE` kullanılarak aşağıdaki eşleme gömülmüş:

```text
api.prestigeclient.vip:443:172.67.137.182
```

Global başlangıç fonksiyonu `sub_140001070`, temel URL'yi açık biçimde kuruyor:

```text
https://api.prestigeclient.vip
```

`sub_140001A50` (`0x140001A50`) buna `/injectorDownload` yolunu ekliyor. İstek `Content-Type: application/json` başlığı ve sıfır uzunluklu POST gövdesiyle gönderiliyor. Yanıt yalnızca curl başarılıysa ve HTTP durumu 200–299 arasındaysa tutuluyor.

### 2. İndirilen içerik sıradan veri değil

Yanıt daha sonra `sub_1400015D0` fonksiyonuna veriliyor. Bu fonksiyon ham yanıtın:

- `MZ` DOS imzasını,
- `PE\0\0` NT imzasını,
- PE32+ (`0x20B`) formatını,
- DLL bayrağını

kontrol ediyor. Yani program sunucudan açıkça bir Windows DLL/PE payload bekliyor.

### 3. Reflective/manual PE loader

`sub_1400015D0` standart Windows yükleyicisini kullanmadan DLL'yi kendi belleğine eşliyor:

- `VirtualAlloc` ile imaj için bellek ayırıyor.
- PE section'larını kopyalıyor.
- Base relocation kayıtlarını uyguluyor.
- Importları `LoadLibraryA` ve `GetProcAddress` ile çözüyor.
- Section izinlerini `VirtualProtect` ile executable/read/write durumlarına getiriyor.
- Exception table ve TLS callback'lerini işliyor.
- DLL giriş noktasını çağırıyor.

Bu davranış MITRE ATT&CK'te **T1620 – Reflective Code Loading** ile uyumludur. MITRE, bu tekniği payload'ı diskte dosya oluşturmadan doğrudan süreç belleğinde çalıştırma yöntemi olarak tanımlar: [MITRE ATT&CK T1620](https://attack.mitre.org/techniques/T1620/).

### 4. `JNI_OnLoad` çağrısı

Manual mapping tamamlandıktan sonra `WinMain`, yüklenen DLL'nin export tablosunda `JNI_OnLoad` adını arıyor ve bulduğu adresi şu şekilde çağırıyor:

```text
JNI_OnLoad(0, 0)
```

Bu, indirilen ikinci aşama kodun gerçekten yürütülmesi için kullanılan son adımdır. Dış EXE yalnızca ağ ve yükleme kabuğudur.

## Yakalanan ikinci aşama: `injector.dll`

Sunucunun 16 Ağustos 2026'da döndürdüğü 5,1 MB DLL ayrıca IDA'da açıldı. `JNI_OnLoad` girişi yoğun sanallaştırılmış koda geçiyor; buna rağmen ağ, UI ve enjeksiyon katmanlarının önemli bölümü statik olarak okunabiliyor.

### DLL'nin doğrulanan görevi

Uygulamaya özgü dizeler ve çağrı zincirleri dosyanın Prestige injector/controller olduğunu güçlü biçimde doğruluyor:

- `PrestigeInjector.dll` ve geliştirici PDB yolu,
- “Opening Minecraft process” ve “Manual-map injection” UI metinleri,
- `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory` ve `CreateRemoteThread`,
- PE başlığı, relocation, import ve exception table işleyen ikinci bir manual mapper,
- alternatif olarak geçici DLL ve uzaktaki `LoadLibraryA` yolunu kullanan klasik enjeksiyon.

Bu API'ler tek başına RAT kanıtı değildir; bir Minecraft injector'ın temel işleviyle doğrudan uyumludur.

### Üçüncü aşama indirme protokolü

IDA referansları DLL'nin aşağıdaki uygulama uç noktalarını kullandığını gösteriyor:

```text
/prestigeDownload      JSON: token, version
/injectionDownload     JSON: token
/login                 JSON: token, challenge
/newModLogin           JSON: token, challenge
/newFirstLogin         JSON: email, password, hwid, challenge
/injectorAccountInfo   JSON: token, challenge
/injectorBetaToggle    JSON: token, challenge, active
```

`/injectionDownload` fonksiyonunda nlohmann/json ile `token` nesnesi hazırlanıyor, JSON metnine çevriliyor ve libcurl seçenekleriyle POST gövdesi olarak gönderiliyor. `sub_180086DA0` callback'i yanıt baytlarını değiştirmeden büyüyen bellek buffer'ına ekliyor. Başarı işleyicisi `sub_180097440`, buffer adresini ve uzunluğunu sırasıyla `qword_1802186E8` ve `qword_1802186F0` globallerine yazıyor.

Kritik nokta yalnızca “download” dizesi değildir. `sub_18006E0B0`, bu iki globali yerel bir `{pointer,length}` çiftine kopyalıyor ve çifti doğrudan `sub_180052E50` remote manual mapper'ına veriyor. Arada arşiv açma, kaynak dönüştürme, hash kontrolü veya imza doğrulaması yoktur. İkinci tüketici `sub_18006EF90` da aynı global buffer'ı aynı mapper'a bağlar. Böylece aşağıdaki veri akışı doğrudan A-seviyesi kanıtla sabittir:

```text
HTTPS response bytes
  -> sub_180086DA0 (append only)
  -> qword_1802186E8 / qword_1802186F0 (pointer / length)
  -> sub_18006E0B0 veya sub_18006EF90
  -> sub_180052E50
  -> VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
```

UI metni de “securely downloading the Injection payload” diyerek katman ayrımını doğruluyor. Bu nedenle yakalanan `injector.dll`, nihai Minecraft modülü değil; hesabı doğrulayıp asıl injection payload'ını alan controller'dır.

Firejail `--private` içinde, gerçek kimlik bilgisi kullanılmadan dummy token ile yapılan güvenli doğrulama isteği `HTTP/2 400`, sıfır uzunluklu gövde döndürdü. Token brute-force edilmedi, hesap açılmadı ve kullanıcı sırrı kullanılmadı. Üçüncü aşama anonim bir istekle alınamıyor; geçerli hesap token'ı gerekiyor.

### Parola veri akışı ve resmî gizlilik beyanı

Resmî gizlilik politikası donanım özellikleri, kullanıcı adı/e-posta ve “hashed passwords (SHA256)” toplanabileceğini söylüyor. IDA veri akışı bu beyanın istemci tarafındaki SHA-256 kısmıyla uyumludur:

```text
ImGui login_password alanı (byte_180218700)
  -> sub_180084CD0
  -> CryptoPP::SHA256
  -> CryptoPP::HashFilter
  -> CryptoPP::HexEncoder
  -> CryptoPP::StringSink<std::string>
  -> sub_180098190 / sub_180097950
  -> sub_18008AE20
  -> /newFirstLogin JSON "password" alanı
```

`sub_180084CD0` içinde `CryptoPP::SHA256::vftable` (`0x180084D83`), `HashFilter` kurucusu (`0x180084E5D`) ve `HexEncoder`/`StringSink` zinciri (`0x180084DFF–0x180084E30`) doğrudan görülüyor. Kod, HexEncoder için büyük harf, sıfır grup boyutu, `":"` ayırıcı ve boş sonlandırıcı varsayılanlarını kullanıyor; grup boyutu sıfır olduğundan sonuç ayırıcısız 64 karakterlik büyük harfli SHA-256 hex değeridir. Crypto++'ın resmî API belgesi aynı varsayılanları ve çıktı biçimini tanımlar.

Bu nedenle **incelenen DLL için “kayıt sırasında düz metin parola gönderiyor” iddiasını destekleyen kanıt yoktur**; ağ JSON'una dönüştürülmüş hash gider. Bununla birlikte istemci statik analizi, sunucunun bu değeri nasıl sakladığını göstermez. API bu hash'i doğrudan kimlik doğrulamada kabul ediyorsa değer parola-eşdeğeri ve tekrar kullanılabilir olabilir; bu yalnızca bir protokol riski çıkarımıdır, yakalama olmadan doğrulanmış bulgu değildir. Salt'sız tek tur SHA-256'nın sunucu tarafı parola saklama yöntemi olarak kullanılıp kullanılmadığı da bu istemciden belirlenemez.

Kaynaklar: [Prestige Terms & Privacy Policy](https://www.prestigeclient.vip/tos), [Crypto++ HexEncoder API](https://cryptopp.com/docs/ref/class_hex_encoder.html), [Crypto++ HexEncoder örneği](https://www.cryptopp.com/wiki/HexEncoder).

### Resmî ürün beyanlarıyla anti-analysis bağlamı

Resmî site, 7 Ağustos 2026 güncellemesinde erken hook motoru, bellekte kalan baytları temizleyen “zero-trace cleanup” ve capture'larda görünmeyen streamproof arayüzü açıkça pazarlıyor; injectable sürüm için ayrıca “screenshare bypass” ifadesini kullanıyor. Bu tarih, incelenen DLL'nin 7 Ağustos derleme zamanıyla örtüşüyor. Dolayısıyla anti-debug/anti-VM, bellek temizliği ve capture görünmezliği bulgularının en azından bir bölümü ilan edilen hile ve ekran paylaşımı kaçınma amacıyla açıklanabilir. **Bu özellikler tek başına RAT kanıtı değildir.** Öte yandan ürün beyanı, uzaktan gelen imzasız payload'ın hash veya yayıncı doğrulaması olmadan çalıştırılması riskini ortadan kaldırmaz.

Kaynak: [Prestige Client resmî site ve 7 Ağustos 2026 changelog'u](https://www.prestigeclient.vip/).

### Genel malware yetenek matrisi

| Davranış sınıfı | Exact ikinci aşama sonucu | Doğrudan dayanak |
|---|---|---|
| Uzak payload alma | **Doğrulandı** | `/injectionDownload`; response callback; global pointer/length |
| Süreç enjeksiyonu | **Doğrulandı** | `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`; iki mapper |
| Reflective/manual PE loading | **Doğrulandı** | PE header, section, relocation, import ve exception-table işleme |
| Anti-debug / anti-VM | **Doğrulandı** | `CheckRemoteDebuggerPresent`, CPUID, BIOS ve 30 süreç adı |
| Sistem parmak izi/HWID | **Doğrulandı** | WMI UUID, baseboard/BIOS/CPU/disk seri no; `MachineGuid` |
| Ağ üzerinden hesap verisi | **Doğrulandı, sınırlı** | ilk kayıt: e-posta, SHA-256 parola hex'i ve HWID; diğer çağrılar: token/challenge |
| Keylogging | **Bulunmadı** | `GetAsyncKeyState`/hook yok; `GetKeyState` yalnız modifier/UI tuşları |
| Clipboard hırsızlığı | **Bulunmadı** | GUI clipboard adaptörü var; ağ yoluna xref yok |
| Ekran görüntüsü/kamera/mikrofon | **Bulunmadı** | `BitBlt`/`PrintWindow`/capture API yok; GDI yalnız ikon/UI |
| Browser cookie/password theft | **Bulunmadı** | browser DB yolları, DPAPI, Vault/Credential API yok |
| Kalıcılık | **Bulunmadı** | Run/RunOnce yazma, servis, scheduled task, startup zinciri yok |
| Privilege escalation | **Bulunmadı** | token privilege/service/driver yükleme zinciri yok |
| Fidyeleme/veri yok etme | **Bulunmadı** | dosya dolaşıp şifreleme, shadow-copy silme, ransom note yok |
| Arşivleme/exfiltration | **Bulunmadı** | uygulama düzeyinde ZIP/7z/archive veya dosya-upload yolu yok |
| RAT komut döngüsü | **Bulunmadı** | komut protokolü, beacon döngüsü veya operatör görevleri yok |
| Üçüncü aşamanın davranışı | **Belirlenemedi** | Authenticated payload ele geçirilmedi |

Bu tablodaki “bulunmadı”, yalnızca SHA-256 `1472c12a…aa2ad` için statik görünürlüğü ifade eder; üçüncü aşamayı veya başka tarihte sunulan sürümü kapsamaz.

### RAT/stealer göstergeleri için negatif bulgular

İkinci aşamanın import, string ve xref taramasında şunlar bulunmadı:

- Chromium `Login Data`/`Local State`, LevelDB veya tarayıcı profili yolları,
- `CryptUnprotectData`, Credential Manager veya Vault API'leri,
- `GetAsyncKeyState`/`SetWindowsHookEx` türü keylogger API'leri,
- `BitBlt`, `PrintWindow`, kamera veya mikrofon yakalama zinciri,
- Run key, servis, scheduled task ya da PowerShell/cmd tabanlı persistence.

Clipboard okuma/yazma yardımcıları mevcut; fakat bunların ağ çağrısına giden referansı bulunmadı ve biçimleri GUI kütüphanesinin normal kopyala/yapıştır entegrasyonuyla uyumlu. Bu negatif bulgu “temiz” sertifikası değildir: sanallaştırılmış kod statik görünürlüğü azaltır ve henüz alınamayan üçüncü aşama ayrı değerlendirilmelidir.

### HWID toplama: ne topluyor, ne anlama geliyor?

`sub_180055290` bir donanım kimliği bileşimi oluşturuyor. IDA'da parametreleriyle doğrulanan WMI sorguları şunlardır:

```text
SELECT UUID         FROM Win32_ComputerSystemProduct
SELECT SerialNumber FROM Win32_BaseBoard
SELECT SerialNumber FROM Win32_BIOS
SELECT ProcessorId  FROM Win32_Processor
SELECT SerialNumber FROM Win32_DiskDrive WHERE Index = 0
```

Aynı fonksiyon `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` değerini okuyor. Bu, cihazı oldukça kararlı biçimde parmak izleme yeteneğidir. Kodun doğrulanan çağrıları bunu login/HWID eşleştirme nesnesinde kullanıyor; tek başına credential theft değildir. Yine de kullanıcıya açıkça belgelenmesi gereken cihaz telemetrisidir.

### Otomatik tarama sonuçlarının elle doğrulanması

`capa 9.4.0` reflective loading, DLL/thread injection, process discovery, WMI ve sandbox kaçınmayı doğru yakaladı. Aynı tarama “PowerShell”, “keylogging” ve “clipboard collection” etiketleri de üretti. Bu üçü doğrudan hüküm olarak kullanılmadı:

- “PowerShell” eşleşmesindeki iki `system()` çağrısının her ikisinde komut `start <çözülmüş URL>` biçiminde kuruluyor; PowerShell/cmd script'i yok.
- “Keylogging” eşleşmesi `GetKeyState` çağrılarına dayanıyor. Kod modifier/UI durumlarını okuyor; `GetAsyncKeyState`, hook kurulumu, tuş dizisi buffer'ı veya ağ aktarımı yok.
- Clipboard fonksiyonları UTF-8/UTF-16 dönüşümlü ImGui kopyala/yapıştır adaptörüdür ve network çağrısına veri akışı bulunmadı.
- GDI eşleşmeleri 32×32 pencere ikonunu `CreateDIBSection` ile UI dokusuna dönüştürüyor ve DPI ölçüyor; ekran yakalama API zinciri değil.
- libcurl içinde gömülü `multipart`, cookie, HSTS, FTP/SMB upload dizeleri uygulamanın bunları kullandığını göstermez. Uygulamaya özgü xref'ler JSON POST çağrılarına gidiyor.
- “Credit-card parsing/Luhn” eşleşmeleri `0x1800A13B0` ve `0x1800A3DD0` çevresindeki MSVC `std::regex` parser koduna düştü (`std::_Node_if::vftable`, regex escape/sayı sözdizimi); kart verisi yolu veya uygulama çağırıcısı değil.
- “Geographical location” eşleşmesi yalnız `GetLocaleInfo(A/Ex)` API'sini yeterli kabul eden geniş capa kuralından geldi; şehir/ülke/GeoID toplama ve ağ gönderimi bulunmadı.

`FLOSS 3.1.1` stack/tight/decoded modlarında 526,72 saniyelik taramayı tamamladı. Yalnız 7 stack string, 6 tight string ve tek anlamsız sayısal decoded string (`769630810`) çıkardı; yeni domain, URL, komut protokolü, credential yolu veya RAT ailesi işareti üretmedi. Bu sonuç `.vlizer` sanallaştırmasını çözmüş sayılmaz; yalnız FLOSS'un tanıdığı klasik string-decoder kalıplarında ek IOC bulunmadığını gösterir.

Bu ayrım önemlidir: otomatik aracın tek bir API/dize üzerinden verdiği ATT&CK etiketi, bağlamı doğrulanmadan “malware kanıtı” değildir.

### Güçlü anti-analiz katmanı

Daha derin IDA incelemesi, controller'ın analizi özellikle engellediğini doğruladı:

- CPUID ve BIOS registry değerleriyle VMware, VirtualBox, KVM, QEMU, Xen, Parallels ve başka hypervisor'ları arıyor.
- `CheckRemoteDebuggerPresent` kullanıyor.
- IDA, Ghidra, x64dbg, WinDbg, Fiddler, mitmproxy, HTTP Toolkit, dnSpy, Cheat Engine, Scylla, Detect It Easy ve API Monitor dahil 30 süreç adını kara listeye alıyor.
- Bir araç/VM algılanınca güvenlik uyarısı gösterip ana süreci `TerminateProcess` ile kapatıyor.

Bu, neden sıradan sandbox koşularının gerçek indirme/enjeksiyon yoluna ulaşamayabileceğini açıklıyor. Aynı zamanda yalnızca “normal injector yanlış pozitifi” savunmasını zayıflatıyor: kod, tersine mühendislik ve ağ gözlemini aktif biçimde önlemek için tasarlanmış. Ancak anti-analiz, tek başına veri hırsızlığı veya belirli bir RAT ailesi kanıtı değildir.

### İnternetteki Chrome/Vault/LSASS iddiası

Bir sosyal medya paylaşımında Chrome'un `--headless --remote-debugging-port=9222 --incognito` ile çalıştırıldığı, `VaultSvc` ve `lsass.exe` hedeflendiği ve verilerin ZIP'lenerek `/injectorAccountInfo` yoluna gönderildiği ileri sürülüyor. Bu iddia exact hash üzerinde doğrulanmadı:

- İlgili Chrome argümanları, `chrome.exe`, `lsass.exe`, `VaultSvc` veya ZIP/archive göstergeleri bulunmuyor.
- `CreateProcessW` için tek uygulama çağrısı mevcut host executable'ını `--security-notice` ile yeniden başlatıyor; browser açmıyor.
- `/injectorAccountInfo` gövdesi dosya/arşiv değil `token` ve `challenge` alanlarından oluşuyor.
- Winsock çağrılarının doğrudan referansları statik bağlı libcurl katmanında; ayrı bir RAT socket döngüsü görülmedi.

Dolayısıyla bu iddia başka bir sürüm/üçüncü payload söz konusu değilse, sandbox süreç ağacının veya otomatik davranış etiketlerinin yanlış yorumlanmasına benziyor. Ayrıca internette `prestige-client.live` üzerinden dağıtılan ve gerçekten stealer olarak raporlanan JAR'lar farklı hash/domain kullanan ayrı bir zincirdir; `prestigeclient.vip` örneğine otomatik olarak atfedilemez.

### 16 Ağustos Reddit/Triage iddiasının süreç-atıf denetimi

16 Ağustos 2026 tarihli [Reddit gönderisi](https://www.reddit.com/r/minecraftclients/comments/1vpfkic/prestige_client_is_so_trash_bro/), exact dış loader hash'imiz için bir [Triage görevi](https://tria.ge/260623-fqhjgsat5q/behavioral1) ve VirusTotal Graph bağlantısı yayımlıyor. Triage üst özeti 43 imzayı görev seviyesinde birleştirerek browser profile okuma, Drivers/System32'a dosya bırakma, servis image path değiştirme, RDP portu ve COM hijacking gibi etiketler gösteriyor. Bu özet **imzaların hepsinin Prestige sürecinden geldiğini söylemez**.

Triage HTML süreç ağacında:

```text
Explorer.EXE (derinlik 1)
├── Prestige-Client.exe, PID 79 (derinlik 2)
├── chrome.exe, PID 81 (derinlik 2)
└── diğer sandbox/Windows süreçleri
```

`chrome.exe`, Prestige'in çocuğu değil; ikisi Explorer altında ayrı kardeş süreçlerdir. Prestige satırında görünen süreç-özel imzalar `GetForegroundWindowSpam` ve `SetWindowsHookEx` ile sınırlıdır. Chrome satırı ise kendi Windows/registry/process imzalarını taşır. Dolayısıyla görevin küresel “Reads user/profile data of web browsers” veya persistence etiketlerini yalnız üst özetten Prestige'e bağlamak süreç-atıf hatasıdır. Reddit yorumundaki “execution parents, Prestige'in başlattıkları değil Prestige'i başlatanlardır” itirazı da VirusTotal Graph yönünü yorumlarken geçerli metodolojik uyarıdır.

Bu denetim Triage'i değersiz kılmaz: görev exact hash'i, PE indirmeyi ve anti-analysis davranışını bağımsız olarak doğrular. Fakat aynı görevde çalışan Chrome/Windows süreçlerinin davranışları ayrıştırılmadan `stealer`, `persistence` veya `privilege escalation` hükmü çıkarılamaz. IDA'daki exact kod-xref incelemesi de bu toplu etiketlerin iddia ettiği Chrome DB, servis, RDP, Run key ve COM-hijack uygulama zincirlerini göstermedi.

### Tarihsel örnekler ve bağımsız sandbox korelasyonu

Kamuya açık raporlar aynı ürün/alana ait daha eski fakat **farklı hash'ler** gösteriyor:

| SHA-256 | Tarih/biçim | Korelasyon | Bu araştırma açısından anlamı |
|---|---|---|---|
| `ea194857ac2623ad4b0a8ac8115c9eb7fa23af566d8cfd028f97e9c0e5919034` | Mart 2026, EXE | Aynı API ve `/login`; anti-VM | Aile/altyapı sürekliliği; RAT kanıtı değil |
| `1921984948718074c52de01fb2ac75de1136ecce0adbb4b119072ffacd249aa5` | Ocak 2026, DLL | Aynı pinned host/IP ve Prestige dizeleri | Controller soyunun daha eski örneği |
| `5bff5030f0d4cc53cde783876f92ea3e09465d9ca59ce8ae0a7bb82d870ec045` | 2026, DLL | Aynı host/IP ve koruma profili | Ek aile korelasyonu |

[Hybrid Analysis ilk örneğe](https://hybrid-analysis.com/sample/ea194857ac2623ad4b0a8ac8115c9eb7fa23af566d8cfd028f97e9c0e5919034/69bec6398558e575170256ca) yüksek risk skoru verse de “keylogging” ayrıntısında yalnız VK 18/17/16/91/92/93 için `GetKeyState` görülür; bunlar Alt/Ctrl/Shift/Windows/Menu tuşlarıdır. “Credential” etiketi ise tek `NtQueryInformationToken` çağrısına ve düşük relevance değerine bağlanmıştır. [Triage'ın görünen davranış haritası](https://tria.ge/260303-b9evgsgy3a/behavioral1) anti-VM, registry ve sistem keşfi gösterirken credential access, collection, C2 veya exfiltration davranışı göstermemektedir. Bu kamu raporları ürünün uzun süredir anti-analizli loader/controller mimarisi kullandığını destekler; exact güncel üçüncü aşamanın RAT olduğunu ispatlamaz.

28 Mart 2026 tarihli bağımsız [ANY.RUN kaydı](https://any.run/report/e88dc150d4e79efd2186355036b9548ac29a8063d04c7a83457e1b0a9c398d29/f11f44b5-7569-4dcd-a86c-88f4be4bb736), aynı API'nin o tarihte `/injectorNewDownload` üzerinden yaklaşık 5 MB executable döndürdüğünü ve diske `5bff5030…ec045` hash'li geçici DLL bırakıldığını gösteriyor. [Aynı DLL'nin Hybrid Analysis raporu](https://hybrid-analysis.com/sample/5bff5030f0d4cc53cde783876f92ea3e09465d9ca59ce8ae0a7bb82d870ec045/69c82afe8a7dbe1cd60d3bcc), dosyayı 7.844.880 bayt PE64 DLL olarak tanımlıyor ve process-injection API dizelerini gösteriyor. Bu tarihsel nesne güncel authenticated üçüncü aşama değildir; güncel controller soyunun eski bir üyesiyle uyumludur.

### 5. Ağdan ikinci aşama alma

Harici sistemden executable payload indirme davranışı **T1105 – Ingress Tool Transfer** ile de eşleşir: [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/).

## Neden “sadece injector” açıklaması yeterli değil?

Minecraft için native DLL yüklemek teknik olarak bir injector'ın beklenen işlevi olabilir. Ancak bu örnekte kullanıcıya dağıtılan dosya:

1. Çalıştıracağı DLL'yi yanında taşımıyor ve hash/publisher doğrulaması yapmıyor.
2. DLL'yi her çalıştırmada uzaktaki özel bir API'den alabiliyor.
3. Sunucunun o anda döndürdüğü herhangi bir uyumlu DLL'yi belleğe eşliyor.
4. İndirilen DLL'nin Authenticode imzasını veya bilinen hash'ini doğrulamıyor.
5. İkinci aşamayı diske bırakmadan çalıştırdığı için normal dosya taramalarından kaçınabiliyor.
6. Dış EXE'nin kendisi de dijital olarak imzalanmamış.

Dolayısıyla geliştirici bugün yalnızca Minecraft modülü döndürse bile, aynı mekanizma yarın kullanıcıya özel RAT, stealer veya başka bir payload döndürebilir. Kullanıcının çalışacak kodu önceden denetlemesi mümkün değildir. Güvenlik açısından sorun yalnızca “şu anki payload ne?” değil, sunucunun **uzaktan keyfî kod seçebilmesi**dir.

## RAT iddiası için karar tablosu

| İddia | Sonuç | Gerekçe |
|---|---|---|
| Dosya bir uzaktan payload loader'ıdır | **Doğrulandı** | URL, HTTP isteği, PE kontrolü ve manual mapper doğrudan kodda |
| Ağdan gelen DLL'yi bellekte çalıştırır | **Doğrulandı** | `VirtualAlloc` → PE mapping → `VirtualProtect` → export çağrısı |
| Geliştirici sunucusu çalışacak kodu sonradan değiştirebilir | **Doğrulandı** | Payload hash/imza pinning yok; yanıt doğrudan çalıştırılıyor |
| İncelenen dış EXE zararlı olarak algılanıyor | **Güçlü biçimde destekleniyor** | Aynı hash için 46/68 çoklu motor sonucu |
| Yakalanan ikinci aşama Minecraft injector/controller'dır | **Doğrulandı** | UI, API yolları ve iki ayrı process-injection uygulaması |
| İkinci aşama üçüncü bir injection payload'ı indirir | **Doğrulandı** | `/injectionDownload`, token'lı JSON POST ve bellek yanıt callback'i |
| Üçüncü aşama yanıtı dönüşmeden mapper'a verilir | **Doğrulandı** | Pointer/length globalleri doğrudan `sub_180052E50` tüketicisine gider |
| İkinci aşama VM/debugger/analiz araçlarından kaçar | **Doğrulandı** | CPUID, BIOS registry, debugger kontrolü ve 30 süreçlik kara liste |
| İkinci aşama kalıcı donanım parmak izi toplar | **Doğrulandı** | Beş WMI alanı ve `MachineGuid` |
| İlk kayıt parolası düz metin gönderilir | **Çürütüldü (bu hash için)** | UI parolası Crypto++ SHA256→HashFilter→HexEncoder hattından sonra JSON'a giriyor |
| Yakalanan iki örnek cookie/token çalıyor | **Doğrulanmadı** | Browser/DPAPI/credential zinciri görülmedi |
| Yakalanan iki örnek kalıcılık kuruyor | **Doğrulanmadı** | Run key, servis, task veya ilgili komut zinciri görülmedi |
| Yakalanan iki örnek tam özellikli bir RAT'tır | **Kanıtlanmadı** | RAT komut döngüsü, gözetleme veya C2 protokolü gösterilemedi; üçüncü aşama eksik |

En doğru kamuya açık ifade şudur:

> “Prestige Client'ın incelenen dış EXE'si imzasız bir uzak loader'dır. 16 Ağustos 2026'da yakalanan ikinci aşama, yoğun korumalı bir Minecraft injector/controller çıktı; bu DLL'de doğrudan RAT/stealer kanıtı bulunmadı. Ancak controller, token'la üçüncü ve değiştirilebilir bir injection payload'ı daha indirip Minecraft sürecine yükler. Kullanıcı çalışacak nihai kodun hash'ini veya imzasını doğrulayamadığı için zincire güvenilemez ve kullanılmamalıdır.”

## Yaygın savunmalara teknik yanıt

### “Anti-crack olduğu için böyle görünüyor”

Anti-crack, obfuscation veya lisans kontrolü reflective loader davranışını açıklayabilir; fakat riski ortadan kaldırmaz. Kod koruma gerekçesi, imzasız ve doğrulanmayan uzak DLL'yi çalıştırmanın güvenli olduğu anlamına gelmez.

### “Uzun süredir kullanıyorum, bir şey olmadı”

Bu mimaride sunucunun yanıtı zamana, hesaba, IP'ye veya kampanyaya göre değişebilir. Bir kullanıcının geçmişte sorun yaşamaması başka bir kullanıcının aynı payload'ı aldığı anlamına gelmez.

### “Antivirüsler hile yazılımlarını zaten yanlış pozitif görüyor”

Tek bir generic tespit yanlış pozitif olabilir. Burada değerlendirme yalnızca AV skoruna dayanmıyor: 46/68 sonucu, bağımsız IDA analizinde doğrulanan uzaktan indirme ve reflective loading zinciriyle birlikte ele alınıyor.

### “DLL injection client'ın normal görevi”

Yerel, hash'i bilinen bir DLL'yi kullanıcının seçtiği Minecraft sürecine yüklemek ile sunucudan o anda gelen doğrulanmamış DLL'yi kendi belleğinde çalıştırmak aynı güven modeli değildir.

## IOC'ler

```text
SHA256  4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08
MD5     d101c0eeb89ce736928a061f100337de
SHA256  1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad  (injector.dll)
MD5     af658bbb582714a733d212e60c0e17c7                                  (injector.dll)
Domain  api.prestigeclient.vip
URL     https://api.prestigeclient.vip/injectorDownload
Path    /injectionDownload
Path    /prestigeDownload
IP      172.67.137.182
Export  JNI_OnLoad
```

IP bir CDN/ters proxy adresi olabilir; ortak altyapı nedeniyle yalnızca IP bazlı engelleme yanlış pozitif yaratabilir. Domain ve tam URL daha seçici IOC'lerdir.

## Ham bayt ve disassembly kanıt eki

Aşağıdaki baytlar IDA veritabanlarından doğrudan okunmuştur; yorumun bağımsız doğrulanabilmesi için opcode ve semantik birlikte verilmiştir. S1 `.text` için `file_offset = VA - 0x140000000 - 0x1000 + 0x400`; S2 için image base `0x180000000` kullanılır. Tam adres/ofset tablosu kanıt defterindedir.

### Dış loader pinned resolve — `0x140001316`, dosya `0x716`

```text
48 8d 15 fb 7f 0a 00 33 c9 e8 9c 10 00 00 48 8b
0d 7d 46 0b 00 4c 8b c0 ba db 27 00 00 48 89 05
76 46 0b 00 e8 41 3e 00 00
```

`lea rdx` pinned `api.prestigeclient.vip:443:172.67.137.182` dizesini alır; `mov edx,0x27DB` libcurl `CURLOPT_RESOLVE` option'ını hazırlar.

### Dış loader PE/DLL kapısı — `0x1400015F1`, dosya `0x9F1`

```text
48 83 fa 40 ... b8 4d 5a 00 00 66 39 01 ...
41 81 3c 0e 50 45 00 00 ... b8 0b 02 00 00 ...
b8 00 20 00 00 66 41 85 44 0e 16
```

Sabitler sırasıyla minimum DOS header boyutu, `MZ`, `PE\0\0`, PE32+ `0x20B` ve DLL characteristic `0x2000` kontrolleridir. Başarılı yanıt sıradan JSON/veri değil, map edilebilir x64 DLL olarak beklenir.

### Mapped export'un çalıştırılması — `0x140001494–0x1400014CF`

```text
8b 0b 48 8d 15 53 7f 0a 00 48 03 ce e8 ab c7 08 00
...
41 0f b7 0c 7e 41 8b 04 8f 48 03 c6 ... 33 d2 33 c9 ff d0
```

Export isimleri `JNI_OnLoad` ile karşılaştırılır; bulunan adres `RCX=0`, `RDX=0` ile dolaylı çağrılır. Bu, indirme/manual-map sonrasında payload kodunun gerçekten yürütüldüğünü gösterir.

### `/injectionDownload` libcurl kurulumu — `0x1800879A9`

```text
e8 02 6d 05 00 4c 8d 05 eb f3 ff ff ba 2b 4e 00 00
48 8b 0d bf 13 19 00 e8 ea 6c 05 00 4c 8d 45 b0 ba
11 27 00 00 48 8b 0d aa 13 19 00 e8 d5 6c 05 00
```

Buradaki libcurl option sabitleri `0x4e2b` (20011, write callback) ve `0x2711` (10001, write data) olup response callback'i ve hedef buffer'ı kurar.

### Response pointer/length'in globallere yazılması — `0x180097545`

```text
0f 84 47 01 00 00 48 8b 4c 24 20 48 85 c9 0f 84
31 01 00 00 48 89 05 88 11 18 00 48 89 0d 89 11
18 00 48 85 db 74 56 8b
```

İki `mov [rip+...]` yazımı indirilen buffer'ın adres ve boyutunu `qword_1802186E8/F0` alanlarına taşır.

### Globallerin pointer/length çiftine alınması — `0x18006E0F2`

```text
c7 44 24 54 00 00 00 00 48 8b 05 e7 a5 1a 00 48
89 44 24 48 8b 05 e4 a5 1a 00 89 44 24 50 48 8d
51 30 49 8d 4b d0 e8 23 a8 fe ff 90 48 8b d0 48
8d 8c
```

### Aynı çiftin remote manual mapper'a verilmesi — `0x18006E1D8`

```text
e8 43 ac fe ff 4c 8d 44 24 48 48 8b 17 e8 66 4c
fe ff 48 8b 0f 84 c0 0f 85 a7 01 00 00 ff 15 65
b0 0d 00 48 8d 0d 5e a7
```

`lea r8,[rsp+48h]` pointer/length çiftini üçüncü argüman olarak hazırlar; hemen sonraki çağrı `sub_180052E50` manual mapper'ıdır. Bu dört kesit beraber, ağ yanıtının yalnız indirilmediğini, hedef sürece executable PE olarak aktarıldığını gösterir.

### `system()` otomatik PowerShell etiketinin çürütülmesi — `0x1800737AF–0x180073806`

```text
lea rcx, "start "
call sub_18004B080
...
call sub_18007A7A0        ; "start " + çözülmüş değer
...
call cs:system
```

Aynı yapı ikinci UI yolunda da bulunur. Çözülen komut bir URL açma işlevidir; PowerShell script yürütme zinciri değildir.

### Kayıt parolasının SHA-256 hattı — `0x180084D83–0x180084E5D`

```text
0x180084D83  48 8d 05 de 9e 0c 00 48 89 44 24 70
0x180084DFF  48 8d 05 42 ad 0c 00 48 89 07 48 8d 05 a8 ae 0c 00
0x180084E4F  45 33 c9 4c 8b c0 48 8d 54 24 70 48 8b ce e8 1e 50 02 00
```

İlk kesit `CryptoPP::SHA256::vftable`, ikinci kesit StringSink/HexEncoder vtable'ları, üçüncü kesit `HashFilter` kurulumudur. UI parolası bu hattan sonra `/newFirstLogin` JSON `password` alanına gider; exact S2 için düz metin parola gönderme iddiası desteklenmez.

## Kullanmış olanlar ne yapmalı?

- Dosyayı tekrar çalıştırmayın ve mevcut kopyayı karantinaya alın.
- EDR, proxy, DNS ve firewall geçmişinde domain ve URL için arama yapın.
- İkinci aşama diske yazılmadan çalıştığı için yalnızca dosya sistemi taramasına güvenmeyin; process-memory ve EDR telemetry daha değerlidir.
- Tarayıcı oturumlarını sonlandırın, önemli hesap parolalarını temiz bir cihazdan değiştirin ve MFA etkinleştirin. Bu adım, cookie hırsızlığı kanıtlandığı için değil, çalıştırılan ikinci aşama bilinmediği için ihtiyati tedbirdir.
- Olay ciddi veya kurumsal bir cihazdaysa bellek/EDR artefaktlarını koruyup profesyonel olay müdahalesi uygulayın.

## Sınırlamalar ve bir sonraki kanıt eşiği

Bu araştırma kasıtlı olarak yerel/dinamik yürütme yapmadı. Dış loader ve yakalanan injector DLL için CAPEv2 `static` görevleri dosya kimliklerini veritabanında doğruladı fakat processing worker görevleri almadı: ilk görevler 6/7 ve yeniden zamanlanan görevler 8/9 `pending`, `machine_id=null`, `analysis_started_on=null`, hata listesi boş. Bu nedenle CAPE davranış raporu varmış gibi sunulmuyor. Kesin “RAT” sınıflandırması için token akışına uygun biçimde `/injectionDownload` yanıtının da kontrollü ortamda yakalanması ve aşağıdaki davranışlardan en az birinin gösterilmesi gerekir:

- Komut alıp çalıştırma,
- ekran/klavye/clipboard toplama,
- tarayıcı cookie/token veya credential erişimi,
- dosya yükleme/indirme ve uzaktan yönetim,
- kalıcılık,
- operatör C2 protokolü.

Sunucu çevrimdışıysa veya temiz payload döndürüyorsa tek bir sandbox koşusu da geçmişte ya da hedefli kullanıcılara RAT dağıtılmadığını kanıtlayamaz. Sunucu kontrollü payload mimarisi bu belirsizliği kalıcı hâle getirir.

## Kaynaklar

- [Aynı SHA-256 için Manalyzer statik raporu ve 46/68 sonucu](https://manalyzer.org/report/4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08)
- [MITRE ATT&CK T1620 – Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
- [MITRE ATT&CK T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1497.001 – Virtualization/Sandbox Evasion: System Checks](https://attack.mitre.org/techniques/T1497/001/)
- [Mandiant capa 9.4.0 release ve kurulum bilgisi](https://github.com/mandiant/capa/releases/tag/v9.4.0)
- [FLOSS resmi proje/dokümantasyon kaynağı](https://github.com/mandiant/flare-floss)
- [Prestige Client resmî site ve 7 Ağustos 2026 changelog'u](https://www.prestigeclient.vip/)
- [Prestige Terms & Privacy Policy](https://www.prestigeclient.vip/tos)
- [Crypto++ HexEncoder resmî API belgesi](https://cryptopp.com/docs/ref/class_hex_encoder.html)
- [Mart 2026 Prestige-Injector ANY.RUN kaydı ve indirilen DLL hash'i](https://any.run/report/e88dc150d4e79efd2186355036b9548ac29a8063d04c7a83457e1b0a9c398d29/f11f44b5-7569-4dcd-a86c-88f4be4bb736)
- [ANY.RUN'da düşen `5bff5030…` DLL'nin Hybrid Analysis raporu](https://hybrid-analysis.com/sample/5bff5030f0d4cc53cde783876f92ea3e09465d9ca59ce8ae0a7bb82d870ec045/69c82afe8a7dbe1cd60d3bcc)
- [Tarihsel Prestige EXE — Hybrid Analysis, `ea194857…`](https://hybrid-analysis.com/sample/ea194857ac2623ad4b0a8ac8115c9eb7fa23af566d8cfd028f97e9c0e5919034/69bec6398558e575170256ca)
- [Tarihsel Prestige DLL — Hybrid Analysis, `19219849…`](https://hybrid-analysis.com/sample/1921984948718074c52de01fb2ac75de1136ecce0adbb4b119072ffacd249aa5/69769f65431daf03810be9aa)
- [Tarihsel örneğin davranış görünümü — Triage](https://tria.ge/260303-b9evgsgy3a/behavioral1)
- [Doğrulanamayan Chrome/Vault/LSASS iddiasının yayımlandığı gönderi](https://www.reddit.com/user/Alarmed-Web4073/comments/1vhk7ho/prestige_client_injector_is_an_information/)
- [16 Ağustos 2026 Reddit gönderisi ve kaynak bağlantıları](https://www.reddit.com/r/minecraftclients/comments/1vpfkic/prestige_client_is_so_trash_bro/)
- [Reddit gönderisindeki exact-hash Triage görevi](https://tria.ge/260623-fqhjgsat5q/behavioral1)
- [Farklı domain/hash kullanan sahte Prestige stealer zinciri — MalwareBazaar](https://bazaar.abuse.ch/sample/72d80252032723c3b7f9c04be3fcdf69e96dad41cd8b7968266b296643357316/)

## Paylaşılabilir kısa özet

> Prestige Client'ın `4507816e…e6b08` hash'li dış EXE'sini ve 16 Ağustos'ta sunucudan gelen `1472c12a…aa2ad` hash'li DLL'yi IDA ile inceledim. EXE, DLL'yi doğrulamadan belleğe manual-map ediyor. Yakalanan DLL yoğun korumalı bir Minecraft injector/controller; iki ayrı process-injection yöntemi var ve token'la `/injectionDownload` üzerinden üçüncü payload'ı alıyor. Bu iki dosyada RAT/stealer/persistence davranışını doğrudan kanıtlayamadım; bu nedenle “RAT kesin” iddiasını yayımlamıyorum. Fakat geliştiricinin son payload'ı uzaktan ve kullanıcı doğrulaması olmadan değiştirebilmesi, zinciri kullanmamak için yeterli ve kanıtlanmış bir risk.
