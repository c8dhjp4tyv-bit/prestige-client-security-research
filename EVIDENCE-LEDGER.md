# Prestige Client evidence ledger

**Date:** 16 August 2026<br>
**Purpose:** Tie every material conclusion to an exact sample, virtual address, file offset, call chain, source, and explicit limitation.<br>
**Main report:** [`REPORT.md`](REPORT.md)

## Final assessment

> **High-risk loader/injector chain that executes unsigned, remotely replaceable PE payloads without an expected hash or publisher check; its captured second stage includes dedicated anti-analysis, hardware fingerprinting, and two Minecraft process-injection paths.**

A RAT command loop, browser credential theft, keylogging, screen capture, persistence, ransomware, and file exfiltration were not established in the two captured hashes. Because the authenticated third-stage payload was not obtained, its final behavior cannot honestly be classified as either clean or a RAT.

## Evidence levels

| Level | Meaning |
|---|---|
| A | Exact-sample bytes, PE structures, IDA disassembly/decompilation, xref, or uninterrupted data flow |
| B | Independent exact-hash report or historical different hash using the same infrastructure |
| C | Automated AV, capa, or sandbox label; not a behavioral conclusion until manually validated |
| D | Social-media, video, or otherwise unverified allegation |

## Artifact custody

| ID | Role | Size | SHA-256 | Source and validation |
|---|---|---:|---|---|
| S1 | Outer loader | 767,488 | `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08` | User-supplied `Prestige-Client.exe`; local hashes, PE parsing, IDA database `prestige_client_static` |
| S2 | Injector/controller DLL | 5,105,566 | `1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad` | Captured 16 August 2026 from `POST /injectorDownload`; response named `injector.dll`; local hashes and IDA database `prestige_injector_payload` |
| A1 | Capture archive | — | `5ccc313babf89e0efdd9540d8e73e01a66d839cae0b6177d8e73c15cd835108b` | Archive containing S2, response headers, and capture metadata |

S1 and S2 have no Authenticode signature. Suspicious binaries are excluded from the repository; published artifacts are pinned by [`SHA256SUMS`](SHA256SUMS).

## Virtual-address to file-offset mapping

Both PEs have `.text` RVA `0x1000` and raw offset `0x400`:

```text
file_offset = VA - image_base - 0x1000 + 0x400
```

| Sample | VA | File offset | Function |
|---|---:|---:|---|
| S1 | `0x140001316` | `0x716` | Pinned hostname/IP and `CURLOPT_RESOLVE` |
| S1 | `0x14000142C` | `0x82C` | Response to manual mapper and export search |
| S1 | `0x1400014CF` | `0x8CF` | Indirect `JNI_OnLoad(0,0)` call |
| S1 | `0x1400015F1` | `0x9F1` | PE/DLL validation gate |
| S1 | `0x1400017FD` | `0xBFD` | Import resolution through `LoadLibraryA` |
| S1 | `0x140001912` | `0xD12` | Section permissions through `VirtualProtect` |
| S2 | `0x180052E50` | `0x52250` | Remote manual mapper |
| S2 | `0x180044E70` | `0x44270` | Remote `LoadLibraryA` fallback |
| S2 | `0x1800879A9` | `0x86DA9` | `/injectionDownload` callback/data setup |
| S2 | `0x180097545` | `0x96945` | Response pointer/length written to globals |
| S2 | `0x18006E0F2` | `0x6D4F2` | Globals copied to local pointer/length pair |
| S2 | `0x18006E1D8` | `0x6D5D8` | Pair passed to remote mapper |
| S2 | `0x18007C540` | `0x7B940` | Debugger/analysis-tool controls |
| S2 | `0x180055290` | `0x54690` | WMI/HWID collection |
| S2 | `0x180084D83` | `0x84183` | Crypto++ SHA-256 password path |

## Confirmed claims

### C01 — The outer sample makes a pinned HTTPS request

- **Status:** Confirmed, level A.
- **Evidence:** `WinMain` at `0x1400012D0`; `0x140001316` references `api.prestigeclient.vip:443:172.67.137.182` and selects option `0x27DB`/10203.
- **URL:** `sub_140001070` constructs `https://api.prestigeclient.vip`; `sub_140001A50` appends `/injectorDownload`.
- **Semantics:** libcurl documents the `HOST:PORT:ADDRESS` override in [`CURLOPT_RESOLVE`](https://curl.se/libcurl/c/CURLOPT_RESOLVE.html).

```text
0x140001316 / file 0x716
48 8d 15 fb 7f 0a 00 33 c9 e8 9c 10 00 00 48 8b
0d 7d 46 0b 00 4c 8b c0 ba db 27 00 00 48 89 05
76 46 0b 00 e8 41 3e 00 00
```

### C02 — The response is expected to be an executable x64 DLL

- **Status:** Confirmed, level A.
- **Evidence:** `sub_1400015D0` checks `MZ`, `PE\0\0`, PE32+ magic `0x20B`, and DLL characteristic `0x2000`, starting at `0x1400015F1` / file `0x9F1`.

### C03 — S1 manually maps the response into its own memory

- **Status:** Confirmed, level A.
- **Function:** `sub_1400015D0`.
- **Sequence:** `VirtualAlloc` -> header/section copies -> relocations -> `LoadLibraryA`/`GetProcAddress` -> `VirtualProtect` -> `RtlAddFunctionTable` -> TLS callbacks -> DLL entry point.
- **Classification:** [MITRE T1620](https://attack.mitre.org/techniques/T1620/).

### C04 — The mapped DLL is executed

- **Status:** Confirmed, level A.
- **Evidence:** `WinMain` searches the mapped export table for `JNI_OnLoad` at `0x140001494–0x1400014C2`, clears RCX/RDX, and executes `call rax` at `0x1400014CF`.

```text
33 d2 33 c9 ff d0
```

S1 is not merely a passive updater.

### C05 — There is no expected hash or publisher gate

- **Status:** Confirmed, level A plus negative search.
- **Evidence:** S1 response bytes flow directly from downloader to PE checks, mapper, and export execution. S2 callback bytes flow through `qword_1802186E8/F0` to `sub_180052E50`.
- **Cross-check:** No `WinVerifyTrust`, certificate-chain import, payload allowlist, or publisher string in either IDB; both PE Security Directories are empty.
- **Reference:** Microsoft [`WinVerifyTrust`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust).
- **Limitation:** TLS authenticates the connection, not the stability or prior audit status of the server-selected payload.

### C06 — S2 is a Prestige injector/controller

- **Status:** Confirmed, level A.
- **Evidence:** Response filename `injector.dll`; PDB `Prestige-Injector\\x64\\DLL\\PrestigeInjector.pdb`; exports `JNI_OnLoad`/`DllEntryPoint`; Minecraft/manual-map UI strings; product-specific API paths; protected `.vm_sec` and `.vlizer` sections.

### C07 — S2 retrieves an authenticated third-stage payload

- **Status:** Confirmed, level A.
- **Function:** `sub_180087770`.
- **Evidence:** nlohmann/json constructs `{"token": ...}` for `/injectionDownload`; libcurl URL, POST body/length, write callback, and userdata are configured.
- **References:** [`CURLOPT_WRITEFUNCTION`](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html) and [`CURLOPT_WRITEDATA`](https://curl.se/libcurl/c/CURLOPT_WRITEDATA.html).

### C08 — Third-stage response bytes flow directly to the remote mapper

- **Status:** Confirmed, level A.
- **Chain:** `sub_180086DA0 -> sub_180097440 -> qword_1802186E8/F0 -> sub_18006E0B0 or sub_18006EF90 -> sub_180052E50`.
- **Transformations:** No archive extraction, decryption, expected hash, Authenticode, or publisher gate; the pointer/length pair reaches the PE consumer.

### C09 — S2 implements remote manual-map injection

- **Status:** Confirmed, level A.
- **Function:** `sub_180052E50`.
- **Imports:** `OpenProcess` at `0x180149318`, `VirtualAllocEx` at `0x180149270`, `WriteProcessMemory` at `0x180149228`, `ReadProcessMemory` at `0x180149278`, and `CreateRemoteThread` at `0x180149280`.
- **Semantics:** The function parses PE headers, sections, relocations, imports, and exception data, writes remote memory, and starts a remote thread.
- **References:** [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory), [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread), and [MITRE T1055](https://attack.mitre.org/techniques/T1055/).

### C10 — A second `LoadLibraryA` injection path exists

- **Status:** Confirmed, level A.
- **Function:** `sub_180044E70`.
- **Evidence:** It prepares a temporary DLL path, resolves remote `LoadLibraryA`, allocates/writes remote memory, and starts a remote thread. This is independent from C09.

### C11 — S2 contains targeted anti-debug/analysis blocking

- **Status:** Confirmed, level A.
- **Function:** `sub_18007C540`; `CheckRemoteDebuggerPresent` import at `0x180149368`.
- **Evidence:** Case-insensitive comparison against 30 analysis-process names covering IDA, Ghidra, x64dbg, WinDbg, Fiddler, mitmproxy, HTTP Toolkit, dnSpy, Cheat Engine, Scylla, DIE, API Monitor, and others.
- **Response:** Warning, restart current host with `--security-notice`, and `TerminateProcess(...,0x4EC)`.
- **Limitation:** Compatible with malware evasion and commercial cheat/anti-crack protection; not standalone RAT proof.

### C12 — S2 checks for VM/sandbox environments

- **Status:** Confirmed, level A.
- **Evidence:** CPUID hypervisor vendor, BIOS/baseboard registry fields, and strings for VMware, VBox, KVM, QEMU/TCG, Xen, Parallels, bhyve, ACRN, and others.
- **Classification:** [MITRE T1497.001](https://attack.mitre.org/techniques/T1497/001/).

### C13 — S2 collects a persistent device fingerprint

- **Status:** Confirmed, level A.
- **Function:** `sub_180055290`.
- **Fields:** `Win32_ComputerSystemProduct.UUID`, baseboard/BIOS serial, CPU `ProcessorId`, disk 0 serial, and `MachineGuid`.
- **Limitation:** Device fingerprinting is proven; credential theft is not implied.

### C14 — First-login password is SHA-256/hex encoded client-side

- **Status:** Confirmed, level A.
- **Flow:** `login_password -> sub_180084CD0 -> CryptoPP::SHA256 -> HashFilter -> HexEncoder -> StringSink -> /newFirstLogin JSON password`.
- **Addresses:** SHA-256 vtable `0x180084D83`; HexEncoder/StringSink `0x180084DFF–0x180084E30`; HashFilter `0x180084E5D`.
- **Format:** Uppercase, separator-free, 64-character hexadecimal digest. [Crypto++ HexEncoder API](https://cryptopp.com/docs/ref/class_hex_encoder.html).
- **Limitation:** Server storage and whether the digest is replayable cannot be established from the client.

### C15 — Official product statements acknowledge stealth behavior

- **Status:** Confirmed, level B; vendor statement.
- **Source:** The [official site](https://www.prestigeclient.vip/) 7 August 2026 changelog advertises early hooking, “zero-trace cleanup,” capture-invisible UI, and screenshare bypass.
- **Limitation:** Marketing copy is neither an independent audit nor proof/refutation of a RAT.

### C16 — Independent tools flag the exact outer loader

- **Status:** Confirmed, level B/C.
- **Source:** [Exact-hash Manalyzer report](https://manalyzer.org/report/4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08), including a reported 46/68 result.
- **Limitation:** An AV score does not identify a RAT family or prove exfiltration.

### C17 — The Reddit/Triage summary is vulnerable to process-attribution error

- **Status:** Confirmed, level B/D review.
- **Sources:** [Reddit post](https://www.reddit.com/r/minecraftclients/comments/1vpfkic/prestige_client_is_so_trash_bro/) and [exact-hash Triage task](https://tria.ge/260623-fqhjgsat5q/behavioral1).
- **Process tree:** `Prestige-Client.exe` PID 79 and `chrome.exe` PID 81 are sibling processes beneath `Explorer.EXE`; Chrome is not a child of Prestige.
- **Attribution:** The task summary aggregates 43 signatures across processes. Visible Prestige-specific signatures are `GetForegroundWindowSpam` and `SetWindowsHookEx`; task-wide browser/persistence labels cannot automatically be assigned to Prestige.
- **IDA cross-check:** The claimed Chrome-profile, service, RDP, Run-key, and COM-hijack implementations were not found in S1/S2.

## Unproven or refuted claims

These findings are limited to exact samples S1 and S2. They do not assert that a feature has never existed in any version, and they preserve the limitations created by virtualization and the missing third stage.

| ID | Claim | Result | Search/evidence context |
|---|---|---|---|
| N01 | Full RAT/C2 command loop | **Not proven** | No operator dispatcher, beacon/task loop, command IDs, remote shell, or separate C2 protocol |
| N02 | Browser cookie/password theft | **Not proven** | No `Login Data`, `Local State`, profile/LevelDB flow, DPAPI/CredRead/Vault imports, or network consumer |
| N03 | Headless Chrome debug theft | **Refuted for S2** | No application matches for `chrome.exe`, `--headless`, `remote-debugging-port`, `9222`, or incognito; the only `CreateProcessW` caller restarts the current host with `--security-notice` |
| N04 | Keylogger | **Not proven** | No `GetAsyncKeyState`/`SetWindowsHookEx` import; `GetKeyState` is used for UI modifiers, with no keystroke buffer/network flow |
| N05 | Clipboard theft | **Not proven** | `sub_18001FBD0/FD20` are ImGui UTF-8/UTF-16 clipboard adapters without network consumers |
| N06 | Screenshot/camera/microphone | **Not proven** | No `BitBlt`, `PrintWindow`, or media-capture chain; GDI xrefs rasterize a 32×32 icon and calculate DPI |
| N07 | Persistence | **Not proven** | No Run/RunOnce, service, scheduled-task, or startup implementation |
| N08 | Privilege escalation/driver | **Not proven** | No token-to-elevated-action, driver/service install, or UAC-bypass chain |
| N09 | Ransomware/destruction | **Not proven** | No file-tree encryption, ransom note, shadow-copy deletion, or related command chain |
| N10 | File archival/exfiltration | **Not proven** | No application ZIP/7z/archive creation or file-upload flow; cookie/multipart/upload strings belong to statically linked libcurl |
| N11 | `/injectorAccountInfo` sends ZIP/credentials | **Refuted for S2** | Request JSON contains only `token` and `challenge`; no file/archive pointer or multipart consumer |
| N12 | PowerShell execution | **Refuted for S2** | capa-matched `system()` callers build `start <URL>`; no PowerShell/cmd script chain |
| N13 | Credit-card/Luhn collection | **Refuted for S2** | Matches are MSVC `std::regex` parser internals with no card data or application caller |
| N14 | Geolocation collection | **Not proven** | capa label comes from broad `GetLocaleInfo(A/Ex)` logic; no city/country/GeoID collection or transmission |
| N15 | Plaintext registration password | **Refuted for S2** | C14 shows SHA-256/HexEncoder before the request field |
| N16 | Named advanced threat group/RAT family | **Not proven** | No family-specific config, C2, mutex, protocol, crypto, or code-similarity evidence |
| N17 | Third stage is clean or malicious | **Undetermined** | `/injectionDownload` requires a valid token; dummy token produced HTTP 400 with an empty body |

## Negative-search scope

IDA import queries returned no result in S1/S2 for:

```text
WinVerifyTrust, CryptUnprotectData, CredRead*, Vault*, GetAsyncKeyState,
SetWindowsHook*, BitBlt, PrintWindow, RegSetValue*, CreateService*,
OpenSCManager*, ChangeServiceConfig*
```

S2 contains `cookie`, `.onion`, multipart, and upload text inside statically linked libcurl error/documentation strings. Application xrefs lead to JSON API POSTs. “Not found” refers to import/string/xref coverage; it is not a mathematical proof that every virtualized instruction in `.vlizer` was recovered.

## Correct use of external sources

| Source | Supports | Does not support |
|---|---|---|
| Exact-hash Manalyzer | Sample identity and independent multi-engine warning | RAT family or exfiltration |
| Exact-hash Triage | Same executable and task-level activity | Assigning every task signature to the Prestige PID |
| Historical ANY.RUN | March 2026 continuity of executable controller delivery from the same API | August 2026 third stage or RAT conclusion |
| Historical Hybrid Analysis | Same-domain, anti-VM, and injection-lineage correlation | Replacement for exact-hash behavior |
| Official Prestige site/policy | Vendor claims about injection, cleanup, screenshare bypass, HWID, and SHA-256 | Independent security certification |
| Reddit/video | Origin of community allegations | Exact-sample behavior proof |
| MITRE/Microsoft/curl/Crypto++ | General technique/API semantics | Proof that the sample uses them; IDA supplies that proof |

## Safe reproducibility

These commands do not execute the samples:

```sh
sha256sum Prestige-Client.exe injectorDownload.bin
file Prestige-Client.exe injectorDownload.bin
objdump -h Prestige-Client.exe
objdump -h injectorDownload.bin
yara prestige_chain.yar Prestige-Client.exe
yara prestige_chain.yar injectorDownload.bin
```

Repository checks:

```sh
sha256sum -c SHA256SUMS
jq empty iocs.json
sh -n capture-third-stage.sh
```

The exact-hash YARA rule identifies only the two captured artifacts. The structural rule identifies the observed Prestige controller lineage through a combined PDB/API/section signature. A structural match is not proof of RAT behavior.

## Defensible public wording

Supported:

> The analyzed Prestige Client version executes unsigned, user-unverifiable PE payloads selected by a remote server. Its second stage can download and inject a further authenticated payload into Minecraft. Anti-analysis and hardware fingerprinting are also confirmed. This architecture is unsafe even if a particular final payload is benign, and the software should not be used.

Unsupported:

> Prestige is definitively a RAT, definitely steals passwords/cookies, belongs to a named advanced group, or owns every signature shown in the task-wide Triage summary.
