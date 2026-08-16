# Prestige Client injector investigation

**Publication date:** 16 August 2026<br>
**Scope:** `Prestige-Client.exe` and the `injector.dll` captured from the official API on 16 August 2026<br>
**Primary SHA-256:** `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08`

## Executive conclusion

The analyzed Prestige Client chain is unsafe.

The outer executable obtains an unsigned DLL from a private API and executes it in memory without pinning an expected hash, Authenticode signer, or publisher. The captured DLL is a protected Minecraft injector/controller. It authenticates to the API, obtains a further PE payload, and can inject that response into Minecraft through two independent injection implementations.

This is not, by itself, proof that the two captured files are a full-featured RAT. Direct browser-credential theft, keylogging, screen capture, persistence, ransomware, file exfiltration, and an operator command loop were not found in either exact hash. The authenticated third stage was unavailable, so neither “definitely a RAT” nor “clean” is a defensible conclusion.

What is proven is a remotely mutable arbitrary-code delivery chain. The server—not the user—selects the final executable code. The user cannot verify it before execution. That confirmed architecture is enough to recommend that nobody run the software.

## Methodology and evidence standard

Neither PE was executed locally. Both samples were examined in separate IDA databases using PE-header inspection, imports, strings, cross-references, Hex-Rays output, raw instruction bytes, and end-to-end tracking of network response buffers to their consumers. Additional non-executing triage used capa 9.4.0 and FLOSS 3.1.1. CAPEv2 received static-only submissions; no guest was assigned and no dynamic behavior report was produced.

Evidence levels used in this report:

- **A — direct:** exact-sample bytes, PE structures, disassembly/decompilation, xrefs, and uninterrupted data flow.
- **B — correlated:** independent report for the same hash or historical samples using the same infrastructure.
- **C — automated:** antivirus, capa, or sandbox label that requires manual validation.
- **D — allegation:** social-media or video claim not demonstrated on the exact samples.

Every material claim is indexed in [`EVIDENCE-LEDGER.md`](EVIDENCE-LEDGER.md).

## Sample identities

### Outer loader

| Property | Value |
|---|---|
| Filename | `Prestige-Client.exe` |
| Type | PE32+, Windows GUI, AMD64 |
| Size | 767,488 bytes |
| MD5 | `d101c0eeb89ce736928a061f100337de` |
| SHA-1 | `feb0a5a4280eef41b7fa96be26e4698eb30804a2` |
| SHA-256 | `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08` |
| Import hash | `c48ec9fabbe14329942c8cc66b3ae7bd` |
| PE timestamp | 26 May 2026 11:03:24 UTC |
| Authenticode | None; empty Security Directory |

### Captured controller

| Property | Value |
|---|---|
| Response filename | `injector.dll` |
| Type | PE32+ DLL, AMD64 |
| Size | 5,105,566 bytes |
| MD5 | `af658bbb582714a733d212e60c0e17c7` |
| SHA-1 | `d0f2618ca857d1e803e1ca0aeaf13584a8df80e9` |
| SHA-256 | `1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad` |
| PE timestamp | 7 August 2026 15:45:15 UTC |
| Authenticode | None |
| PDB trace | `Prestige-Injector\\x64\\DLL\\PrestigeInjector.pdb` |
| Protection markers | Large executable `.vlizer`; writable `.vm_sec` |

An independent [Manalyzer report for the exact outer-loader hash](https://manalyzer.org/report/4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08) reports a 46/68 multi-engine result. Antivirus labels do not prove a RAT family and are not used as the basis of the behavioral conclusions below.

## Stage one: remote DLL retrieval and in-memory execution

IDA identifies `WinMain` at `0x1400012D0`. It initializes libcurl and installs the following `CURLOPT_RESOLVE` entry:

```text
api.prestigeclient.vip:443:172.67.137.182
```

The base URL is `https://api.prestigeclient.vip`; downloader function `sub_140001A50` appends `/injectorDownload`. It sends an empty JSON POST and retains a response only after a successful curl result and HTTP status in the 200–299 range.

The response is not treated as ordinary data. `sub_1400015D0` checks:

- `MZ` (`0x5A4D`)
- `PE\0\0` (`0x4550`)
- PE32+ optional-header magic (`0x20B`)
- the `IMAGE_FILE_DLL` characteristic (`0x2000`)

It then implements a complete reflective/manual loader:

1. Allocate image memory with `VirtualAlloc`.
2. Copy headers and sections.
3. Apply base relocations.
4. Resolve imports through `LoadLibraryA` and `GetProcAddress`.
5. Apply section protections using `VirtualProtect`.
6. Register the exception table through `RtlAddFunctionTable`.
7. Invoke TLS callbacks and the DLL entry point.
8. Search the mapped export table for `JNI_OnLoad`.
9. Execute the export as `JNI_OnLoad(0, 0)`.

This behavior is consistent with [MITRE ATT&CK T1620 — Reflective Code Loading](https://attack.mitre.org/techniques/T1620/).

### Raw evidence: pinned resolution

At VA `0x140001316`, file offset `0x716`:

```text
48 8d 15 fb 7f 0a 00 33 c9 e8 9c 10 00 00 48 8b
0d 7d 46 0b 00 4c 8b c0 ba db 27 00 00 48 89 05
76 46 0b 00 e8 41 3e 00 00
```

The code takes the embedded host mapping and uses option `0x27DB`/10203, documented by libcurl as [`CURLOPT_RESOLVE`](https://curl.se/libcurl/c/CURLOPT_RESOLVE.html).

### Raw evidence: PE/DLL gate

At VA `0x1400015F1`, file offset `0x9F1`:

```text
48 83 fa 40 ... b8 4d 5a 00 00 66 39 01 ...
41 81 3c 0e 50 45 00 00 ... b8 0b 02 00 00 ...
b8 00 20 00 00 66 41 85 44 0e 16
```

The constants implement the minimum header-length, `MZ`, `PE\0\0`, PE32+, and DLL-characteristic checks.

### Raw evidence: mapped export execution

At `0x140001494–0x1400014CF`:

```text
8b 0b 48 8d 15 53 7f 0a 00 48 03 ce e8 ab c7 08 00
...
41 0f b7 0c 7e 41 8b 04 8f 48 03 c6 ... 33 d2 33 c9 ff d0
```

The export name is compared with `JNI_OnLoad`; RCX and RDX are cleared and `call rax` transfers execution to the mapped payload.

## Missing trust boundary

The network response follows this path:

```text
HTTP response
  -> PE-structure checks
  -> manual mapper
  -> mapped entry point and JNI_OnLoad
```

There is no expected SHA-256 allowlist, Authenticode gate, or pinned publisher between receipt and execution. `WinVerifyTrust` and certificate-chain APIs are not imported, both samples have empty PE Security Directories, and IDA xrefs show no equivalent custom verification gate. Microsoft documents [`WinVerifyTrust`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust) as the Windows trust-provider interface for verifying signed objects.

TLS protects transport to the selected server. It does not prove that the payload is stable, previously audited, or identical for every account.

## Stage two: controller and third-stage injection

The captured response is attributable to Prestige rather than a generic library:

- PDB trace names `Prestige-Injector`.
- Exports include `JNI_OnLoad` and `DllEntryPoint`.
- UI strings describe opening a Minecraft process and manual-map injection.
- Application-specific Prestige API paths are present.
- `.vm_sec` and `.vlizer` sections indicate heavy virtualization/protection.

Function `sub_180087770` creates a JSON body containing the account token and posts it to `/injectionDownload`. The receive callback `sub_180086DA0` appends each libcurl chunk to a growing buffer. The response then follows this data flow:

```text
sub_180086DA0
  -> sub_180097440
  -> qword_1802186E8 / qword_1802186F0
  -> sub_18006E0B0 or sub_18006EF90
  -> sub_180052E50 remote manual mapper
```

No archive extraction, decryption, hash allowlist, Authenticode, or publisher check appears in this path. The same pointer/length pair reaches the PE consumer.

### Raw evidence: response callback and userdata

At VA `0x1800879A9`, file offset `0x86DA9`:

```text
e8 02 6d 05 00 4c 8d 05 eb f3 ff ff ba 2b 4e 00 00
48 8b 0d bf 13 19 00 e8 ea 6c 05 00 4c 8d 45 b0 ba
11 27 00 00 48 8b 0d aa 13 19 00 e8 d5 6c 05 00
```

Options `0x4E2B`/20011 and `0x2711`/10001 are [`CURLOPT_WRITEFUNCTION`](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html) and [`CURLOPT_WRITEDATA`](https://curl.se/libcurl/c/CURLOPT_WRITEDATA.html).

### Raw evidence: pointer and length storage

At VA `0x180097545`, file offset `0x96945`:

```text
0f 84 47 01 00 00 48 8b 4c 24 20 48 85 c9 0f 84
31 01 00 00 48 89 05 88 11 18 00 48 89 0d 89 11
18 00 48 85 db 74 56 8b
```

The two RIP-relative stores place the response address and size into `qword_1802186E8/F0`.

### Raw evidence: remote mapper call

At VA `0x18006E1D8`, file offset `0x6D5D8`:

```text
e8 43 ac fe ff 4c 8d 44 24 48 48 8b 17 e8 66 4c
fe ff 48 8b 0f 84 c0 0f 85 a7 01 00 00 ff 15 65
b0 0d 00 48 8d 0d 5e a7
```

`lea r8,[rsp+48h]` prepares the pointer/length pair as the third argument before the call to `sub_180052E50`.

The mapper uses `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory`, and `CreateRemoteThread`. Microsoft documents the relevant semantics for [`VirtualAllocEx`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), [`WriteProcessMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory), and [`CreateRemoteThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread). This is consistent with [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/).

A separate fallback function, `sub_180044E70`, writes a temporary DLL path and starts remote `LoadLibraryA`. It is independent of the manual mapper.

## Anti-analysis behavior

`sub_18007C540` combines `CheckRemoteDebuggerPresent` with a case-insensitive process-name blacklist. The 30 exact names cover IDA/IDA64, Ghidra, x64dbg/x32dbg, WinDbg, Fiddler, mitmproxy, HTTP Toolkit, dnSpy, Cheat Engine, Scylla, Detect It Easy, API Monitor, and other analysis tools.

On detection, it shows a “Security compatibility issue,” restarts the current host with `--security-notice`, and calls `TerminateProcess(..., 0x4EC)`.

VM checks include CPUID hypervisor vendors and BIOS/baseboard registry strings associated with VMware, VirtualBox, KVM, QEMU/TCG, Xen, Parallels, bhyve, ACRN, and others. This is consistent with [MITRE ATT&CK T1497.001](https://attack.mitre.org/techniques/T1497/001/). These techniques are compatible with malware evasion but can also appear in commercial cheat/anti-crack products; they are not standalone proof of a RAT.

## Hardware fingerprinting and password handling

`sub_180055290` collects:

- `Win32_ComputerSystemProduct.UUID`
- baseboard and BIOS serials
- CPU `ProcessorId`
- disk 0 serial
- Windows `MachineGuid`

The values support account/HWID enforcement. They establish persistent device fingerprinting, not browser credential theft.

The first-login password follows this exact client-side path:

```text
login_password
  -> sub_180084CD0
  -> CryptoPP::SHA256
  -> HashFilter
  -> HexEncoder
  -> StringSink
  -> /newFirstLogin JSON password field
```

The encoder produces an uppercase, separator-free 64-character hexadecimal digest. This refutes the allegation that this exact DLL sends the registration password as plaintext. It does not reveal how the server stores or reuses that digest.

## Claims that were tested and not established

| Claim | Result on the two exact samples | Basis |
|---|---|---|
| Full RAT/C2 command loop | Not proven | No command dispatcher, task loop, remote shell, command IDs, or distinct operator protocol |
| Browser credential theft | Not proven | No `Login Data`/`Local State` profile chain, DPAPI/CredRead/Vault imports, or exfiltration xref |
| Headless Chrome theft | Refuted for S2 | No `chrome.exe`, `--headless`, `remote-debugging-port`, `9222`, or incognito application strings |
| Keylogger | Not proven | No `GetAsyncKeyState` or `SetWindowsHookEx`; `GetKeyState` serves UI modifier state |
| Clipboard theft | Not proven | Clipboard xrefs are ImGui UTF-8/UTF-16 adapters with no network consumer |
| Screen/camera/microphone capture | Not proven | No `BitBlt`, `PrintWindow`, or media-capture chain |
| Persistence | Not proven | No Run key, service, scheduled task, or startup implementation |
| Privilege escalation/driver | Not proven | No elevated-action, service/driver-install, or UAC-bypass chain |
| Ransomware/destruction | Not proven | No file-tree encryption, ransom note, or shadow-copy deletion chain |
| File archival/exfiltration | Not proven | No application archive creation or file-upload data flow |
| ZIP upload via `/injectorAccountInfo` | Refuted for S2 | Request JSON contains only token and challenge |
| PowerShell execution | Refuted for S2 | capa matches are `system("start " + URL)` UI paths, not PowerShell |
| Credit-card/Luhn collection | Refuted for S2 | Matches are MSVC `std::regex` parser internals without an application caller |
| Specific advanced threat group | Not proven | No family config, C2, mutex, protocol, or code-similarity evidence |
| Third stage is clean or malicious | Undetermined | Valid account token required; exact payload absent |

## Review of the Reddit/Triage allegation

The [Reddit post](https://www.reddit.com/r/minecraftclients/comments/1vpfkic/prestige_client_is_so_trash_bro/) links an [exact-hash Triage task](https://tria.ge/260623-fqhjgsat5q/behavioral1). Its process tree places `Prestige-Client.exe` PID 79 and `chrome.exe` PID 81 at the same depth under `Explorer.EXE`. They are siblings; Chrome is not a child of Prestige.

The task-level summary aggregates 43 signatures across all processes. The visible process-specific Prestige signatures are `GetForegroundWindowSpam` and `SetWindowsHookEx`. Browser-profile, service, RDP, and persistence labels from the aggregate summary cannot be assigned to the Prestige PID without process-level evidence. IDA did not reveal the claimed Chrome-profile, Run-key, service, RDP, or COM-hijack implementations in S1 or S2.

This correction does not make the loader safe. It prevents weak sandbox attribution from obscuring the stronger, directly proven remote-loading and injection chain.

## Indicators

```text
SHA256  4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08
MD5     d101c0eeb89ce736928a061f100337de
SHA256  1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad
MD5     af658bbb582714a733d212e60c0e17c7
Domain  api.prestigeclient.vip
URL     https://api.prestigeclient.vip/injectorDownload
Path    /injectionDownload
Path    /prestigeDownload
IP      172.67.137.182
Export  JNI_OnLoad
```

The IP is shared Cloudflare infrastructure and is not independently malicious. Prefer exact hashes, hostname, full paths, and behavioral detections.

## Guidance for previous users

- Do not run the client again; quarantine existing copies.
- Search EDR, proxy, DNS, and firewall history for the hostname and paths.
- Do not rely only on filesystem scanning; stage two runs without an ordinary disk-backed load.
- As a precaution, revoke browser sessions, change important passwords from a clean device, and enable MFA. This is precautionary because the final payload is unknown—not because browser theft was proven.
- Preserve memory and EDR evidence and seek professional incident response for organizational systems.

## Limitations and next evidence threshold

CAPEv2 static tasks remained pending without a machine assignment or analysis start. No CAPE behavioral report is claimed. A conclusive RAT finding requires the authenticated `/injectionDownload` response and direct evidence of at least one RAT capability: command execution, surveillance capture, credential access, file transfer, persistence, or an operator C2 protocol.

A clean response in one sandbox run would not prove that previous or targeted users received the same payload. Server-selected delivery makes the uncertainty inherent.

## Sources

- [Exact-hash Manalyzer report](https://manalyzer.org/report/4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08)
- [MITRE ATT&CK T1620 — Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
- [MITRE ATT&CK T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1497.001 — Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497/001/)
- [Prestige Client official site](https://www.prestigeclient.vip/)
- [Prestige Terms and Privacy Policy](https://www.prestigeclient.vip/tos)
- [Crypto++ HexEncoder API](https://cryptopp.com/docs/ref/class_hex_encoder.html)
- [Historical March 2026 ANY.RUN record](https://any.run/report/e88dc150d4e79efd2186355036b9548ac29a8063d04c7a83457e1b0a9c398d29/f11f44b5-7569-4dcd-a86c-88f4be4bb736)
- [Historical dropped DLL on Hybrid Analysis](https://hybrid-analysis.com/sample/5bff5030f0d4cc53cde783876f92ea3e09465d9ca59ce8ae0a7bb82d870ec045/69c82afe8a7dbe1cd60d3bcc)
- [Reddit source post](https://www.reddit.com/r/minecraftclients/comments/1vpfkic/prestige_client_is_so_trash_bro/)
- [Exact-hash Triage task linked from Reddit](https://tria.ge/260623-fqhjgsat5q/behavioral1)

## Shareable summary

> The analyzed Prestige Client executable downloads an unsigned DLL and manually maps it without verifying an expected hash or publisher. The captured controller then obtains a token-protected third-stage PE and can inject that response into Minecraft. The two captured files do not contain proven RAT/stealer/persistence behavior, so this report does not claim “definitely a RAT.” The remotely replaceable, unverifiable code-delivery architecture is nevertheless proven and is sufficient reason not to use the software.
