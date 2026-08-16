# Prestige `injector.dll` static technical analysis

**Date:** 16 August 2026<br>
**Method:** IDA, local PE tooling, capa/FLOSS, and CAPEv2 static-only submission<br>
**Execution:** None

## Sample identity

| Field | Value |
|---|---|
| Source | `POST https://api.prestigeclient.vip/injectorDownload` |
| HTTP filename | `injector.dll` |
| Size | 5,105,566 bytes |
| MD5 | `af658bbb582714a733d212e60c0e17c7` |
| SHA-1 | `d0f2618ca857d1e803e1ca0aeaf13584a8df80e9` |
| SHA-256 | `1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad` |
| Type | PE32+ AMD64 DLL |
| Timestamp | 7 August 2026 15:45:15 UTC |
| Authenticode | None |
| Exports | `JNI_OnLoad`, `DllEntryPoint` |
| PDB | `C:\\Users\\vikkn\\Documents\\Prestige Software Development\\Prestige-Injector\\x64\\DLL\\PrestigeInjector.pdb` |

Capture archive SHA-256: `5ccc313babf89e0efdd9540d8e73e01a66d839cae0b6177d8e73c15cd835108b`.

## PE protection layout

Image base is `0x180000000`, image size approximately `0x4E8000`. IDA identified 5,163 functions and 9,225 strings.

| Section | Size | Permissions | Interpretation |
|---|---:|---|---|
| `.text` | `0x148000` | RX | Conventional code |
| `.vm_sec` | `0x0C200` | RW | VM/protection data marker |
| `.vlizer` | `0x2AD99E` | RX | Approximately 2.8 MB of virtualized/protected code |

The short clear-text `JNI_OnLoad` stub resolves both of the following mappings and then transfers control into `.vlizer`:

```text
api.prestigeclient.vip:443:172.67.137.182
api.prestigeclient.vip:80:172.67.137.182
```

## Anti-analysis and VM evasion

Confirmed controls include:

- `CheckRemoteDebuggerPresent`;
- CPUID `0x40000000` hypervisor-vendor inspection;
- BIOS/baseboard registry fields including `SystemManufacturer`, `SystemProductName`, `BaseBoardManufacturer`, and `BaseBoardProduct`;
- strings for VMware, VirtualBox, KVM, QEMU/TCG, Xen, Parallels, bhyve, ACRN, QNX, OpenBSD VMM, HAXM, and Jailhouse;
- case-insensitive comparison against 30 running analysis-tool names.

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

On detection, `sub_18007C460` displays a security-compatibility warning, relaunches the current host with `--security-notice`, and terminates the main process with exit code `0x4EC`. This may prevent ordinary sandbox runs from reaching payload retrieval.

These controls are compatible with sophisticated malware evasion but also with commercial cheat/anti-reversing protection. They increase risk and impede auditability; they do not independently prove a RAT.

## Product API surface

The DLL statically links libcurl and nlohmann/json. Application-specific paths include:

| Path | Statically observed JSON fields |
|---|---|
| `/prestigeDownload` | `token`, `version` |
| `/injectionDownload` | `token` |
| `/login` | `token`, `challenge` |
| `/newModLogin` | `token`, `challenge` |
| `/newFirstLogin` | `email`, `password`, `hwid`, `challenge` |
| `/injectorAccountInfo` | `token`, `challenge` |
| `/injectorBetaToggle` | `token`, `challenge`, `active` |

### `/injectionDownload` data flow

`sub_180087770`:

1. obtains the session token;
2. creates `{"token": ...}` with nlohmann/json;
3. serializes the object;
4. configures libcurl URL, POST body/length, JSON header, response callback, and userdata;
5. uses `sub_180086DA0` to append response chunks unchanged to memory;
6. stores successful buffer address and length in `qword_1802186E8/F0` through `sub_180097440`;
7. passes that pair through `sub_18006E0B0` or `sub_18006EF90` directly to manual mapper `sub_180052E50`.

No expected payload hash, Authenticode publisher check, public-key signature, archive extraction, or content transformation was found between the response and mapper.

A dummy-token request from a private Firejail environment returned HTTP 400 with an empty body. No brute force or account creation was attempted. The authenticated third stage remains unavailable.

## Password data flow

The `login_password` UI buffer at `byte_180218700` enters `sub_180084CD0`, which constructs Crypto++ SHA-256, `HashFilter`, `HexEncoder`, and `StringSink<std::string>` objects. Only the resulting value reaches the `/newFirstLogin` JSON `password` field.

```text
0x180084D83  48 8D 05 DE 9E 0C 00 48 89 44 24 70
              CryptoPP::SHA256 vtable

0x180084DFF  48 8D 05 42 AD 0C 00 48 89 07 48 8D 05 A8 AE 0C 00
              StringSink/HexEncoder vtables and constructor path

0x180084E4F  45 33 C9 4C 8B C0 48 8D 54 24 70 48 8B CE E8 1E 50 02 00
              HashFilter construction
```

The encoder parameters produce a separator-free 64-character uppercase hexadecimal SHA-256 digest. This matches the [official policy](https://www.prestigeclient.vip/tos) and [Crypto++ API](https://cryptopp.com/docs/ref/class_hex_encoder.html). It does not establish secure server-side storage or prevent replay of the digest.

## Hardware fingerprinting

`sub_180055290` combines:

- `Win32_ComputerSystemProduct.UUID`
- `Win32_BaseBoard.SerialNumber`
- `Win32_BIOS.SerialNumber`
- `Win32_Processor.ProcessorId`
- `Win32_DiskDrive.SerialNumber` for disk index 0
- `HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid`

This proves persistent device fingerprinting used in account/HWID flows. It does not by itself prove credential theft.

## Process injection

The primary chain uses:

```text
OpenProcess
  |- VirtualAllocEx
  |- WriteProcessMemory / ReadProcessMemory
  `- CreateRemoteThread
```

- `sub_180052E50` validates and manually maps a PE into the target, including sections, relocations, imports, and exception data.
- `sub_180044E70` implements a separate temporary-DLL/remote-`LoadLibraryA` fallback.
- UI text explicitly describes opening a Minecraft process, manual mapping, and removing/cleaning payload material from the game.

This behavior is invasive and naturally suspicious to EDR, while also matching the advertised injector function. It is process injection, not standalone proof of a RAT.

## RAT/stealer hypothesis

No direct application-level evidence was found for:

- Chromium `Login Data`, `Local State`, browser profile, or LevelDB access;
- `CryptUnprotectData`, CredRead, or Vault APIs;
- `GetAsyncKeyState`, `SetWindowsHookEx`, or a keystroke buffer/network path;
- `BitBlt`, `PrintWindow`, camera, or microphone capture;
- Run keys, services, scheduled tasks, or command-based persistence;
- an operator command loop or distinct RAT C2 protocol.

Clipboard helpers `sub_18001FBD0` and `sub_18001FD20` are ImGui copy/paste adapters and do not connect to a network consumer in the recovered call graph.

### Validation of automated labels

capa 9.4.0 independently matched process injection, reflective loading, WMI, process discovery, and anti-VM capabilities. Potentially misleading labels were manually reviewed:

- “PowerShell” matches are two `system("start " + URL)` UI paths, not PowerShell.
- `GetKeyState` is used for UI modifier state; there is no async-state/hook/keystroke-buffer chain.
- Clipboard functions are ImGui integration.
- GDI code rasterizes a 32×32 icon and handles DPI; it is not screen capture.
- Credit-card/Luhn matches are MSVC `std::regex` internals without application callers.
- Geolocation comes from broad locale-API matching without collection/transmission of location data.

FLOSS 3.1.1 recovered seven stack strings, six tight strings, and one numeric decoded string but no additional IOC or RAT/stealer string. This is not exhaustive because `.vlizer` is virtualized.

## Critical opcode witnesses

Image base `0x180000000`:

```text
0x180097545  0f8447010000488b4c24204885c90f84310100004889058811180048890d89111800
              response pointer/length -> qword_1802186E8/F0

0x18006E0F2  c744245400000000488b05e7a51a0048894424488b05e4a51a0089442450
              globals -> local pointer/length pair

0x18006E1D8  e843acfeff4c8d442448488b17e8664cfeff
              lea r8,[rsp+48h] -> call sub_180052E50
```

Full evidence context is in [`REPORT.md`](REPORT.md) and [`EVIDENCE-LEDGER.md`](EVIDENCE-LEDGER.md).

## Verdict

The captured second stage is a heavily protected Minecraft injector/controller with extensive anti-VM and anti-debug controls. Static evidence does not establish that this DLL itself is a RAT or browser stealer. It does establish that the DLL downloads an unavailable third-stage payload and can inject it into Minecraft without a user-verifiable payload hash or signature.

The overall chain is therefore unsafe even without overclaiming the missing RAT evidence.

## CAPEv2 status

Static-only tasks were accepted and hashes recorded, but remained pending with `machine_id=null` and `analysis_started_on=null`. No dynamic task was opened and the sample was not executed.
