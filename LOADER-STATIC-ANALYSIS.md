# `Prestige-Client.exe` static analysis

**Date:** 16 August 2026<br>
**Method:** IDA static reverse engineering, local PE tooling, and CAPEv2 static-only submission<br>
**Execution:** None

## Conclusion

**Risk: high — do not run.** The executable downloads a second-stage PE/DLL from a pinned HTTPS endpoint, manually maps it without writing a conventional DLL to disk, and calls the downloaded module's `JNI_OnLoad` export. It has no Authenticode signature and does not verify an expected hash or publisher for the received payload.

Static analysis of the shell alone cannot establish whether every server response is a cheat module, stealer, RAT, or another payload. It does establish an unsafe stager/loader trust model in which the remote server can change the code executed on a user's machine.

## Identity

- Type: PE32+, Windows GUI, AMD64
- Size: 767,488 bytes
- MD5: `d101c0eeb89ce736928a061f100337de`
- SHA-1: `feb0a5a4280eef41b7fa96be26e4698eb30804a2`
- SHA-256: `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08`
- Import hash: `c48ec9fabbe14329942c8cc66b3ae7bd`
- ssdeep: `12288:LghUjKHgMt5PsrSuf+v+4o0+W6YLqjlOHnfR7oBmTzipavj/FYi8l5FUnI:vjKHgkKWv+4o0j6YLqjlOHnfR7okTz48`
- PE timestamp: 26 May 2026 11:03:24 UTC
- Authenticode: none; empty Security Directory
- Overlay: none

## IDA evidence

1. `WinMain` at `0x1400012D0` initializes libcurl and uses `CURLOPT_RESOLVE` to map `api.prestigeclient.vip:443` directly to `172.67.137.182`.
2. `sub_140001A50` posts an empty body to `https://api.prestigeclient.vip/injectorDownload`. Response bytes are accumulated in memory and retained only for curl success and HTTP 200–299.
3. `sub_1400015D0` is an x64 reflective/manual PE loader:
   - checks `MZ`, `PE\0\0`, PE32+, and DLL flags;
   - allocates image memory through `VirtualAlloc`;
   - copies sections and applies relocations;
   - resolves imports through `LoadLibraryA`/`GetProcAddress`;
   - applies protections through `VirtualProtect`;
   - processes the exception table, TLS callbacks, and DLL entry point.
4. `WinMain` searches the mapped export table for `JNI_OnLoad` and calls the result with both arguments set to zero.
5. Invalid network/payload state produces `Prestige failed to start. Please check your connection and try again.` and terminates the process.

No hash/publisher gate occurs between response receipt and execution.

## Context and negative findings

- The PE statically links libcurl; generic HTTP/FTP/SMB/LDAP/TLS strings are library content, not independent application behaviors.
- `IsDebuggerPresent` references occur in MSVC runtime diagnostics and are not the primary risk finding.
- No registry import or explicit persistence mechanism was found in the outer shell.
- `.text` entropy is 6.425; there is no obvious high-entropy packer section or overlay. Staging provides the main concealment boundary.

## Indicators

- Domain: `api.prestigeclient.vip`
- URL: `https://api.prestigeclient.vip/injectorDownload`
- Pinned IP: `172.67.137.182`
- SHA-256: `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08`
- Mapped export: `JNI_OnLoad`

The IP may be shared Cloudflare infrastructure and must not be classified by itself.

## CAPEv2 status

Static-only tasks were accepted and their sample identities/hashes were recorded, but the processing worker did not produce a report. The last tasks remained pending with no machine or guest assignment. No dynamic sample execution occurred, and this repository does not claim a CAPE behavior report.
