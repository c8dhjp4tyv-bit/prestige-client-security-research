# Prestige Client security research

Evidence-based static security analysis of the Prestige Client loader and injector chain.

## Bottom line

The captured chain must not be considered safe.

The outer executable downloads an unsigned PE/DLL from the official Prestige API, manually maps it into memory, and executes its `JNI_OnLoad` export without checking an expected hash, Authenticode signature, or publisher. The captured controller DLL then requests an authenticated third-stage PE and passes the response directly to code that injects it into Minecraft.

The two captured samples do **not** contain proven browser theft, keylogging, screen capture, persistence, ransomware, or a RAT command loop. The authenticated third stage was not obtained, so this repository does not claim that Prestige is definitively a RAT. It proves something narrower but still serious: an unsigned, remotely replaceable arbitrary-code delivery and process-injection chain that users cannot independently verify.

## Analyzed samples

| Role | SHA-256 | Size |
|---|---|---:|
| Outer loader, `Prestige-Client.exe` | `4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08` | 767,488 bytes |
| Captured controller, `injector.dll` | `1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad` | 5,105,566 bytes |

Neither sample has an Authenticode signature. Suspicious binaries are intentionally excluded from this repository.

## Confirmed findings

- Pinned HTTPS request to `api.prestigeclient.vip:443:172.67.137.182`.
- `POST /injectorDownload` returns a PE32+ DLL.
- The outer loader validates only PE structure, then performs reflective/manual mapping.
- It resolves imports, applies relocations and protections, invokes TLS/entry-point code, finds `JNI_OnLoad`, and executes it as `JNI_OnLoad(0, 0)`.
- No expected payload hash, Authenticode, or publisher verification exists before execution.
- The controller uses `/injectionDownload` with an account token to obtain another payload.
- The response pointer and length flow directly into a remote manual mapper.
- Two Minecraft injection paths exist: remote manual mapping and a `LoadLibraryA` fallback.
- Dedicated anti-debug, anti-VM, and analysis-tool process blacklisting are present.
- Persistent hardware fingerprinting uses WMI fields and `MachineGuid`.
- The first-login password is passed through Crypto++ SHA-256 and hexadecimal encoding before entering the JSON request; the claim that this exact DLL sends that password in plaintext is false.

## Not proven on the captured samples

- RAT command-and-control loop
- Browser cookie or password theft
- Keylogging or clipboard theft
- Screenshot, camera, or microphone capture
- Persistence or privilege escalation
- File archival/exfiltration
- Ransomware or destructive behavior
- Attribution to a specific malware family or advanced threat group

Absence of those behaviors in the two captured files does not establish that the unavailable third stage is clean.

## Repository contents

- [`REPORT.md`](REPORT.md) — publishable investigation and technical conclusions
- [`EVIDENCE-LEDGER.md`](EVIDENCE-LEDGER.md) — claim-by-claim evidence, addresses, file offsets, limitations, and source quality
- [`LOADER-STATIC-ANALYSIS.md`](LOADER-STATIC-ANALYSIS.md) — outer executable analysis
- [`INJECTOR-STATIC-ANALYSIS.md`](INJECTOR-STATIC-ANALYSIS.md) — captured controller analysis
- [`iocs.json`](iocs.json) — machine-readable sample identities and network indicators
- [`prestige_chain.yar`](prestige_chain.yar) — exact-hash and structural detection rules
- [`capture-third-stage.sh`](capture-third-stage.sh) — non-executing Whonix capture helper; token is read without placing it on the command line
- [`SHA256SUMS`](SHA256SUMS) — integrity manifest for published artifacts

## Evidence policy

Exact-sample bytes, PE structures, IDA disassembly/decompilation, cross-references, and uninterrupted data flow are treated as primary evidence. Public sandbox and antivirus labels are correlation only. Social-media statements are recorded as claims, never as proof.

The public Triage task linked from Reddit contains Chrome and Prestige as sibling processes under Explorer. Task-wide browser and persistence signatures therefore cannot automatically be attributed to the Prestige PID.

## Safe verification

Do not run the samples on a personal or production Windows system.

```sh
sha256sum -c SHA256SUMS
jq empty iocs.json
sh -n capture-third-stage.sh
```

The observed IP is Cloudflare/shared reverse-proxy infrastructure. Do not classify or block the IP by itself; combine exact hashes, hostname, paths, and behavior.

## Responsible wording

Supported:

> The analyzed Prestige Client chain downloads unsigned and unpinned PE payloads, executes them in memory, and can inject a server-selected third-stage PE into Minecraft. This remotely mutable trust model is unsafe and the software should not be used.

Unsupported without the missing third stage:

> Prestige is definitively a RAT, definitely steals browser credentials, or belongs to a named advanced threat group.
