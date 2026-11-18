# Java4Shell (CVE-2026-114938) — My Take

Independent write-up and hands-on verification of **Java4Shell**, a memory-corruption vulnerability in OpenJDK's AVX-512 Base64 decoder, disclosed by [Calif.io](https://calif.io/java4shell/) on 17 November 2026.

**This repo is commentary and independent reproduction of an already-public, already-patched vulnerability — not new research.** All credit for discovering and weaponizing the bug belongs to Quang Luong and Jenish Rakholiya at Calif.io.

> Status: public, patched 2026-11-17 13:00 PT. Calif is still withholding the per-product exploit chains.

---

## Contents

| File | Description |
|---|---|
| `writeup.md` | Full write-up: root-cause explanation in my own words, why exploitation is non-trivial despite the score, my own PoC run, takeaways |
| `Base64Trigger.java` | Calif's published, safe, self-contained PoC — decodes malformed input into an oversized 4096-byte buffer so no real memory is corrupted; just demonstrates the out-of-bounds masked write |
| `Java4ShellExploit.java` | My own attempt at a chain: warm → spray → trigger → disclose. Reliably proves the overflow and dumps its exact byte pattern; heap adjacency is probabilistic and often not reached. **Read "What this file actually shows" before you judge it.** |

---

## TL;DR

OpenJDK's JIT-compiled Base64 decoder uses a hand-written AVX-512 (`VMOVDQU8` / `evmovdqub`) fast path for the final bytes of input. A malformed trailing `=` makes an internal length calculation underflow, so `bzhiq(-1, -1)` yields an all-ones store mask — the SIMD store writes a full 64 bytes instead of a few. With a 65-byte input (`64 × A + "="`), the routine has already written 48 valid bytes, so 62 bytes land past the end of the 50-byte result array *before* Java rejects the input with `IllegalArgumentException`.

- **Trigger:** `64 × "A" + "="` (on OpenJDK 17: `128 × "A" + "="`)
- **Affected:** OpenJDK 17.0.6+ and every distribution built on it — Corretto, Temurin, Microsoft Build of OpenJDK, Zulu, Liberica, SapMachine, Red Hat OpenJDK, Oracle JDK/JRE, Oracle GraalVM. Oracle-listed vulnerable builds: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3
- **Hardware requirement:** x86-64 CPU with AVX-512 VBMI (Intel Ice Lake / Sapphire Rapids / Emerald Rapids / Granite Rapids Xeon; AMD Zen 4+). **ARM64 is not affected.**
- **Scoring:** CVSS 4.0 **9.2 CRITICAL** per Calif. Oracle scores it **8.1 High** under CVSS v3.1. Both numbers are in the wild; pick the one your vuln-management tooling believes in.
- **Impact demonstrated by Calif.io:** pre-auth RCE in Keycloak, Jira, Confluence, Artifactory, Jenkins, PingFederate; post-auth RCE in Kafka, Solr, Elasticsearch, Gerrit, Spinnaker. Plus a client-side variant from samczsun: a Java program that opens TLS to a malicious server is compromisable with no listener at all.
- **Fix:** patch to a corrected OpenJDK/Oracle build. If you cannot patch today: `-XX:-UseBASE64Intrinsics`, or `-XX:UseAVX=2` on x86-64 only (ARM JVMs reject the flag and won't start).

**Oracle CVSS 8.1 vs Calif 9.2:** the gap is real, not a typo in either place. v3.1 discounts the hardware precondition and the no-universal-exploit reality; v4.0 does not. Plan as if it's 9.2.

See `writeup.md` for the full breakdown, and the [original disclosure](https://calif.io/java4shell/) for the authoritative version.

---

## Am I exposed?

Two independent conditions, both required:

**1. Is the CPU eligible?** On Linux:

```bash
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
```

All four flags must appear. Empty output = not hardware-eligible.

**2. Does attacker-controlled data reach `java.util.Base64`?** The usual routes are `Authorization: Basic`, JWT/SAML assertions, file upload metadata, and any API field that decodes base64. Basic auth alone covers a depressing number of products.

Check your runtime version against the affected list. Anything ≥ 17.0.6 below the fixed builds is in scope.

---

## Running the PoC

```bash
javac Base64Trigger.java
java Base64Trigger
```

On a vulnerable JDK on AVX-512 VBMI hardware, expect:

```
rejected=true changed=62 first=50 last=111
REPRODUCED
```

On a patched JDK, an ineligible CPU, or ARM64, expect `changed=0` and `NOT REPRODUCED` — the decode is rejected before any out-of-bounds write occurs.

To confirm you're actually exercising the intrinsic rather than a Java fallback, run once with `-XX:-UseBASE64Intrinsics` and watch it flip to `NOT REPRODUCED`.

---

## Running my chain attempt

```bash
javac Java4ShellExploit.java
java Java4ShellExploit            # safe mode (default): overflow proof + byte-pattern dump
java Java4ShellExploit --tight    # real escape: overflow leaves the buffer and smashes a neighbour's header
```

Safe mode always completes. Tight mode is the actual primitive and **can crash the VM** — that is expected behaviour, not a bug in the harness. Retry.

Expected safe-mode output on eligible hardware:

```
 Overflow verified: 62 bytes past offset 48
 +00: 00 00 ... (48 bytes of zeros / register leftovers)
 +48: 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a 9a
```

### What this file actually shows

Reliably: the overflow is real, its length is 62, and its byte pattern is deterministic. Byte 0 is fully attacker-controlled (the final decoded sextet), byte 1 is 4-bit controlled, bytes 2–47 are vector-register leftovers, and bytes 48–63 are **always `0x9a`**. That is the entire write primitive: a fixed-value spill whose only free variable is where it lands.

Unreliably: adjacency. The spray interleaves `buffer → victim` inside a TLAB and checks whether a victim's header got hit. In practice the header is what dies — mark word, klass, and length all get zeroed. And the length field lands at overflow offset ~12–18, i.e. inside the zero region, so a hit usually sets `length = 0` rather than something useful. `0x9a9a9a9a` as a signed int is negative, so the `0x9a` tail alone doesn't help either.

Consequence: **this file is a heap-adjacency probe, not a working leak.** It gets you to the same cliff edge Calif's write-up describes, then stops. Turning a hit into a reader/writer pair requires the app-specific grooming in their article.

### Known limits of my version

- Single-threaded. Real targets have per-request worker threads with separate TLABs, which is exactly what the "spray and pray" in the original solves and my local version doesn't have to.
- No TLAB-exit control, no region arithmetic, no G1 modelling.
- No repair path — smashed headers stay smashed.
- Trigger length is picked from the runtime version (`64` on 21+, `128` on 17). Hardcoding it is the most common way people conclude the bug "doesn't work".
- No network layer. No TCP ACK pacing, no request parking, no partial-body release.

If you want a chain that actually leaks, read the [Calif write-up](https://calif.io/java4shell/) and the [Datadog analysis](https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/) instead of mine.

---

## Mitigation

1. **Patch.** Fixed builds shipped 2026-11-17. This is the only real answer.
2. **Interim:** `-XX:-UseBASE64Intrinsics`. Costs some decode throughput, kills the bug outright.
3. **Alternative interim:** `-XX:UseAVX=2` — x86-64 only.
4. **Partial, not a mitigation:** nginx `proxy_request_buffering on` (default) defeats grooming profiles that need streamed partial bodies. It does *not* stop chains that fire from a single complete request, and it stops applying entirely after a WebSocket upgrade.
5. **Audit:** if you run AVX-512 hosts and any of the listed products, assume exposure until you can prove the build is fixed.

---

## References

- [Java4Shell: Write once, RCE everywhere](https://calif.io/java4shell/) — original disclosure, Calif.io
- [OpenJDK security advisory, 2026-11-17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- [Oracle Critical Patch Update advisory, November 2026](https://www.oracle.com/security-alerts/cspunov2026.html)
- [Red Hat: RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018) · [CVE page](https://access.redhat.com/security/cve/cve-2026-114938)
- [Datadog Security Labs — technical analysis](https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/)
- [Qualys — find, mitigate, patch](https://blog.qualys.com/vulnerabilities-threat-research/2026/11/17/how-to-find-mitigate-and-patch-the-critical-java4shell-flaw-cve-2026-114938-now)
- [Wiz — everything you need to know](https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk)
- [Horizon3 — analysis](https://horizon3.ai/attack-research/vulnerabilities/cve-2026-114938/)
- [The Hacker News coverage](https://thehackernews.com/2026/11/java4shell-cve-2026-114938-enables-pre.html)
- [NYT story](https://www.nytimes.com/2026/11/17/us/politics/ai-security-bug-java.html)
- [ikow/java4shell-poc](https://github.com/ikow/java4shell-poc) — another independent PoC, plus Suricata/Sigma/ModSecurity rules

---

## Author

Yash Balaji Bhure ([@yashbhure009](https://github.com/yashbhure009)) — Computer Engineering, MMCOE Pune · [LinkedIn](https://www.linkedin.com/in/yashbhure009)

## Disclosure note

This repo intentionally stops where Calif.io's public write-up stops: root cause, general exploitation technique, and a safe PoC. No undisclosed, product-specific exploit chains are included or reproduced here.

## License

MIT for my own code and prose. Calif's PoC is reproduced with attribution.
