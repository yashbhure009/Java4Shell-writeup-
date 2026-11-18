# Java4Shell (CVE-2026-114938) — My Take

My write-up and hands-on verification of **Java4Shell**, a critical (CVSS 9.2) memory-corruption vulnerability in OpenJDK's hardware-accelerated Base64 decoder, disclosed by [Calif.io](https://calif.io/java4shell) on November 17, 2026.

This repo is **commentary and independent reproduction** of an already-public, already-patched vulnerability — not new research. All credit for discovering and weaponizing the bug belongs to Quang Luong and Jenish Rakholiya at Calif.io.

## Contents

| File | Description |
|---|---|
| [`writeup.md`](./writeup.md) | Full write-up: root-cause explanation in my own words, why exploitation is non-trivial despite the high CVSS, my own PoC run, and takeaways |
| [`Base64Trigger.java`](./Base64Trigger.java) | Calif.io's published, safe, self-contained PoC — decodes malformed input into an oversized 4096-byte buffer so no real memory is corrupted; just demonstrates the out-of-bounds masked write |

## TL;DR

OpenJDK's JIT-compiled Base64 decoder uses a hand-written AVX-512 (`VMOVDQU8`) fast path for the final bytes of input. A malformed trailing `=` character causes an internal length calculation to underflow, which turns the SIMD store's byte-mask into "write all 64 bytes" instead of a few — overflowing the destination buffer before the JVM rejects the input with `IllegalArgumentException`.

- **Trigger:** 64× `A` + one trailing `=` (128× `A` + `=` on OpenJDK 17)
- **Affected:** OpenJDK 17.0.6+ and all major distributions built on it (Corretto, Temurin, Zulu, Liberica, SapMachine, Oracle JDK/JRE, GraalVM, etc.)
- **Hardware requirement:** x86-64 CPU with AVX-512 VBMI (Intel Ice Lake/Sapphire Rapids/Emerald Rapids/Granite Rapids Xeon; AMD Zen 4+). **ARM64 is not affected.**
- **Impact demonstrated by Calif.io:** pre-auth RCE in Keycloak, Jira, Confluence, Artifactory, Jenkins, PingFederate; post-auth RCE in Kafka, Solr, Elasticsearch, Gerrit, Spinnaker
- **Fix:** patch to a corrected OpenJDK/Oracle build. If you can't patch immediately: `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=2` (x86-64 only)

See [`writeup.md`](./writeup.md) for the full breakdown.

## Running the PoC

```bash
javac Base64Trigger.java
java Base64Trigger
```

On a vulnerable JDK + AVX-512 VBMI–capable CPU, expect:

```
rejected=true changed=62 first=50 last=111
REPRODUCED
```

On a patched JDK, an unaffected CPU, or ARM64, expect `changed=0` and `NOT REPRODUCED` — the decode is rejected before any out-of-bounds write occurs. Check CPU eligibility with:

```bash
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
```

All four flags must be present for the vulnerable code path to be hardware-eligible.

## References

- [Java4Shell: Write once, RCE everywhere](https://calif.io/java4shell) — original disclosure, Calif.io
- [OpenJDK security advisory, 2026-11-17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- [Oracle security alert](https://www.oracle.com/security-alerts/cspunov2026.html)
- [NYT coverage](https://www.nytimes.com/2026/11/17/us/politics/ai-security-bug-java.html)

## Author

**Yash Balaji Bhure** ([@yashbhure009](https://github.com/yashbhure009)) — Computer Engineering, MMCOE Pune · [LinkedIn](https://linkedin.com/in/yashbhure)

## Disclosure note

This repo intentionally stops where Calif.io's public write-up stops: root cause, general exploitation technique, and a safe PoC. No undisclosed, product-specific exploit chains are included or reproduced here.
