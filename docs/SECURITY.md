# Bootlegger: Security Model & Paranoid Threat Assessment

> *"Být paranoidní nestačí." — Bootlegger Design Maxim*

This document formalizes the threat landscape, adversarial assumptions, and defense mechanisms implemented in Bootlegger.

---

## 1. Threat Landscape & Adversary Profiles

Bootlegger is engineered to withstand adversaries beyond standard opportunistic attackers:

| Adversary | Capabilities | Bootlegger Defense |
|---|---|---|
| **Forensic Investigator** | Performs static file analysis, byte-level diffing, string searches, magic byte matching, and archive format validation. | **Zero-Footprint Format:** No `BOOTLEG` magic bytes or recognizable headers. Output is a 100% compliant POSIX / GNU TAR archive. Standard tools (`tar -tf`, `tar -xf`, `7-zip`, `file`) confirm valid archive structure and extract all decoy files with 100% bitwise integrity. |
| **Statistical Analyst** | Runs Shannon entropy tests, sliding-window entropy graphs, and Chi-square ($\chi^2$) distribution analyses to detect hidden cryptographic noise. | **Dilution Accountant:** Enforces strict dilution budgets ($\le 3\%$). Spreads shards across block padding so high-entropy clusters are dispersed and normalized by surrounding cover data. |
| **Active Tamperer / Interceptor** | Man-in-the-middle or malicious inspector who alters, inspects, selectively extracts, or re-packs files to install honeypots. | **Tripwire Anti-Tamper:** Every cover file's path, size, BLAKE3 content hash, order, and timestamp is bound to AEAD Additional Authenticated Data (AAD). Modifying even 1 bit in 1 file prevents decryption, rendering the container permanently inert. |
| **Coercive Interrogator (Rubber-Hose Cryptanalysis)** | Threatens or legally compels the user to provide decryption keys under duress. | **Plausible Deniability:** The archive is a fully functional, legitimate archive of source code, documents, or media. The user can honestly claim it is an ordinary backup archive. No examiner can prove an encrypted payload exists without the passphrase. |

---

## 2. Core Security Pillars

### 2.1. Zero Static Signatures
Traditional steganographic utilities often betray their existence by writing a signature (e.g. `STEG`, `MAGIC`, or container version numbers). Bootlegger contains **zero static markers**:
* No recognizable byte patterns at fixed offsets.
* No salt stored in plaintext. The 16-byte cryptographic salt is deterministically derived from the carrier structure itself.
* The length of the secret payload is encrypted using a ChaCha20 PRNG stream mask.

### 2.2. The Dilution Principle ("Buď tak akorát nebo víc, ale nikdy ne míň")
Just as micro-dosed alcohol in a solution is undetectable by taste or visual inspection, secret data must be micro-dosed into a carrier.
* Storing a 50 MB secret inside a 100 KB document collection is reckless and mathematically provable as an anomaly.
* Bootlegger's `DilutionAccountant` refuses to pack if the secret exceeds the safe stealth budget. If a user tries to pack into insufficient cover, Bootlegger halts and calculates the exact number of additional decoy files required.

### 2.3. Tripwire Integrity Pinning
When `--tripwire` is enabled during packaging:
1. Bootlegger calculates a Merkle / BLAKE3 root of all decoy files.
2. The root is passed directly into ChaCha20-Poly1305 as Additional Authenticated Data (AAD).
3. Poly1305 validates the MAC tag over both ciphertext and AAD.
4. If any decoy file is modified, deleted, renamed, or re-ordered, the calculated AAD will not match, causing AEAD decryption to fail.
5. Even if the attacker extracts the archive, tampers with a file, and re-packs with standard `tar` (which zeroes out slack space), the secret is irrevocably lost to them.

### 2.4. Memory Hygiene & Anti-Forensics
* **Key Zeroization:** All derived session keys (`enc_key`, `prng_seed`, and Argon2 master key material) implement the `Zeroize` trait and are wiped from memory immediately upon completion or scope exit.
* **No Temporary Files:** Key derivation and encryption/decryption operate strictly in-memory.

---

## 3. Operational Security Best Practices for Users

To maximize plausible deniability in practice:

1. **Choose Plausible Cover Files:**
   * Use real, realistic document sets, open-source project codebases, or log archives.
   * Do not create synthetic or empty files with random names (e.g., `file_001.txt`). An examiner reading the archive should find legitimate, meaningful content.
2. **Use Natural Size Distributions:**
   * Pick cover files that naturally have non-512-byte sizes (e.g., text files, source code, CSVs, markdown docs). This maximizes natural block slack capacity.
3. **Always Run `bootlegger check` Before Packaging:**
   * Confirm that your cover set provides ample stealth budget.
4. **Use Strong Passphrases:**
   * Argon2id provides state-of-the-art resistance against GPU/ASIC cracking, but a passphrase should still have sufficient entropy (e.g., 4–6 random words or 20+ characters).
