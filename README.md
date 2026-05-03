Readme · MD
Copy

# RSA Cryptography in Cloud Computing
 
**COSC370 — Cloud Computing | Spring 2026**  
**EJ Knights & Lei Tapungot | Dr. Lu**
 
Enterprise-grade RSA cryptography implementation in Java 25, covering the full lifecycle of RSA in cloud security — from mathematical foundations through hybrid encryption, real-world attack demonstrations, and post-quantum migration.
 
---
 
## Project Structure
 
```
src/main/java/
├── com/rsa/cloud/                         # EJ Knights
│   ├── Main.java                          # Demo runner — all 10 demonstrations
│   ├── core/
│   │   ├── RSAKeyGenerator.java           # RSA keypair generation (2048/3072/4096-bit, CRT)
│   │   ├── OAEPEncryptionService.java     # RSA-OAEP encryption/decryption (SHA-256/384/512)
│   │   ├── PSSSignatureService.java       # RSA-PSS signing + PKCS#1 v1.5 comparison
│   │   └── KeySerializationService.java   # PEM, PKCS#8, PKCS#12 serialization
│   ├── pki/
│   │   ├── X509CertificateService.java    # X.509 v3 cert generation + PKIX chain validation
│   │   └── JWTService.java                # JWT RS256/PS256 from scratch (no library)
│   ├── model/
│   │   └── RSAKeySpec.java                # Immutable record wrapping an RSA keypair
│   └── util/
│       └── SecurityProvider.java          # BouncyCastle JCE provider registration
│
└── com/crypto/demo/                       # Lei Tapungot
    ├── crypto/
    │   └── EnvelopeCrypto.java            # Envelope encrypt/decrypt (AES-GCM + RSA-OAEP)
    ├── hybrid/
    │   ├── EnvelopeEncryptionService.java # Envelope service
    │   └── HybridEncryptionService.java   # Full hybrid engine + multi-recipient wrapping
    ├── attacks/
    │   ├── AttackDemoSuite.java           # Runs all three attacks in sequence
    │   ├── BleichenbacherDemo.java        # PKCS#1 v1.5 padding oracle + OAEP immunity
    │   ├── TimingAttackDemo.java          # RSA decryption timing variance measurement
    │   └── RocaDemo.java                  # CVE-2017-15361 fingerprint detection
    ├── benchmark/
    │   ├── BenchmarkRunner.java           # JMH runner — full benchmark suite
    │   ├── CryptoBenchmark.java           # JMH @Benchmark methods (RSA vs ML-KEM)
    │   └── SimpleBenchmark.java           # Plain Java benchmark (no JMH processor needed)
    └── util/
        └── CryptoConfig.java              # BouncyCastle provider registration
```
 
---
 
## Team Responsibilities
 
### EJ Knights — RSA Core
- RSA mathematical core and key generation engine
- OAEP encryption service
- PEM / PKCS#8 / PKCS#12 serialization via BouncyCastle
- PSS signature service and tamper-detection demonstration
- X.509 certificate generation and PKIX chain validation
- JWT RS256 / PS256 from scratch (no external JWT library)
- Final report
### Lei Tapungot — Hybrid, Attacks & Post-Quantum
- Hybrid encryption engine (AES-256-GCM + RSA-OAEP)
- Multi-recipient key wrapping
- AWS KMS envelope encryption simulation
- Attack demonstration suite (Bleichenbacher, timing, ROCA)
- Post-quantum engine (ML-KEM-768, ML-DSA-65)
- JMH benchmark suite (RSA vs ML-KEM comparison)
- Documentation
---
 
## Technology Stack
 
| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Java LTS | 25 |
| Build | Apache Maven | 3.9+ |
| Crypto provider | BouncyCastle | 1.78.1 |
| Post-quantum | JDK native (JEP 496/497) | Java 25 built-in |
| Benchmarking | JMH | 1.37 |
| Testing | JUnit 5 | 5.10.2 |
 
---
 
## Build & Run
 
```bash
# Compile all source files
mvn clean compile
 
# EJ's RSA core demo (10 demonstrations)
mvn exec:java -Dexec.mainClass=com.rsa.cloud.Main
 
# Lei's attack suite
mvn exec:java -Dexec.mainClass=com.crypto.demo.attacks.AttackDemoSuite
 
# Lei's benchmark (quick, ~1 minute)
mvn exec:java -Dexec.mainClass=com.crypto.demo.benchmark.SimpleBenchmark
 
# Lei's JMH benchmarks (rigorous, ~5-10 minutes)
mvn exec:java -Dexec.mainClass=com.crypto.demo.benchmark.BenchmarkRunner
 
# Tests
mvn test
```
 
---
 
## What This Project Demonstrates
 
### RSA Core (EJ)
 
**Key Generation** — 2048 and 4096-bit keypairs with CRT enforced. CRT gives ~4× faster private-key operations by splitting the exponentiation into two half-size problems. Validates prime distance per NIST SP 800-56B.
 
**OAEP Encryption** — RSA-OAEP with SHA-256/384/512. Demonstrates the 190-byte plaintext ceiling for RSA-2048 and why hybrid encryption is required. Every call produces a different ciphertext — IND-CCA2 secure.
 
**Key Serialization** — Round-trip in PEM (RFC 7468), encrypted PKCS#8 (AES-256-CBC, PBKDF2 100k iterations), and PKCS#12 (.p12) using `DERBMPString` per RFC 7292.
 
**PSS Signatures** — RSA-PSS with configurable salt length. 1-bit tamper detection demonstrated live. Side-by-side comparison with deterministic PKCS#1 v1.5.
 
**X.509 Certificates** — Self-signed CA and CA-signed end-entity certificates with full v3 extensions. PKIX chain validation using `JcaX509CertificateHolder` to preserve ASN.1 DN encoding.
 
**JWT RS256 / PS256** — JWT signing and verification from scratch. RS256 is deterministic; PS256 is randomized. PS256 required by OpenID FAPI 2.0.
 
---
 
### Hybrid Encryption (Lei)
 
AES-256-GCM encrypts the actual data. RSA-OAEP wraps only the 32-byte AES key. Supports multi-recipient wrapping: one AES encryption, N RSA-wrapped copies. Mirrors the AWS KMS GenerateDataKey envelope encryption pattern.
 
---
 
### Attack Demonstrations (Lei)
 
**Bleichenbacher (1998)** — PKCS#1 v1.5 leaks 1 bit per query. ~1M adaptive queries recovers full plaintext. OAEP is immune: 0 valid responses for all malleated ciphertexts.
 
**Timing Side-Channel (Kocher 1996)** — RSA decryption time varies with private key bit pattern. Nanosecond variance measured live. BouncyCastle applies RSA blinding automatically.
 
**ROCA — CVE-2017-15361** — Infineon TPM restricted prime space to ~2^35 candidates. Fingerprint detectable in milliseconds without factoring. Java SecureRandom keys are not vulnerable.
 
---
 
### Post-Quantum Migration (Lei)
 
Java 25 native APIs — no external library:
 
```java
KEM.getInstance("ML-KEM-768")        // JEP 496 — replaces RSA-OAEP for key exchange
Signature.getInstance("ML-DSA-65")   // JEP 497 — replaces RSA-PSS for signatures
```
 
Hybrid handshake: X25519 ECDH + ML-KEM-768 combined via HKDF-SHA256. If either is broken, the other still protects.
 
---
 
### Benchmark Results (Lei)
 
| Operation | RSA-4096 | ML-KEM-768 | Speedup |
|-----------|----------|------------|---------|
| Key generation | ~300–500 ms | ~0.5–2 ms | ~200–500× |
| Encrypt / Encapsulate | ~2–5 ms | ~0.3–1 ms | ~5–10× |
| Decrypt / Decapsulate | ~2–8 ms | ~0.3–1 ms | ~5–10× |
| Ciphertext size | 512 bytes | 1088 bytes | — |
| Quantum-safe | No | Yes (FIPS 203) | — |
 
---
 
## RSA Mathematical Foundation
 
```
n = p × q              modulus (public)
φ(n) = (p−1)(q−1)     Euler's totient (secret)
e = 65537              public exponent
d = e⁻¹ mod φ(n)      private exponent
 
Encrypt: C = Mᵉ mod n      Decrypt: M = Cᵈ mod n
 
CRT decryption (~4× faster):
  m₁ = C^dP mod p   m₂ = C^dQ mod q
  h  = qInv × (m₁ − m₂) mod p
  M  = m₂ + h × q
```
 
---
 
## References
 
1. Rivest, Shamir & Adleman (1978). *A Method for Obtaining Digital Signatures.* CACM 21(2).
2. Bleichenbacher (1998). *Chosen Ciphertext Attacks Against PKCS #1.* CRYPTO 1998.
3. Kocher (1996). *Timing Attacks on Implementations of RSA.* CRYPTO 1996.
4. Brumley & Boneh (2003). *Remote Timing Attacks Are Practical.* USENIX Security.
5. Nemec et al. (2017). *ROCA — Return of Coppersmith's Attack.* ACM CCS 2017.
6. Bellare & Rogaway (1995). *Optimal Asymmetric Encryption.* EUROCRYPT 1994.
7. Shor (1997). *Polynomial-Time Algorithms for Prime Factorization.* SIAM.
8. NIST FIPS 203 (2024). *ML-KEM Standard (Kyber).*
9. NIST SP 800-56B Rev. 2 (2019). *Recommendation for RSA Key-Establishment.*
10. RFC 8017 (2016). *PKCS #1: RSA Cryptography Specifications v2.2.*
11. RFC 8446 (2018). *The Transport Layer Security (TLS) Protocol Version 1.3.*
12. Wang (2024). *JEP 496 — ML-KEM.* openjdk.org/jeps/496
13. Wang (2024). *JEP 497 — ML-DSA.* openjdk.org/jeps/497
14. Oracle (2026). *Java Cryptography Architecture — JDK 25.*
15. AWS (2024). *KMS Cryptographic Details Whitepaper.*
 
