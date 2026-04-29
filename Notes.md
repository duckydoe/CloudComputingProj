# RSA — Cloud Computing Study Notes

---

## RSA Overview

- **RSA** = Rivest-Shamir-Adleman (1977) — oldest, most deployed asymmetric cryptosystem
- Uses a **key pair** → public key (shared freely) + private key (kept secret)
- Anything encrypted with the public key can **only** be decrypted with the private key
- Solves the **key distribution problem** — no need to share a secret before communicating
- Used for: encryption, digital signatures, key exchange, identity verification

---

## The Math

- Security is based on the **Integer Factorization Problem** — multiplying two large primes is easy; reversing it is computationally infeasible
- Choose two large primes: **P** and **Q**
- Compute **N = P × Q** → the modulus, this is public
- Compute **φ(N) = (P−1)(Q−1)** → Euler's Totient
- Choose **E = 65537** → public exponent (standard choice, prime, fast)
- Compute **D** = modular inverse of E mod φ(N) → the private exponent
- **Public key** = (N, E) | **Private key** = (N, D) | P and Q are destroyed after
- **Encryption:** C = Mᴱ mod N | **Decryption:** M = Cᴰ mod N
- **Signing:** S = Mᴰ mod N | **Verification:** M = Sᴱ mod N
- ⚠️ Raw/Textbook RSA is **never used in production** — no randomness, same input always gives same output

---

## Key Sizes & Security Levels

| Key Size | Security Equivalent | Status |
|----------|---------------------|--------|
| RSA-512 | ~56-bit | **BROKEN** — factored in 1999 |
| RSA-1024 | ~80-bit | **INSECURE** — do not use |
| RSA-2048 | ~112-bit | ✅ Minimum standard, secure through ~2030 |
| RSA-3072 | ~128-bit | Recommended if data lifetime exceeds 5 years |
| RSA-4096 | ~140-bit | High-security / CA use — 4–8× slower than 2048 |

- NIST mandates **RSA-2048 minimum** for current systems
- RSA-4096 is used for Certificate Authorities and keys with very long lifetimes
- For performance-sensitive cloud workloads, consider **ECDSA P-256** (equivalent to RSA-3072, far smaller and faster)

---

## Padding Schemes — Critical Layer

> Raw RSA is deterministic and insecure. Padding adds randomness and structure.

### PKCS#1 v1.5
- Legacy standard from 1993, still widely deployed in TLS and email (S/MIME)
- Vulnerable to **Bleichenbacher's padding oracle attack (1998)** — avoid for new encryption
- Still acceptable for signatures in legacy systems — but PSS is preferred

### OAEP — Optimal Asymmetric Encryption Padding
- Current standard for RSA **encryption**
- Uses a mask generation function (MGF1 + SHA-256 or SHA-512) to randomize output
- Identical plaintexts produce **different ciphertexts** every time (semantic security)
- Required by AWS KMS, Azure Key Vault, GCP Cloud KMS
- RSA-2048 with OAEP-SHA256 can encrypt **at most ~190 bytes** — why hybrid encryption exists

### PSS — Probabilistic Signature Scheme
- Current standard for RSA **signatures**
- Uses a random salt — same message signed twice gives different signatures
- **Required by TLS 1.3** (PKCS#1 v1.5 signatures are banned in TLS 1.3)
- Configure salt length = hash output length (e.g. 32 bytes for SHA-256)

### Padding Quick Reference

| Use Case | Use This | Avoid |
|----------|----------|-------|
| Encrypting data | OAEP (SHA-256 or SHA-512) | Textbook RSA, PKCS#1 v1.5 |
| Signing data | PSS (SHA-256 or SHA-512) | PKCS#1 v1.5 if avoidable |
| TLS 1.3 | PSS required by spec | PKCS#1 v1.5 banned |

---

## Hybrid Encryption — How RSA Actually Works in the Cloud

> RSA alone can only encrypt ~190 bytes and is far too slow for bulk data. The solution is **hybrid encryption** — used by every major cloud provider.

### Sender Side
1. Generate a random **256-bit AES session key**
2. Encrypt the actual data with **AES-256-GCM** using that key
3. Encrypt the AES key with the recipient's **RSA public key (OAEP)**
4. Transmit: encrypted data + RSA-wrapped AES key + GCM auth tag + IV

### Receiver Side
1. Decrypt the wrapped AES key using your **RSA private key**
2. Use the recovered AES key to decrypt the data with **AES-256-GCM**
3. GCM auth tag automatically detects any tampering

- **AWS KMS envelope encryption** works exactly this way — the RSA key lives in the HSM, it never touches your data directly
- Common pairings: **RSA-OAEP + AES-256-GCM** (cloud standard), **RSA-OAEP + ChaCha20-Poly1305** (mobile/IoT)

---

## RSA in Major Cloud Platforms

### AWS KMS
- Supports RSA-2048, 3072, 4096
- Encryption: `RSAES_OAEP_SHA_256` (recommended), `RSAES_OAEP_SHA_1`
- Signing: `RSASSA_PSS_SHA_256/384/512` and `RSASSA_PKCS1_V1_5` variants
- Keys stored in **FIPS 140-2 Level 3 HSMs** — private key never leaves
- ~$1/month per key + $0.03 per 10,000 API calls

### Azure Key Vault
- RSA 2048, 3072, 4096 — software or HSM-backed tiers
- Uses **JWA names**: RS256 (PKCS#1 v1.5), PS256 (PSS) — maps to JWT/JWK standards
- Managed HSM = single-tenant FIPS 140-2 Level 3 with customer-controlled keys

### GCP Cloud KMS
- Algorithm names are explicit: `RSA_DECRYPT_OAEP_2048_SHA256`, `RSA_SIGN_PSS_4096_SHA512`, etc.
- **External Key Manager (EKM)**: keep RSA private key on-premises — GCP workloads still use it with full audit logs
- **Key Access Justifications**: require explicit, logged reason for every key usage

### HashiCorp Vault (Transit Engine)
- Provides RSA as a service — works on-prem or cloud
- Auto-rotation: old versions kept for decryption, new version used for all new operations
- Vault itself can be sealed/unsealed using an RSA key from AWS/Azure/GCP KMS

---

## RSA in TLS/HTTPS

| Feature | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|
| RSA key exchange | Allowed (static) | **Removed** — forward secrecy required |
| RSA for auth | RSA cert signatures | RSA-PSS only |
| Padding for auth | PKCS#1 v1.5 or PSS | **PSS required**, PKCS#1 v1.5 banned |
| Forward secrecy | Optional | **Mandatory** |

- TLS 1.2 RSA key exchange = stolen private key can decrypt **all past recorded sessions**
- TLS 1.3 uses **ephemeral keys** — past sessions are safe even if private key is later compromised
- Cloud CDNs (Cloudflare, CloudFront, Fastly) support **dual-cert deployment**: ECDSA for modern clients, RSA for legacy — same domain
- Let's Encrypt, AWS ACM, Azure Certificate Service all issue free RSA-2048 or ECDSA P-256 certs

---

## Digital Signatures in the Cloud

### What a Signature Proves
- **Authentication** — signer holds the private key
- **Integrity** — 1-bit change in data invalidates the signature
- **Non-repudiation** — signer cannot deny having signed

### Signing Use Cases

| Use Case | What's Signed | Scheme |
|----------|---------------|--------|
| JWT (RS256) | JSON payload | RSASSA-PKCS1-v1_5 SHA-256 |
| JWT (PS256) | JSON payload | RSASSA-PSS SHA-256 (preferred) |
| Container image signing | Docker image digest | RSA-PSS or ECDSA |
| SAML assertions | XML document | RSA-SHA256 (enterprise SSO) |
| Lambda code signing | Deployment package hash | RSA-PSS via AWS Signer |
| TLS certificates | Public key + subject | RSA-PSS (TLS 1.3) |

- **AWS Signer**: managed code signing, key in KMS, signing enforced at Lambda runtime
- Always **hash first, then sign** — RSA-PSS signs a hash (SHA-256), never the raw message

---

## Key Lifecycle Management

### Generation
- Always use a **CSPRNG** (cryptographically secure random number generator)
- Generate inside the HSM where possible — private key material never exported
- Standard public exponent: **e = 65537** (prime, fast exponentiation, universally used)

### Storage
- Never store private keys in code, env variables, or plain config files
- Cloud-native: use KMS — access via IAM/RBAC, key bytes never leave the HSM
- PEM files: Base64-encoded, encrypt at rest, restrict permissions (`chmod 600`)
- ⚠️ A private key in an unencrypted file on a cloud instance is only as secure as that instance

### Rotation
- Common policy: rotate operational keys every **1–2 years**
- Keep old versions active for decryption, use new version for all new operations
- Compromised key = **immediate revocation** + CRL/OCSP update (rotation alone is not enough)
- AWS KMS auto-rotation creates new key material annually automatically

### Key Formats

| Format | Extension | Used In |
|--------|-----------|---------|
| PEM | .pem | Linux, cloud CLIs, OpenSSL — most common |
| DER | .der / .cer | Java, IoT, Windows |
| PKCS#12 | .p12 / .pfx | Windows, client certificate auth |
| JWK | .json | OAuth2, OIDC, JWT — cloud API native |
| PKCS#8 | .key | Encrypted private key container |

---

## Known RSA Attacks

| Attack | Target | Mitigation |
|--------|--------|------------|
| Integer factorization (GNFS) | Small keys | Use 2048+ bit keys |
| Bleichenbacher oracle (1998) | PKCS#1 v1.5 encryption | Use OAEP; constant-time decryption |
| Timing side-channel | Private key operations | Blinding (built into OpenSSL, Go, Java) |
| Common modulus attack | Shared N with different E | Never reuse modulus between key pairs |
| Low-exponent attack | e=3 without padding | Use e=65537; always use OAEP/PSS |
| ROCA (CVE-2017-15361) | Infineon chip-generated keys | Patch firmware; regenerate affected keys |
| Wiener's attack | Small private exponent D | Enforced correct by all standard keygen tools |
| Shor's Algorithm (quantum) | All RSA key sizes | Migrate to post-quantum (see below) |

> **ROCA** was a real-world disaster — Infineon chips had a flawed key generation algorithm making keys far easier to factor. Hundreds of millions of devices affected, including Estonian national ID cards and YubiKeys.

---

## Post-Quantum Cryptography — The RSA Successor

### Why It Matters
- **Shor's Algorithm (1994)** proves a large enough quantum computer can factor RSA in hours
- No such computer exists yet — estimates range from **2030–2040+**
- **Harvest now, decrypt later**: adversaries may be storing RSA-encrypted traffic today to decrypt once quantum computers arrive

### NIST PQC Standards (Finalized 2024)

| Algorithm | Type | Replaces |
|-----------|------|----------|
| ML-KEM (Kyber) | Key encapsulation | RSA encryption / key wrapping |
| ML-DSA (Dilithium) | Digital signatures | RSA-PSS signatures |
| FN-DSA (FALCON) | Compact signatures | RSA signing in constrained environments |
| SLH-DSA (SPHINCS+) | Hash-based signatures | RSA signing — most conservative option |

### Current Best Practice — Hybrid Mode
- Combine classical RSA/ECDH with a post-quantum algorithm in the **same handshake**
- If either is broken, the other still protects you
- Already deployed: **X25519 + ML-KEM-768** in Google Chrome, Cloudflare, AWS SDK

### Migration Checklist
- [ ] Inventory all RSA usages: TLS certs, JWTs, signing keys, KMS keys
- [ ] Upgrade TLS to 1.3 now (immediate win, enables future PQ integration)
- [ ] Prioritize data with >10 year sensitivity (healthcare, government, financial)
- [ ] Enable hybrid PQ-TLS in test environments with AWS SDK or OpenSSL 3.x

---

## Key Numbers to Know

| Fact | Value |
|------|-------|
| RSA-2048 max plaintext (OAEP-SHA256) | ~190 bytes |
| Standard public exponent | 65537 (0x10001) |
| Largest RSA key factored (classical) | 829 bits (RSA-250, 2020) |
| RSA-1024 cracked in | ~74 CPU-years (2009) |
| NIST minimum through 2030 | RSA-2048 |
| TLS 1.3 HTTPS share (2024) | >70% of web traffic |
| AWS KMS key cost | ~$1/month per key |
