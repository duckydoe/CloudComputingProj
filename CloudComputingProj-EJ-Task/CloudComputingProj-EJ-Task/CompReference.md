# RSA Cloud Computing Security — Component Reference
 
**COSC370 | Java 21+ | BouncyCastle 1.78.1**
 
---
 
## Project Structure
 
```
src/main/java/com/rsa/cloud/
├── Main.java                        # Runs all 10 demonstrations in sequence
├── core/
│   ├── RSAKeyGenerator.java         # RSA keypair generation (2048/3072/4096-bit)
│   ├── OAEPEncryptionService.java   # RSA-OAEP encryption and decryption
│   ├── PSSSignatureService.java     # RSA-PSS signing, verification, tamper detection
│   └── KeySerializationService.java # PEM, PKCS#8, and PKCS#12 serialization
├── pki/
│   ├── X509CertificateService.java  # X.509 v3 cert generation and chain validation
│   └── JWTService.java              # JWT RS256/PS256 from scratch
├── model/
│   └── RSAKeySpec.java              # Immutable record wrapping an RSA keypair
└── util/
    └── SecurityProvider.java        # Registers BouncyCastle as JCE provider
```
 
---
 
## Build & Run
 
```bash
mvn clean compile   # compile all 9 source files
mvn exec:java       # run Main.java
```
 
---
 
## SecurityProvider
 
Registers BouncyCastle at JVM startup as the top-priority JCE provider. Every service class calls `SecurityProvider.ensureRegistered()` in its static block — safe to call multiple times, thread-safe via double-checked locking.
 
```java
SecurityProvider.ensureRegistered();
// All Cipher.getInstance() and Signature.getInstance() calls now use BouncyCastle
```
 
---
 
## RSAKeySpec
 
Immutable Java 25 `record` that wraps a keypair. Enforces CRT private key, validates key size (2048 / 3072 / 4096 only), and stores a UUID key ID and creation timestamp.
 
```java
RSAKeySpec spec = RSAKeySpec.of(publicKey, privateCrtKey, 2048);
spec.keyId();           // UUID
spec.publicKey();       // RSAPublicKey
spec.privateKey();      // RSAPrivateCrtKey (CRT guaranteed)
spec.keySizeBits();     // 2048
```
 
---
 
## RSAKeyGenerator
 
Generates RSA keypairs using BouncyCastle with `SecureRandom.getInstanceStrong()`. CRT parameters are always enforced — giving ~4× faster private key operations. Validates prime distance per NIST SP 800-56B.
 
```java
RSAKeyGenerator gen = new RSAKeyGenerator();
RSAKeySpec key2048 = gen.generate(RSAKeyGenerator.KeySize.RSA_2048);
RSAKeySpec key4096 = gen.generate(RSAKeyGenerator.KeySize.RSA_4096);
RSAKeyGenerator.inspectKeyMath(key2048); // prints n, e, d, p, q, CRT params
```
 
| Key Size | Security | Use Case |
|----------|----------|---------|
| RSA_2048 | ~112-bit | Default — NIST minimum through 2030 |
| RSA_3072 | ~128-bit | Data lifetime beyond 2030 |
| RSA_4096 | ~140-bit | CA certificates |
 
---
 
## OAEPEncryptionService
 
RSA-OAEP encryption and decryption. OAEP is randomized — identical plaintexts produce different ciphertexts on every call. Required by AWS KMS, Azure Key Vault, and GCP Cloud KMS. Hard limit: **190 bytes max** for RSA-2048/SHA-256 (use hybrid encryption for larger data).
 
```java
OAEPEncryptionService oaep = new OAEPEncryptionService(); // SHA-256 default
 
byte[] ciphertext = oaep.encrypt(plaintext, keySpec.publicKey());
byte[] recovered  = oaep.decrypt(ciphertext, keySpec.privateKey());
 
oaep.maxPlaintextBytes(keySpec.publicKey()); // 190 for RSA-2048
oaep.demonstrateSizeLimit(keySpec.publicKey()); // shows the rejection live
```
 
**Why OAEP, not raw RSA:** Raw RSA is deterministic and vulnerable to chosen-plaintext attacks. OAEP injects a random seed per encryption and provides IND-CCA2 security. PKCS#1 v1.5 was broken by Bleichenbacher (1998) — avoid for new encryption.
 
---
 
## PSSSignatureService
 
RSA-PSS signing and verification. PSS is randomized via a per-call random salt — the same document signed twice produces different signatures. Required by TLS 1.3. PKCS#1 v1.5 signing is included for side-by-side comparison.
 
```java
PSSSignatureService pss = new PSSSignatureService(); // SHA-256, salt=32
 
byte[] sig   = pss.sign(document, keySpec.privateKey());
boolean ok   = pss.verify(document, sig, keySpec.publicKey());
 
// Demos
pss.demonstrateTamperDetection(doc, 7, privateKey, publicKey); // flips 1 bit, shows rejection
pss.demonstratePSSvsPKCS1(doc, privateKey, publicKey);          // shows PSS ≠ deterministic
```
 
| | PSS | PKCS#1 v1.5 |
|--|-----|-------------|
| Randomized | ✅ | ❌ |
| Security proof | ✅ Tight | ❌ None |
| TLS 1.3 | ✅ Required | ❌ Banned |
 
---
 
## KeySerializationService
 
Serializes and deserializes RSA keys in the three formats used across cloud infrastructure.
 
```java
KeySerializationService ser = new KeySerializationService();
 
// PEM
String pubPEM      = ser.publicKeyToPEM(keySpec.publicKey());
String encPrivPEM  = ser.encryptedPrivateKeyToPEM(keySpec.privateKey(), passphrase);
RSAPublicKey pub   = ser.publicKeyFromPEM(pubPEM);
RSAPrivateCrtKey priv = ser.encryptedPrivateKeyFromPEM(encPrivPEM, passphrase);
 
// PKCS#12
byte[] p12 = ser.toP12(keySpec, certificate, "alias", passphrase);
KeyStore.PrivateKeyEntry entry = ser.fromP12(p12, "alias", passphrase);
 
ser.demonstrateP12RoundTrip(keySpec, cert, passphrase);
```
 
| Format | Extension | Used In |
|--------|-----------|---------|
| PEM | `.pem` | Linux, cloud CLIs, OpenSSL |
| PKCS#8 | `.key` | Encrypted private key (AES-256-CBC, PBKDF2 100k iterations) |
| PKCS#12 | `.p12` / `.pfx` | Windows, Java KeyStore, client cert auth |
 
---
 
## X509CertificateService
 
Generates X.509 v3 certificates and validates certificate chains using PKIX (RFC 5280). Produces self-signed CA certs and CA-signed end-entity certs with full v3 extensions.
 
```java
X509CertificateService cs = new X509CertificateService();
 
// Self-signed CA certificate
X509Certificate caCert = cs.generateSelfSigned(
    caKey, "CN=My Root CA, O=My Org, C=US", 3650, List.of(), true
);
 
// End-entity certificate signed by the CA
X509Certificate serverCert = cs.issueEndEntityCertificate(
    serverKey, "CN=api.example.com, O=My Org, C=US",
    List.of("api.example.com", "*.api.example.com"), 365, caCert, caKey
);
 
// Chain validation
ValidationResult result = cs.validateChain(serverCert, List.of(), caCert);
result.valid();   // true / false
result.detail();  // human-readable reason if false
 
X509CertificateService.printCertificate(serverCert);
```
 
> ⚠️ Use `O=` (letter O) not `0=` (zero) in DN strings — BouncyCastle will throw `Unknown object id - 0`.
 
---
 
## JWTService
 
Issues and verifies JWTs from scratch — no external library. Demonstrates RS256 (deterministic) vs PS256 (randomized). PS256 is the recommended choice for new implementations.
 
```java
JWTService jwt = new JWTService(JWTService.Algorithm.PS256);
 
String token = jwt.issueWithStandardClaims(
    "user-001", "https://auth.example.com", "https://api.example.com",
    3600, keySpec.privateKey()
);
 
Map<String, Object> claims = jwt.verify(token, keySpec.publicKey());
 
JWTService.demonstrateRS256vsPS256(claims, privateKey, publicKey);
```
 
`verify()` checks: structure (3 parts) → header `alg` field → RSA signature → `exp` claim not expired.
 
| Algorithm | Deterministic | Security Proof | Required By |
|-----------|---------------|---------------|-------------|
| RS256 | ✅ Same token every time | ❌ | Legacy systems |
| PS256 | ❌ Different every time | ✅ | FAPI 2.0, financial APIs |
 
---
 
## References
 
1. Rivest, Shamir & Adleman (1978). RSA. *CACM 21(2).*
2. NIST FIPS 203 (2024). ML-KEM Standard.
3. NIST SP 800-56B Rev. 2 (2019). RSA Key-Establishment.
4. RFC 8017 (2016). PKCS #1 v2.2.
5. RFC 8446 (2018). TLS 1.3.
6. Bleichenbacher (1998). Chosen Ciphertext Attacks. *CRYPTO 1998.*
7. AWS KMS Cryptographic Details Whitepaper (2024).