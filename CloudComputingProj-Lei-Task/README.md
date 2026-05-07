# RSA Cryptography in Cloud Computing Security
**COSC370 — Lei Tapungot**

This project investigates RSA cryptography within the Cloud Computing security model. It implements hybrid encryption, live AWS KMS integration, real-world attack demonstrations, post-quantum cryptography, and performance benchmarks — all in Java 25 using the BouncyCastle library and AWS SDK v2.

---

## Prerequisites

Before running this project, make sure you have the following installed:

| Requirement | Version | Download |
|---|---|---|
| Java JDK | 25.0.2 | https://www.oracle.com/java/technologies/downloads/ |
| Apache Maven | 3.9+ | https://maven.apache.org/download.cgi |
| AWS Account | — | https://aws.amazon.com (for KMS demo only) |

Verify your installations:
```bash
java --version
mvn --version
```

---

## Project Structure

```
CloudComputingProj-Lei-Task/
├── pom.xml
└── src/main/java/com/crypto/demo/
    ├── util/
    │   └── CryptoConfig.java          # BouncyCastle provider setup
    ├── hybrid/
    │   ├── HybridEncryptionService.java  # AES-256-GCM + RSA-OAEP engine
    │   └── HybridTest.java               # Hybrid encryption demo runner
    ├── kms/
    │   ├── KmsIntegrationService.java    # AWS KMS SDK v2 integration
    │   └── EnvelopeEncryptionDemo.java   # KMS demo runner
    ├── attacks/
    │   ├── AttackDemoSuite.java          # Runs all 3 attacks in sequence
    │   ├── BleichenbacherDemo.java       # PKCS#1 v1.5 padding oracle
    │   ├── TimingAttackDemo.java         # RSA timing side-channel
    │   └── RocaDemo.java                 # CVE-2017-15361 fingerprint check
    ├── pqc/
    │   ├── PostQuantumEngine.java        # ML-KEM-768 + HKDF-SHA256
    │   └── PostQuantumDemo.java          # Post-quantum demo runner
    └── benchmark/
        ├── CryptoBenchmark.java          # JMH benchmark definitions
        ├── BenchmarkRunner.java          # JMH runner
        └── SimpleBenchmark.java          # Plain Java benchmark runner
```

---

## Build

Navigate to the project folder and build with Maven:

```bash
cd CloudComputingProj-Lei-Task
mvn clean package -DskipTests
```

You should see `BUILD SUCCESS` when complete.

---

## Running the Demos

All demos use the individual JAR classpath to preserve BouncyCastle's signed JAR integrity. A batch script is provided for convenience.

### Windows (PowerShell or Command Prompt)

**Run all demos at once:**
```bash
.\rundemo.bat
```

This runs in sequence:
1. Hybrid Encryption Engine
2. Attack Demonstration Suite
3. Post-Quantum Engine
4. Benchmark Suite

---

### Run individually

**1. Hybrid Encryption Engine**

Demonstrates AES-256-GCM + RSA-OAEP hybrid encryption with multi-recipient key wrapping.

```bash
java -cp "target\classes;%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.78.1\bcprov-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcpkix-jdk18on\1.78.1\bcpkix-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcutil-jdk18on\1.78.1\bcutil-jdk18on-1.78.1.jar" com.crypto.demo.hybrid.HybridTest
```

Expected output:
```
Recipients AES key sizes:
  bob : 512 bytes
  alice : 512 bytes
SUCCESS: All recipients decrypted correctly!
```

---

**2. AWS KMS Integration + Envelope Encryption**

Requires AWS credentials. Set environment variables first:

```bash
# Windows PowerShell
$env:AWS_REGION="us-east-1"
$env:AWS_ACCESS_KEY_ID="your-access-key-id"
$env:AWS_SECRET_ACCESS_KEY="your-secret-access-key"
```

```bash
# Windows Command Prompt
set AWS_REGION=us-east-1
set AWS_ACCESS_KEY_ID=your-access-key-id
set AWS_SECRET_ACCESS_KEY=your-secret-access-key
```

Then run:
```bash
java -cp "target\classes;%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.78.1\bcprov-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcpkix-jdk18on\1.78.1\bcpkix-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcutil-jdk18on\1.78.1\bcutil-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\kms\2.25.60\kms-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\sdk-core\2.25.60\sdk-core-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\auth\2.25.60\auth-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\regions\2.25.60\regions-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\utils\2.25.60\utils-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\aws-core\2.25.60\aws-core-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\identity-spi\2.25.60\identity-spi-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\http-auth-spi\2.25.60\http-auth-spi-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\http-auth-aws\2.25.60\http-auth-aws-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\http-client-spi\2.25.60\http-client-spi-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\apache-client\2.25.60\apache-client-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\checksums\2.25.60\checksums-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\checksums-spi\2.25.60\checksums-spi-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\json-utils\2.25.60\json-utils-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\third-party-jackson-core\2.25.60\third-party-jackson-core-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\protocol-core\2.25.60\protocol-core-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\aws-json-protocol\2.25.60\aws-json-protocol-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\endpoints-spi\2.25.60\endpoints-spi-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\metrics-spi\2.25.60\metrics-spi-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\profiles\2.25.60\profiles-2.25.60.jar;%USERPROFILE%\.m2\repository\software\amazon\awssdk\annotations\2.25.60\annotations-2.25.60.jar;%USERPROFILE%\.m2\repository\org\apache\httpcomponents\httpclient\4.5.13\httpclient-4.5.13.jar;%USERPROFILE%\.m2\repository\org\apache\httpcomponents\httpcore\4.4.13\httpcore-4.4.13.jar;%USERPROFILE%\.m2\repository\commons-logging\commons-logging\1.2\commons-logging-1.2.jar;%USERPROFILE%\.m2\repository\commons-codec\commons-codec\1.15\commons-codec-1.15.jar;%USERPROFILE%\.m2\repository\org\reactivestreams\reactive-streams\1.0.4\reactive-streams-1.0.4.jar;%USERPROFILE%\.m2\repository\org\slf4j\slf4j-simple\2.0.13\slf4j-simple-2.0.13.jar;%USERPROFILE%\.m2\repository\org\slf4j\slf4j-api\2.0.13\slf4j-api-2.0.13.jar" com.crypto.demo.kms.EnvelopeEncryptionDemo
```

> **NOTE:** KMS creates real AWS keys that cost ~$1/month each. In the nature of our project, you would have to create your own AWS account and input your access key information to run this demo.

---

**3. Attack Demonstration Suite**

Demonstrates Bleichenbacher (1998), Timing Side-Channel (Kocher 1996), and ROCA (CVE-2017-15361).

```bash
java -cp "target\classes;%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.78.1\bcprov-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcpkix-jdk18on\1.78.1\bcpkix-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcutil-jdk18on\1.78.1\bcutil-jdk18on-1.78.1.jar" com.crypto.demo.attacks.AttackDemoSuite
```

Expected output:
```
Bleichenbacher: PKCS#1 v1.5 VULNERABLE, OAEP SECURE
Timing: 381,011 ns delta visible
ROCA: Java key NOT vulnerable, Infineon key VULNERABLE
```

---

**4. Post-Quantum Engine**

Demonstrates ML-KEM-768 key exchange and HKDF-SHA256 session key derivation using Java 25 JEP 496.

```bash
java -cp "target\classes;%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.78.1\bcprov-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcpkix-jdk18on\1.78.1\bcpkix-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcutil-jdk18on\1.78.1\bcutil-jdk18on-1.78.1.jar" com.crypto.demo.pqc.PostQuantumDemo
```

Expected output:
```
Shared secrets match: true
Session keys match  : true
Key length          : 256 bits (AES-256)
```

---

**5. Benchmark Suite**

Compares RSA-4096 vs ML-KEM-768 performance.

```bash
java -cp "target\classes;%USERPROFILE%\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.78.1\bcprov-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcpkix-jdk18on\1.78.1\bcpkix-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\bouncycastle\bcutil-jdk18on\1.78.1\bcutil-jdk18on-1.78.1.jar;%USERPROFILE%\.m2\repository\org\apache\commons\commons-math3\3.6.1\commons-math3-3.6.1.jar;%USERPROFILE%\.m2\repository\net\sf\jopt-simple\jopt-simple\5.0.4\jopt-simple-5.0.4.jar;%USERPROFILE%\.m2\repository\org\openjdk\jmh\jmh-core\1.37\jmh-core-1.37.jar" com.crypto.demo.benchmark.SimpleBenchmark
```

Expected output:
```
Key generation  : RSA=978ms  ML-KEM=0.96ms  Speedup=1015x
Decrypt         : RSA=11ms   ML-KEM=0.79ms  Speedup=14x
```

---

## Dependencies

All dependencies are managed by Maven and downloaded automatically on first build.

| Dependency | Version | Purpose |
|---|---|---|
| BouncyCastle | 1.78.1 | RSA-OAEP, PSS, cryptographic primitives |
| AWS SDK v2 KMS | 2.25.60 | Cloud key management |
| JMH Core | 1.37 | Benchmark framework |
| SLF4J Simple | 2.0.13 | Logging |
| JUnit 5 | 5.10.2 | Testing |

---

