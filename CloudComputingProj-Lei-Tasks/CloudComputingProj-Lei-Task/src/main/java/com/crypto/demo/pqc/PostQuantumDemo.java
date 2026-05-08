package com.crypto.demo.pqc;

import com.crypto.demo.util.CryptoConfig;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * POST-QUANTUM ENGINE DEMO
 *
 * Demonstrates ML-KEM-768 key exchange and HKDF-SHA256 session key derivation
 * using Java 25 native JEP 496 APIs.
 *
 * Run: Right-click PostQuantumDemo.java -> Run As -> Java Application
 *
 * NOTE: Requires Java 25. Verify in Eclipse:
 *   Project -> Properties -> Java Compiler -> Compiler compliance level = 25
 */
public class PostQuantumDemo {

    public static void main(String[] args) throws Exception {
        CryptoConfig.init();
        PostQuantumEngine pqe = new PostQuantumEngine();
        HexFormat hex = HexFormat.of();

        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║       POST-QUANTUM ENGINE DEMO                   ║");
        System.out.println("║  ML-KEM-768 + HKDF-SHA256 (Java 25 JEP 496)     ║");
        System.out.println("║  COSC370 - Lei Tapungot                          ║");
        System.out.println("╚══════════════════════════════════════════════════╝\n");

        System.out.println("Why post-quantum?");
        System.out.println("  Shor's Algorithm (1994) breaks RSA on a quantum computer.");
        System.out.println("  ML-KEM is based on lattice problems — quantum-resistant.");
        System.out.println("  NIST finalized ML-KEM as FIPS 203 in August 2024.\n");

        // STEP 1: Key Generation
        System.out.println("── STEP 1: ML-KEM-768 Key Generation ─────────────");
        long t0 = System.nanoTime();
        KeyPair aliceKeyPair = pqe.generateMlKemKeyPair();
        long keyGenTime = System.nanoTime() - t0;

        System.out.println("Alice generated ML-KEM-768 key pair.");
        System.out.println("  Public key  : "
                + aliceKeyPair.getPublic().getEncoded().length + " bytes");
        System.out.println("  Private key : "
                + aliceKeyPair.getPrivate().getEncoded().length + " bytes");
        System.out.printf("  Key gen time: %.3f ms%n%n", keyGenTime / 1_000_000.0);

        // STEP 2: Encapsulation (Bob)
        System.out.println("── STEP 2: Encapsulation (Bob) ────────────────────");
        System.out.println("Bob encapsulates a shared secret using Alice's public key.");

        long t1 = System.nanoTime();
        PostQuantumEngine.EncapsulationResult bobResult =
                pqe.encapsulate(aliceKeyPair.getPublic());
        long encapTime = System.nanoTime() - t1;

        byte[]    bobCiphertext   = bobResult.ciphertext();
        SecretKey bobSharedSecret = bobResult.sharedSecret();

        System.out.println("  Ciphertext  : "
                + bobCiphertext.length + " bytes  <- Bob sends this to Alice");
        System.out.println("  Bob secret  : "
                + bobSharedSecret.getEncoded().length + " bytes  <- Bob keeps this");
        System.out.printf("  Encap time  : %.3f ms%n", encapTime / 1_000_000.0);
        System.out.println("  Bob secret  : "
                + hex.formatHex(bobSharedSecret.getEncoded()).substring(0, 32)
                + "...  (first 16 bytes shown)\n");

        // STEP 3: Decapsulation (Alice)
        System.out.println("── STEP 3: Decapsulation (Alice) ──────────────────");
        System.out.println("Alice decapsulates using her private key + Bob's ciphertext.");

        long t2 = System.nanoTime();
        SecretKey aliceSharedSecret = pqe.decapsulate(
                aliceKeyPair.getPrivate(),
                bobCiphertext
        );
        long decapTime = System.nanoTime() - t2;

        System.out.println("  Alice secret: "
                + aliceSharedSecret.getEncoded().length + " bytes");
        System.out.printf("  Decap time  : %.3f ms%n", decapTime / 1_000_000.0);
        System.out.println("  Alice secret: "
                + hex.formatHex(aliceSharedSecret.getEncoded()).substring(0, 32)
                + "...  (first 16 bytes shown)\n");

        boolean secretsMatch = Arrays.equals(
                aliceSharedSecret.getEncoded(),
                bobSharedSecret.getEncoded()
        );
        System.out.println("  Shared secrets match: " + secretsMatch
                + "  <- Both sides computed the same secret\n");

        // STEP 4: HKDF-SHA256 Key Derivation
        System.out.println("── STEP 4: HKDF-SHA256 Session Key Derivation ─────");
        System.out.println("Both sides independently derive an AES-256 session key.");
        System.out.println("Info label: \"COSC370-ML-KEM-768-AES-session-key\"\n");

        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        String info = "COSC370-ML-KEM-768-AES-session-key";

        SecretKey aliceSessionKey = pqe.hkdfDerive(aliceSharedSecret, salt, info);
        SecretKey bobSessionKey   = pqe.hkdfDerive(bobSharedSecret,   salt, info);

        System.out.println("  Alice AES-256 key: "
                + hex.formatHex(aliceSessionKey.getEncoded()).substring(0, 32) + "...");
        System.out.println("  Bob   AES-256 key: "
                + hex.formatHex(bobSessionKey.getEncoded()).substring(0, 32) + "...");

        boolean keysMatch = Arrays.equals(
                aliceSessionKey.getEncoded(),
                bobSessionKey.getEncoded()
        );
        System.out.println("\n  Session keys match: " + keysMatch
                + "  <- Both derived the same AES key");
        System.out.println("  Key length        : "
                + aliceSessionKey.getEncoded().length * 8 + " bits (AES-256)\n");

        // STEP 5: Full Hybrid Handshake
        System.out.println("── STEP 5: Full Hybrid Handshake Summary ──────────");
        PostQuantumEngine.HybridHandshakeResult handshake = pqe.performHybridHandshake();
        System.out.println("  Public key bytes  : " + handshake.publicKeyBytes());
        System.out.println("  Private key bytes : " + handshake.privateKeyBytes());
        System.out.println("  Ciphertext bytes  : " + handshake.ciphertextBytes());
        System.out.println("  Secrets match     : " + handshake.secretsMatch());
        System.out.println("  Session keys match: " + handshake.sessionKeysMatch());

        // STEP 6: RSA vs ML-KEM Size Comparison
        System.out.println("\n── STEP 6: RSA-4096 vs ML-KEM-768 Comparison ─────");
        pqe.printSizeComparison();

        // STEP 7: Timing Summary
        System.out.println("\n── STEP 7: Timing Summary ─────────────────────────");
        System.out.printf("  ML-KEM-768 key generation : %.3f ms%n",
                keyGenTime / 1_000_000.0);
        System.out.printf("  ML-KEM-768 encapsulation  : %.3f ms%n",
                encapTime / 1_000_000.0);
        System.out.printf("  ML-KEM-768 decapsulation  : %.3f ms%n",
                decapTime / 1_000_000.0);
        System.out.printf("  Total handshake           : %.3f ms%n",
                (keyGenTime + encapTime + decapTime) / 1_000_000.0);
        System.out.println("  (RSA-4096 key generation  : ~300-500 ms for comparison)");

        System.out.println("\n── SUMMARY ───────────────────────────────────────");
        System.out.println("ML-KEM-768 handshake  : COMPLETE");
        System.out.println("HKDF session key      : DERIVED");
        System.out.println("Quantum resistance    : YES — lattice-based, Shor-proof");
        System.out.println("Standard              : NIST FIPS 203 (Aug 2024)");
        System.out.println("Java 25 native API    : YES — no external PQC library");
        System.out.println("Migration path        : Replace RSA key exchange with");
        System.out.println("                        ML-KEM, keep AES-256-GCM for data");
    }
}