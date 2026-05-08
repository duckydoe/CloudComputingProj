package com.crypto.demo.benchmark;

import com.crypto.demo.util.CryptoConfig;
import com.crypto.demo.pqc.PostQuantumEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * CRYPTO BENCHMARK SUITE — Plain Java (no JMH annotation processor needed)
 *
 * Measures RSA-4096 vs ML-KEM-768 vs AES-256 using System.nanoTime().
 * Includes warmup rounds to let the JIT compiler stabilise before measuring.
 *
 * Run: Right-click SimpleBenchmark.java -> Run As -> Java Application
 *   or: java -cp target\rsa-crypto-demo-1.0-SNAPSHOT.jar com.crypto.demo.benchmark.SimpleBenchmark
 */
public class SimpleBenchmark {

    private static final int WARMUP_ROUNDS   = 5;
    private static final int MEASURE_ROUNDS  = 10;
    private static final byte[] PLAINTEXT    = new byte[32];

    static { CryptoConfig.init(); }

    public static void main(String[] args) throws Exception {
        CryptoConfig.init();
        PostQuantumEngine pqe = new PostQuantumEngine();

        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║         CRYPTO BENCHMARK SUITE                   ║");
        System.out.println("║  RSA-4096 vs ML-KEM-768 vs AES-256               ║");
        System.out.println("║  COSC370 - Lei Tapungot                          ║");
        System.out.println("╚══════════════════════════════════════════════════╝\n");
        System.out.println("Warmup rounds   : " + WARMUP_ROUNDS);
        System.out.println("Measured rounds : " + MEASURE_ROUNDS);
        System.out.println("Running...\n");

        // ── Pre-generate keys for encrypt/decrypt benchmarks ─────────
        System.out.println("Setting up keys...");

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(4096, new SecureRandom());
        KeyPair rsaKeyPair = rsaKpg.generateKeyPair();

        KeyPairGenerator mlkemKpg = KeyPairGenerator.getInstance("ML-KEM");
        mlkemKpg.initialize(new NamedParameterSpec("ML-KEM-768"));
        KeyPair mlkemKeyPair = mlkemKpg.generateKeyPair();

        Cipher rsaCipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), buildOaepParams());
        byte[] rsaCiphertext = rsaCipher.doFinal(PLAINTEXT);

        PostQuantumEngine.EncapsulationResult mlkemEnc =
                pqe.encapsulate(mlkemKeyPair.getPublic());

        System.out.println("Keys ready. Running benchmarks...\n");

        // ── 1. KEY GENERATION ────────────────────────────────────────
        System.out.println("── 1. KEY GENERATION ─────────────────────────────");

        double rsaKeyGenMs = measureMs(WARMUP_ROUNDS, MEASURE_ROUNDS, () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(4096, new SecureRandom());
            kpg.generateKeyPair();
        });

        double mlkemKeyGenMs = measureMs(WARMUP_ROUNDS, MEASURE_ROUNDS, () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
            kpg.initialize(new NamedParameterSpec("ML-KEM-768"));
            kpg.generateKeyPair();
        });

        double aesKeyGenMs = measureMs(WARMUP_ROUNDS, MEASURE_ROUNDS, () -> {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, new SecureRandom());
            kg.generateKey();
        });

        System.out.printf("  RSA-4096  key gen : %8.3f ms/op%n", rsaKeyGenMs);
        System.out.printf("  ML-KEM-768 key gen: %8.3f ms/op%n", mlkemKeyGenMs);
        System.out.printf("  AES-256   key gen : %8.3f ms/op%n", aesKeyGenMs);
        System.out.printf("  RSA / ML-KEM ratio: %.0fx slower%n%n",
                rsaKeyGenMs / mlkemKeyGenMs);

        // ── 2. ENCRYPT / ENCAPSULATE ─────────────────────────────────
        System.out.println("── 2. ENCRYPT / ENCAPSULATE ──────────────────────");

        double rsaEncMs = measureMs(WARMUP_ROUNDS, MEASURE_ROUNDS, () -> {
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), buildOaepParams());
            c.doFinal(PLAINTEXT);
        });

        double mlkemEncMs = measureMs(WARMUP_ROUNDS, MEASURE_ROUNDS, () ->
                pqe.encapsulate(mlkemKeyPair.getPublic()));

        System.out.printf("  RSA-4096  encrypt    : %8.3f ms/op%n", rsaEncMs);
        System.out.printf("  ML-KEM-768 encapsulate: %8.3f ms/op%n", mlkemEncMs);
        System.out.printf("  RSA / ML-KEM ratio   : %.0fx slower%n%n",
                rsaEncMs / mlkemEncMs);

        // ── 3. DECRYPT / DECAPSULATE ─────────────────────────────────
        System.out.println("── 3. DECRYPT / DECAPSULATE ──────────────────────");

        double rsaDecMs = measureMs(WARMUP_ROUNDS, MEASURE_ROUNDS, () -> {
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding",
                    BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate(), buildOaepParams());
            c.doFinal(rsaCiphertext);
        });

        final byte[] mlkemCt = mlkemEnc.ciphertext();
        double mlkemDecMs = measureMs(WARMUP_ROUNDS, MEASURE_ROUNDS, () ->
                pqe.decapsulate(mlkemKeyPair.getPrivate(), mlkemCt));

        System.out.printf("  RSA-4096  decrypt    : %8.3f ms/op%n", rsaDecMs);
        System.out.printf("  ML-KEM-768 decapsulate: %8.3f ms/op%n", mlkemDecMs);
        System.out.printf("  RSA / ML-KEM ratio   : %.0fx slower%n%n",
                rsaDecMs / mlkemDecMs);

        // ── 4. CIPHERTEXT SIZES ───────────────────────────────────────
        System.out.println("── 4. CIPHERTEXT / KEY SIZES ─────────────────────");
        System.out.printf("  RSA-4096  ciphertext : %d bytes%n",
                rsaCiphertext.length);
        System.out.printf("  ML-KEM-768 ciphertext: %d bytes%n",
                mlkemEnc.ciphertext().length);
        System.out.printf("  RSA-4096  public key : %d bytes%n",
                rsaKeyPair.getPublic().getEncoded().length);
        System.out.printf("  ML-KEM-768 public key: %d bytes%n%n",
                mlkemKeyPair.getPublic().getEncoded().length);

        // ── 5. SUMMARY TABLE ─────────────────────────────────────────
        System.out.println("╔══════════════════════════════════════════════════════════════════╗");
        System.out.println("║                    BENCHMARK RESULTS SUMMARY                     ║");
        System.out.println("╠══════════════════════╦═══════════════╦═══════════════╦═══════════╣");
        System.out.println("║ Operation            ║ RSA-4096      ║ ML-KEM-768    ║ Speedup   ║");
        System.out.println("╠══════════════════════╬═══════════════╬═══════════════╬═══════════╣");
        System.out.printf( "║ Key generation       ║ %8.3f ms   ║ %8.3f ms   ║ %5.0fx    ║%n",
                rsaKeyGenMs, mlkemKeyGenMs, rsaKeyGenMs / mlkemKeyGenMs);
        System.out.printf( "║ Encrypt/Encapsulate  ║ %8.3f ms   ║ %8.3f ms   ║ %5.0fx    ║%n",
                rsaEncMs, mlkemEncMs, rsaEncMs / mlkemEncMs);
        System.out.printf( "║ Decrypt/Decapsulate  ║ %8.3f ms   ║ %8.3f ms   ║ %5.0fx    ║%n",
                rsaDecMs, mlkemDecMs, rsaDecMs / mlkemDecMs);
        System.out.println("╠══════════════════════╬═══════════════╬═══════════════╬═══════════╣");
        System.out.printf( "║ Ciphertext size      ║ %6d bytes   ║ %6d bytes   ║    N/A    ║%n",
                rsaCiphertext.length, mlkemEnc.ciphertext().length);
        System.out.printf( "║ Public key size      ║ %6d bytes   ║ %6d bytes   ║    N/A    ║%n",
                rsaKeyPair.getPublic().getEncoded().length,
                mlkemKeyPair.getPublic().getEncoded().length);
        System.out.println("╠══════════════════════╬═══════════════╬═══════════════╬═══════════╣");
        System.out.println("║ Quantum-safe         ║ NO            ║ YES (FIPS 203)║    —      ║");
        System.out.println("╚══════════════════════╩═══════════════╩═══════════════╩═══════════╝");

        System.out.println("\n── CONCLUSION ────────────────────────────────────");
        System.out.println("ML-KEM-768 is significantly faster than RSA-4096");
        System.out.println("for all key exchange operations, while providing");
        System.out.println("quantum resistance. The tradeoff is a larger");
        System.out.println("ciphertext (1088 vs 512 bytes) — acceptable for");
        System.out.println("the security guarantee it provides.");
    }

    // ----------------------------------------------------------------
    // MEASUREMENT HELPER
    // ----------------------------------------------------------------

    @FunctionalInterface
    interface Benchmark { void run() throws Exception; }

    /**
     * Measures average execution time of a benchmark operation.
     * Runs warmup rounds first to let JIT stabilise, then measures.
     *
     * @return Average time in milliseconds per operation
     */
    private static double measureMs(int warmup, int measure, Benchmark b)
            throws Exception {
        // Warmup
        for (int i = 0; i < warmup; i++) b.run();

        // Measure
        List<Long> times = new ArrayList<>();
        for (int i = 0; i < measure; i++) {
            long start = System.nanoTime();
            b.run();
            times.add(System.nanoTime() - start);
        }

        // Return average in ms, excluding top and bottom outlier
        Collections.sort(times);
        List<Long> trimmed = times.subList(1, times.size() - 1);
        return trimmed.stream().mapToLong(Long::longValue).average().orElse(0)
                / 1_000_000.0;
    }

    private static OAEPParameterSpec buildOaepParams() {
        return new OAEPParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }
}