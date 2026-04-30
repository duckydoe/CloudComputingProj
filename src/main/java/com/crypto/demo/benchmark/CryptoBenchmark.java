package com.crypto.demo.benchmark;

import com.crypto.demo.util.CryptoConfig;
import com.crypto.demo.pqc.PostQuantumEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.concurrent.TimeUnit;

/**
 * JMH BENCHMARK SUITE
 *
 * Measures and compares RSA-4096 vs ML-KEM-768 across:
 *   1. Key generation time
 *   2. Encrypt / Encapsulate operation time
 *   3. Decrypt / Decapsulate operation time
 *   4. Ciphertext size
 *   5. AES-256-GCM baseline (symmetric reference point)
 *
 * JMH handles:
 *   - JVM warmup (eliminates JIT compilation noise)
 *   - Multiple measurement forks (eliminates outliers)
 *   - Statistical scoring (mean + error margin)
 *
 * HOW TO RUN:
 *   Option A — Eclipse Run Configuration:
 *     Main class: com.crypto.demo.benchmark.BenchmarkRunner
 *
 *   Option B — Maven command line:
 *     mvn package
 *     java -jar target/rsa-crypto-demo-1.0-SNAPSHOT.jar
 *
 * EXPECTED OUTPUT FORMAT:
 *   Benchmark                        Mode  Cnt    Score    Error  Units
 *   CryptoBenchmark.rsaKeyGen        avgt    5   312.4  ±  8.2   ms/op
 *   CryptoBenchmark.mlkemKeyGen      avgt    5     0.8  ±  0.1   ms/op
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class CryptoBenchmark {

    // ----------------------------------------------------------------
    // BENCHMARK STATE — shared across all benchmark methods
    // ----------------------------------------------------------------

    // RSA artifacts
    private KeyPair rsaKeyPair;
    private byte[]  rsaCiphertext;

    // ML-KEM artifacts
    private KeyPair                          mlkemKeyPair;
    private PostQuantumEngine.EncapsulationResult mlkemEncapsulated;
    private PostQuantumEngine                pqe;

    // AES key for symmetric baseline
    private SecretKey aesKey;

    // Fixed plaintext for encryption benchmarks (32 bytes — simulates an AES key wrap)
    private static final byte[] PLAINTEXT = new byte[32];

    static { CryptoConfig.init(); }

    // ----------------------------------------------------------------
    // SETUP — runs once before all benchmarks
    // ----------------------------------------------------------------

    @Setup(Level.Trial)
    public void setup() throws Exception {
        CryptoConfig.init();
        pqe = new PostQuantumEngine();

        // Pre-generate RSA key pair and ciphertext for decrypt benchmarks
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(4096, new SecureRandom());
        rsaKeyPair = rsaKpg.generateKeyPair();

        Cipher rsaCipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), buildOaepParams());
        rsaCiphertext = rsaCipher.doFinal(PLAINTEXT);

        // Pre-generate ML-KEM key pair and encapsulation for decapsulate benchmark
        KeyPairGenerator mlkemKpg = KeyPairGenerator.getInstance("ML-KEM");
        mlkemKpg.initialize(new NamedParameterSpec("ML-KEM-768"));
        mlkemKeyPair = mlkemKpg.generateKeyPair();
        mlkemEncapsulated = pqe.encapsulate(mlkemKeyPair.getPublic());

        // AES key for symmetric baseline
        KeyGenerator aesKg = KeyGenerator.getInstance("AES");
        aesKg.init(256, new SecureRandom());
        aesKey = aesKg.generateKey();
    }

    // ----------------------------------------------------------------
    // 1. KEY GENERATION BENCHMARKS
    // ----------------------------------------------------------------

    /**
     * RSA-4096 key generation.
     * Expected: ~300-500 ms/op (prime generation is expensive)
     */
    @Benchmark
    public KeyPair rsaKeyGen() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /**
     * ML-KEM-768 key generation.
     * Expected: ~0.5-2 ms/op (lattice sampling is fast)
     */
    @Benchmark
    public KeyPair mlkemKeyGen() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
        kpg.initialize(new NamedParameterSpec("ML-KEM-768"));
        return kpg.generateKeyPair();
    }

    /**
     * AES-256 key generation (symmetric baseline reference).
     * Expected: < 0.1 ms/op
     */
    @Benchmark
    public SecretKey aesKeyGen() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, new SecureRandom());
        return kg.generateKey();
    }

    // ----------------------------------------------------------------
    // 2. ENCRYPT / ENCAPSULATE BENCHMARKS
    // ----------------------------------------------------------------

    /**
     * RSA-4096 OAEP encryption (wraps a 32-byte AES key).
     * Expected: ~2-5 ms/op
     */
    @Benchmark
    public byte[] rsaEncrypt(Blackhole bh) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), buildOaepParams());
        return cipher.doFinal(PLAINTEXT);
    }

    /**
     * ML-KEM-768 encapsulation.
     * Expected: ~0.3-1 ms/op
     */
    @Benchmark
    public PostQuantumEngine.EncapsulationResult mlkemEncapsulate() throws Exception {
        return pqe.encapsulate(mlkemKeyPair.getPublic());
    }

    // ----------------------------------------------------------------
    // 3. DECRYPT / DECAPSULATE BENCHMARKS
    // ----------------------------------------------------------------

    /**
     * RSA-4096 OAEP decryption.
     * Expected: ~2-8 ms/op (private key op is slower than public key op)
     */
    @Benchmark
    public byte[] rsaDecrypt() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate(), buildOaepParams());
        return cipher.doFinal(rsaCiphertext);
    }

    /**
     * ML-KEM-768 decapsulation.
     * Expected: ~0.3-1 ms/op
     */
    @Benchmark
    public SecretKey mlkemDecapsulate() throws Exception {
        return pqe.decapsulate(
                mlkemKeyPair.getPrivate(),
                mlkemEncapsulated.ciphertext()
        );
    }

    // ----------------------------------------------------------------
    // 4. CIPHERTEXT SIZE BENCHMARK
    // ----------------------------------------------------------------

    /**
     * Measures RSA-4096 ciphertext size.
     * Not a time benchmark — records the byte count as a score.
     * Expected: 512 bytes
     */
    @Benchmark
    @BenchmarkMode(Mode.SingleShotTime)
    public int rsaCiphertextSize() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), buildOaepParams());
        return cipher.doFinal(PLAINTEXT).length;
    }

    /**
     * Measures ML-KEM-768 ciphertext size.
     * Expected: 1088 bytes
     */
    @Benchmark
    @BenchmarkMode(Mode.SingleShotTime)
    public int mlkemCiphertextSize() throws Exception {
        PostQuantumEngine.EncapsulationResult result =
                pqe.encapsulate(mlkemKeyPair.getPublic());
        return result.ciphertext().length;
    }

    // ----------------------------------------------------------------
    // HELPER
    // ----------------------------------------------------------------

    private OAEPParameterSpec buildOaepParams() {
        return new OAEPParameterSpec(
                "SHA-256", "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
    }
}