package com.crypto.demo.pqc;

import com.crypto.demo.util.CryptoConfig;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * POST-QUANTUM ENGINE — ML-KEM-768
 *
 * Uses Java 25 JEP 496 native ML-KEM support. No external PQC library needed.
 *
 * What is ML-KEM?
 *   ML-KEM (Module Lattice Key Encapsulation Mechanism) is the NIST-finalized
 *   post-quantum key exchange standard (FIPS 203, formerly CRYSTALS-Kyber).
 *   It is designed to resist attacks from both classical and quantum computers.
 *
 * Why does quantum computing break RSA?
 *   RSA security relies on factoring large numbers being hard.
 *   Shor's Algorithm (1994) solves this in polynomial time on a quantum computer.
 *   A sufficiently powerful quantum computer would break all RSA keys instantly.
 *   ML-KEM is based on the hardness of lattice problems, which Shor's Algorithm
 *   cannot solve.
 *
 * ML-KEM-768 parameters:
 *   Public key  : 1184 bytes  (vs 512 bytes for RSA-4096)
 *   Private key : 2400 bytes  (vs 2349 bytes for RSA-4096)
 *   Ciphertext  : 1088 bytes  (vs 512 bytes for RSA-4096)
 *   Shared secret: 32 bytes
 *   Security    : ~184 bits classical, ~128 bits quantum
 *
 * How KEM works (different from RSA encrypt/decrypt):
 *   Alice generates a key pair (publicKey, privateKey)
 *   Bob runs encapsulate(publicKey) → (ciphertext, sharedSecret)
 *   Alice runs decapsulate(privateKey, ciphertext) → sharedSecret
 *   Both now have the same sharedSecret — without ever transmitting it.
 *   The sharedSecret is then used to derive an AES session key via HKDF.
 *
 * Hybrid mode:
 *   For the transition period (now through ~2030), best practice is to
 *   combine ML-KEM with classical RSA so the session is secure even if
 *   ONE of the two algorithms is broken. This is what TLS 1.3 PQC drafts do.
 */
public class PostQuantumEngine {

    private static final String ML_KEM_768   = "ML-KEM-768";
    private static final int    AES_KEY_BITS = 256;
    private static final int    HKDF_LEN     = 32; // 256-bit derived key

    static { CryptoConfig.init(); }

    // ----------------------------------------------------------------
    // ML-KEM KEY GENERATION
    // ----------------------------------------------------------------

    /**
     * Generates an ML-KEM-768 key pair using Java 25 JEP 496.
     *
     * The KeyPairGenerator uses "ML-KEM" as the algorithm name.
     * NamedParameterSpec selects the ML-KEM-768 parameter set.
     *
     * @return ML-KEM-768 KeyPair (publicKey for encapsulation, privateKey for decapsulation)
     */
    public KeyPair generateMlKemKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
        kpg.initialize(new NamedParameterSpec(ML_KEM_768));
        return kpg.generateKeyPair();
    }

    // ----------------------------------------------------------------
    // ENCAPSULATION (Bob's side)
    // ----------------------------------------------------------------

    /**
     * Encapsulates a shared secret using Alice's ML-KEM-768 public key.
     *
     * Bob runs this with Alice's public key. He gets back:
     *   - ciphertext   : send this to Alice
     *   - sharedSecret : keep this, derive AES key from it
     *
     * The sharedSecret never travels over the network.
     *
     * @param publicKey Alice's ML-KEM-768 public key
     * @return EncapsulationResult containing ciphertext + sharedSecret
     */
    public EncapsulationResult encapsulate(PublicKey publicKey)
            throws GeneralSecurityException {

        // Java 25 KEM API: use "ML-KEM" as the algorithm
        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Encapsulator encapsulator = kem.newEncapsulator(publicKey);
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();

        return new EncapsulationResult(
                encapsulated.encapsulation(),   // ciphertext (byte[]) → send to Alice
                encapsulated.key()              // sharedSecret (SecretKey) → keep locally
        );
    }

    // ----------------------------------------------------------------
    // DECAPSULATION (Alice's side)
    // ----------------------------------------------------------------

    /**
     * Decapsulates the shared secret using Alice's ML-KEM-768 private key.
     *
     * Alice receives Bob's ciphertext and recovers the same sharedSecret
     * that Bob generated, without it ever being transmitted.
     *
     * @param privateKey  Alice's ML-KEM-768 private key
     * @param ciphertext  Ciphertext received from Bob (encapsulated.encapsulation())
     * @return The shared secret key (same as Bob's sharedSecret)
     */
    public SecretKey decapsulate(PrivateKey privateKey, byte[] ciphertext)
            throws GeneralSecurityException {

        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Decapsulator decapsulator = kem.newDecapsulator(privateKey);
        return decapsulator.decapsulate(ciphertext);
    }

    // ----------------------------------------------------------------
    // HKDF KEY DERIVATION
    // ----------------------------------------------------------------

    /**
     * Derives an AES-256 session key from the ML-KEM shared secret using HKDF-SHA256.
     *
     * Why HKDF?
     *   The ML-KEM shared secret is already cryptographically strong, but HKDF
     *   provides domain separation — you can derive multiple independent keys
     *   (encryption key, MAC key, IV) from the same shared secret by changing
     *   the "info" parameter. This is standard practice in TLS 1.3.
     *
     * HKDF two-step process:
     *   Extract: salt + sharedSecret → pseudorandom key (PRK)
     *   Expand:  PRK + info + length → derived key material
     *
     * @param sharedSecret  The 32-byte ML-KEM shared secret
     * @param salt          Optional salt (use a nonce or session ID in production)
     * @param info          Context label e.g. "COSC370-AES-session-key"
     * @return AES-256 SecretKey derived from the shared secret
     */
    /**
     * HKDF-SHA256 implemented via HMAC-SHA256 (RFC 5869).
     *
     * Two steps:
     *   Extract: PRK = HMAC-SHA256(salt, ikm)
     *   Expand:  OKM = HMAC-SHA256(PRK, info || 0x01)
     *
     * This is identical to what TLS 1.3 uses for session key derivation.
     */
    public SecretKey hkdfDerive(SecretKey sharedSecret, byte[] salt, String info)
            throws GeneralSecurityException {

        byte[] ikm = sharedSecret.getEncoded();

        // Step 1 — Extract: PRK = HMAC-SHA256(salt, IKM)
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        byte[] actualSalt = (salt != null && salt.length > 0)
                ? salt : new byte[32]; // default salt = 32 zero bytes per RFC 5869
        mac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        // Step 2 — Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] infoBytes = info.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] input = new byte[infoBytes.length + 1];
        System.arraycopy(infoBytes, 0, input, 0, infoBytes.length);
        input[infoBytes.length] = 0x01; // counter byte per RFC 5869
        byte[] okm = mac.doFinal(input);

        // Truncate to HKDF_LEN bytes and wrap as AES-256 key
        return new SecretKeySpec(Arrays.copyOf(okm, HKDF_LEN), "AES");
    }

    // ----------------------------------------------------------------
    // FULL HYBRID HANDSHAKE
    // ----------------------------------------------------------------

    /**
     * Performs a complete ML-KEM-768 + HKDF-SHA256 hybrid key exchange.
     *
     * This simulates a TLS-style handshake between Alice and Bob:
     *
     *   Step 1: Alice generates ML-KEM-768 key pair, shares publicKey
     *   Step 2: Bob encapsulates → gets (ciphertext, bobSecret)
     *   Step 3: Bob sends ciphertext to Alice
     *   Step 4: Alice decapsulates → gets aliceSecret
     *   Step 5: Both derive AES-256 session key via HKDF
     *   Step 6: Verify both session keys match
     *
     * @return HybridHandshakeResult with both derived keys and sizes
     */
    public HybridHandshakeResult performHybridHandshake() throws GeneralSecurityException {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        String info = "COSC370-ML-KEM-768-AES-session-key";

        // Step 1: Alice generates key pair
        KeyPair aliceKeyPair = generateMlKemKeyPair();

        // Step 2 & 3: Bob encapsulates using Alice's public key
        EncapsulationResult bobResult = encapsulate(aliceKeyPair.getPublic());

        // Step 4: Alice decapsulates using her private key + Bob's ciphertext
        SecretKey aliceSharedSecret = decapsulate(
                aliceKeyPair.getPrivate(),
                bobResult.ciphertext()
        );

        // Step 5: Both derive AES-256 session key via HKDF
        SecretKey aliceSessionKey = hkdfDerive(aliceSharedSecret, salt, info);
        SecretKey bobSessionKey   = hkdfDerive(bobResult.sharedSecret(), salt, info);

        return new HybridHandshakeResult(
                aliceKeyPair.getPublic().getEncoded().length,
                aliceKeyPair.getPrivate().getEncoded().length,
                bobResult.ciphertext().length,
                aliceSharedSecret.getEncoded(),
                bobResult.sharedSecret().getEncoded(),
                aliceSessionKey.getEncoded(),
                bobSessionKey.getEncoded()
        );
    }

    // ----------------------------------------------------------------
    // RSA vs ML-KEM SIZE COMPARISON
    // ----------------------------------------------------------------

    /**
     * Compares key and ciphertext sizes between RSA-4096 and ML-KEM-768.
     * This feeds directly into the JMH benchmark suite.
     */
    public void printSizeComparison() throws GeneralSecurityException {
        // ML-KEM-768 sizes
        KeyPair mlkemPair = generateMlKemKeyPair();
        EncapsulationResult mlkemResult = encapsulate(mlkemPair.getPublic());

        // RSA-4096 sizes
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(4096, new SecureRandom());
        KeyPair rsaPair = rsaKpg.generateKeyPair();

        System.out.println("\n┌─────────────────────────────────────────────────┐");
        System.out.println("│         RSA-4096 vs ML-KEM-768 Size Comparison  │");
        System.out.println("├──────────────────┬──────────────┬────────────────┤");
        System.out.println("│ Metric           │ RSA-4096     │ ML-KEM-768     │");
        System.out.println("├──────────────────┼──────────────┼────────────────┤");
        System.out.printf( "│ Public key       │ %4d bytes   │ %4d bytes      │%n",
                rsaPair.getPublic().getEncoded().length,
                mlkemPair.getPublic().getEncoded().length);
        System.out.printf( "│ Private key      │ %4d bytes   │ %4d bytes      │%n",
                rsaPair.getPrivate().getEncoded().length,
                mlkemPair.getPrivate().getEncoded().length);
        System.out.printf( "│ Ciphertext       │  512 bytes   │ %4d bytes      │%n",
                mlkemResult.ciphertext().length);
        System.out.println("│ Quantum-safe     │ NO           │ YES (FIPS 203) │");
        System.out.println("│ Shor's resistant │ NO           │ YES            │");
        System.out.println("└──────────────────┴──────────────┴────────────────┘");
    }

    // ----------------------------------------------------------------
    // RESULT RECORDS
    // ----------------------------------------------------------------

    /**
     * Result of encapsulate().
     * ciphertext   = send to the other party
     * sharedSecret = keep locally, derive session key from it
     */
    public record EncapsulationResult(byte[] ciphertext, SecretKey sharedSecret) {}

    /**
     * Full hybrid handshake result for display/verification.
     */
    public record HybridHandshakeResult(
            int publicKeyBytes,
            int privateKeyBytes,
            int ciphertextBytes,
            byte[] aliceSharedSecret,
            byte[] bobSharedSecret,
            byte[] aliceSessionKey,
            byte[] bobSessionKey
    ) {
        public boolean secretsMatch() {
            return Arrays.equals(aliceSharedSecret, bobSharedSecret);
        }
        public boolean sessionKeysMatch() {
            return Arrays.equals(aliceSessionKey, bobSessionKey);
        }
    }
}