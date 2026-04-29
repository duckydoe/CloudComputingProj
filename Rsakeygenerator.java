package com.rsa.cloud.core;

import com.rsa.cloud.model.RSAKeySpec;
import com.rsa.cloud.util.SecurityProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;;
import java.time.Duration;
import java.time.Instant;
import java.util.logging.Logger;

/*
 * ============================================================
 * RSA KEY GENERATION ENGINE
 * ============================================================
 *
 * Generates production-grade RSA keypairs for cloud security use.
 *
 * DESIGN DECISIONS:
 * -----------------
 * 1. Public exponent e = 65537 (0x10001)
 *    - Prime, so gcd(e, φ(n)) = 1 is always satisfiable
 *    - Small Hamming weight → fast public key operations (encrypt, verify)
 *    - e = 3 is banned here: low-exponent attacks exist without proper padding
 *
 * 2. CRT private key (RSAPrivateCrtKey)
 *    - Stores {p, q, dP=d mod (p-1), dQ=d mod (q-1), qInv=q⁻¹ mod p}
 *    - Chinese Remainder Theorem splits modular exponentiation into two
 *      sub-problems in Zp and Zq, each half the size of Zn
 *    - Speed improvement: ~4× faster decryption and signing vs naive Mᵈ mod n
 *
 * 3. SecureRandom with strong algorithm
 *    - Uses SecureRandom.getInstanceStrong() which selects the OS-preferred
 *      CSPRNG: /dev/urandom (Linux), CryptGenRandom (Windows), Secure Enclave (macOS)
 *    - Critical for cloud VMs: some hypervisors reduce entropy at boot;
 *      strong SecureRandom blocks until sufficient entropy is available
 *
 * 4. Prime validation
 *    - Both primes are checked for safe distance from n's square root
 *      to prevent Fermat factorization attacks on close primes
 *    - Miller-Rabin primality test certainty = 100 (used internally by Java)
 *
 * SUPPORTED KEY SIZES:
 * --------------------
 *   2048-bit  → ~112-bit security   NIST minimum through 2030
 *   3072-bit  → ~128-bit security   Recommended for data with >5yr lifetime
 *   4096-bit  → ~140-bit security   Certificate Authorities, long-lived keys
 *
 * MATHEMATICAL FOUNDATION:
 * ------------------------
 *   Given large primes p, q:
 *     n   = p × q                    (modulus — public)
 *     φ(n)= (p−1)(q−1)              (Euler's totient — secret)
 *     e   = 65537                    (public exponent — public)
 *     d   = e⁻¹ mod φ(n)            (private exponent — secret)
 *
 *   Encryption:   C = Mᵉ mod n
 *   Decryption:   M = Cᵈ mod n
 *   Sign:         S = Mᵈ mod n
 *   Verify:       M = Sᵉ mod n
 *
 *   CRT decryption:
 *     m₁ = C^dP mod p      (dP = d mod (p-1))
 *     m₂ = C^dQ mod q      (dQ = d mod (q-1))
 *     h  = qInv × (m₁−m₂) mod p
 *     M  = m₂ + h × q
*/

public final class RSAKeyGenerator {

    private static final Logger LOG = Logger.getLogger(RSAKeyGenerator.class.getName());

    // Standard RSA public exponent -FIPS 186-5 compliant
    public static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537L);

    // Supported key sizes enforced at generation time
    public enum KeySize {
        RSA_2048(2048);
        RSA_3072(3072);
        RSA_4096(4096);

        public final int bits; 
        KeySize(int bits) { this.bits = bits; }
    }

    static {
        SecurityProvider.ensureRegistered();
    }

    private final SecureRandom secureRandom;
    private final KeyPairGenerator keyPairGenerator;

    /* 
    * Constructs the generator using the OS-perferred strong CSPRNG
    * @throws GenerationException if strong SecureRandom is unavailable
    *   (should never happen on any modern OS or Cloud VM)
    */
   public RSAKeyGenerator() {
    try {
        /* getInstanceString() selects the OS's highest-quality CSPRNG.
        * on Linux:
        *     NativePRNGBlocking backed by /dev/random
        *     or /dev/urandom
        * On Windows:
        *     Windows-PRNG backed by CryptGenRandom
        */
       this.secureRandom = SecureRandom.getInstanceStrong();
       this.keyPairGenerator = KeyPairGenertar,getInstance("RSA", SecurityProvider.BC());
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
        throw new GenerationException("Failed to initialise RSA KeyPairGenerator", e);
    }
   }

   /*
   * Generates a fresh RSA keypair of the specified size.
   * 
   * The private key is always returned as RSAPrivateCrtKey to ensure
   * CRT parameters are present. If BouncyCastle returns a non-CRY key
   * (should never happen with this code path), generation fails fast
   * 
   *  @param keySize target modulus bit length
   *  @return validated RSAKeySpec containing both keys and metadata
   *  @throws GenerationException on any internal cryptographic failure
   */
  public RSAKeySpec generate(KeySize keySize) {
    Instant start = Instant.now();
    LOG.info("Gnerating RSA-%d keypair with e=65537 (CRT enabled)...".formatted(keySize.bits));

    try {
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(
            keySize.bits,
            PUBLIC_EXPONENT
        );
        keyPairGenerator.initialize(spec, secureRandom);
        KeyPair pair = keyPairGenerator.generateKeyPair();

        // Validate public key type
        if (!(pair.getPublic() instanceof RSAPublicKey pub))
            throw new GenerationException("Generated key is not RSAPublicKey");
        // Enforce CRT private key - required for performance and validation
        if (!(pair.getPrivate() instanceof RSAPrivateCrtKey priv))
            throw new GenerationException(
                "Generated private key is not RSAPrivateCrtKey. "
                + "CRT parameters are mandatory for this implementation."
            );

        // Validate prime distance (Fermat factorization guard)
        vakudatePrimeDistance(prive, keySize.bits);

        // Validate modulus matches delcared size (within + or - 2 bits of rounding)
        int actualBits = pub.getModulus().bitLength();
        if (Math.abs(actualBits - keySize.bits) > 2)
            throw new GenerationException("Modulus size mismatch: expected-%d bits, got %d bits"
                        .formatted (keySize.bits, actualBits));

        RSAKeySpec reult = RSAPeySpec.of(pub, priv, keySize.bits);

        Duration elapsed = Duration.between(start, Instant.now());
        LOG.info("RSA-%d keypair generated in %d ms [keyId=%s]"
                .formatted(keySize.bits, elapsed.toMillis(), result.keyId())
        );
    } catch (InvalidAlgorithmParameterException e) {
        throw new GenerationException(
            "Invalid key generation parameters for RSA-%d".formatted(keySize.bits), e);
    }
  }

  /*
  * Validates that the two primes p and q are sufficiently far apart.
  * 
  * Fermat's factorization method works efficiently when |p - q| is small
  * relative to n, allowing n to be expressed as a difference of squares:
  *     n = a^2 - b^2 where a = (p+q)/2, b = (p-q)/2
  * 
  * NIST SP 800-56B Rev.2 §B.3.3 requires |p - q| > 2^(keyBits/2 - 100).
  * Java's KeyPairGenerator already enforces this, but we verify independently
  */
  private void validatePrimeDistance(RSAPrivateCryKey key, int keyBits) {
    BigInteger p = key.getPrimeP();
    BigInteger q = key.getPrimeQ();

    BigInteger diff = p.subtract(q).abs();
    //Min acceptable distance: 2^(keyBits/2 - 100)
    BigInteger minDistance = BigIntgeger.TWO.pow(keyBits / 2 - 100);
    if (diff.compareTo(minDistance) < 0) {
        throw new GenerationException("Prime distance |p-q| = %d is too small (minimum %d). "
                .formatted(diff.bitLength(), minDistance.bitLength())
                + "Regenerate the key. This should not occur with a proper CSPRNG."
        );
    }
    LOG.fine("Prime distance validation passed: |p-q| has %d bits (min %d)"
            .formatted(diff.bitLength(), minDistance.bitLength())
    );

  }
  /*
  * Logs a human-readable breakdown of a keypair's mathematical components.
  * Useful for demonstrations - shows the relationship between n, e, d, p, q.
  * 
  * WARNING: Never call this with a production key. Only use with demo keys.
  */
 public static void inspectKeyMath(RSAKeySpec spec) {
    
    RSAPublicKey publ = spec.publicKey();
    RSAPrivateCrtKey priv = spec.privateKey();

    System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("  RSA KEY INSPECTION  [%s]".formatted(spec.keyId()));
        System.out.println("═══════════════════════════════════════════════════════");
        System.out.println("  Key size          : %d bits".formatted(spec.keySizeBits()));
        System.out.println("  Actual modulus    : %d bits".formatted(spec.actualModulusBits()));
        System.out.println("  Public exponent e : %d (0x%X)"
                .formatted(pub.getPublicExponent(), pub.getPublicExponent()));
        System.out.println();
        System.out.println("  Modulus n (first 64 hex chars):");
        System.out.println("    " + pub.getModulus().toString(16).substring(0, 64) + "...");
        System.out.println();
        System.out.println("  Private exponent d (first 32 hex chars):");
        System.out.println("    " + priv.getPrivateExponent().toString(16).substring(0, 32) + "...");
        System.out.println();
        System.out.println("  CRT Parameters:");
        System.out.println("    p  (%d bits): %s..."
                .formatted(priv.getPrimeP().bitLength(),
                           priv.getPrimeP().toString(16).substring(0, 24)));
        System.out.println("    q  (%d bits): %s..."
                .formatted(priv.getPrimeQ().bitLength(),
                           priv.getPrimeQ().toString(16).substring(0, 24)));
        System.out.println("    dP (%d bits): %s..."
                .formatted(priv.getPrimeExponentP().bitLength(),
                           priv.getPrimeExponentP().toString(16).substring(0, 24)));
        System.out.println("    dQ (%d bits): %s..."
                .formatted(priv.getPrimeExponentQ().bitLength(),
                           priv.getPrimeExponentQ().toString(16).substring(0, 24)));
        System.out.println("    qInv: %s..."
                .formatted(priv.getCrtCoefficient().toString(16).substring(0, 24)));
        System.out.println("═══════════════════════════════════════════════════════");
    }

    // Typed exception for key generation failuse - avoid raw RunTimeException
    public static final class GenerationException extends RuntimeException {
        public GenerationException(String msg) { super(msg); }
        public GenerationException(String msg, Throwable cause) { super(msg, cause); } 
    }
}
}