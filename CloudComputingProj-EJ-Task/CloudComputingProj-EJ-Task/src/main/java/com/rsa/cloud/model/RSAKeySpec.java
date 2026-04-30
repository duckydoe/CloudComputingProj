package com.rsa.cloud.model;

import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;

/*
 * Strongly typed container for an RSA keypair produced by RSAKeyGenerator.
 *
 * Uses RSAPrivateCrtKey (not the base RSAPrivateKey interface) to ensure
 * that the Chinese Remainder Theorem (CRT) parameters — p, q, dP, dQ, qInv —
 * are always present. CRT reduces private-key operations from O(log³ n) to
 * O(log³ p) ≈ O(log³ n / 4), giving a ~4× speedup on decryption and signing.
 *
 * Records are immutable by default in Java 25 — no defensive copying needed.
*/
public record RSAKeySpec(
    String keyId,
    RSAPublicKey publicKey,
    RSAPrivateCrtKey privateKey,
    int keySizeBits,
    Instant createdAt
) {
    public RSAKeySpec {
        if (keyId == null || keyId.isBlank())
            throw new IllegalArgumentException("keyId must not be blank");
        if (publicKey == null)
            throw new IllegalArgumentException("publicKey must not be null");
        if (privateKey == null)
            throw new IllegalArgumentException("privteKey must not be null");
        if (keySizeBits != 2048 && keySizeBits != 3072 && keySizeBits != 4096)
            throw new IllegalArgumentException(
                "Unsupported key size: " + keySizeBits 
                + ". Use 2048, 3072, or 4096."
            );
        if (createdAt == null)
            throw new IllegalArgumentException("createdAt must not be null");

        // Verify CRT parameters are populated
        if (privateKey.getPrimeP() == null || privateKey.getPrimeQ() == null)
            throw new IllegalArgumentException(
                "Private key is missing CRT parameters (p, q). "
                + " Ensure key was generated via Key Pair Generator, not reconstructed from raw d."
            );
    }

    /*
    * Factory - generates a random keyId using UUID v4.
    * Use when a stable ID is not yet assigned.
    */
   public static RSAKeySpec of(RSAPublicKey pub, RSAPrivateCrtKey priv, int bits){
    return new RSAKeySpec(
        UUID.randomUUID().toString(),
        pub,
        priv,
        bits,
        Instant.now()
    );
   }

   /*
   * Returns the RSA modulus bit length as reported by the public key
   */
  public int actualModulusBits(){
    return publicKey.getModulus().bitLength();
  }

  @Override 
  public String toString() {
    return "RSAKeySpec{keyId='%s', bits=%d, modulus=%d-bit, created=%s}"
            .formatted(keyId, keySizeBits, actualModulusBits(), createdAt);
  }
}
