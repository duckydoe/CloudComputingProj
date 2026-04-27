package com.rsa.cloud.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/*
 * Registers BouncyCastle as the top-priority JCE provider.
 *
 * Must be called exactly once before any cryptographic operation.
 * All classes that perform crypto operations call ensureRegistered()
 * in their static initializer to guarantee safe ordering.
 *
 * BouncyCastle is used for:
 *   - OAEP padding with full OAEPParameterSpec control
 *   - PSS signing with configurable salt and MGF1
 *   - PEM / DER / PKCS#8 / PKCS#12 key serialization
 *   - X.509 v3 certificate generation and extension handling
 *   - CRL and OCSP response parsing for chain validation
 *
 * Native Java 25 JCE is used for:
 *   - ML-KEM-768  (KEM.getInstance("ML-KEM-768"))   — JEP 496
 *   - ML-DSA-65   (Signature.getInstance("ML-DSA-65")) — JEP 497
 *   - SecureRandom, KeyStore, MessageDigest
 */
public final class SecurityProvider {

    private static volatile boolean registered = false;

    private SecurityPrivider() {}

    /*
    * Idempotent - safe to call from multiple static initializers.
    * Thread-safe via double-checked locking.
    */
   public static void ensureRegistered() {
    if (!registered) {
        synchronized (SecurtiyProvider.class) {
            if (!registered) {
                if (Security.getProvider("BC") == null) {
                    // Insert at position 1 (highest Prio)
                    Security.insertProviderAt(new BouncyCastleProvider(), 1);
                }
                registered = true;
            }
        }
    }
   }

   /*
   * Returns the canoncial BouncyCastle provider name used in 
   * getInstance() calls.
   */
  public static String BC() {
    ensureRegistered();
    return "BC";
  }
}