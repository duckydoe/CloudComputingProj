package com.rsa.cloud.core;

import com.rsa.cloud.util.SecurityProvider;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.logging.Logger;

/*
* PSS Signature Service
* ----------------------
*   Provides RSA-PSS digital signatures and verification.
*   Also implements PKCS#1 v1.5 signatures for legacy comparison.
*
*   PSS - Probablistic Signature Scheme (RFC 8017 §8.1):
*   
*   PSS is the current recommended scheme for RSA signatures.
*   It is probabilistic (included a random salt) and h as a tight
*       security reduction to the RSA problem in the random oracle
*       model.
 * PSS ENCODING PROCESS (sign):
 * ----------------------------
 *   Input: message M, salt length sLen, hash H
 *
 *   1. mHash = H(M)                       — hash the message
 *   2. salt  = random(sLen bytes)         — fresh randomness per signature
 *   3. M'    = 0x00...00 || mHash || salt — 8 zero bytes + hash + salt
 *   4. H'    = H(M')                      — hash the extended message
 *   5. PS    = 0x00...(emLen−sLen−hLen−2) — zero padding string
 *   6. DB    = PS || 0x01 || salt
 *   7. dbMask = MGF1(H', emLen−hLen−1)
 *   8. maskedDB = DB XOR dbMask
 *   9. maskedDB[0] &= 0x7F             — clear top bit
 *  10. EM   = maskedDB || H' || 0xBC
 *  11. S    = EM^d mod n               — RSA private key operation
 *
 * WHY PSS IS BETTER THAN PKCS#1 v1.5 FOR SIGNATURES:
 * ----------------------------------------------------
 *   PKCS#1 v1.5 signatures are deterministic — same message + same key
 *   always produces the same signature. This enables fault injection attacks
 *   and provides no tight security proof.
 *
 *   PSS is randomized (via the salt), has a proven security reduction to RSA,
 *   and is required by TLS 1.3 (RFC 8446 §4.2.3) for RSA certificate signatures.
 *   PKCS#1 v1.5 signatures are banned in TLS 1.3 handshakes.
 *
 * SALT LENGTH:
 * ------------
 *   NIST SP 800-131A recommends sLen = hLen (e.g., 32 bytes for SHA-256).
 *   Using sLen = 0 is allowed but removes the randomization benefit.
 *   Using sLen = -1 (TRAILER_FIELD) uses maximum salt — valid but less portable.
 *
 * HASH-THEN-SIGN DISCIPLINE:
 * --------------------------
 *   RSA-PSS operates on the HASH of the message, not the raw message bytes.
 *   The Signature class handles hashing internally when initialized with
 *   "SHA256withRSA/PSS", so callers pass the raw message — hashing is implicit.
 *   This is the correct pattern. Never pre-hash and then pass to PSS manually
 *   unless you're using NONEwithRSA/PSS, which is for expert use only.
 *
 * TAMPER DETECTION:
 * -----------------
 *   PSS verification rejects any signature where:
 *     - The signature was created with a different private key
 *     - The message has been modified by even 1 bit
 *     - The signature bytes have been corrupted or truncated
 *     - A different hash algorithm or salt length was used
 *   All of these produce a SignatureException or return false from verify().
*/

public final class PSSSignatureService {

    private static final Logger LOG = Logger.getLogger(PSSSignatureService.class.getName());

    public enum PSSConfig {

        SHA256_SALT32(
            "SHA256withRSA/PSS",
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
        ),
        SHA384_SALT48(
            "SHA384withRSA/PSS",
            new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
        ),
        SHA512_SALT64(
            "SHA512withRSA/PSS",
            new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
        );

        public final String jceName;
        public final PSSParameterSpec spec;

        PSSConfig(String jceName, PSSParameterSpec spec) {
            this.jceName = jceName;
            this.spec = spec;
        }
    }

    static { SecurityProvider.ensureRegistered(); }

    private final PSSConfig config;

    public PSSSignatureService() {
        this(PSSConfig.SHA256_SALT32);
    }

    public PSSSignatureService(PSSConfig config) {
        this.config = config;
    }


    public byte[] sign(byte[] message, PrivateKey privateKey) {
        if (message == null || message.length == 0)
            throw new SignatureServiceException("Message must not be null or empty");

        try {
            Signature sig = Signature.getInstance(config.jceName, SecurityProvider.BC());
            sig.setParameter(config.spec);
            sig.initSign(privateKey, new SecureRandom());
            sig.update(message);
            byte[] signature = sig.sign();

            LOG.fine("PSS signed %d-byte message -> %d-byte signature (config=%s)"
                .formatted(message.length, signature.length, config.name()));
                return signature;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new SignatureServiceException("PSS algorithm not available: " + config.jceName, e);
        } catch (InvalidKeyException e){
            throw new SignatureServiceException("Invalid private key for PSS signing", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SignatureServiceException("Invalid PSS parameters: " + config.spec, e);
        } catch (SignatureException e) {
            throw new SignatureServiceException("PSS signing failed", e);
        }
    }


    public boolean verify(byte[] message, byte[] signature, PublicKey publicKey) {
        if (message == null || signature == null)
            return false;

        try {
            Signature sig = Signature.getInstance(config.jceName, SecurityProvider.BC());
            sig.setParameter(config.spec);
            sig.initVerify(publicKey);
            sig.update(message);
            boolean valid = sig.verify(signature);
            
            LOG.fine("PSS verify: %s (message=%d bytes, sig=%d bytes)"
                .formatted(valid ? "VALID" : "INVALID", message.length, signature.length)
            );
            return valid;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new SignatureServiceException("PSS algorithm not available", e);
        } catch (InvalidKeyException e) {
            throw new SignatureServiceException("Invalid public key for PSS verification", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SignatureServiceException("Invalid PSS parameters", e);
        } catch (SignatureException e) {
            LOG.fine("PSS SignatureException during verification (treating as invalid): " + e.getMessage());
            return false;
        }
    }


    public byte[] signPKCS1v15(byte[] message, PrivateKey privateKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA", SecurityProvider.BC());
            sig.initSign(privateKey);
            sig.update(message);
            return sig.sign();
        } catch (Exception e) {
            throw new SignatureServiceException("PKCS#1 v1.5 signing failed", e);
        }
    }

    public boolean verifyPKCS1v15(byte[] message, byte[] signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA", SecurityProvider.BC());
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (SignatureException e) {
            return false;
        } catch (Exception e) {
            throw new SignatureServiceException("PKCS#1 v1.5 verification failed", e);
        }
    }


    public void demonstrateTamperDetection(byte[] document, int tamperByteIndex, PrivateKey privateKey, PublicKey publicKey) {
        System.out.println(" === Tamper Detection Demonstration === ");
        System.out.printf("  Document: %d bytes%n", document.length);
        System.out.printf("  PSS Config: %s%n", config.name());
        System.out.println();

        byte[] signature = sign(document, privateKey);

        System.out.printf("  [1] Signed original document -> %d-byte PSS signature%n", signature.length);

        boolean originalValid = verify(document, signature, publicKey);
        System.out.printf("  [2] Original verification: %s %n", originalValid ? "VALID" : "FAILED (unexpected!");

        byte[] tampered = Arrays.copyOf(document, document.length);
        tampered[tamperByteIndex] ^= 0x01;

        System.out.printf("  [3] Tampered byte[%d]: 0x%02X -> 0x%02X (1-bit flip)%n",
            tamperByteIndex,
            document[tamperByteIndex] & 0xFF,
            tampered[tamperByteIndex] & 0xFF
        );

        long startNs = System.nanoTime();
        boolean tamperedValid = verify(tampered, signature, publicKey);
        long elapsedNs = System.nanoTime() - startNs;

        System.out.printf("  [4] Tampered verification: %s  (detected in %.2f ms)%n",
            tamperedValid ? "VALID (wrong!)" : "INVALID - TAMPER DETECTED",
            elapsedNs / 1_000_000.0
        );

        System.out.println();
        if (!originalValid || tamperedValid) {
            System.out.println("  ERROR: Tamper detection did not behave correctly!");
        } else {
            System.out.println("  PSS correctly accepts valid signatures and rejects tampered data.");
            System.out.println("  Mathematical guarantee: SHA-256 collision resistance means");
            System.out.println("  any 1-bit change to the document produces a completely");
            System.out.println("  different hash, which PSS cannot match to the stored H'.");
        }

        System.out.println("========================================");
    }

    public void demonstratePSSvsPKCS1(byte[] message, PrivateKey privateKey, PublicKey publicKey) {
        System.out.println(" === PSS vs PKCS#1 v1.5 Comparison === ");

        byte[] pss1 = sign(message, privateKey);
        byte[] pss2 = sign(message, privateKey);
        byte[] pkcs1 = signPKCS1v15(message, privateKey);
        byte[] pkcs2 = signPKCS1v15(message, privateKey);

        System.out.println("PSS (call 1):      "
            + toHexPrefix(pss1, 16) + "..."
        );

        System.out.println("PSS (call 1):      "
            + toHexPrefix(pss2, 16) + "..."
        );

        System.out.println("PSS indentical?     "
            +Arrays.equals(pss1, pss2)
            + " <- randomized by salt, DIFFERENT each time"
        );

        System.out.println();
        System.out.println("PKCS#1 v1.5 (1):     "
            + toHexPrefix(pkcs1, 16) + "..."
        );
        System.out.println("PKCS#1 v1.5 (2):     "
            + toHexPrefix(pkcs2, 16) + "..."
        );
        System.out.println("PKCS#1 identical?    "
            + Arrays.equals(pkcs1, pkcs2)
            + " <- deterministic, SAME every time"
        );

        System.out.println();
        System.out.println("Both PSS variants verifiy correctly: "
            + (verify(message, pss1, publicKey) && verify(message, pss2, publicKey))
        );
        System.out.println("====================================================");
    }

    private static String toHexPrefix(byte[] bytes, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(n, bytes.length); i++)
            sb.append("%02X".formatted(bytes[i] & 0xFF));
        return sb.toString();
    }

    public static final class SignatureServiceException extends RuntimeException {
        public SignatureServiceException(String msg) { super(msg); }
        public SignatureServiceException(String msg, Throwable cause) { super(msg, cause);}
    }
}
