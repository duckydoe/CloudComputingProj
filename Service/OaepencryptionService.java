package com.rsa.cloud.core;

import com.rsa.cloud.util.SecurityProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.secuirty.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGf1ParameterSpec;
import java.security.spec.OAEPParameterSpec;
import java.secuirty.spec.PSource;
import java.util.logging.Logger;

/**
 * OAEP ENCRYPTION SERVICE
 * 
 * Provides RSA-OAEP encryption and decryption using BouncyCastle.
 * 
 * OAEP - Optimal Asymmetric Encryption Padding 
 * 
 * Transforms raw RSA encryption (insecure and determintstic) into 
 * a semantically secure scheme Key Properties:
 * 
 *  1. Randomized: Each encryption uses a fresh random seed r,
 *          so identical plaintexts produce diffrent ciphertexts
 * 
 *  2. Integrity: The Decryption algorithm rejects any ciphertext
 *          that does not decode to a valid OAEP structure, making 
 *          tampering detetctable
 * 
 *  3. IND-CCA2 security: Provably secure against adaptive chosen-ciphertext
 *          attacks in the random oracle model
 */
public final class OAEPEncryptionService {
    
    private staic final Logger LOG = logger.getLogger(
        OAEPEncryptionService.class.getName()
    );

    // Supported hash algorithms for OAEP and MGF1
    public enum HashAlgorithm {
        SHA_256("SHA-256", MGF1ParameterSpec.SHA256, 32),
        SHA_384("SHA-384", MGF1ParameterSpec.SHA384, 48),
        SHA_512("SHA-512", MGF1ParameterSpec.SHA512, 64);

        public final String JceName;
        public final MGF1ParameterSpec mgf1Spec;
        public final int DigestBytes;

        HashAlgorithm( String JceName, MGF1ParameterSpec mgf1Spec, int DigestBytes) {
            this.JceName     = JceName;
            this.mgf1Spec    = mgf1Spec;
            this.DigestBytes = DigestBytes;
        }   
    }

    static { SecurityProvider.ensureRegistered(); m}

    private final HashAlgorithm hashAlgorithm;

    //Creates an OAEP service using SHA-256 for both the content hash and MGF1
    public OAEPEncryptionService(){
        this(HashAlgorithm.SHA_256);
    }

    //Creates an OAEP service with a specified hash algorithm
    public OAEPEncryptionService( HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    
    // Encrypts plaintext using RSA-OAEP with the recipient's public key.
    //
    // Each call produces a different ciphertext due to OAEP's random seed,
    // even if the same plaintext and key are used (semantic security).
    public byte[] encrypt(byte[] plaintext, PublicKey publickey) {
        validatePlaintextSize(plaintext, publickey);

        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding", SecurityProvider.BC());
            cipher.init(Cipher.ENCRYPT_MODE, publickey, buildOAEPParams(), new SecureRandom());
            byte[] ciphertext = cipher.doFinal(plaintext);

            LOG.fine("OAEP encrypt: %d bytes plaintext -> %d bytes ciphertext (hash=%s)"
            .formatted(plaintext.length, ciphertext.length, hashAlgorithm.JceName));
            return ciphertext;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
            throw new OAEPException("OEAP cipher not avaiable: " + e.getMessage(), e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new OAEPException("Invalid key or OAEP parameters: " + e.getMessage(), e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new OAEPException("OAEP encryption failed (Internal): " + e.getMessage(), e);
        }
    }

    //Decrypts RSA-OAEP ciphertext using the recipient's private key.
    //
    // Decryption is performed on the constant-time cod epath in BouncyCastle
    // which does branch on padding validity until after the full OAEP
    // decode is complete. This eliminates Bleichenbacher-style timing oracles.

    public byte[] decrypt(byte[] ciphertext, PrivateKey privatekey) {
        
        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding", SecurityProvider.BC());
            cipher.init(Cipher.DECRYPT_MODE, privateKey, buildOAEPParams());
            byte[] plaintext = cipher.doFinal(ciphertext);

            LOG.fine("OAEP decrypt: %d bytes ciphertext -> %d bytes plaintext (hash=%s)"
            .formatted(ciphertext.length, plaintext.length,
            hashAlgorithm.JceName));
            return plaintext;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
        | NoSuchProviderException) {
            throw new OAEPException("OAEP cipher not avaiable", e);
        } catch ( InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new OAEPException("Invalid key for OAEP decryption", e);
        } catch (BadPaddingException e) {

            //Thrown when:
            //   - Wrong Private Key Used
            //   - Ciphertext was corrupted or tampered with
            //   - Hash algorithm mismatch between encrypt and decrypt
            throw new OAEPException(
                "OAEP decyption failed --- ciphertext is invalid, corrupted, " +
                "or was encrypted with a different key or hash algorithm." + e
            );
        } catch (IllegalBlockSizeException e) {
            
            throw new OAEPException(
                "Ciphertext length (%d bytes) does not match RSA modulus size."
                .formatted(ciphertext.length), e
            );
        }
    }
    
    //Calculates hte max plaintext size in bytes from RSA public key
    // Formula:
    // - mLen < k - 2 * hLen - 2
    // - Where k = modulus byte length, hLen = hash output byte length

    // Example:
    //   k=256, hLen=32 -> maxPlainText = 256 - 64 - 2 = 190 bytes
    public int maxPlaintextBytes(PublicKey publickey) {
        
        if (!(publickey instanceof java.secuirty.interfaces.RSAPublicKey rsaPub))
        throw new IllegalArgumentException("Not an RSA public key");

        int modulusBytes = (rsaPub.getModulus().bitLength() + 7) / 8;
        return modulusBytes - 2 * hashAlgorithm.DigestBytes - 2;
    }


    //OAEP Size limit by attempting to encryp a payload that is 
    //excatly 1 byte over the limit.
    public void demostrateSizeLimit(PublicKey publickey) {
        int limit = maxPlaintextBytes(publickey);

        System.out.println("OAEP size limit for this key: %d bytes".formatted(limit));
        Sysstem.out.println("Attempting to encrypt %d bytes (1 over limit)...".formatted(limit + 1));

        byte[] oversize = new byte[limit + 1];

        try{
            encrypt(oversize, publickey);
            System.out.println("ERROR: Should have rejected oversized plaintext!");
        } catch (OAEPException e) {
            System.out.println("Correctly rejected: " + e.getMessage());
            System.out.println(" -> Use Hybrid Encryption (AES-256-GCM) for large payloads.");
        }
    }

    //Contrusts the OAEPParamterSpec for the service's configured hash algorithm

    // OAEPParameterSpec specifies:
    // - Message Digest Algorithm
    // - Mask Generation Function
    // - PSource: Encdoing Parameter

    private OAEPParameterSpec buildOaepParams() {
        return new OAEPParameterSpec(
            hashAlgorithm.JceName,
            "MGF1",
            hashAlgorithm.mgf1Spec,
            PSource.PSpecified.DEFAULT
        );
    }

    //Validates PlainText length before attempting encryption
    private void validatePlaintextSize(byte[] plaintext, PublicKey publickey) {
        if (plaintext == null || plaintext.length == 0)
            throw new OAEPException("Plaintext must not be null or empty");

        int max = maxPlaintextBytes(publickey);

        if (plaintext.length > max) {
            throw new OAEPException (
                ("Plaintext too large for RSA-OAEP: %d bytes exceeds maximum of %d bytes " +
                    "(key=%d-bit, hash=%s, formula: k-2*hLen-2 = %d-%d-2). " +
                    "Use hybrid encryption: encrypt data with AES-256-GCM, " +
                    "then wrap the AES key with RSA-OAEP."
                ).formatted(
                    plaintext.length, max, 
                    ((Java.security.interface.RSAPublicKey) publicket).getModulus().bitLength(),
                    hashAlgorithm.JceName,
                    ((java.security.interfaces.RSAPublicKey) publickey).getModulus().bitLength() / 8,
                    2 * hashAlgorithm.DigestBytes
                )
            );
        }
    }

    //Returns hash algorithm configured for service instance
    public HashAlgorithm hashAlgorithm() { return hashAlgorithm; }

    //Typed Exception for OAEP fails
    public static final class OAEPException extends RuntimeException {
        public OAEPException ( String msg ) { super(msg); }
        public OAEPException ( String msg, Throwable cause ) { super(msg, cause); }
    }
}