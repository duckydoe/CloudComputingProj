package com.crypto.demo.hybrid;

import com.crypto.demo.util.CryptoConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;

/**
 * HYBRID ENCRYPTION SERVICE
 *
 * Combines AES-256-GCM (data encryption) with RSA-OAEP (key wrapping).
 *
 * Why hybrid?
 *   RSA-OAEP can only encrypt ~190 bytes directly.
 *   AES-256-GCM can encrypt gigabytes with authentication.
 *   Solution: RSA wraps the 32-byte AES key, AES encrypts the data.
 *
 * Flow:
 *   ENCRYPT: plaintext -> AES-256-GCM -> ciphertext
 *                         AES key     -> RSA-OAEP  -> wrappedKey
 *
 *   DECRYPT: wrappedKey -> RSA-OAEP -> AES key
 *            ciphertext -> AES-256-GCM -> plaintext
 */
public class HybridEncryptionService {

    // AES-256-GCM constants
    private static final int AES_KEY_BITS   = 256;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS   = 128;

    static { CryptoConfig.init(); }

    // ----------------------------------------------------------------
    // PUBLIC API
    // ----------------------------------------------------------------

    /**
     * Encrypts plaintext using AES-256-GCM, then wraps the AES key
     * with RSA-OAEP-SHA256. Returns a HybridCiphertext bundle.
     */
    public HybridCiphertext encrypt(byte[] plaintext, PublicKey rsaPublicKey)
            throws GeneralSecurityException {

        SecretKey aesKey = generateAesKey();
        byte[] nonce = generateNonce();
        byte[] ciphertext = aesGcmEncrypt(plaintext, aesKey, nonce);
        byte[] wrappedKey = rsaWrapKey(aesKey, rsaPublicKey);

        return new HybridCiphertext(wrappedKey, nonce, ciphertext);
    }

    /**
     * Unwraps the AES key with RSA-OAEP, then decrypts the ciphertext
     * with AES-256-GCM.
     */
    public byte[] decrypt(HybridCiphertext bundle, PrivateKey rsaPrivateKey)
            throws GeneralSecurityException {

        SecretKey aesKey = rsaUnwrapKey(bundle.wrappedKey(), rsaPrivateKey);
        return aesGcmDecrypt(bundle.ciphertext(), aesKey, bundle.nonce());
    }

    // ----------------------------------------------------------------
    // AES-256-GCM
    // ----------------------------------------------------------------

    private SecretKey generateAesKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS, new SecureRandom());
        return kg.generateKey();
    }

    private byte[] generateNonce() {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private byte[] aesGcmEncrypt(byte[] plaintext, SecretKey key, byte[] nonce)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return cipher.doFinal(plaintext);
    }

    private byte[] aesGcmDecrypt(byte[] ciphertext, SecretKey key, byte[] nonce)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return cipher.doFinal(ciphertext);
    }

    // ----------------------------------------------------------------
    // RSA-OAEP KEY WRAPPING
    // ----------------------------------------------------------------

    private byte[] rsaWrapKey(SecretKey aesKey, PublicKey rsaPublicKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.WRAP_MODE, rsaPublicKey, buildOaepParams());
        return cipher.wrap(aesKey);
    }

    private SecretKey rsaUnwrapKey(byte[] wrappedKey, PrivateKey rsaPrivateKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.UNWRAP_MODE, rsaPrivateKey, buildOaepParams());
        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    private OAEPParameterSpec buildOaepParams() {
        return new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
    }

    // ----------------------------------------------------------------
    // RESULT BUNDLE
    // ----------------------------------------------------------------

    /**
     * Immutable bundle holding everything the recipient needs to decrypt.
     *
     * wrappedKey  = AES key encrypted with RSA-OAEP  (512 bytes for 4096-bit RSA)
     * nonce       = GCM nonce                         (12 bytes)
     * ciphertext  = AES-GCM encrypted data            (plaintext length + 16 byte tag)
     */
    public record HybridCiphertext(
            byte[] wrappedKey,
            byte[] nonce,
            byte[] ciphertext
    ) {
        public void printSizes() {
            System.out.println("  Wrapped AES key : " + wrappedKey.length  + " bytes");
            System.out.println("  GCM nonce       : " + nonce.length       + " bytes");
            System.out.println("  Ciphertext      : " + ciphertext.length  + " bytes");
        }
    }

    // ----------------------------------------------------------------
    // MULTI-RECIPIENT KEY WRAPPING
    // ----------------------------------------------------------------

    /**
     * Holds AES-encrypted data and a wrapped AES key per recipient.
     * wrappedKeys = Map<recipientId, RSA-wrapped AES key>
     * nonce       = GCM nonce
     * ciphertext  = AES-GCM encrypted data
     */
    public record MultiRecipientHybridCiphertext(
            Map<String, byte[]> wrappedKeys,
            byte[] nonce,
            byte[] ciphertext
    ) {
        public void printSizes() {
            System.out.println("Recipients AES key sizes:");
            wrappedKeys.forEach((id, key) -> 
                System.out.println("  " + id + " : " + key.length + " bytes")
            );
            System.out.println("GCM nonce       : " + nonce.length);
            System.out.println("Ciphertext      : " + ciphertext.length);
        }
    }

    /**
     * Encrypts plaintext with AES-GCM and wraps the AES key for multiple recipients.
     * recipientPublicKeys = Map<recipientId, PublicKey>
     */
    public MultiRecipientHybridCiphertext encryptForRecipients(
            byte[] plaintext,
            Map<String, PublicKey> recipientPublicKeys
    ) throws GeneralSecurityException {

        SecretKey aesKey = generateAesKey();
        byte[] nonce = generateNonce();
        byte[] ciphertext = aesGcmEncrypt(plaintext, aesKey, nonce);

        Map<String, byte[]> wrappedKeys = new HashMap<>();
        for (Map.Entry<String, PublicKey> entry : recipientPublicKeys.entrySet()) {
            wrappedKeys.put(entry.getKey(), rsaWrapKey(aesKey, entry.getValue()));
        }

        return new MultiRecipientHybridCiphertext(wrappedKeys, nonce, ciphertext);
    }

    /**
     * Decrypts multi-recipient ciphertext for a given recipientId and RSA private key.
     */
    public byte[] decryptForRecipient(
            MultiRecipientHybridCiphertext bundle,
            String recipientId,
            PrivateKey rsaPrivateKey
    ) throws GeneralSecurityException {

        byte[] wrappedKey = bundle.wrappedKeys().get(recipientId);
        if (wrappedKey == null) {
            throw new IllegalArgumentException("No AES key for recipient: " + recipientId);
        }

        SecretKey aesKey = rsaUnwrapKey(wrappedKey, rsaPrivateKey);
        return aesGcmDecrypt(bundle.ciphertext(), aesKey, bundle.nonce());
    }
}