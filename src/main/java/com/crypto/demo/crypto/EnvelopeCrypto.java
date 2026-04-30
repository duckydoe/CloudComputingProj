package com.crypto.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class EnvelopeCrypto {

    // Simulated "KMS CMK" (RSA key pair)
    private static final KeyPair rsaKeyPair;

    static {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            rsaKeyPair = kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // =========================
    // ENVELOPE ENCRYPTION
    // =========================
    public static String encrypt(String plaintext) throws Exception {

        // 1. Generate AES-256 data key
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        // 2. Generate IV for GCM
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        // 3. Encrypt data with AES-GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

        byte[] ciphertext = aesCipher.doFinal(
                plaintext.getBytes(StandardCharsets.UTF_8)
        );

        // 4. Wrap AES key using RSA-OAEP
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());

        byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());

        // 5. Encode everything as Base64
        String encKey = Base64.getEncoder().encodeToString(encryptedKey);
        String ivStr = Base64.getEncoder().encodeToString(iv);
        String cipherTextStr = Base64.getEncoder().encodeToString(ciphertext);

        // 6. Return envelope format
        return encKey + ":" + ivStr + ":" + cipherTextStr;
    }

    // =========================
    // ENVELOPE DECRYPTION
    // =========================
    public static String decrypt(String envelope) throws Exception {

        String[] parts = envelope.split(":");

        byte[] encryptedKey = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

        // 1. Unwrap AES key using RSA private key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());

        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedKey);

        SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");

        // 2. Decrypt data using AES-GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

        byte[] plain = aesCipher.doFinal(ciphertext);

        return new String(plain, StandardCharsets.UTF_8);
    }
}