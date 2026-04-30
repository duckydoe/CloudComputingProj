package com.crypto.demo.hybrid;

import java.security.*;
import java.util.Arrays;

public class HybridEncryptionTest {

    public static void main(String[] args) throws Exception {

        System.out.println("=== Hybrid Encryption Test ===");

        HybridEncryptionService service = new HybridEncryptionService();

        // Generate RSA keys
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.generateKeyPair();

        String message = "Testing Hybrid Encryption";
        byte[] plaintext = message.getBytes();

        // Encrypt
        var encrypted = service.encrypt(plaintext, kp.getPublic());
        encrypted.printSizes();

        // Decrypt
        byte[] decrypted = service.decrypt(encrypted, kp.getPrivate());

        // Verify
        System.out.println("Original : " + message);
        System.out.println("Decrypted: " + new String(decrypted));

        if (Arrays.equals(plaintext, decrypted)) {
            System.out.println("SUCCESS");
        } else {
            System.out.println("FAIL");
        }
    }
}