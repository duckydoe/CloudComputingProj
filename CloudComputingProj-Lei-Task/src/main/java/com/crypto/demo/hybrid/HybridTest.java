package com.crypto.demo.hybrid;

import java.security.*;
import java.util.HashMap;
import java.util.Map;

public class HybridTest {
    public static void main(String[] args) throws Exception {
        HybridEncryptionService hybrid = new HybridEncryptionService();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);

        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob   = kpg.generateKeyPair();

        Map<String, PublicKey> recipients = new HashMap<>();
        recipients.put("alice", alice.getPublic());
        recipients.put("bob", bob.getPublic());

        //Encrypts message with AES_GCM and wraps the keys for each recipient with RSA-OAEP
        String message = "A very secret, secret message";
        byte[] plaintext = message.getBytes();

        HybridEncryptionService.MultiRecipientHybridCiphertext bundle =
                hybrid.encryptForRecipients(plaintext, recipients);

        bundle.printSizes();

        byte[] aliceDecrypted = hybrid.decryptForRecipient(bundle, "alice", alice.getPrivate());
        System.out.println("Alice decrypted: " + new String(aliceDecrypted));

        byte[] bobDecrypted = hybrid.decryptForRecipient(bundle, "bob", bob.getPrivate());
        System.out.println("Bob decrypted: " + new String(bobDecrypted));

        if (message.equals(new String(aliceDecrypted)) &&
            message.equals(new String(bobDecrypted))) {
            System.out.println("SUCCESS: All recipients decrypted correctly!");
        } else {
            System.out.println("FAIL: Decryption mismatch!");
        }
    }
}