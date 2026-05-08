package com.crypto.demo.kms;
 
import com.crypto.demo.util.CryptoConfig;
import software.amazon.awssdk.services.kms.KmsClient;
 
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
 
/**
 * ENVELOPE ENCRYPTION DEMO
 *
 * Drives KmsIntegrationService to demonstrate:
 *   1. CreateKey (encrypt/decrypt CMK + signing CMK)
 *   2. KMS Encrypt + Decrypt (small plaintext, direct RSA-OAEP)
 *   3. KMS Sign + Verify (RSA-PSS)
 *   4. Envelope Encryption (GenerateDataKey -> local AES-GCM -> store encryptedKey)
 *   5. KMS vs Local BouncyCastle comparison
 *   6. Full audit log printout
 *
 * HOW TO RUN:
 *   Set env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
 *   Then: mvn exec:java -Dexec.mainClass="com.crypto.demo.kms.EnvelopeEncryptionDemo"
 *
 * NOTE: This creates real KMS keys that incur AWS charges (~$1/key/month).
 *       Use scheduleKeyDeletion() in the AWS console to clean up after grading.
 */
public class EnvelopeEncryptionDemo {
 
    public static void main(String[] args) throws Exception {
        CryptoConfig.init();
        KmsIntegrationService kms = new KmsIntegrationService();
 
        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║         AWS KMS INTEGRATION DEMO                 ║");
        System.out.println("║  COSC370 - Lei Tapungot                          ║");
        System.out.println("╚══════════════════════════════════════════════════╝\n");
 
        // ----------------------------------------------------------------
        // STEP 1: Create keys
        // ----------------------------------------------------------------
        System.out.println("── STEP 1: Creating CMKs in AWS KMS ──────────────");
        String encryptKeyId   = kms.createRsaKey("COSC370-demo-encrypt-key");
        String signingKeyId   = kms.createSigningKey("COSC370-demo-signing-key");
        // Symmetric key required for GenerateDataKey (envelope encryption)
        // KMS rule: GenerateDataKey only works with symmetric CMKs, not RSA keys
        String symmetricKeyId = kms.createSymmetricKey("COSC370-demo-symmetric-key");
        System.out.println("Encrypt CMK  (RSA-4096)  : " + encryptKeyId);
        System.out.println("Signing CMK  (RSA-4096)  : " + signingKeyId);
        System.out.println("Symmetric CMK (AES-256)  : " + symmetricKeyId);
 
        // ----------------------------------------------------------------
        // STEP 2: KMS Encrypt + Decrypt (direct, small plaintext)
        // ----------------------------------------------------------------
        System.out.println("\n── STEP 2: KMS Direct Encrypt / Decrypt ──────────");
        byte[] smallPlaintext = "Hello from COSC370 KMS demo!".getBytes(StandardCharsets.UTF_8);
 
        byte[] kmsCiphertext  = kms.kmsEncrypt(encryptKeyId, smallPlaintext);
        byte[] kmsDecrypted   = kms.kmsDecrypt(encryptKeyId, kmsCiphertext);
 
        System.out.println("Original  : " + new String(smallPlaintext, StandardCharsets.UTF_8));
        System.out.println("Decrypted : " + new String(kmsDecrypted,   StandardCharsets.UTF_8));
        System.out.println("Match     : " + Arrays.equals(smallPlaintext, kmsDecrypted));
 
        // ----------------------------------------------------------------
        // STEP 3: KMS Sign + Verify
        // ----------------------------------------------------------------
        System.out.println("\n── STEP 3: KMS Sign / Verify ─────────────────────");
        byte[] message   = "Document requiring a signature.".getBytes(StandardCharsets.UTF_8);
        byte[] signature = kms.kmsSign(signingKeyId, message);
        boolean valid    = kms.kmsVerify(signingKeyId, message, signature);
 
        System.out.println("Message       : " + new String(message, StandardCharsets.UTF_8));
        System.out.println("Signature len : " + signature.length + " bytes");
        System.out.println("Valid         : " + valid);
 
        // Tamper test — real KMS throws KmsInvalidSignatureException instead of returning false
        byte[] tamperedMessage = "Document requiring a TAMPERED signature.".getBytes(StandardCharsets.UTF_8);
        boolean tamperedValid;
        try {
            tamperedValid = kms.kmsVerify(signingKeyId, tamperedMessage, signature);
        } catch (software.amazon.awssdk.services.kms.model.KmsInvalidSignatureException e) {
            // KMS explicitly rejects invalid signatures with an exception — this is correct behaviour
            tamperedValid = false;
        }
        System.out.println("Tampered valid: " + tamperedValid + "  <- Expected: false (KMS rejected tampered message)");
 
        // ----------------------------------------------------------------
        // STEP 4: Envelope Encryption (GenerateDataKey)
        // ----------------------------------------------------------------
        System.out.println("\n── STEP 4: Envelope Encryption (GenerateDataKey) ──");
 
        // Simulate a large payload — envelope encryption handles arbitrary sizes
        String largePayload = "CONFIDENTIAL CLOUD DATA: " + "X".repeat(500);
        byte[] largePlaintext = largePayload.getBytes(StandardCharsets.UTF_8);
 
        System.out.println("Plaintext size  : " + largePlaintext.length + " bytes");
 
        KmsIntegrationService.EnvelopeCiphertext envelope =
                kms.envelopeEncrypt(symmetricKeyId, largePlaintext);
 
        System.out.println("\nEnvelope bundle sizes:");
        envelope.printSizes();
 
        byte[] envelopeDecrypted = kms.envelopeDecrypt(symmetricKeyId, envelope);
        System.out.println("\nDecrypted size  : " + envelopeDecrypted.length + " bytes");
        System.out.println("Match           : " + Arrays.equals(largePlaintext, envelopeDecrypted));
 
        // ----------------------------------------------------------------
        // STEP 5: KMS vs Local BouncyCastle comparison
        // ----------------------------------------------------------------
        System.out.println("\n── STEP 5: KMS vs Local BouncyCastle Comparison ──");
 
        // For comparison we need the public key locally — KMS exposes it via GetPublicKey.
        // Here we generate a local keypair at the same spec for the comparison demo.
        // In a real deployment you'd call kmsClient.getPublicKey() to get the CMK's public key.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096, new SecureRandom());
        KeyPair localKeyPair = kpg.generateKeyPair();
 
        byte[] comparisonPlaintext = "Comparison test payload.".getBytes(StandardCharsets.UTF_8);
        kms.compareKmsVsLocal(
                encryptKeyId,
                localKeyPair.getPublic(),   // local public key (stand-in; see note above)
                localKeyPair.getPrivate(),
                comparisonPlaintext
        );
 
        // ----------------------------------------------------------------
        // STEP 6: Full audit log
        // ----------------------------------------------------------------
        System.out.println("\n── STEP 6: Full Audit Log ─────────────────────────");
        kms.getAuditLogger().printFullLog();
 
        kms.close();
        System.out.println("Demo complete.");
    }
}