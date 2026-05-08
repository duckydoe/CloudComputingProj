package com.crypto.demo.kms;
 
import com.crypto.demo.hybrid.HybridEncryptionService;
import com.crypto.demo.util.CryptoConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;
 
import java.net.URI;
 
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.time.Instant;
import java.util.*;
 
/**
 * AWS KMS INTEGRATION LAYER
 *
 * Demonstrates live AWS KMS operations using SDK v2, mirroring the local
 * BouncyCastle implementations in HybridEncryptionService.
 *
 * Operations covered:
 *   1. CreateKey        - Provision an RSA-4096 CMK in AWS KMS
 *   2. Encrypt          - KMS-side RSA-OAEP encryption
 *   3. Decrypt          - KMS-side RSA-OAEP decryption
 *   4. Sign             - KMS-side RSA-PSS signing
 *   5. Verify           - KMS-side RSA-PSS verification
 *   6. GenerateDataKey  - Envelope encryption (KMS generates AES key)
 *
 * Key design point:
 *   With KMS, the private key NEVER leaves the HSM.
 *   Every operation is logged in CloudTrail automatically — this is the
 *   auditability advantage over local key management.
 *
 * Prerequisites (set as environment variables or AWS config):
 *   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
 *
 * Maven dependencies needed in pom.xml:
 *   software.amazon.awssdk : kms : 2.25.x
 *   software.amazon.awssdk : sts : 2.25.x  (for caller identity logging)
 */
public class KmsIntegrationService {
 
    // GCM constants (mirrors HybridEncryptionService)
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS    = 128;
 
    private final KmsClient kmsClient;
    private final AuditLogger auditLogger;
 
    static { CryptoConfig.init(); }
 
    // ----------------------------------------------------------------
    // CONSTRUCTOR
    // ----------------------------------------------------------------
 
    /**
     * Default constructor. Auto-detects LocalStack: if LOCALSTACK_ENDPOINT env var
     * is set (e.g. http://localhost:4566), the client points there with dummy
     * credentials — no real AWS account needed. Otherwise uses real AWS.
     */
    public KmsIntegrationService() {
        this.kmsClient   = buildKmsClient();
        this.auditLogger = new AuditLogger();
    }
 
    /** Constructor for testing with a pre-built KmsClient. */
    public KmsIntegrationService(KmsClient kmsClient) {
        this.kmsClient   = kmsClient;
        this.auditLogger = new AuditLogger();
    }
 
    /**
     * Builds a KmsClient pointed at LocalStack if LOCALSTACK_ENDPOINT is set,
     * otherwise builds a standard client against real AWS.
     */
    private static KmsClient buildKmsClient() {
        String endpoint = System.getenv("LOCALSTACK_ENDPOINT");
        if (endpoint != null && !endpoint.isBlank()) {
            System.out.println("[KMS] LocalStack mode -> " + endpoint);
            return KmsClient.builder()
                    .endpointOverride(URI.create(endpoint))
                    .region(Region.US_EAST_1)
                    .credentialsProvider(StaticCredentialsProvider.create(
                            AwsBasicCredentials.create("test", "test")))
                    .build();
        }
        System.out.println("[KMS] Real AWS mode (resolving credentials from environment)");
        return KmsClient.builder()
                .region(Region.of(
                        System.getenv().getOrDefault("AWS_REGION", "us-east-1")))
                .build();
    }
 
    // ----------------------------------------------------------------
    // 1. CREATE KEY
    // ----------------------------------------------------------------
 
    /**
     * Provisions a new RSA-4096 asymmetric CMK in AWS KMS.
     *
     * KeyUsage    = ENCRYPT_DECRYPT  -> allows Encrypt + Decrypt API calls
     * KeySpec     = RSA_4096         -> matches our local 4096-bit RSA keys
     *
     * The private key is generated inside the HSM and never exported.
     *
     * @param description Human-readable label for the key in the KMS console.
     * @return The KMS Key ID (UUID format) for use in subsequent operations.
     */
    public String createRsaKey(String description) {
        auditLogger.log("CreateKey", "KeySpec=RSA_4096, KeyUsage=ENCRYPT_DECRYPT");
 
        CreateKeyRequest request = CreateKeyRequest.builder()
                .description(description)
                .keySpec(KeySpec.RSA_4096)
                .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                .build();
 
        CreateKeyResponse response = kmsClient.createKey(request);
        String keyId = response.keyMetadata().keyId();
 
        auditLogger.log("CreateKey SUCCESS", "KeyId=" + keyId);
        return keyId;
    }
 
    /**
     * Provisions a new RSA-4096 asymmetric CMK in AWS KMS for signing.
     *
     * KeyUsage = SIGN_VERIFY -> allows Sign + Verify API calls.
     * A separate key is required because KMS does not allow a single key
     * to be used for both encryption and signing.
     *
     * @param description Human-readable label.
     * @return The KMS Key ID.
     */
    public String createSigningKey(String description) {
        auditLogger.log("CreateKey (Signing)", "KeySpec=RSA_4096, KeyUsage=SIGN_VERIFY");
 
        CreateKeyRequest request = CreateKeyRequest.builder()
                .description(description)
                .keySpec(KeySpec.RSA_4096)
                .keyUsage(KeyUsageType.SIGN_VERIFY)
                .build();
 
        CreateKeyResponse response = kmsClient.createKey(request);
        String keyId = response.keyMetadata().keyId();
 
        auditLogger.log("CreateKey (Signing) SUCCESS", "KeyId=" + keyId);
        return keyId;
    }
 
    /**
     * Provisions a symmetric AES-256 CMK in AWS KMS.
     *
     * This is REQUIRED for GenerateDataKey (envelope encryption).
     * KMS rule: GenerateDataKey only works with symmetric keys, not RSA keys.
     *
     * KeySpec  = SYMMETRIC_DEFAULT -> AES-256-GCM inside KMS
     * KeyUsage = ENCRYPT_DECRYPT
     *
     * @param description Human-readable label.
     * @return The KMS Key ID.
     */
    public String createSymmetricKey(String description) {
        auditLogger.log("CreateKey (Symmetric)", "KeySpec=SYMMETRIC_DEFAULT, KeyUsage=ENCRYPT_DECRYPT");
 
        CreateKeyRequest request = CreateKeyRequest.builder()
                .description(description)
                .keySpec(KeySpec.SYMMETRIC_DEFAULT)
                .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                .build();
 
        CreateKeyResponse response = kmsClient.createKey(request);
        String keyId = response.keyMetadata().keyId();
 
        auditLogger.log("CreateKey (Symmetric) SUCCESS", "KeyId=" + keyId);
        return keyId;
    }
 
    // ----------------------------------------------------------------
    // 2. ENCRYPT  (KMS-side RSA-OAEP)
    // ----------------------------------------------------------------
 
    /**
     * Encrypts plaintext using KMS RSA-OAEP-SHA-256.
     *
     * KMS limitation: plaintext must be <= 446 bytes for RSA_4096 + OAEP_SHA_256.
     * For larger data, use envelopeEncrypt() instead.
     *
     * @param keyId     KMS Key ID (from createRsaKey).
     * @param plaintext Raw bytes to encrypt (max 446 bytes).
     * @return KMS ciphertext blob.
     */
    public byte[] kmsEncrypt(String keyId, byte[] plaintext) {
        auditLogger.log("Encrypt", "KeyId=" + keyId
                + ", Algorithm=RSAES_OAEP_SHA_256"
                + ", PlaintextBytes=" + plaintext.length);
 
        EncryptRequest request = EncryptRequest.builder()
                .keyId(keyId)
                .plaintext(SdkBytes.fromByteArray(plaintext))
                .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
                .build();
 
        EncryptResponse response = kmsClient.encrypt(request);
        byte[] ciphertext = response.ciphertextBlob().asByteArray();
 
        auditLogger.log("Encrypt SUCCESS", "CiphertextBytes=" + ciphertext.length);
        return ciphertext;
    }
 
    // ----------------------------------------------------------------
    // 3. DECRYPT  (KMS-side RSA-OAEP)
    // ----------------------------------------------------------------
 
    /**
     * Decrypts a KMS ciphertext blob using RSA-OAEP-SHA-256.
     *
     * The private key never leaves KMS — decryption happens inside the HSM.
     *
     * @param keyId      KMS Key ID used during encryption.
     * @param ciphertext Ciphertext blob returned by kmsEncrypt().
     * @return Decrypted plaintext bytes.
     */
    public byte[] kmsDecrypt(String keyId, byte[] ciphertext) {
        auditLogger.log("Decrypt", "KeyId=" + keyId
                + ", Algorithm=RSAES_OAEP_SHA_256"
                + ", CiphertextBytes=" + ciphertext.length);
 
        DecryptRequest request = DecryptRequest.builder()
                .keyId(keyId)
                .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
                .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
                .build();
 
        DecryptResponse response = kmsClient.decrypt(request);
        byte[] plaintext = response.plaintext().asByteArray();
 
        auditLogger.log("Decrypt SUCCESS", "PlaintextBytes=" + plaintext.length);
        return plaintext;
    }
 
    // ----------------------------------------------------------------
    // 4. SIGN  (KMS-side RSA-PSS)
    // ----------------------------------------------------------------
 
    /**
     * Signs a message using KMS RSA-PSS-SHA-256.
     *
     * KMS signs the raw message (not a pre-hashed digest) when using
     * RSASSA_PSS_SHA_256. The message must be <= 4096 bytes.
     * For larger payloads, hash locally and pass the digest.
     *
     * @param signingKeyId KMS Key ID (from createSigningKey).
     * @param message      Raw message bytes to sign.
     * @return DER-encoded RSA-PSS signature.
     */
    public byte[] kmsSign(String signingKeyId, byte[] message) {
        auditLogger.log("Sign", "KeyId=" + signingKeyId
                + ", Algorithm=RSASSA_PSS_SHA_256"
                + ", MessageBytes=" + message.length);
 
        SignRequest request = SignRequest.builder()
                .keyId(signingKeyId)
                .message(SdkBytes.fromByteArray(message))
                .messageType(MessageType.RAW)
                .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PSS_SHA_256)
                .build();
 
        SignResponse response = kmsClient.sign(request);
        byte[] signature = response.signature().asByteArray();
 
        auditLogger.log("Sign SUCCESS", "SignatureBytes=" + signature.length);
        return signature;
    }
 
    // ----------------------------------------------------------------
    // 5. VERIFY  (KMS-side RSA-PSS)
    // ----------------------------------------------------------------
 
    /**
     * Verifies a KMS RSA-PSS signature against a message.
     *
     * @param signingKeyId KMS Key ID used during signing.
     * @param message      Original message bytes.
     * @param signature    Signature bytes from kmsSign().
     * @return true if the signature is valid, false otherwise.
     */
    /**
     * Verifies a KMS RSA-PSS signature against a message.
     *
     * Note: real AWS KMS throws KmsInvalidSignatureException when the signature
     * is invalid, rather than returning false. This method catches that and
     * returns false cleanly so callers don't need to handle the exception.
     */
    public boolean kmsVerify(String signingKeyId, byte[] message, byte[] signature) {
        auditLogger.log("Verify", "KeyId=" + signingKeyId
                + ", Algorithm=RSASSA_PSS_SHA_256"
                + ", MessageBytes=" + message.length
                + ", SignatureBytes=" + signature.length);
 
        VerifyRequest request = VerifyRequest.builder()
                .keyId(signingKeyId)
                .message(SdkBytes.fromByteArray(message))
                .messageType(MessageType.RAW)
                .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PSS_SHA_256)
                .signature(SdkBytes.fromByteArray(signature))
                .build();
 
        try {
            VerifyResponse response = kmsClient.verify(request);
            boolean valid = response.signatureValid();
            auditLogger.log("Verify SUCCESS", "SignatureValid=" + valid);
            return valid;
        } catch (KmsInvalidSignatureException e) {
            // Real AWS KMS throws this instead of returning false for bad signatures
            auditLogger.log("Verify FAILED", "Invalid signature — KMS rejected it");
            return false;
        }
    }
 
    // ----------------------------------------------------------------
    // 6. ENVELOPE ENCRYPTION  (GenerateDataKey)
    // ----------------------------------------------------------------
 
    /**
     * ENVELOPE ENCRYPTION DEMO
     *
     * This is the AWS KMS recommended pattern for encrypting arbitrary-size data.
     *
     * Flow:
     *   1. Call KMS GenerateDataKey → KMS returns:
     *        - plaintext AES-256 key  (use locally, then discard)
     *        - encrypted AES-256 key  (store alongside ciphertext)
     *   2. Encrypt data locally with AES-256-GCM using the plaintext key.
     *   3. Discard the plaintext key from memory.
     *   4. Store: { encryptedDataKey, nonce, ciphertext } — KMS key never exposed.
     *
     * To decrypt:
     *   1. Call KMS Decrypt on the encryptedDataKey → get plaintext AES key back.
     *   2. Decrypt ciphertext locally with AES-256-GCM.
     *
     * Advantage: KMS only ever sees the 32-byte AES key, not your data.
     *
     * @param kmsKeyId  KMS CMK ID used to protect the data key.
     * @param plaintext Arbitrary-size data to encrypt.
     * @return EnvelopeCiphertext bundle (encryptedDataKey + nonce + ciphertext).
     */
    public EnvelopeCiphertext envelopeEncrypt(String kmsKeyId, byte[] plaintext)
            throws GeneralSecurityException {
 
        auditLogger.log("GenerateDataKey", "KeyId=" + kmsKeyId + ", KeySpec=AES_256");
 
        // Step 1: Ask KMS to generate a fresh AES-256 data key
        GenerateDataKeyRequest dataKeyRequest = GenerateDataKeyRequest.builder()
                .keyId(kmsKeyId)
                .keySpec(DataKeySpec.AES_256)
                .build();
 
        GenerateDataKeyResponse dataKeyResponse = kmsClient.generateDataKey(dataKeyRequest);
 
        byte[] plaintextDataKey  = dataKeyResponse.plaintext().asByteArray();
        byte[] encryptedDataKey  = dataKeyResponse.ciphertextBlob().asByteArray();
 
        auditLogger.log("GenerateDataKey SUCCESS",
                "PlaintextKeyBytes=" + plaintextDataKey.length
                + ", EncryptedKeyBytes=" + encryptedDataKey.length);
 
        // Step 2: Encrypt the actual data locally using the plaintext data key
        SecretKey aesKey = new SecretKeySpec(plaintextDataKey, "AES");
        byte[] nonce     = generateNonce();
        byte[] ciphertext = aesGcmEncrypt(plaintext, aesKey, nonce);
 
        auditLogger.log("LocalAES-GCM Encrypt",
                "PlaintextBytes=" + plaintext.length
                + ", CiphertextBytes=" + ciphertext.length);
 
        // Step 3: Zero out the plaintext key — it must not linger in memory
        Arrays.fill(plaintextDataKey, (byte) 0);
 
        return new EnvelopeCiphertext(encryptedDataKey, nonce, ciphertext);
    }
 
    /**
     * Decrypts an EnvelopeCiphertext bundle.
     *
     * @param kmsKeyId  KMS CMK ID used during envelopeEncrypt().
     * @param bundle    EnvelopeCiphertext from envelopeEncrypt().
     * @return Decrypted plaintext.
     */
    public byte[] envelopeDecrypt(String kmsKeyId, EnvelopeCiphertext bundle)
            throws GeneralSecurityException {
 
        auditLogger.log("Decrypt (data key)", "KeyId=" + kmsKeyId
                + ", EncryptedKeyBytes=" + bundle.encryptedDataKey().length);
 
        // Step 1: Ask KMS to decrypt the encrypted data key
        DecryptRequest decryptRequest = DecryptRequest.builder()
                .keyId(kmsKeyId)
                .ciphertextBlob(SdkBytes.fromByteArray(bundle.encryptedDataKey()))
                .build();
 
        DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
        byte[] plaintextDataKey = decryptResponse.plaintext().asByteArray();
 
        auditLogger.log("Decrypt (data key) SUCCESS",
                "PlaintextKeyBytes=" + plaintextDataKey.length);
 
        // Step 2: Decrypt the ciphertext locally
        SecretKey aesKey  = new SecretKeySpec(plaintextDataKey, "AES");
        byte[] plaintext  = aesGcmDecrypt(bundle.ciphertext(), aesKey, bundle.nonce());
 
        auditLogger.log("LocalAES-GCM Decrypt",
                "CiphertextBytes=" + bundle.ciphertext().length
                + ", PlaintextBytes=" + plaintext.length);
 
        // Zero out the recovered plaintext key
        Arrays.fill(plaintextDataKey, (byte) 0);
 
        return plaintext;
    }
 
    // ----------------------------------------------------------------
    // KMS vs LOCAL COMPARISON
    // ----------------------------------------------------------------
 
    /**
     * Compares KMS encryption output vs local BouncyCastle RSA-OAEP encryption.
     *
     * Key insight: the ciphertexts will NOT be identical (OAEP is randomized),
     * but BOTH should decrypt to the same plaintext. This validates that KMS
     * and BouncyCastle implement the same RSA-OAEP-SHA-256 standard correctly.
     *
     * @param kmsKeyId      KMS CMK ID.
     * @param rsaPublicKey  Corresponding RSA public key (exported from KMS via GetPublicKey).
     * @param rsaPrivateKey Local RSA private key (for BouncyCastle decryption side only).
     * @param plaintext     Data to encrypt (max 190 bytes for local RSA, 446 for KMS).
     */
    public void compareKmsVsLocal(String kmsKeyId,
                                  PublicKey rsaPublicKey,
                                  PrivateKey rsaPrivateKey,
                                  byte[] plaintext) throws GeneralSecurityException {
 
        System.out.println("\n=== KMS vs Local BouncyCastle Comparison ===");
 
        // --- KMS path ---
        byte[] kmsCiphertext  = kmsEncrypt(kmsKeyId, plaintext);
        byte[] kmsDecrypted   = kmsDecrypt(kmsKeyId, kmsCiphertext);
 
        // --- Local BouncyCastle path ---
        byte[] localCiphertext = localRsaOaepEncrypt(plaintext, rsaPublicKey);
        byte[] localDecrypted  = localRsaOaepDecrypt(localCiphertext, rsaPrivateKey);
 
        // --- Results ---
        System.out.println("\n[KMS]");
        System.out.println("  Ciphertext length : " + kmsCiphertext.length + " bytes");
        System.out.println("  Decrypted match   : " + Arrays.equals(plaintext, kmsDecrypted));
 
        System.out.println("\n[Local BouncyCastle]");
        System.out.println("  Ciphertext length : " + localCiphertext.length + " bytes");
        System.out.println("  Decrypted match   : " + Arrays.equals(plaintext, localDecrypted));
 
        System.out.println("\n[Ciphertexts identical?] "
                + Arrays.equals(kmsCiphertext, localCiphertext)
                + "  <- Expected: false (OAEP is randomized)");
        System.out.println("[Both decrypt correctly?] "
                + (Arrays.equals(plaintext, kmsDecrypted)
                && Arrays.equals(plaintext, localDecrypted))
                + "  <- Expected: true");
        System.out.println("=============================================\n");
    }
 
    // ----------------------------------------------------------------
    // LOCAL RSA-OAEP (BouncyCastle) — for comparison only
    // ----------------------------------------------------------------
 
    private byte[] localRsaOaepEncrypt(byte[] plaintext, PublicKey rsaPublicKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey, buildOaepParams());
        return cipher.doFinal(plaintext);
    }
 
    private byte[] localRsaOaepDecrypt(byte[] ciphertext, PrivateKey rsaPrivateKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPadding",
                BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey, buildOaepParams());
        return cipher.doFinal(ciphertext);
    }
 
    private OAEPParameterSpec buildOaepParams() {
        return new OAEPParameterSpec(
                "SHA-256", "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
    }
 
    // ----------------------------------------------------------------
    // AES-256-GCM helpers (local — mirrors HybridEncryptionService)
    // ----------------------------------------------------------------
 
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
    // AUDIT LOGGER
    // ----------------------------------------------------------------
 
    /**
     * Lightweight audit logger that prints every KMS API call with a timestamp.
     *
     * In production, AWS CloudTrail does this automatically for every KMS call.
     * This logger demonstrates the same auditability concept locally.
     */
    public static class AuditLogger {
        private final List<String> log = new ArrayList<>();
 
        public void log(String operation, String details) {
            String entry = "[" + Instant.now() + "] KMS::" + operation + " | " + details;
            log.add(entry);
            System.out.println(entry);
        }
 
        /** Prints the full audit trail for this session. */
        public void printFullLog() {
            System.out.println("\n=== FULL KMS AUDIT LOG ===");
            log.forEach(System.out::println);
            System.out.println("==========================\n");
        }
 
        public List<String> getLog() {
            return Collections.unmodifiableList(log);
        }
    }
 
    // ----------------------------------------------------------------
    // RESULT BUNDLES
    // ----------------------------------------------------------------
 
    /**
     * Envelope encryption result bundle.
     *
     * encryptedDataKey = AES-256 key encrypted by KMS CMK  (512 bytes for RSA_4096)
     * nonce            = GCM nonce                          (12 bytes)
     * ciphertext       = AES-GCM encrypted data             (plaintext + 16 byte tag)
     *
     * Store all three fields. The encryptedDataKey is safe to store alongside
     * the ciphertext — without the KMS CMK it is computationally infeasible
     * to decrypt.
     */
    public record EnvelopeCiphertext(
            byte[] encryptedDataKey,
            byte[] nonce,
            byte[] ciphertext
    ) {
        public void printSizes() {
            System.out.println("  Encrypted data key : " + encryptedDataKey.length + " bytes");
            System.out.println("  GCM nonce          : " + nonce.length            + " bytes");
            System.out.println("  Ciphertext         : " + ciphertext.length       + " bytes");
        }
    }
 
    // ----------------------------------------------------------------
    // CLEANUP
    // ----------------------------------------------------------------
 
    /** Returns the audit logger so callers can print the full session log. */
    public AuditLogger getAuditLogger() {
        return auditLogger;
    }
 
    /**
     * Closes the KMS client. Call this when done to release SDK resources.
     */
    public void close() {
        kmsClient.close();
    }
}