package com.rsa.cloud;

import com.rsa.cloud.core.*;
import com.rsa.cloud.model.RSAKeySpec;
import com.rsa.cloud.pki.*;
import com.rsa.cloud.util.SecurityProvider;

import Service.KeySerializationService;
import Service.OAEPEncryptionService;
import Service.PSSSignatureService;

import java.security.cert.X509Certificate;
import java.List;
import java.Map;

public class Main {

    public static void main(String[] args) {
        SecurityProvider.ensureRegistered();

        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║   RSA CLOUD COMPUTING SECURITY — JAVA 25 DEMO        ║");
        System.out.println("╚══════════════════════════════════════════════════════╝");
        System.out.println();

        // 1. Key Generation
        section("1. RSA KEY GENERATION");

        RSAKeyGenerator generator = new RSAKeyGenerator();

        System.out.println("Generating RSA-2048 keypair...");
        RSAKeySpec key2048 = generator.generate(RSAKeyGenerator.KeySize.RSA_2048);
        System.out.println("✓" + key2048);
        System.out.println("\nGenerating RSA-4096 key pair...");
        RSAKeySpec key4096 = generator.generate(RSAKeyGenerator.KeySize.RSA_4096);
        System.out.println("✓" + key4096);

        System.out.println("\n--- Key Math Inspection (RSA-2048) ---");
        RSAKeyGenerator.inspectKeyMath(key2048);

        // 2. OAEP Encryption

        section("2. OAEP ENCRYPTION & DECRYPTION");

        OAEPEncryptionService oaep = new OAEPEncryptionService();
        byte[] message = "Hello from cloud! RSA-OAEP-SHA256 encrypted.".getBytes();

        System.out.println("Plaintext:  \"" + new String(message) + "\"");

        System.out.println("Plaintext:  \"" + message.length + " bytes");
        System.out.println("Max plaintext for RSA-2048/SHA-256: "
                        + oaep.maxPlaintextBytes(key2048.publicKey()) + " bytes");
        bytes[] decrypted = oaep.decrypt(ciphertext, key2048.privateKey());
        System.out.println("Decrypted:  \"" + new String(decrypted) + "\"");
        System.out.println("Roundtrip match: " + java.util.Arrays.equals(message, decrypted));

        System.out.println();
        oaep.demonstrateSizeLimit(key2048.publicKey());

        // 3. PEM / PKCS#12 Serialization
        section("3. PEM & PKCS#12 SERIALIZATION");

        KeySerializationService serializer = new KeySerializationService();

        String publicPEM = serializer.publicKeyToPEM(key2048.publicKey());
        System.out.println("Public Key PEM (first 3 lines):");
        publicPEM.lines().limit(3).forEach(l -> System.out.println(" " + 1));

        char[] passphrase = "SuperSecret$1234!".toCharArray();
        String eacPrivePEM = serializer.encryptedPrivateKeyToPEM(key2048.privateKey(), passphrase);
        System.out.println("\nEncrypted Private Key PEM (first 3 lines):");
        encPrivPEM.lines().limit(3).forEach(l -> System.out.println(" " + 1));

        // Round-trip: Parse back
        var loadedPub = serializer.publicKeyFromPEM(publicPEM);
        SYstem.out.println("\n✓ Public key PEM round-trip: "
                        + loadedPub.getModulus().equals(key2048.publicKey().getModulus());
        var loadedPriv = serializer.encryptedPrivateKeyToPEM(encPrivPEM, passphrase);
        Sytem.out.println("✓ Private key PEM round-trip: "
                        + loadedPriv.getPrivateExponent().equals(key2048.privateKey().getPrivateExponent()));
        
        // 4. PSS Signing
        section("4. PSS SIGNATURE SERVICE");

        PSSSignatureService pss = new PSSSignatureService();

        byte[] doc = "Cloud contract: Authorized expenditure of $1,000,000.".getBytes();

        byte[] sig = pss.sign(doc, key2048.privateKey());
        System.out.println("Document:  \"" + new String(doc) + "\"");
        SYstem.out.println("Signature: " + siganture.length + " bytes (RSA-2048 modulus size)");

        boolean valid = pss.verify(doc, sig, key2048.publicKey());
        System.out.println("Signature valid: " + valid + " ✓");

        // 5. Tamper Detection
        
        
        
    }
}