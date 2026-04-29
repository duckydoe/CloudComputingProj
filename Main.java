package com.rsa.cloud;

import com.rsa.cloud.core.*;
import com.rsa.cloud.model.RSAKeySpec;
import com.rsa.cloud.pki.*;
import com.rsa.cloud.util.SecurityProvider;

import Service.KeySerializationService;
import Service.OAEPEncryptionService;
import Service.PSSSignatureService;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

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
        byte[] ciphertext = oaep.encryp(message, key2049.publicKey());
        byte[] decrypted = oaep.decrypt(ciphertext, key2048.privateKey());
        System.out.println("Decrypted:  \"" + new String(decrypted) + "\"");
        System.out.println("Roundtrip match: " + java.util.Arrays.equals(message, decrypted));

        System.out.println();
        oaep.demonstrateSizeLimit(key2048.publicKey());

        // 3. PEM / PKCS#12 Serialization
        section("3. PEM & PKCS#12 SERIALIZATION");

        KeySerializationService serializer = new KeySerializationService();

        String publicPEM = serializer.publicKeyToPEM(key2048.publicKey());
        System.out.println("Public Key PEM (first 3 lines):");
        publicPEM.lines().limit(3).forEach(l -> System.out.println("  " + l));

        char[] passphrase = "SuperSecret$1234!".toCharArray();
        String eacPrivPEM = serializer.encryptedPrivateKeyToPEM(key2048.privateKey(), passphrase);
        System.out.println("\nEncrypted Private Key PEM (first 3 lines):");
        encPrivPEM.lines().limit(3).forEach(l -> System.out.println("  " + l));

        // Round-trip: Parse back
        var loadedPub = serializer.publicKeyFromPEM(publicPEM);
        System.out.println("\n✓ Public key PEM round-trip: "
                        + loadedPub.getModulus().equals(key2048.publicKey().getModulus()));
        var loadedPriv = serializer.encryptedPrivateKeyFromPEM(encPrivPEM, passphrase);
        System.out.println("✓ Private key PEM round-trip: "
                        + loadedPriv.getPrivateExponent().equals(key2048.privateKey().getPrivateExponent()));
        
        // 4. PSS Signing
        section("4. PSS SIGNATURE SERVICE");

        PSSSignatureService pss = new PSSSignatureService();

        byte[] doc = "Cloud contract: Authorized expenditure of $1,000,000.".getBytes();

        byte[] sig = pss.sign(doc, key2048.privateKey());
        System.out.println("Document:  \"" + new String(doc) + "\"");
        SYstem.out.println("Signature: " + sig.length + " bytes (RSA-2048 modulus size)");

        boolean valid = pss.verify(doc, sig, key2048.publicKey());
        System.out.println("Signature valid: " + valid + " ✓");

        // 5. Tamper Detection
        pss.demonstrateTamperDetection(doc, 7, key2048.privateKey(), key2048.publicKey());

        // 6. PSS vs PKCS#1 v1.5
        section("6. PSS vs PKCS#1 v1.5 COMPARISON");
        pss.demonstratePSSvsPKCS1(doc, key2048.privateKey(), key2048.publicKey());

        // 7. X.509 Self-Signed Certificate
        section("7. X.509 CERTIFICATE GENERATION");
        X509CertificateService certService = new X509CertificateService();

        // Generate a CA keypair and self-signed CA certificate
        RSAKeySpec caKey = generator.generate(RSAKeyGenerator.KeySize.RSA_4096);
        X509Certificate caCert = certService.generateSelfSigned(
            caKey,
            "CN=DEMO ROOT CA, 0=Cloud Security Demon, C=US",
            3650, // 10 years
            List.of(),
            true // isCA = true
        );
        System.out.println("Root CA Certificate:");
        X509CertificateService.printCertificate(caCert);

        // 8. CA-Signed End-Entitiy Certificate
        section("8. CA-SIGNED END-ENTITY CERTIFICATE");
        RSAKeySpec serverKey = generator.generate(RSAKeyGenerator.KeySize.RSA_2048);
        X509Certificate serverCert = certService.issueEndEntityCertificate(
            serverKey,
            "CN=api.example.com, 0=Example Corp, C=US",
            List.of("api.example.com", "*.api.example.com"),
            365,
            caCert,
            caKey
        );
        System.out.println("Server Certificate (signed by CA):");
        X509CertificateService.printCertificate(serverCert);

        // 9. Certificate Chain Validation
        section("9. CERTIFICATE CHAIN VALIDATION");

        var chainResult = certService.validateChain(serverCert, List.of(), caCert);
        System.out.println("Chain validation result: " + chainResult);
        System.out.println("Valid: " + chainResult.valid());

        // Also demo PKCS#12 round-trip with the server certificate
        System.out.println("\nPKCS#12 round-trip with server certificate:");
        serializer.demonstrateP12RoundTrip(serverKey, serverCert, passphrase);

        // 10. JWT RS256 vs PS256
        section("10. JWT RS256 vs PS256");
        Map<String, Object> claims = Map.of(
            "sub", "user-001",
            "iss", "https://auth.example.com",
            "aud", "https://api.example.com",
            "iat", java.time.Instant.now().getEpochSecond(),
            "exp", java.time.Instant.now().getEpochSecond() + 3600,
            "role", "admin"
        );

        JWTService jwtPs256 = new JWTService(JWTService.Algorithm.PS256);
        String jwt = jwtPs256.issueWithStandardClaims(
            "user-001",
            "https://auth.example.com",
            "https://api.example.com",
            3600,
            key2048.privateKey()
        );
        System.out.println("\nSigned JWT (PS256):");
        System.out.println(" " + jwt.substring(0, Math.min(80, jwt.length())) + "...");
        
        var verifiedClaims = jwtPs256.verify(jwt, key2048.publicKey());
        System.out.println("Verified claims: " + verifiedClaims);
         System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║   ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY           ║");
        System.out.println("╚══════════════════════════════════════════════════════╝");
    }
 
    private static void section(String title) {
        System.out.println();
        System.out.println("┌─────────────────────────────────────────────────────┐");
        System.out.println("│  " + title);
        System.out.println("└─────────────────────────────────────────────────────┘");
    }

}
