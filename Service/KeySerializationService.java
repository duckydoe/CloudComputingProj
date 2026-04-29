package com.rsa.cloud.core;

import com.rsa.cloud.model.RSAKeySpec;
import com.rsa.cloud.util.SecurityProvider;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Logger;
/*
* Key Serialization Service
*
*   Serialized and deserializes RSA keys in the formats used across
* cloud-infrastructure, enterprise systems, and standard PKI
*
* Formats Supported:
*      1. PEM - Privacy Enhanced Mail (RFC 7468)
*           The most common format in Linux/cloud environments.
*      2. PKCS#8 - Public Key Cryptography Standard #8
*           Algorithm-agnostic private key container
*                PrivateKeyInfo
*                EncryptedPrivateKeyInfo
*      3. PKCS#12 - Personal Information Exchanged Syntax (RFC 7292)
*           Binary format bundling: 
*               private key + certificate 
*               + optional chain certificates
*           Password-protected using AES-256-CBC for key
*            encryption and SHA-256 for MAC.
*           File extensions:
*               .p12 (general), .pfx (Windows legacy naming)
*
*/

public final class KeySerializationService {

    private static final Logger LOG = Logger.getLogger(KeySerializationService.class.getName());


    private static final int PBKDF2_ITERATIONS = 100_000;

    static { SecurityProvider.ensureRegistered(); }


    public String publicKeyToPEM( RSAPublicKey publicKey) {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)){
            writer.writeObject(publicKey);
        } catch (IOException e) {
            throw new SerializationException("Failed to Serialize Public Key to PEM", e);
        }
        return sw.toString();
    }

    public String privateKeyToPEM(RSAPrivateCrtKey privateKey) {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(privateKey);
        } catch (IOException e) {
            throw new SerializationException("Failed to Serialize Private Key to PEM", e);
        }
        LOG.warning("Exported Unencrypted Private Key PEM - Ensure This is For Demo Use Only.");

        return sw.toString();
    }


    public String encryptedPrivateKeyToPEM(RSAPrivateCrtKey privateKey, char[] passphrase) {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            JcePEMEncryptorBuilder encryptorBuilder = 
                new JcePEMEncryptorBuilder("AES-256-CBC")
                    .setProvider(SecurityProvider.BC())
                    .setSecureRandom(new SecureRandom());
            
            writer.writeObject(privateKey, encryptorBuilder.build(passphrase));
        } catch (IOException e) {
            throw new SerializationException("Failed to Serialize Encrypted Private Key to PEM", e);
        }
        return sw.toString();
    }


    public RSAPublicKey publicKeyFromPEM(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();

            if (!(obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki))
                throw new SerializationException(
                    "PEM does not contain a public key. Got: "
                    + (obj == null ? "null" : obj.getClass().getSimpleName()));

            Key key = new JcaPEMKeyConverter()
                    .setProvider(SecurityProvider.BC())
                    .getPublicKey(spki);

            if (!(key instanceof RSAPublicKey rsaPub))
                throw new SerializationException("PEM key is not an RSA public key");

            return rsaPub;
        } catch(IOException e) {
            throw new SerializationException("Failed to parse public key PEM", e);
        }
    }

    public RSAPrivateCrtKey encryptedPrivateKeyFromPEM(String pem, char[] passphrase) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();

            PrivateKey key;
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo encrypted){

                InputDecryptorProvider decrypter =
                    new org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder()
                                                    .setProvider(SecurityProvider.BC())
                                                    .build(passphrase);
                PrivateKeyInfo pki = encrypted.decryptPrivateKeyInfo(decrypter);
                key = new JcaPEMKeyConverter().setProvider(SecurityProvider.BC()).getPrivateKey(pki);

            } else if(obj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair encryptedPair){

                org.bouncycastle.openssl.PEMKeyPair pair = 
                    encryptedPair.decryptKeyPair (
                        new JcePEMDecryptorProviderBuilder()
                            .setProvider(SecurityProvider.BC())
                            .build(passphrase)
                    );
                    key = new JcaPEMKeyConverter().setProvider(SecurityProvider.BC())
                                                    .getPrivateKey(pair.getPrivateKeyInfo());
            }else {
                throw new SerializationException(
                    "PEM Does Not Contain an Encrypted Private Key. "
                    + "Got: " + (obj == null ? "null" : obj.getClass().getSimpleName())
                );
            }

            if (!(key instanceof RSAPrivateCrtKey crtKey))
                throw new SerializationException("Decoded Key is Not an RSAPrivateCrtKey");
            return crtKey;
        } catch (IOException e) {
            throw new SerializationException("Failed to Parse Encrypted PEM", e);
        } catch (PKCSException | OperatorCreationException e) {
            throw new SerializationException(
                "Decryption Failed - Wrong passphrase or Corrupted PEM", e
            );
        }
    }

    public byte[] toP12(RSAKeySpec spec, 
            X509Certificate cert,
            String alias,
            char[] passphrase) {

        try {
            JcaPKCS12SafeBagBuilder keyBagBuilder = 
                new JcaPKCS12SafeBagBuilder(spec.privateKey(),
                    new JcePKCSPBEOutputEncryptorBuilder(
                        org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC
                    ).setProvider(SecurityProvider.BC())
                    .build(passphrase)).addBagAttribute(
                        org.bouncycastle.asn1.pkcs.
                        PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                        new org.bouncycastle.asn1.DERUTF8String(alias)
                    ).addBagAttribute(
                        org.bouncycastle.asn1.pkcs.
                        PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                        new org.bouncycastle.asn1.DEROctetString(
                            computeSubjectKeyId(spec.publicKey())
                        )
                    );

                    JcaPKCS12SafeBagBuilder certBagBuilder 
                    = new JcaPKCS12SafeBagBuilder(cert).addBagAttribute(
                        org.bouncycastle.asn1.pkcs.
                        PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                        new org.bouncycastle.asn1.DERUTF8String(alias)
                    ).addBagAttribute(
                        org.bouncycastle.asn1.pkcs.
                        PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                        new org.bouncycastle.asn1.DEROctetString(
                            computeSubjectKeyId(spec.publicKey())
                        )
                    );


                    org.bouncycastle.pkcs.PKCS12PfxPduBuilder pfxBuilder
                    = new org.bouncycastle.pkcs.PKCS12PfxPduBuilder();

                    pfxBuilder.addData(keyBagBuilder.build());

                    pfxBuilder.addEncryptedData(
                        new JcePKCSPBEOutputEncryptorBuilder(
                            org.bouncycastle.asn1.pkcs.
                            PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC)
                            .setProvider(SecurityProvider.BC())
                            .build(passphrase),
                                new org.bouncycastle.pkcs.
                                PKCS12SafeBag[] { certBagBuilder.build()}
                        );

                        org.bouncycastle.pkcs.PKCS12PfxPdu pfx
                        = pfxBuilder.build(
                            new JcePKCS12MacCalculatorBuilder(
                                org.bouncycastle.asn1.
                                nist.NISTObjectIdentifiers.id_sha256
                            ).setProvider(SecurityProvider.BC()),
                            passphrase
                        );

                        return pfx.getEncoded();
        } catch (Exception e) {
            throw new SerializationException("Failed to Create PKCS#12 Archive", e);
        }
    }

    public KeyStore.PrivateKeyEntry fromP12(byte[] p12Bytes, String alias, char[] passphrase) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", SecurityProvider.BC());
            ks.load(new ByteArrayInputStream(p12Bytes), passphrase);

            if (!ks.containsAlias(alias))
                throw new SerializationException(
            "Alias '%s' Not Found in PKCS#12. Available: %s"
            .formatted(alias, java.util.Collections.list(ks.aliases())));

            KeyStore.Entry entry = ks.getEntry(alias,
                new KeyStore.PasswordProtection(passphrase)
            );
            if(!(entry instanceof KeyStore.PrivateKeyEntry pke))
                throw new SerializationException("Entry '%s' is Not a privateKeyEntry"
                .formatted(alias));

                return pke;
        } catch (Exception e) {
            throw new SerializationException("Failed to Load PKCS#12 Archive", e);
        }
    }

    public void demonstrateP12RoundTrip(RSAKeySpec spec,
                                X509Certificate cert,
                                char[] passphrase) {
        System.out.println("PKCS#12 Round-Trip Demonstration");
        System.out.println("--------------------------------------");

        byte[] p12 = toP12(spec, cert, "demo-key", passphrase);
        System.out.printf("Created PKCS#12 Archive: %d bytes%n", p12.length);
        KeyStore.PrivateKeyEntry loaded = fromP12(p12, "demo-key", passphrase);
        System.out.println("Loaded Private Key: " + loaded.getPrivateKey().getAlgorithm());
        System.out.println("Loaded Certificate Subject: " + ((X509Certificate) loaded.getCertificate()).getSubjectX500Principal());
        
            java.security.interfaces.RSAPrivateKey loadedPriv =
                                    (java.security.interfaces.RSAPrivateKey)
                                    loaded.getPrivateKey();
            
            boolean match = loadedPriv.getPrivateExponent()
                                    .equals(spec.privateKey().
                                    getPrivateExponent());
            System.out.println("Private Exponent Matches Original: " + match);
    }

    private byte[] computeSubjectKeyId(RSAPublicKey publicKey) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return sha1.digest(publicKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new SerializationException("SHA-1 Not Available for SubjectKeyId Computation", e);
        }
    }

    public static final class SerializationException extends RuntimeException {
        public SerializationException(String msg) {
            super(msg); }
            public SerializationException(String msg, Throwable cause) {
                super(msg, cause);
            }
        }
    }
