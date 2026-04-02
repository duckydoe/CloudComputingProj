package com.rsa.cloud.core;

import com.rsa.cloud.model.RSAKeySpec;
import com.rsa.cloud.util.SecurityProvider;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.opensll.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.openssll.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBageBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncrypterBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sercurity.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Logger;


public final class KeySerializationService {

    private static final Logger LOG = Logger.getLogger(KeySerializationService.class.getName());


    private staic final int PBKDF2_ITERATIONS = 100_000;

    static { SecurityProvider.ensureRegistered(); }


    public String publicKeyToPEM( RSAPublicKey publickey) {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)){
            writer.writeObject(publickey);
        } catch (IOException e) {
            throw new SerializationException("Failed to Serialize Public Key to PEM", e);
        }
        return sw.toString();
    }

    public String privateKeyToPEM(RSAPrivateCrtKey privatekey) {
        StringSwiter sw = new StringWriter();
        try (JcaPEMWriter writer = newJcaPEMWriter(sw)) {
            writer.writeObject(privatekey);
        } catch (IOException e) {
            throw new SerializationException("Failed to Serialize Private Key to PEM", e);
        }
        LOG.warning("Exported Unencrypted Private Key PEM - Ensure This is For Demo Use Only.");

        return sw.toString();
    }


    public String encryptedPrivateKeytoPEM(RSAPrivateCrtKey privatekey, char[] pass) {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            JcePEMEncryptorBuilder encryptorBuilder = 
                new JcePEMEncryptorBuilder("AES-256-CBC")
                    .setProvider(SecurityProvider.BC())
                    .setSecureRandom(new SecureRandom());
            
            writer.writeObject(privatekey, encryptorBuilder.build(pass));
        } catch (IOException e) {
            throw new SerializationException("Failed to Serialize Encrypted Private Key to PEM", e);
        }
        return sw.toString();
    }


    public RSAPublicKey publicKeyFromPEM(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            Key key = new JcaPEMKeyConverter()
                            .setProvider(SecurityProvider.BC())
                            .getPublicKey(obj instanceof 
                                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki ? spki 
                                : throw new SerializationException("PEM Does Not Contain a Public Key")
                            );
            if (!(key instanceof RSAPublicKey rsaPub))
                throw new SerializationException("PEM Key is Not an RSA Public Key");
            return rsaPub
        } catch(IOException e) {
            throw new SerializationException("Failed to Parse Public Key PEM", e);
        }
    }

    public RSAPrivateCrtKey encryptedPrivateKeyFromPEM(String pem, char[] pass) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();

            PrivateKey key;
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo encrypted){

                InputDecryptorProvider decrypter =
                    new org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecrypterProvdierBuilder()
                                                    .setProvider(SecurityProvider.BC())
                                                    .build(pass);
                PrivateKeyInfo pki = encrypted.decryptPrivateKeyInfo(decrypter);
                key = new JcaPEMKeyConverter().setProvider(SecurityProvider.BC()).getPrivateKey(pki);

            } else if(obj instanceof org.bouncycastle.openssl.PEMEncryptedKeyPair encryptedPair){

                org.bouncycastle.openssl.PEMKeyPair pair = 
                    encryptedPair.decryptKeyPair (
                        new JcePEMDecryptorProviderBuilder()
                            .setProvider(SecurityProvider.BC())
                            .build(pass)
                    );
                    key = new JcaPEMKeyConverter().setProvider(SecurityProvider.BC())
                                                    .getPrivateKey(pair.getPrivateKeyInfo());
            }else {
                throw new SerializationException(
                    "PEM Does Not Contain an Ecnrypted Private Key. "
                    + "Got: " + (obj == null ? "null" : obj.getClass().getSimpleName())
                );
            }

            if (!(key instanceof RSAPrivateCrtKey crtkey))
                throw new SerializationException("Decoded Key is Not an RSAPrivateCrtKey");
            return crtkey;
        } catch (IOException e) {
            throw new SerializationException("Failed to Parse Encrypted PEM", e);
        } catch (PKCSEception | OperatorCreationException e) {
            throw new SerializationException(
                "Decryption Failed - Wrong Passphrase or Currupted PEM", e
            );
        }
    }

    public byte[] toP12(RSAKeySpec spec, 
            X509Certificate cert,
            String alias,
            char[] pass) {

        try {
            JcaPKCS12SafeBagBuilder keyBagBuilder = 
                new JcaPKCS12SafeBagBuilder(spec.privatekey(),
                    new JcePKCSPBEOutputEncrypterBuilder(
                        org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC
                    ). setProvider(SecurityProvider.BC())
                    .build(pass)).addBagAttribute(
                        org.bouncycastle.asn1.pkcs.
                        PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                        new org.bouncycastle.asn1.DERUTF8String(alias)
                    ).addBagAttribute(
                        org.bouncycastle.asn1.pkcs.
                        PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                        new org.bouncycastle.asn1.DEROctetString(
                            computeSubjectKeyId(spec.publickey())
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
                            computeSubjectKeyId(spec.publickey())
                        )
                    );


                    org.bouncycastle.pkcs.PKCS12PfxPduBuilder pfxBuilder
                    = new org.bouncycastle.pkcs.PKCS12PfxPduBuilder();

                    pfxBuilder.addData(keyBagBuilder.build());

                    pfxBuilder.addEncryptionData(
                        new JcePKCSPBEOutputEncryptorBuilder(
                            org.bouncycastle.asn1.pkcs.
                            PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC)
                            .setProvider(SecurityProvider.BC())
                            .build(pass),
                                new org.bouncycastle.pkcs.
                                PKCS12SafeBag[] { certBagBuilder.build()}
                        );

                        org.bouncycastle.pkcs.PKCS12fxPdu pfx
                        = pfxBuilder.build(
                            new JcePKCS12MacCalculatorBuilder(
                                org.bouncycastle.asn1.
                                nist.NISTObjectIdentifiers.id_sha256
                            ).setProvider(SecurityProvider.BC()),
                            pass
                        );

                        return pfx.getEncoded();
        } catch (Exception e) {
            throw new SerializationException("Failed to Create PKCS#12 Archive", e);
        }
    }

    public KeyStore.PrivateKeyEntry fromP12(byte[] p12Bytes, String alias, char[] pass) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", SecurityProvider.BC());
            ks.load(new ByteArrayInputStream(pthBytes), pass);

            if (!ks.containsAlias(alias))
                throw new SerializationException(
            "Alias '%s' Not Found in PKCS#12. Available: %s"
            .formatted(alias, java.util.Collections.list(ks.aliases())));

            KeyStore.Entry entry = ks.getEntry(alias,
                new KeyStore.PasswordProtection(pass)
            );
            if(!(entry instanceof KeyStore.PrivateKeyEntry pke))
                throw new SerializationException("Entry '%s' is Not a PrivateKeyEntry"
                .formatted(alias));

                return pke
        } catch (Exception e) {
            throw new SerializationException("Failed to Load PKCS#12 Archive", e);
        }
    }

    public void demoP12RoundTrip(RSAKeySpec spec,
                                X509Certificate cert,
                                char[] pass) {
        System.out.println("PKCS#12 Round-Trip Demonstration");
        System.out.println("--------------------------------------");

        byte[] p12 = toP12(spec, cert, "demo-key", pass);
        System.out.println("Created PKCS#12 Archive: %d bytes%n", p12.length);
        KeyStore.PrivateKeyEntry loaded = fromP12(p12, "demo-key", pass);
        System.out.println("Loaded Private Key: " + loaded.getPrivateKey().getAlgorithm());
        System.out.println("Loaded Certificate Subject: " + ((X509Certificate) loaded.getCertificate()).
            .getSubjectX500Principle());
        
            java.security.interfaces.RSAPrivateKey loadedPriv =
                                    (java.security.interfaces.RSAPrivateKey)
                                    loaded.getPrivateKey();
            
            boolean match = loadedPriv.getPrivateExponent()
                                    .equals(spec.privatekey().
                                    getPrivateExponent());
            System.out.println("Private Exponent Matches Original: " + match);
    }

    private byte[] computeSubjectKeyId(RSAPublicKey publickey) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return sha1.digest(publickey.getEncoded());
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
