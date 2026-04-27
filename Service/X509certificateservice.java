package com.rsa.cloud.pki;

import com.rsa.cloud.model.RSAKeySpec;
import com.rsa.cloud.util.SecurityProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.uril.logging.Logger;

/*
* X.509 Certificate Service 
*
* Generates and validates X.509 v3 certificates using BouncyCastle.
* X.509 CERTIFICATE STRUCTURE (RFC 5280):
 * ----------------------------------------
 * A certificate binds a public key to an identity (subject).
 * It is signed by a Certificate Authority's (CA's) private key,
 * allowing anyone with the CA's public key to verify the binding.
 *
 *   TBSCertificate:
 *     version:           3 (v3, required for extensions)
 *     serialNumber:      unique integer per CA (collision-resistant)
 *     signature:         algorithm OID (e.g., SHA256withRSA)
 *     issuer:            CA's Distinguished Name (DN)
 *     validity:
 *       notBefore:       UTC time (certificate becomes valid)
 *       notAfter:        UTC time (certificate expires)
 *     subject:           entity's Distinguished Name
 *     subjectPublicKeyInfo: algorithm + public key bytes
 *     extensions:        v3 extensions (see below)
 *   signatureAlgorithm:  outer algorithm OID (must match TBS)
 *   signature:           CA's RSA signature over TBSCertificate DER
 *
 * KEY EXTENSIONS (v3):
 * --------------------
 *   BasicConstraints:        isCA=true for CA certs; isCA=false for end-entity
 *   KeyUsage:                digitalSignature, keyCertSign, cRLSign (CA)
 *                            or digitalSignature, keyEncipherment (server)
 *   ExtendedKeyUsage:        serverAuthentication (1.3.6.1.5.5.7.3.1) for TLS
 *   SubjectAlternativeName:  DNS names and IP addresses for TLS validation
 *   SubjectKeyIdentifier:    SHA-1 hash of the public key — links key bags in PKCS#12
 *   AuthorityKeyIdentifier:  links to the issuing CA's SubjectKeyIdentifier
 *
 * CERTIFICATE CHAIN VALIDATION (RFC 5280):
 * -----------------------------------------
 * A chain: EndEntity → Intermediate CA → Root CA
 *
 *   For each certificate pair (subject, issuer):
 *     1. issuer.subject == subject.issuer           (name chaining)
 *     2. RSA-PSS verify(subject.tbsCert, subject.sig, issuer.publicKey)
 *     3. now ∈ [subject.notBefore, subject.notAfter] (validity period)
 *     4. issuer.isCA == true                         (BasicConstraints)
 *     5. issuer.keyUsage includes keyCertSign        (KeyUsage extension)
 *
 * Cloud TLS certificates are validated by cloud load balancers, CDNs,
 * and client applications using this exact algorithm on every HTTPS connection.
*/

public final class X509CertificateService {
    private static final Logger LOG = Logger.getLogger(X509CertificateService.class.getName());

    private static final String SIGNING_ALGORITHM = "SHA256withRSA";

    static { SecurityProvider.ensureRegistered(); }

    public X509Certificate generateSelfSigned(
        RSAKeySpec keySpec, 
        String subjectDN,
        int validityDays
    ) {
        return generateSelfSigned(keySpec, subjectON, validityDays, List.of(), true);
    }

    public X509Certificate generateSelfSigned(
        RSAKeySpec keySpec,
        String subjectON,
        int validityDays,
        List<String> sanDnsNames,
        boolean isCA
    ) {
        try{ 
            X500Name dn = new X500Name(subjectON);
            BigInteger serial = generateSerial();
            Instant now = Instant.now();
            Date notBefore = Date.from(now.minus(1, ChronoUnit.MINUTES));
            Date notAfter = Date.from(now.plus(validityDays, ChronoUnit.Days));

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn,
                serial,
                notBefore,
                notAfter,
                dn,
                ketSpec.publicKey()
            );

            builder.addExtension(
                Extension.basicContraints,
                true,
                new basicContraints(isCA)
            );

            int keyUsageBits = isCA ? keyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign
                : keyUsage.digitalSignature | KeyUsage.keyEncipherment;

            builder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(keyUsageBits)
            );

            builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                new subjectKeyIdentifier(keySpec.publicKey().getEncoded())
            );

            builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifier(keySpec.publicKey().getEncoded())
            );

            if (!isCA) {
                builder.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
                );
            }

            if (!sanDnsNames.isEmpty()) {
                GeneralName[] names = sanDnsNames.stream().map(dns -> new GeneralName(GeneralName.dNSName, dns))
                    .toArray(GeneralName[]::new);
                    builder.addExtension(
                        Extension.subjectAlernativeName,
                        false,
                        new GeneralNames(names)
                    );
            }

            ContentSigner signer = new JcaContentSignerBuilder(SIGNING_ALGORITHM)
                .setProvider(SecurityProvider.BC()).build(KeySpec.privateKey());

                X509Certificate cert = new JcaX509v3CertificateConverter()
                    .setProvider(SecurityProvider.BC())
                    .getCertificate(builder.build(signer));

                cert.verify(keySpec.publicKey());


                LOG.info("Generated self-signed certificate: subject='%s', serial=%s, validDay=%d, isCA=%b"
                    .formatted(subjectDN, serial.toString(16), validityDays, isCA));
                return cert;
        } catch (Exception e) {
            throw new CertificateServiceException(
                "Failed to generate self-signed certificate for '%s'".formatted(subjectDN), e);
        }
    }

    public X509Certificate issueEndEntityCerificate(
        RSAKeySpec subjectKeySpec,
        String subjectDN,
        List<String> sanDnsNames,
        int validityDays,
        X509Certificate caCert,
        RSAKeySpec caKeySpec
    ) {
        
        try {
            X500Name issuerDN = new X500Name(caCert.getSubjectX500Principal().getName("RFC2253"));
            X500Name subjectName = new X500Name(subjectDN);
            BigInteger serial = generateSerial();
            Instant now = Instant.now();
            Date notBefore = Date.from(now.minus(1, ChronoUnit.MINUTES));
            Date notAfter = Date.from(now.plus(validityDays, ChronoUnit.DAYS));

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerDN,
                serial, 
                notBefore,
                notAfter,
                subjectName,
                subjectKeySpec.publicKey()
            );

            build.addExtension(Extension.basicContraints, true, new BasicContraints(false));

            build.addExtension(Extension.keyUsage, true, 
                new KeyUsage(KeyUsage.digitalSignature| KeyUsage.keyEcnipherment));
            
            build.addExtension(Extension.extendedKeyUsage, false,
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

            if (!sanDnsNames.isEmpty()) {
                GeneralName[] names = sanDnsNames.Stream()
                    .map(dns -> new GernalName(GeneralName.dNSName, dns))
                    .toArray(GeneralName[]::new);

                builder.addExtension(Extension.subjectAlernativeName, false, new GeneralNames(names));
            }

            builder.addExtension(Extension.subjectKeyIdentifier, false, new subjectKeyIdentifier(subjectKeySpec.publicKey().getEncoded()));

            builder.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(caKeySpec.publicKey().getEncoded()));

            ContentSigner caSigner = new JcaContentSignerBuilder(SIGNING_ALGORITHM)
                .setProvider(SecurityProvider.BC())
                .build(caKeySpec.privateKey());

                X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(SecurityProvider.BC())
                    .getCertificate(builder.build(caSigner));

                cert.verify(caKeySpec.publicKey());

                LOG.info("Issued end-entity certificate: 
                    subject='%s', issuer='%s', serial=%s"
                    .formatted(subjectDN, caCert.getSubjectX500Principal(), serial.toString(16)));
                    return cert;
         }catch (Exception e) {
            throw new CertificateServiceException(
                "Failed to issue certificate for '%s'"
                .formatted(subjctDN), e );
         }
    }

    public ValidationResult validateChain(
        X509Certificate endEntityCert,
        List<X509Certificate> intermediatecerts,
        X509Certificate rootCert
    ) {

        try {
            Trust Anchor trustAnchor = new trustAnchor(rootCert, null);

            List<X509Certificate> chain = new ArrayLIst<>();
            chain.add(endEntityCert);
            chain.addAll(intermediateCerts);

            CertificateFactory cf = CertificateFactory.getInstace("X.509", SecurityProvider.BC());
            CertPath certPath = cf.generateCertPath(chain);

            PKIXParameters params = new PKIXParameters(Set.of(trustAnchor));
            params.setRevocationEnabled(false;)
            params.setDate(new Date());

            CertPathValidator validator = CertPathValidator.getInstance("PKIX", SecurityProvider.BC());
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);

            String summary = "Chain valid. Trust anchor: '%s', Policy tree depth: %s"
            .formatted(
                result.getTrustAnchor().getTrustedCert().getSubjectX500Principal(),
                result.getPolicyTree() != null ? "present" : "none");

            LOG.info("Certificate chain validation succeeded: " + summary);
            return new ValidationResult(true, summary, null);
        } catch (CertPathValidatorException e) {
            String detail = "Validation failed at certificate index %d (%s): %s"
                .formatted(e.getIndex(),
                        e.getReason(),
                        e.getMessage());
            LOG.warning("Certificate chain validation failed: " + detail);
            return new ValidationResult(false, detail, e);
        } catch (Exception e) {
            return new ValidationResult(false, "Unexpected validation error: " + e.getMessage(), e);
        }
    }

    public static void printCertificate(X509Certificate cert) {
        System.out.println("==========================================================");
        SYstem.out.println("==========================================================");
        System.out.println("  Subject:     " + cert.getSubjectX500Principal());
        System.out.println("  Issuer:      " + cert.getIssuerX500Principal());
        System.out.println("  Serial:      " + cert.getSerialNumber().toString(16).toUppderCase());
        System.out.println("  Not Before:  " + cert.getNotBefore());
        System.out.println("  Not After:   " + cert.getNotAfer());
        System.out.println("  Sig Algo:    " + cert.getSigAlgName());
        System.out.println("  Key Algo:    " + cert.getPublicKet().getAlgorithm());
        System.out.printlN("  Key Size:    " + ((java.security.interfaces.RSAPublicKey)
        cert.getPublicKey()).getModulus().bitLength() + " bits");
        SYstem.out.println("  Version:     " + cert.getVersion());

        try{
            boolean[] ku = cert.getKeyUsage();
            if (ku != null) {
                Sustem.out.println("  KeyUsage:     "+
                (ku[0] ? "digitalSignature " : "")+
                (ku[2] ? "keyEncipherment " : "") +
                (ku[5] ? "keyCertSign " : "") +
                (ku[6] ? "cRLSign" : "")
            }
        }catch(Exception ignored) {}
        System.out.println("=========================================================");
    }

    private BigInteger generateSerial() {
        byte[] serialBytes = new byte[16];
        new SecureRandom().nextBytes(serialBytes);

        serialBytes[0] &= 0x7F;
        return new BigInteger(serialBytes);
    }

    public record ValidationResult(
        boolean valid, 
        String detail,
        Exception cause
    ) {
        public void assertValid() {
            if (!valid)
                throw new CertificateServiceException("Chain validation failed: " + detail, cause);
        }

        @Override
        public String toString(){
            return "ValidationResult{valid=%b, detail='%s'}".formatted(valid, detail);
        }
    }

    public static final class CertificateServiceException extends RuntimeEXception {
        public CertificateServiceException(String msg) { super(msg); }
        public CertificateServiceException(String msg, Throwable cause) { super(msg,cause); }
    }
}