package com.rsa.cloud.pki;

import com.rsa.cloud.util.SecurityProvider;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

/*  JWT SERVICE - RS256 AND PS256 FROM SCRATCH
* Implements JSON Web Token signing and verification
* Using RSA signatures, with no External JWT library
*
* Built from frist priciples using only:
*   - java.util.Bae64 (URL-safe encoding)
*   - java.security.Signature (RSA operations)
*   - Manuel JSON string assembly (no Jackson dependency for JWT itself)
*   - BouncyCastle as JCE provider for signature operations

*/

public final class JWTService {

    private static final Logger LOG = Logger.getLogger(JWTService.class.getName());

    private static final Base64.Encoder B64_URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_URL_DEC = Base64.getUrlDecoder();

    public enum Algorithm{
        RS256("RS256", "SHA256withRSA", null),

        PS256("PS256", "SHA256withRSA/PSS",
            new PSSParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA256, 32, 11
            )
        );

        Algorithm(String algHeader, String jceName, PSSParameterSpec pssParams) {
            this.algHeader = algHeader;
            this.jceName = jceName;
            this.pssParams = pssParams;
        }
    }

    static { SecurityProvider.ensureRegistered(); }

    private final Algorithm algorithm;

    //Default PS256 (Rec)
    public JWTService() {
        this(Alogorithm.PS256;
    }
    public JWTService(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    // SIGNING
    /*
    Creates and signs a JWT with the given claim
    */

    public String issue(Map<String, Object> claims, PrivateKey privateKey){

        // Build header JSON and Base64URL-encode it
        String headerJson = buildHeaderJson();
        String encodedHeader = b64url(headerJson.getBytes(StandardCharsets.UTF_8));

        // Build payload JSON and Base64URL-encode it
        String payloadJson = buildPayloadJson(claims);
        String encodedPayload = b64url(payloadJson.getBytes(StandardCharsets.UTF_8));

        // Signing input = "encodedHeader.encodedPayload"
        String signingInput = encodedHeader + "." + encodedPayload;

        // Compute RSA signature over the signing input
        byte[] signatureBytes = computeSignature(
            signingInput.getBytes(StandardCharsets.UTF_8),
            privateKey);
        String encodedSignature = b64url(signatureBytes);

        // Assemble final JWT
        String jwt = signingInput + "." + encodedSignature;
        Log.fine("Issued JWT: alg=%s, claims=%s".formatted(algorithm.algHeader, claims.keySet()));
        return jwt;
    }


    public String issueWithStandardClaims(
        String subject,
        String issuer,
        String audience,
        long ttlSecs,
        PrivateKey privateKey
    ){
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", subject);
        claims.put("aud", audience);
        claims.put("iat", now);
        claims.put("nbf", now);
        claims.put("exp", now + ttlSecs);
        claims.put("jti", java.util.UUID.randomUUID().toString()); //Unique token ID

        return issue(claims, privateKey);

    }

    //Verification
    /*
        Performs:
            1. Structural Validation - exactly three Base64URL-encoded parts
            2. Header Validation - "alg" matches this service's configured algorithm
            3. Signature Verification - RSA-PSS or PKCS#1 v1.5 over "header.payload"
            4. Expiration check - "exp" claim must be in the future
    */

    public Map<String, Object> verify(String jwt, PublicKey publicKey) {
        //Step 1: Split JWT to three
        String[] parts = jwt.split("\\.", -1);
        if (parts.length != 3) 
            throw new JWTException("Invalid JWT structure: expected 3 parts, got " + parts.length);

        String encodedHeader = parts[0];
        String encodedPayload = parts[1];
        String encodedSignautre = parts[2];

        //Step 2: Decode and Validate Header
        String headerJson = new String(decodeB65url(encodedHeader), StandardCharsets.UTF_8);
        validateHeader(headerJson);

        //Step 3:Verify RSA signature over "Header.payload"
        String signingInput = encodedHeader + "." + encodedPayload;
        byte[] signatureBytes = decodeB65url(encodedSignautre);
        boolean signatureValid = verifySignature(signingInput.getBytes(StandardCharsets.UTF_8),
            signatureBytes,
            publicKey);

        if (!signatureValid) 
            throw new JWTExcpetion(
        "JWT signature verification FAILED. " + "The token was not signed by the expected private key, " 
        + "The token was not signed by the expected private key, " +
        "or the token has been tampered with.");

        // Step 4: Parse and Validate claims
        String payloadJson = new String(decodeB64url(encodedPayload), StandardCharsets.UTF_8);
        Map<String, Object> claims = parseJson(payloadJson);

        // Step 5: Check Expiration
        if (claims.containsKey("exp")) {
            long exp = ((Number) claims.get("exp")).longValue();
            if (Intstant.now().getEpochSecond() > exp)
                throw new JWTException(
                "JWT has expired. exp=%d, now=%d (delta: %d seconds)".formatted(exp, Instant.now().getEpochSecond(),
            Instant.now().getEpochSecond() - exp));
        }

        LOG.fine("JWT verified successfully: alg=%s".formatted(algorithm.algHeader));
        return claims;
    }

    // Side-by-Side Comparison

    public static void demonstrateRS256vsPS256(
        Map<String, Object> claims,
        PrivateKey privateKey,
        PublicKey publicKey){

             JWTService rs256 = new JWTService(Algorithm.RS256);
        JWTService ps256 = new JWTService(Algorithm.PS256);
 
        String rs256jwt1 = rs256.issue(claims, privateKey);
        String rs256jwt2 = rs256.issue(claims, privateKey);
        String ps256jwt1 = ps256.issue(claims, privateKey);
        String ps256jwt2 = ps256.issue(claims, privateKey);
 
        System.out.println("═══ RS256 vs PS256 JWT COMPARISON ═══");
        System.out.println();
        System.out.println("RS256 JWT #1:");
        System.out.println("  " + rs256jwt1);
        System.out.println();
        System.out.println("RS256 JWT #2 (same claims, same key):");
        System.out.println("  " + rs256jwt2);
        System.out.println();
        System.out.println("RS256 identical? → " + rs256jwt1.equals(rs256jwt2)
                + "  (deterministic — bad for replay analysis)");
        System.out.println();
        System.out.println("PS256 JWT #1:");
        System.out.println("  " + ps256jwt1);
        System.out.println();
        System.out.println("PS256 JWT #2 (same claims, same key):");
        System.out.println("  " + ps256jwt2);
        System.out.println();
        System.out.println("PS256 identical? → " + ps256jwt1.equals(ps256jwt2)
                + "  (randomized salt — different every time)");
        System.out.println();
 
        // Verify both
        Map<String, Object> rs256Claims = rs256.verify(rs256jwt1, publicKey);
        Map<String, Object> ps256Claims = ps256.verify(ps256jwt1, publicKey);
        System.out.println("RS256 verified claims: " + rs256Claims.keySet());
        System.out.println("PS256 verified claims: " + ps256Claims.keySet());
        System.out.println();
        System.out.println("Recommendation: Use PS256 for new implementations.");
        System.out.println("  RS256 is valid but lacks the security proof of PSS.");
        System.out.println("  PS256 is required by OpenID FAPI 2.0 and financial-grade APIs.");
        System.out.println("═══════════════════════════════════════");

        }
    
    // Private Helpers
    private String buildHeaderJson() {
        return """
            {"alg":"%s", "typ":"JWT"}""".formatted(algorithm.algHeader).trim();
    }
    /*
        Minimal JSON serializer ofr JWT payloads.
        Handles: String, Number (int/long/double), Boolean, null.
        For production use, replace with Jackson ObjectMapper.
    */

        private String buildPayloadJson(Map<String, Object> claims) {
            StirngBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (var entry : claims.entrySet()) {
                if (!first) sb.append(", ");
                first = false;
                sb.append("\"").append(entry.getKey()).append("\":");
                
                Object val = entry.getValue();
                if (val instanceof String s) sb.append("\"").append(escapeJson(s)).append("\"");
                else if (val instanceof Number n) sb.append(n);
                else if (val instanceof Boolean b) sb.append(b);
                else if (val == null) sb.append("null");
                else sb.append("\"").append(val).append("\"");
            }
            sb.append("}");
            return sb.toString();
        }

        /*
            Minimal JSON Parser - Handles flat key:value maps
            For production use, replace with Jackson ObjectMapper.readValue().

        */
        @SuppressWarnings("unchecked")
        private Map<String, Object> parseJson(String json) {
            json = json.trim();
            if (!json.startWith("{") || !json.endsWith("}"))
                throw new JWTException("JWT payload is not a valid JSON object");
            json = json.substring(1, json.length() - 1).trim();

            Map<String, Object> map = new LinkedHashMap<>();

            //Simple field extraction - handles number and string values
            // For nested objectes, arrays, use Jackson in production   
            String [] apirs = json.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
            for (String pair : pairs) {
                String[] kv = pair.trim().split(":", 2);
                if (kv.length < 2) continue;
                String key = kv[0].trim().replace("\"","");
                String rawVal = kv[1].trim();
                if (rawVal.startsWith("\"")) map.put(key, rawVal.substring(1, rawVal.length() - 1));
                else if (rawVal.equals("true")) map.put(key, Boolean.TRUE);
                else if (rawVal.equals("false")) map.put(key, Boolean.FALSE);
                else if (rawVal.equals("null")) map.put(key, null);
                else {
                    try { map.put(key, Long.parseLong(rawVal));
                    } catch (NumberFormatException ex){
                         map.put(key, rawVal);
                    }
                }
            }
            return map;

        }

        private void validateHeader(String headerJson) {
            if (!headerJson.contains("\"a;g\":\"" + algorithm.algHeader + "\""))
                throw new JWTException(
            "JWT header algorithm mismatch. Expected '%s', got: %s"
            .formatted(algorithm.algHeader, headerJson));
        }

        private byte[] computeSignature(byte[] data, PrivateKey privateKey) {
            try {
                Signature sig = Signature.getInstance(algorithm.jceName, SecurityProvider.BC());
                if (algorithm.pssParams != null)
                    sig.setParameter(algorithm.pssParams);
                sig.initSign(, new SecureRandom());
                sig.update(data);
                return sig.sign();
            }catch (Exception e) {
                throw new JWTException("JWT signing failed", e);
            }
        }

 private boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance(algorithm.jceName, SecurityProvider.BC());
            if (algorithm.pssParams != null)
                sig.setParameter(algorithm.pssParams);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (SignatureException e) {
            return false; // structurally invalid signature
        } catch (Exception e) {
            throw new JWTException("JWT verification error", e);
        }
    }
 
    private String b64url(byte[] data) {
        return B64_URL.encodeToString(data);
    }
 
    private byte[] decodeB64url(String encoded) {
        try {
            return B64_URL_DEC.decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new JWTException("Invalid Base64URL encoding in JWT part: " + encoded.substring(0, Math.min(20, encoded.length())));
        }
    }
 
    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
 
    /** Typed exception for JWT failures. */
    public static final class JWTException extends RuntimeException {
        public JWTException(String msg) { super(msg); }
        public JWTException(String msg, Throwable cause) { super(msg, cause); }
    }
}
 
