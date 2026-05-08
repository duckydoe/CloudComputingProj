package com.crypto.demo.util;

import javax.crypto.KEM;
import java.security.*;

public class SmokeTest {

    public static void main(String[] args) throws Exception {
        CryptoConfig.init();

        TestUtils.section("Foundation Smoke Test");

        // 1. BouncyCastle registered?
        Provider bc = Security.getProvider("BC");
        TestUtils.row("BouncyCastle provider", bc != null ? bc.getVersionStr() : "NOT FOUND");

        // 2. Java version
        TestUtils.row("Java version", System.getProperty("java.version"));

        // 3. ML-KEM-768 available?
        try {
            KEM.getInstance("ML-KEM-768");
            TestUtils.row("ML-KEM-768", "available");
        } catch (NoSuchAlgorithmException e) {
            TestUtils.row("ML-KEM-768", "NOT available — check Java version");
        }

        // 4. ML-DSA-65 available?
        try {
            Signature sig = Signature.getInstance("ML-DSA-65");
            TestUtils.row("ML-DSA-65", "available (" + sig.getProvider().getName() + ")");
        } catch (NoSuchAlgorithmException e) {
            TestUtils.row("ML-DSA-65", "NOT available — check Java version");
        }

        // 5. RSA keygen working?
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        TestUtils.row("RSA 2048 keygen", kp.getPublic().getAlgorithm() + " OK");

        System.out.println();
    }
}