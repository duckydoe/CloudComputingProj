package com.crypto.demo.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public final class CryptoConfig {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void init() {}

    private CryptoConfig() {}
}