package com.demo.jwt.common;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Manages cryptographic keys for the demonstration:
 * - Generates an RSA 2048-bit key pair (Issuer private key + public key)
 * - Exports Public Key in PEM and DER format
 * - Maintains an in-memory key registry for key lookup by kid
 */
public class KeyManager {

    public static final String KEY_ID = "auth-rsa-key-1";
    public static final String ISSUER = "https://auth.company-bank.internal";

    private static final KeyPair rsaKeyPair;
    private static final Map<String, PublicKey> inMemoryPublicKeyStore = new HashMap<>();

    static {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, new SecureRandom());
            rsaKeyPair = keyGen.generateKeyPair();
            inMemoryPublicKeyStore.put(KEY_ID, rsaKeyPair.getPublic());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize RSA keys", e);
        }
    }

    public static PrivateKey getPrivateKey() {
        return rsaKeyPair.getPrivate();
    }

    public static PublicKey getPublicKey() {
        return rsaKeyPair.getPublic();
    }

    public static PublicKey getPublicKeyById(String kid) {
        return inMemoryPublicKeyStore.get(kid);
    }

    public static String getPublicKeyPem() {
        String base64Key = Base64.getMimeEncoder(64, new byte[]{'\n'})
                                 .encodeToString(rsaKeyPair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64Key + "\n-----END PUBLIC KEY-----\n";
    }

    public static byte[] getPublicKeyDerBytes() {
        return rsaKeyPair.getPublic().getEncoded();
    }
}
