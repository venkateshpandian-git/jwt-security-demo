package com.demo.jwt.secured;

import com.demo.jwt.common.KeyManager;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * SECURED WEBSERVER (Default Port 8082).
 *
 * Implements strict defense-in-depth following RFC 8725 (JWT Best Current Practices),
 * draft-ietf-oauth-rfc8725bis-10, and RFC 9068, utilizing production-grade
 * Nimbus JOSE+JWT >= 10.0.2 components:
 *
 * 1. Pre-Parse Envelope Defense (RFC 8725 §3.14):
 *    - Strict ceiling on header size (<= 4096 bytes).
 *    - Delimiter count validation (exactly 2 periods for JWS) BEFORE splitting or allocating.
 * 2. Cryptographic Controls & Key-Algorithm Binding (RFC 8725 §3.1, §3.2):
 *    - Configured via Nimbus DefaultJWTProcessor with JWSVerificationKeySelector(RS256).
 *    - Positive Algorithm Allowlist: Only RS256 permitted.
 *    - Strictly rejects "alg": "none" and algorithm confusion (HS256).
 * 3. Dynamic Key & Header Sanitization (RFC 8725 §3.10):
 *    - Drops unverified dynamic key headers (jku, x5u, embedded jwk).
 *    - 'kid' sanitized with strict regex ^[a-zA-Z0-9_-]{1,64}$.
 *    - In-memory key resolution only; zero file-system or dynamic lookups.
 * 4. Claim Validation & Zero-Trust Propagation (RFC 8725 §3.7, §3.9, RFC 9068):
 *    - Explicit typing: 'typ' MUST be 'at+jwt' (RFC 9068).
 *    - Audience isolation: 'aud' MUST match 'secured-admin-api' via DefaultJWTClaimsVerifier.
 *    - Issuer match: 'iss' MUST match configured issuer.
 *    - Expiration: Strict 'exp' validation with max 30-second clock skew.
 */
public class SecuredServer {

    public static final int DEFAULT_PORT = 8082;
    public static final String EXPECTED_AUDIENCE = "secured-admin-api";
    public static final String EXPECTED_TYP = "at+jwt";
    public static final int MAX_TOKEN_BYTES = 4096;
    private static final Pattern SAFE_KID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    private final int port;
    private HttpServer server;

    // Production Nimbus JOSE+JWT processor pipeline
    private static final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    static {
        jwtProcessor = new DefaultJWTProcessor<>();

        // 1. Build in-memory JWKSet from the server's RSA Public Key
        RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey) KeyManager.getPublicKey())
            .keyID(KeyManager.KEY_ID)
            .algorithm(JWSAlgorithm.RS256)
            .build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaJWK));

        // 2. Cryptographic Key Selector: ONLY permits RS256, binds key type to algorithm (RFC 8725 §3.1, §3.2)
        JWSVerificationKeySelector<SecurityContext> keySelector =
            new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        jwtProcessor.setJWSKeySelector(keySelector);

        // Configure Nimbus to enforce RFC 9068 "at+jwt" explicit token typing (RFC 8725 §3.11)
        jwtProcessor.setJWSTypeVerifier(new com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(EXPECTED_TYP)));

        // 3. Strict Claim Verifier: validates aud, iss, exp, required claims, and 30s clock skew (RFC 8725 §3.8, §3.9)
        JWTClaimsSet exactMatchClaims = new JWTClaimsSet.Builder()
            .issuer(KeyManager.ISSUER)
            .audience(EXPECTED_AUDIENCE)
            .build();
        Set<String> requiredClaims = Set.of("sub", "exp", "iat", "role");

        DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
            new DefaultJWTClaimsVerifier<>(exactMatchClaims, requiredClaims);
        claimsVerifier.setMaxClockSkew(30); // 30 seconds leeway per RFC 8725 §3.8
        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);
    }

    public SecuredServer(int port) {
        this.port = port;
    }

    /**
     * Complete, production-grade token verification pipeline.
     * Throws SecurityException if any RFC 8725 defense is violated.
     */
    public static JWTClaimsSet verifyToken(String rawAuthHeader) throws Exception {
        if (rawAuthHeader == null || !rawAuthHeader.startsWith("Bearer ")) {
            throw new SecurityException("RFC 6750: Missing or invalid Authorization Bearer header");
        }

        // DEFENSE 1: Pre-Parse Envelope Byte Ceiling (RFC 8725 §3.14)
        if (rawAuthHeader.length() > MAX_TOKEN_BYTES) {
            throw new SecurityException("RFC 8725 §3.14: Authorization header exceeds 4,096 bytes ceiling ("
                + rawAuthHeader.length() + " bytes). Delimiter/Memory flood blocked.");
        }

        String rawToken = rawAuthHeader.substring(7).trim();

        // DEFENSE 2: Delimiter Count Validation Before Split (CVE-2025-27144 / RFC 8725 §3.14)
        long dotCount = rawToken.chars().filter(ch -> ch == '.').count();
        if (dotCount != 2) {
            throw new SecurityException("RFC 8725 §3.14: Invalid JWS delimiter count. Expected exactly 2 periods, found "
                + dotCount + ". Delimiter flood attack blocked.");
        }

        // Parse JWS Header to inspect untrusted envelope fields
        com.nimbusds.jwt.SignedJWT signedJWT;
        try {
            signedJWT = com.nimbusds.jwt.SignedJWT.parse(rawToken);
        } catch (java.text.ParseException pe) {
            throw new SecurityException("RFC 8725 §3.1: 'alg': 'none' or invalid JWS structure rejected: " + pe.getMessage(), pe);
        }
        JWSHeader header = signedJWT.getHeader();

        // DEFENSE 3: Positive Algorithm Allowlist & Reject "none" (RFC 8725 §3.1)
        JWSAlgorithm algorithm = header.getAlgorithm();
        if (algorithm == null || "none".equalsIgnoreCase(algorithm.getName())) {
            throw new SecurityException("RFC 8725 §3.1: 'alg': 'none' is strictly forbidden. Unsigned tokens are rejected.");
        }

        // DEFENSE 4: Drop dynamic key headers & sanitize 'kid' (RFC 8725 §3.10)
        if (header.getJWKURL() != null || header.getX509CertURL() != null || header.getJWK() != null) {
            throw new SecurityException("RFC 8725 §3.10: Dynamic key headers (jku, x5u, embedded jwk) are forbidden.");
        }

        String kid = header.getKeyID();
        if (kid != null && !SAFE_KID_PATTERN.matcher(kid).matches()) {
            throw new SecurityException("RFC 8725 §3.10: Header 'kid' failed alphanumeric regex validation ("
                + kid + "). Path traversal/injection blocked.");
        }

        // DEFENSE 5: Explicit Token Typing Check (RFC 8725 §3.11 & RFC 9068)
        JOSEObjectType typ = header.getType();
        if (typ == null || !EXPECTED_TYP.equalsIgnoreCase(typ.toString())) {
            throw new SecurityException("RFC 8725 §3.11 & RFC 9068: Expected token type 'typ': '"
                + EXPECTED_TYP + "', but received: '" + (typ != null ? typ.toString() : "null") + "'.");
        }

        // DEFENSE 6: Full Cryptographic Verification & Claim Assertion via Nimbus Processor
        // Validates signature with RS256, enforces key-binding, validates aud, iss, exp, and clock skew
        JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);

        // DEFENSE 7: Role Authorization check
        String role = claims.getStringClaim("role");
        if (!"admin".equals(role)) {
            throw new SecurityException("INSUFFICIENT_PRIVILEGES: Principal role is '" + role + "', but 'admin' is required.");
        }

        return claims;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());

        server.createContext("/api/public-key", new PublicKeyHandler());
        server.createContext("/api/admin/data", new HardenedAdminHandler());
        server.createContext("/api/status", new StatusHandler());

        server.start();
        System.out.println("[SecuredServer] Started on port " + port + " (RFC 8725 HARDENED MODE)");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            System.out.println("[SecuredServer] Stopped");
        }
    }

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        SecuredServer securedServer = new SecuredServer(port);
        securedServer.start();
    }

    static class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }
            String json = """
                {
                    "server": "Secured Server",
                    "port": 8082,
                    "security_posture": "RFC_8725_COMPLIANT",
                    "library": "Nimbus JOSE+JWT 10.0.2",
                    "active_protections": [
                        "Pre-parse header byte ceiling (<= 4096 bytes)",
                        "Pre-parse delimiter count check (exactly 2 dots for JWS)",
                        "Positive algorithm allowlist: [RS256] only via JWSVerificationKeySelector",
                        "Key-to-algorithm binding (HMAC on RSA key rejected at library level)",
                        "alg: none strictly rejected",
                        "kid sanitized via ^[a-zA-Z0-9_-]{1,64}$ with in-memory resolution",
                        "Drop unverified jku, x5u, jwk headers",
                        "Strict typ: at+jwt header enforcement (RFC 9068)",
                        "Audience isolation: aud must match 'secured-admin-api' via DefaultJWTClaimsVerifier",
                        "Strict exp validation with max 30s clock skew"
                    ]
                }
                """;
            sendResponse(exchange, 200, json);
        }
    }

    static class PublicKeyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }
            String pem = KeyManager.getPublicKeyPem();
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
            sendResponse(exchange, 200, pem);
        }
    }

    static class HardenedAdminHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");

            try {
                JWTClaimsSet claims = verifyToken(authHeader);

                String responseJson = String.format("""
                    {
                        "status": "AUTHENTICATED_AND_AUTHORIZED",
                        "server_security": "SECURED_RFC_8725",
                        "library": "Nimbus JOSE+JWT 10.0.2",
                        "message": "Token fully verified against RFC 8725 defense-in-depth criteria.",
                        "verified_claims": {
                            "sub": "%s",
                            "role": "%s",
                            "aud": "%s",
                            "typ": "%s",
                            "alg": "RS256",
                            "exp": "%s"
                        },
                        "confidential_ledger_data": {
                            "account_number": "CORP-TREASURY-VAULT-001",
                            "balance": "$85,420,000.00 USD",
                            "authorized_actions": ["DIRECT_WIRE_TRANSFER"]
                        }
                    }
                    """,
                    claims.getSubject(),
                    claims.getStringClaim("role"),
                    EXPECTED_AUDIENCE,
                    EXPECTED_TYP,
                    claims.getExpirationTime()
                );

                sendResponse(exchange, 200, responseJson);

            } catch (SecurityException se) {
                int status = se.getMessage().contains("INSUFFICIENT_PRIVILEGES") || se.getMessage().contains("Audience") ? 403 : 401;
                if (se.getMessage().contains("4,096") || se.getMessage().contains("delimiter")) {
                    status = 400;
                }
                sendSecurityBlock(exchange, status, "SECURITY_VIOLATION", se.getMessage());
            } catch (Exception e) {
                sendSecurityBlock(exchange, 400, "PARSING_OR_CRYPTO_ERROR", "Token rejected during secure verification: " + e.getMessage());
            }
        }
    }

    private static void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void sendSecurityBlock(HttpExchange exchange, int statusCode, String reasonCode, String message) throws IOException {
        String json = String.format("""
            {
                "status": "BLOCKED_BY_DEFENSIVE_CONTROL",
                "server_security": "SECURED_RFC_8725",
                "http_status": %d,
                "reason_code": "%s",
                "defense_explanation": "%s"
            }
            """, statusCode, reasonCode, message.replace("\"", "\\\""));
        System.out.println("[SecuredServer] BLOCKED (" + statusCode + "): " + reasonCode + " - " + message);
        sendResponse(exchange, statusCode, json);
    }
}
