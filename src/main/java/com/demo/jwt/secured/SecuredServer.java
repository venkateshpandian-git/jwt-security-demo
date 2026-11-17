package com.demo.jwt.secured;

import com.demo.jwt.common.KeyManager;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * SECURED WEBSERVER (Default Port 8082).
 *
 * Implements strict defense-in-depth following RFC 8725 (JWT Best Current Practices)
 * and draft-ietf-oauth-rfc8725bis-10, utilizing Nimbus JOSE+JWT >= 10.0.2:
 *
 * 1. Pre-Parse Envelope Defense:
 *    - Strict ceiling on header size (<= 4096 bytes).
 *    - Delimiter count validation (exactly 2 periods for JWS) BEFORE splitting or allocating.
 * 2. Cryptographic Controls (RFC 8725 §3.1, §3.2):
 *    - Positive Algorithm Allowlist: Only RS256 permitted.
 *    - Key-Algorithm Binding: Public RSA key cannot be evaluated as HMAC.
 *    - Rejection of "alg": "none".
 * 3. Dynamic Key & Header Sanitization (RFC 8725 §3.10):
 *    - Drop any tokens containing jku, x5u, or embedded jwk.
 *    - 'kid' sanitized with strict regex ^[a-zA-Z0-9_-]{1,64}$.
 *    - In-memory key resolution only; zero file-system or dynamic lookups.
 * 4. Claim Validation & Zero-Trust Propagation (RFC 8725 §3.7, §3.9, RFC 9068):
 *    - Explicit typing: 'typ' MUST be 'at+jwt' (RFC 9068).
 *    - Audience isolation: 'aud' MUST match 'secured-admin-api'.
 *    - Issuer match: 'iss' MUST match configured issuer.
 *    - Expiration: Strict 'exp' validation with max 30-second clock skew.
 */
public class SecuredServer {

    public static final int DEFAULT_PORT = 8082;
    public static final String EXPECTED_AUDIENCE = "secured-admin-api";
    public static final String EXPECTED_TYP = "at+jwt";
    private static final int MAX_TOKEN_BYTES = 4096;
    private static final Pattern SAFE_KID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");
    private static final Set<String> ALLOWED_ALGORITHMS = Set.of("RS256");

    private final int port;
    private HttpServer server;

    public SecuredServer(int port) {
        this.port = port;
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
                        "Positive algorithm allowlist: [RS256] only",
                        "Key-to-algorithm binding (HMAC on RSA key rejected)",
                        "alg: none strictly rejected",
                        "kid sanitized via ^[a-zA-Z0-9_-]{1,64}$ with in-memory resolution",
                        "Drop unverified jku, x5u, jwk headers",
                        "Strict typ: at+jwt header enforcement (RFC 9068)",
                        "Audience isolation: aud must match 'secured-admin-api'",
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
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                sendSecurityBlock(exchange, 401, "MISSING_BEARER_TOKEN", "RFC 6750: Missing or invalid Authorization Bearer header");
                return;
            }

            // DEFENSE 1: Pre-Parse Envelope Byte Ceiling (RFC 8725 §3.14)
            if (authHeader.length() > MAX_TOKEN_BYTES) {
                sendSecurityBlock(exchange, 400, "TOKEN_SIZE_LIMIT_EXCEEDED",
                    "RFC 8725 §3.14: Authorization header exceeds 4,096 bytes ceiling (" + authHeader.length() + " bytes). Rejected before parsing.");
                return;
            }

            String rawToken = authHeader.substring(7).trim();

            // DEFENSE 2: Delimiter Count Validation Before Split (CVE-2025-27144 / RFC 8725 §3.14)
            long dotCount = rawToken.chars().filter(ch -> ch == '.').count();
            if (dotCount != 2) {
                sendSecurityBlock(exchange, 400, "INVALID_DELIMITER_COUNT",
                    "RFC 8725 §3.14: Invalid JWS delimiter count. Expected exactly 2 periods, found " + dotCount + ". Delimiter flood attack blocked.");
                return;
            }

            try {
                // Parse JWT using Nimbus JOSE+JWT 10.0.2
                SignedJWT signedJWT = SignedJWT.parse(rawToken);
                JWSHeader header = signedJWT.getHeader();

                // DEFENSE 3: Positive Algorithm Allowlist & Reject "none" (RFC 8725 §3.1)
                JWSAlgorithm algorithm = header.getAlgorithm();
                if (algorithm == null || "none".equalsIgnoreCase(algorithm.getName())) {
                    sendSecurityBlock(exchange, 401, "ALG_NONE_REJECTED",
                        "RFC 8725 §3.1: 'alg': 'none' is strictly forbidden. Unsigned tokens are rejected.");
                    return;
                }

                // DEFENSE 4: Drop dynamic key headers & sanitize 'kid' (RFC 8725 §3.10)
                if (header.getJWKURL() != null || header.getX509CertURL() != null || header.getJWK() != null) {
                    sendSecurityBlock(exchange, 401, "DYNAMIC_KEY_HEADER_REJECTED",
                        "RFC 8725 §3.10: Unverified dynamic key headers (jku, x5u, embedded jwk) are forbidden.");
                    return;
                }

                String kid = header.getKeyID();
                if (kid != null) {
                    if (!SAFE_KID_PATTERN.matcher(kid).matches()) {
                        sendSecurityBlock(exchange, 401, "MALFORMED_KID_INJECTION",
                            "RFC 8725 §3.10: Header 'kid' failed alphanumeric regex validation (" + kid + "). Path traversal/injection blocked.");
                        return;
                    }
                }

                if (!ALLOWED_ALGORITHMS.contains(algorithm.getName())) {
                    sendSecurityBlock(exchange, 401, "ALGORITHM_NOT_ALLOWED",
                        "RFC 8725 §3.1 & §3.2: Algorithm '" + algorithm.getName() + "' is not in positive allowlist " +
                        ALLOWED_ALGORITHMS + ". Algorithm Confusion attack (RS256 -> " + algorithm.getName() + ") blocked.");
                    return;
                }

                // DEFENSE 5: Cryptographic Signature Verification with Bound RSA Public Key
                RSAPublicKey publicKey = (RSAPublicKey) KeyManager.getPublicKey();
                RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
                if (!signedJWT.verify(verifier)) {
                    sendSecurityBlock(exchange, 401, "INVALID_SIGNATURE",
                        "RFC 7519: Cryptographic signature verification failed for algorithm RS256.");
                    return;
                }

                // DEFENSE 6: Explicit Token Typing Check (RFC 8725 §3.11 & RFC 9068)
                if (header.getType() == null || !EXPECTED_TYP.equalsIgnoreCase(header.getType().toString())) {
                    sendSecurityBlock(exchange, 401, "INVALID_TOKEN_TYPE",
                        "RFC 8725 §3.11 & RFC 9068: Expected token type 'typ': '" + EXPECTED_TYP +
                        "', but received: '" + (header.getType() != null ? header.getType().toString() : "null") + "'.");
                    return;
                }

                // DEFENSE 7: Strict Claim Validation
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

                // 7a. Issuer Check
                if (!KeyManager.ISSUER.equals(claims.getIssuer())) {
                    sendSecurityBlock(exchange, 401, "INVALID_ISSUER",
                        "RFC 8725 §3.12: Issuer mismatch. Expected '" + KeyManager.ISSUER + "', found '" + claims.getIssuer() + "'.");
                    return;
                }

                // 7b. Audience Isolation (Confused Deputy Prevention - RFC 8725 §3.9)
                List<String> audiences = claims.getAudience();
                if (audiences == null || !audiences.contains(EXPECTED_AUDIENCE)) {
                    sendSecurityBlock(exchange, 403, "CONFUSED_DEPUTY_AUDIENCE_MISMATCH",
                        "RFC 8725 §3.9: Audience mismatch. Token intended for " + audiences +
                        ", but required audience is '" + EXPECTED_AUDIENCE + "'. Confused Deputy escalation blocked.");
                    return;
                }

                // 7c. Expiration Check with max 30s clock skew (RFC 8725 §3.8)
                Date exp = claims.getExpirationTime();
                if (exp == null) {
                    sendSecurityBlock(exchange, 401, "MISSING_EXPIRATION",
                        "RFC 8725 §3.8: Token must contain an 'exp' (expiration) claim.");
                    return;
                }
                Instant now = Instant.now();
                if (now.isAfter(exp.toInstant().plusSeconds(30))) {
                    sendSecurityBlock(exchange, 401, "TOKEN_EXPIRED",
                        "RFC 8725 §3.8: Token expired at " + exp + ". Replay attack blocked.");
                    return;
                }

                // 7d. Role authorization
                String role = claims.getStringClaim("role");
                if (!"admin".equals(role)) {
                    sendSecurityBlock(exchange, 403, "INSUFFICIENT_PRIVILEGES",
                        "Principal possesses role '" + role + "', but 'admin' role is required.");
                    return;
                }

                // All validations passed!
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
                            "alg": "%s",
                            "exp": "%s"
                        },
                        "confidential_ledger_data": {
                            "account_number": "CORP-TREASURY-VAULT-001",
                            "balance": "$85,420,000.00 USD",
                            "authorized_actions": ["DIRECT_WIRE_TRANSFER"]
                        }
                    }
                    """,
                    claims.getSubject(), role, EXPECTED_AUDIENCE, header.getType(), header.getAlgorithm().getName(), exp
                );

                sendResponse(exchange, 200, responseJson);

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
        System.out.println("[SecuredServer] BLOCKED: " + reasonCode + " - " + message);
        sendResponse(exchange, statusCode, json);
    }
}
