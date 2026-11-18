package com.demo.jwt.unsecured;

import com.demo.jwt.common.KeyManager;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * UNSECURED / VULNERABLE WEBSERVER (Default Port 8081).
 *
 * Demonstrates authentic vulnerabilities found in legacy systems and unpatched libraries:
 * 1. "alg": "none" signature stripping bypass (CVE-2022-23540).
 * 2. Algorithm confusion: failure to bind key type to algorithm; evaluates public RSA key bytes
 *    as an HMAC secret (CVE-2022-29217 / CVE-2024-33663).
 * 3. Confused Deputy / Cross-Service Substitution: verifies signature but completely omits
 *    audience ('aud') and token type ('typ') validation (RFC 8725 §2.4).
 * 4. Unverified 'kid' Path Traversal: resolves key files directly from disk using the raw 'kid'
 *    header without path sanitization; reading empty files yields an empty HMAC secret (RFC 8725 §2.5).
 * 5. Missing expiration validation: completely skips checking the 'exp' claim, allowing indefinite replay.
 * 6. Naive split(".") parsing without delimiter or payload length limits (CVE-2025-27144).
 */
public class UnsecuredServer {

    public static final int DEFAULT_PORT = 8081;
    private final int port;
    private HttpServer server;

    // Keys directory for file-based key lookup
    private static final File KEY_STORE_DIR;

    static {
        KEY_STORE_DIR = new File(System.getProperty("java.io.tmpdir"), "jwt-unsecured-keys");
        KEY_STORE_DIR.mkdirs();
        // Populate standard valid key file
        try {
            File defaultKeyFile = new File(KEY_STORE_DIR, KeyManager.KEY_ID);
            Files.write(defaultKeyFile.toPath(), KeyManager.getPublicKeyDerBytes());
        } catch (IOException ignored) {}
    }

    public UnsecuredServer(int port) {
        this.port = port;
    }

    /**
     * Authentic vulnerable token verification method.
     * Contains the genuine logical and architectural defects documented in RFC 8725.
     */
    public static VerificationResult verifyToken(String authHeader) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new SecurityException("Missing or invalid Authorization header");
        }

        String rawToken = authHeader.substring(7).trim();

        // VULNERABILITY 6: Naive split without checking dot count or length
        String[] parts = rawToken.split("\\.", -1);
        if (parts.length < 2) {
            throw new IllegalArgumentException("Malformed JWT structure: missing parts");
        }

        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

        Map<String, String> headerMap = parseSimpleJson(headerJson);
        Map<String, String> payloadMap = parseSimpleJson(payloadJson);

        String alg = headerMap.getOrDefault("alg", "none");
        String kid = headerMap.get("kid");
        String signatureBase64 = parts.length > 2 ? parts[2] : "";
        String signingInput = parts[0] + "." + parts[1];

        boolean signatureValid = false;
        String exploitType = null;

        // VULNERABILITY 1: "alg": "none" signature stripping bypass
        if ("none".equalsIgnoreCase(alg)) {
            // Unsecured parser accepts unsigned tokens
            signatureValid = true;
            exploitType = "ALG_NONE_BYPASS";
        }
        // VULNERABILITY 7: Embedded JWK Key Injection (CVE-2018-0114, jwt_tool -X i)
        // Vulnerable parser trusts the inline JWK sent by the caller instead of its own trust store
        else if (headerJson.contains("\"jwk\"")) {
            try {
                com.nimbusds.jwt.SignedJWT sjwt = com.nimbusds.jwt.SignedJWT.parse(rawToken);
                com.nimbusds.jose.jwk.JWK embeddedJwk = sjwt.getHeader().getJWK();
                if (embeddedJwk instanceof com.nimbusds.jose.jwk.RSAKey rsaKey) {
                    com.nimbusds.jose.crypto.RSASSAVerifier verifier = new com.nimbusds.jose.crypto.RSASSAVerifier(rsaKey);
                    if (sjwt.verify(verifier)) {
                        signatureValid = true;
                        exploitType = "EMBEDDED_JWK_KEY_INJECTION";
                    }
                }
            } catch (Exception ignored) {}
        }
        // VULNERABILITY 4: 'kid' header path traversal to disk
        // Resolves key directly from disk without sanitizing 'kid' (e.g. /dev/null or ../)
        else if (kid != null) {
            byte[] resolvedKeyBytes = loadKeyFromDisk(kid);
            if (resolvedKeyBytes != null) {
                // If caller requested HMAC, verify with resolved key bytes
                if ("HS256".equalsIgnoreCase(alg)) {
                    signatureValid = verifyHmacSha256(signingInput, signatureBase64, resolvedKeyBytes);
                    if (signatureValid) {
                        exploitType = "KID_PATH_TRAVERSAL_EMPTY_KEY";
                    }
                }
            }
        }

        // VULNERABILITY 2: Algorithm Confusion (RS256 -> HS256)
        // If kid was not resolved or if normal algorithm confusion is attempted:
        // The server expects to verify with its RSA public key, but caller requests HS256!
        // The verifier fails to bind key type and evaluates the RSA public key bytes as the HMAC secret!
        if (!signatureValid && "HS256".equalsIgnoreCase(alg)) {
            byte[] rsaPubDer = KeyManager.getPublicKeyDerBytes();
            byte[] rsaPubPem = KeyManager.getPublicKeyPem().getBytes(StandardCharsets.UTF_8);

            if (verifyHmacSha256(signingInput, signatureBase64, rsaPubDer) ||
                verifyHmacSha256(signingInput, signatureBase64, rsaPubPem)) {
                signatureValid = true;
                exploitType = "ALGORITHM_CONFUSION_RS256_TO_HS256";
            }
        }

        // Standard RS256 verification
        if (!signatureValid && "RS256".equalsIgnoreCase(alg)) {
            Signature rsaSig = Signature.getInstance("SHA256withRSA");
            rsaSig.initVerify(KeyManager.getPublicKey());
            rsaSig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] sigBytes = Base64.getUrlDecoder().decode(signatureBase64);
            signatureValid = rsaSig.verify(sigBytes);
        }

        if (!signatureValid) {
            throw new SecurityException("Invalid cryptographic signature");
        }

        // VULNERABILITY 5: Skipping 'exp' expiration claim check
        // Real legacy vulnerability: parses claims but forgets to call claims.getExpirationTime().before(now)
        if (payloadMap.containsKey("exp") && exploitType == null) {
            long exp = Long.parseLong(payloadMap.get("exp"));
            long now = System.currentTimeMillis() / 1000;
            if (exp < now) {
                exploitType = "EXPIRED_TOKEN_ACCEPTED";
            }
        }

        // VULNERABILITY 3: Confused Deputy - skips 'aud' and 'typ' checks!
        // Accepts any token with a valid signature regardless of target service
        String aud = payloadMap.getOrDefault("aud", "");
        if (!"secured-admin-api".equals(aud) && exploitType == null) {
            exploitType = "CONFUSED_DEPUTY_AUDIENCE_IGNORED";
        }

        return new VerificationResult(payloadMap, headerMap, exploitType);
    }

    /**
     * Genuine file-based key loader vulnerable to path traversal.
     * Takes raw 'kid' without sanitization and resolves it against KEY_STORE_DIR.
     */
    private static byte[] loadKeyFromDisk(String kid) {
        try {
            File file = kid.startsWith("/")
                ? new File(kid)
                : new File(KEY_STORE_DIR, kid).toPath().normalize().toFile();
            if (file.exists() && !file.isDirectory()) {
                try (FileInputStream fis = new FileInputStream(file)) {
                    return fis.readAllBytes();
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static boolean verifyHmacSha256(String data, String signatureB64, byte[] keyBytes) {
        try {
            SecretKey secretKey = new SecretKey() {
                @Override public String getAlgorithm() { return "HmacSHA256"; }
                @Override public String getFormat() { return "RAW"; }
                @Override public byte[] getEncoded() { return keyBytes; }
            };
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            byte[] expectedSig = mac.doFinal(data.getBytes(StandardCharsets.US_ASCII));
            String expectedSigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedSig);
            return expectedSigB64.equals(signatureB64);
        } catch (Exception e) {
            return false;
        }
    }

    public record VerificationResult(
        Map<String, String> claims,
        Map<String, String> headers,
        String exploitDetected
    ) {}

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());

        server.createContext("/api/public-key", new PublicKeyHandler());
        server.createContext("/api/admin/data", new VulnerableAdminHandler());
        server.createContext("/api/status", new StatusHandler());

        server.start();
        System.out.println("[UnsecuredServer] Started on port " + port + " (VULNERABLE MODE)");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            System.out.println("[UnsecuredServer] Stopped");
        }
    }

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        UnsecuredServer unsecuredServer = new UnsecuredServer(port);
        unsecuredServer.start();
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
                    "server": "Unsecured Server",
                    "port": 8081,
                    "security_posture": "VULNERABLE",
                    "vulnerabilities": [
                        "alg: none signature stripping bypass",
                        "Algorithm confusion (RS256 -> HS256 with public key)",
                        "Confused deputy (skips aud and typ checks)",
                        "kid header path traversal",
                        "Missing exp expiration validation",
                        "Pre-parse delimiter flood vulnerability"
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

    static class VulnerableAdminHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");

            try {
                VerificationResult result = verifyToken(authHeader);

                String sub = result.claims().getOrDefault("sub", "anonymous");
                String role = result.claims().getOrDefault("role", "user");
                String aud = result.claims().getOrDefault("aud", "none");
                String alg = result.headers().getOrDefault("alg", "none");
                String exploit = result.exploitDetected() != null ? result.exploitDetected() : "NONE_VALID_AUTHENTICATION";

                String responseJson = String.format("""
                    {
                        "status": "EXPLOITED_OR_AUTHENTICATED",
                        "server_security": "UNSECURED_VULNERABLE",
                        "message": "Access granted to confidential banking ledger!",
                        "exploit_details": "%s",
                        "claims_accepted": {
                            "sub": "%s",
                            "role": "%s",
                            "aud": "%s",
                            "alg": "%s"
                        },
                        "confidential_ledger_data": {
                            "account_number": "CORP-TREASURY-VAULT-001",
                            "balance": "$85,420,000.00 USD",
                            "authorized_actions": ["DIRECT_WIRE_TRANSFER", "DELETE_AUDIT_LOGS"]
                        }
                    }
                    """,
                    exploit, sub, role, aud, alg
                );

                sendResponse(exchange, 200, responseJson);

            } catch (SecurityException se) {
                sendError(exchange, 401, se.getMessage());
            } catch (IllegalArgumentException iae) {
                sendError(exchange, 400, iae.getMessage());
            } catch (Exception e) {
                sendError(exchange, 500, "Error processing token: " + e.getMessage());
            }
        }
    }

    private static Map<String, String> parseSimpleJson(String json) {
        Map<String, String> map = new HashMap<>();
        String cleaned = json.trim().replaceAll("[{}\"]", "");
        for (String pair : cleaned.split(",")) {
            String[] kv = pair.split(":", 2);
            if (kv.length == 2) {
                map.put(kv[0].trim(), kv[1].trim());
            }
        }
        return map;
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

    private static void sendError(HttpExchange exchange, int statusCode, String message) throws IOException {
        String json = String.format("{\"error\": \"%s\", \"server\": \"UnsecuredServer\"}", message.replace("\"", "\\\""));
        sendResponse(exchange, statusCode, json);
    }
}
