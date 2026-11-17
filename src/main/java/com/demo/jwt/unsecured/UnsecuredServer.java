package com.demo.jwt.unsecured;

import com.demo.jwt.common.KeyManager;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * UNSECURED / VULNERABLE WEBSERVER (Default Port 8081).
 *
 * Demonstrates common JWT vulnerabilities and legacy library design flaws:
 * 1. "alg": "none" signature stripping bypass (CVE-2022-23540).
 * 2. Algorithm confusion (RS256 vs HS256 using public RSA key bytes as HMAC secret, CVE-2022-29217).
 * 3. Confused Deputy / Cross-Service Substitution (Missing 'aud' & 'typ' checks, RFC 8725 §2.4).
 * 4. Unverified 'kid' Path Traversal to /dev/null allowing empty-key HMAC forge (RFC 8725 §2.5).
 * 5. Expired token acceptance (skipping 'exp' claim check).
 * 6. Naive split(".") vulnerable to delimiter allocation floods (CVE-2025-27144).
 */
public class UnsecuredServer {

    public static final int DEFAULT_PORT = 8081;
    private final int port;
    private HttpServer server;

    public UnsecuredServer(int port) {
        this.port = port;
    }

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
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                sendError(exchange, 401, "Missing or invalid Authorization header");
                return;
            }

            String rawToken = authHeader.substring(7).trim();

            try {
                // VULNERABILITY 6: Naive split without checking dot count or length
                String[] parts = rawToken.split("\\.", -1);
                if (parts.length < 2) {
                    sendError(exchange, 400, "Malformed JWT structure");
                    return;
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
                String exploitReason = "";

                // VULNERABILITY 1: "alg": "none" signature stripping bypass
                if ("none".equalsIgnoreCase(alg)) {
                    // Accepts unsigned token!
                    signatureValid = true;
                    exploitReason = "VULNERABILITY: 'alg': 'none' accepted without cryptographic signature!";
                    System.out.println("[UnsecuredServer] " + exploitReason);
                }
                // VULNERABILITY 4: 'kid' path traversal (/dev/null empty key)
                else if (kid != null && (kid.contains("/dev/null") || kid.contains("../"))) {
                    File file = new File(kid);
                    byte[] keyBytes = new byte[0];
                    if (file.exists() && file.isFile()) {
                        try (FileInputStream fis = new FileInputStream(file)) {
                            keyBytes = fis.readAllBytes();
                        }
                    }
                    final byte[] fKeyBytes = keyBytes;
                    javax.crypto.SecretKey secretKey = new javax.crypto.SecretKey() {
                        @Override public String getAlgorithm() { return "HmacSHA256"; }
                        @Override public String getFormat() { return "RAW"; }
                        @Override public byte[] getEncoded() { return fKeyBytes; }
                    };
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(secretKey);
                    byte[] expectedSig = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
                    String expectedSigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedSig);
                    if (expectedSigB64.equals(signatureBase64)) {
                        signatureValid = true;
                        exploitReason = "VULNERABILITY: 'kid' path traversal (" + kid + ") resolved to empty key; verified with empty HMAC!";
                        System.out.println("[UnsecuredServer] " + exploitReason);
                    }
                }
                // VULNERABILITY 2: Algorithm Confusion (RS256 -> HS256 with public key bytes)
                else if ("HS256".equalsIgnoreCase(alg)) {
                    // Server has an RSA public key, but caller sent HS256!
                    // Vulnerable verifier uses the RSA public key bytes (or PEM bytes) as the HMAC key!
                    byte[] rsaPubDer = KeyManager.getPublicKeyDerBytes();
                    byte[] rsaPubPem = KeyManager.getPublicKeyPem().getBytes(StandardCharsets.UTF_8);

                    Mac macDer = Mac.getInstance("HmacSHA256");
                    macDer.init(new SecretKeySpec(rsaPubDer, "HmacSHA256"));
                    byte[] expectedSigDer = macDer.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
                    String expectedSigDerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedSigDer);

                    Mac macPem = Mac.getInstance("HmacSHA256");
                    macPem.init(new SecretKeySpec(rsaPubPem, "HmacSHA256"));
                    byte[] expectedSigPem = macPem.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
                    String expectedSigPemB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedSigPem);

                    if (expectedSigDerB64.equals(signatureBase64) || expectedSigPemB64.equals(signatureBase64)) {
                        signatureValid = true;
                        exploitReason = "VULNERABILITY: Algorithm Confusion! Verified HS256 HMAC using public RSA key bytes as secret!";
                        System.out.println("[UnsecuredServer] " + exploitReason);
                    }
                }
                // Standard RS256 verification
                else if ("RS256".equalsIgnoreCase(alg)) {
                    Signature rsaSig = Signature.getInstance("SHA256withRSA");
                    rsaSig.initVerify(KeyManager.getPublicKey());
                    rsaSig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
                    byte[] sigBytes = Base64.getUrlDecoder().decode(signatureBase64);
                    signatureValid = rsaSig.verify(sigBytes);
                }

                if (!signatureValid) {
                    sendError(exchange, 401, "Invalid token signature");
                    return;
                }

                // VULNERABILITY 5: Skipping 'exp' (expiration) check
                // Even if expired, continues!
                if (payloadMap.containsKey("exp")) {
                    long exp = Long.parseLong(payloadMap.get("exp"));
                    long now = System.currentTimeMillis() / 1000;
                    if (exp < now && exploitReason.isEmpty()) {
                        exploitReason = "VULNERABILITY: Token expired " + (now - exp) + " seconds ago, but server does NOT validate 'exp' claim!";
                        System.out.println("[UnsecuredServer] " + exploitReason);
                    }
                }

                // VULNERABILITY 3: Confused Deputy - skips 'aud' and 'typ' checks!
                String role = payloadMap.getOrDefault("role", "user");
                String aud = payloadMap.getOrDefault("aud", "none");
                String sub = payloadMap.getOrDefault("sub", "anonymous");

                if (!"secured-admin-api".equals(aud) && exploitReason.isEmpty()) {
                    exploitReason = "VULNERABILITY: Confused Deputy! Token audience was '" + aud + "', but server skipped 'aud'/'typ' check!";
                    System.out.println("[UnsecuredServer] " + exploitReason);
                }

                // Grant access if role is admin OR if attacker exploited confused deputy / forgery
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
                    exploitReason.isEmpty() ? "Standard valid token accepted" : exploitReason.replace("\"", "\\\""),
                    sub, role, aud, alg
                );

                sendResponse(exchange, 200, responseJson);

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
