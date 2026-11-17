package com.demo.jwt.web;

import com.demo.jwt.common.AttackTokenGenerator;
import com.demo.jwt.common.KeyManager;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

/**
 * Serves the interactive web interface and token generation APIs on port 8080.
 */
public class WebDashboard {

    public static final int DEFAULT_PORT = 8080;
    private final int port;
    private HttpServer server;

    public WebDashboard(int port) {
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());

        server.createContext("/", new StaticFileHandler());
        server.createContext("/api/generate-token", new TokenGeneratorHandler());
        server.createContext("/api/config", new ConfigHandler());

        server.start();
        System.out.println("[WebDashboard] Interactive UI started at http://localhost:" + port);
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            System.out.println("[WebDashboard] Stopped");
        }
    }

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        WebDashboard dashboard = new WebDashboard(port);
        dashboard.start();
    }

    static class ConfigHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            String configJson = """
                {
                    "dashboard_port": 8080,
                    "unsecured_port": 8081,
                    "secured_port": 8082,
                    "unsecured_url": "http://localhost:8081",
                    "secured_url": "http://localhost:8082"
                }
                """;
            byte[] bytes = configJson.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    static class TokenGeneratorHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "*");

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            try {
                String query = exchange.getRequestURI().getQuery();
                String type = "valid";
                if (query != null && query.contains("type=")) {
                    for (String param : query.split("&")) {
                        if (param.startsWith("type=")) {
                            type = param.substring(5);
                        }
                    }
                }

                String token;
                String attackName;
                String cveReference;
                String description;

                switch (type) {
                    case "alg-none" -> {
                        token = AttackTokenGenerator.createAlgNoneToken("attacker-agent", "admin");
                        attackName = "Attack 1: 'alg': 'none' Signature Stripping";
                        cveReference = "CVE-2022-23540 / RFC 8725 §3.1";
                        description = "Sets header 'alg': 'none' and drops signature. Vulnerable servers accept unsigned token as admin.";
                    }
                    case "alg-confusion" -> {
                        token = AttackTokenGenerator.createAlgorithmConfusionToken("attacker-agent", "admin", false);
                        attackName = "Attack 2: Algorithm Confusion (RS256 -> HS256)";
                        cveReference = "CVE-2022-29217 / CVE-2024-33663 / RFC 8725 §3.1";
                        description = "Sets header 'alg': 'HS256' and signs with the server's public RSA key bytes as the HMAC secret.";
                    }
                    case "confused-deputy" -> {
                        token = AttackTokenGenerator.createConfusedDeputyToken("low-privilege-worker");
                        attackName = "Attack 3: Confused Deputy & Cross-Service Substitution";
                        cveReference = "RFC 8725 §2.4, §3.9 / RFC 9068";
                        description = "Legitimate token issued for 'low-privilege-worker-agent' replayed against the high-privilege Admin API.";
                    }
                    case "kid-traversal" -> {
                        token = AttackTokenGenerator.createKidPathTraversalToken("attacker-agent", "admin");
                        attackName = "Attack 4: 'kid' Path Traversal to /dev/null";
                        cveReference = "RFC 8725 §2.5, §3.10";
                        description = "Sets 'kid': '../../../../dev/null'. Vulnerable file key resolver reads empty bytes; token signed with empty secret.";
                    }
                    case "expired" -> {
                        token = AttackTokenGenerator.createExpiredToken("attacker-agent", "admin");
                        attackName = "Attack 5: Expired Token Replay Attack";
                        cveReference = "RFC 8725 §1.2, §3.8";
                        description = "Token that expired 1 hour ago. Vulnerable servers fail to validate 'exp' claim, allowing indefinite replay.";
                    }
                    case "delimiter-flood" -> {
                        token = AttackTokenGenerator.createDelimiterFloodToken(5000);
                        attackName = "Attack 6: Delimiter Flood Pre-Parse DoS";
                        cveReference = "CVE-2025-27144 / RFC 8725bis §3.14";
                        description = "Authorization header packed with 5,000 dots. Causes naive split('.') parsers to exhaust memory or crash.";
                    }
                    default -> {
                        token = AttackTokenGenerator.createValidSecuredToken("alice-admin", "admin");
                        attackName = "Baseline: Legitimate RFC 8725 Admin Token";
                        cveReference = "RFC 8725 / RFC 9068 Compliant";
                        description = "Asymmetric RS256 token with explicit 'typ': 'at+jwt', 'aud': 'secured-admin-api', and 5-min expiration.";
                    }
                }

                // Split token into header and payload for visualization
                String headerDecoded = "{}";
                String payloadDecoded = "{}";
                if (!"delimiter-flood".equals(type)) {
                    String[] parts = token.split("\\.", -1);
                    if (parts.length >= 2) {
                        try {
                            headerDecoded = new String(java.util.Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
                            payloadDecoded = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                        } catch (Exception ignored) {}
                    }
                }

                String jsonResponse = String.format("""
                    {
                        "type": "%s",
                        "attack_name": "%s",
                        "cve_reference": "%s",
                        "description": "%s",
                        "raw_token": "%s",
                        "decoded_header": %s,
                        "decoded_payload": %s
                    }
                    """,
                    type,
                    attackName,
                    cveReference,
                    description,
                    token,
                    headerDecoded,
                    payloadDecoded
                );

                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
                byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } catch (Throwable t) {
                t.printStackTrace();
                String err = "{\"error\": \"" + t.getMessage().replace("\"", "\\\"") + "\"}";
                byte[] b = err.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
                exchange.sendResponseHeaders(500, b.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(b);
                }
            }
        }
    }

    static class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if (path == null || path.equals("/") || path.isEmpty()) {
                path = "/index.html";
            }

            try (InputStream is = getClass().getResourceAsStream("/static" + path)) {
                if (is == null) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }

                String contentType = "text/html; charset=UTF-8";
                if (path.endsWith(".css")) contentType = "text/css; charset=UTF-8";
                else if (path.endsWith(".js")) contentType = "application/javascript; charset=UTF-8";
                else if (path.endsWith(".json")) contentType = "application/json; charset=UTF-8";

                exchange.getResponseHeaders().set("Content-Type", contentType);
                byte[] content = is.readAllBytes();
                exchange.sendResponseHeaders(200, content.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(content);
                }
            }
        }
    }
}
