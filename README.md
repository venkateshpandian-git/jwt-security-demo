# JWT Vulnerability & Defense Laboratory (RFC 8725 / BCP 225)

A lightweight Java demonstration showcasing critical JSON Web Token (JWT) vulnerabilities, library compromises, and defense-in-depth implementations conforming to **RFC 8725** (*JSON Web Token Best Current Practices*), **draft-ietf-oauth-rfc8725bis-10**, and **RFC 9068**.

This repository provides two independent servers running side-by-side:
- 🔴 **Unsecured Server (Port 8081):** Simulates vulnerable parser configurations and legacy library behaviors (`alg: none`, algorithm confusion, unverified `kid`, missing audience/type checks, missing expiration checks).
- 🟢 **Secured Server (Port 8082):** Hardened with modern **Nimbus JOSE+JWT 10.0.2**, enforcing positive algorithm allowlists, key-to-algorithm binding, header sanitization, pre-parse envelope limits, and strict claim validation (`typ: at+jwt`, audience isolation, 30s max clock skew).
- 🌐 **Interactive Web Dashboard (Port 8080):** A side-by-side browser GUI to inspect tokens, fire exploits, and observe defensive controls in real-time.
- 💻 **CLI Test Runner (`./demo.sh test`):** Automated command-line runner that executes all attacks against both servers and prints a formatted comparative report.

---

## Architecture & Attack Taxonomy

| # | Attack Vector | Document Section & CVE | Vulnerable Behavior (:8081) | Secured Defense (:8082) |
|---|---|---|---|---|
| **1** | **`alg: none` Signature Stripping** | CVE-2022-23540<br>RFC 8725 §3.1 | Accepts unsigned tokens with `alg: none`, granting admin authority. | Strictly forbids `none`; requires asymmetric cryptographic verification. |
| **2** | **Algorithm Confusion (RS256 → HS256)** | CVE-2022-29217<br>CVE-2024-33663<br>RFC 8725 §3.1 | Verifies symmetric HMAC-SHA256 using the server's public RSA key bytes as the secret. | Enforces positive algorithm allowlist `[RS256]` and strict key-type binding. |
| **3** | **Confused Deputy & Cross-Service Replay** | RFC 8725 §2.4, §3.9<br>RFC 9068 | Checks signature and `iss` only, allowing worker/agent tokens into Admin API. | Validates explicit `typ: at+jwt` and requires exact `aud: secured-admin-api`. |
| **4** | **`kid` Path Traversal / Injection** | RFC 8725 §2.5, §3.10 | Reads `/dev/null` from file loader (0 bytes); verifies forged token with empty secret. | Regex check `^[a-zA-Z0-9_-]{1,64}$` and in-memory key lookup only. |
| **5** | **Expired Token Replay Attack** | RFC 8725 §1.2, §3.8 | Skips `exp` validation, allowing replayed stolen bearer tokens indefinitely. | Strict `exp` validation with maximum 30-second clock skew. |
| **6** | **Delimiter Flood Pre-Parse DoS** | CVE-2025-27144<br>RFC 8725bis §3.14 | Naively splits on `.` without limits, causing parser memory exhaustion. | Enforces 4,096-byte header ceiling and asserts period count == 2 before split. |
| **7** | **Baseline Legitimate Request** | RFC 8725 / RFC 9068 | Authenticates valid token. | Authenticates and authorizes valid RFC 8725 access token. |

---

## Quickstart

### Prerequisites
- Java 17+ (e.g. OpenJDK 27)
- Apache Maven 3.9+
- `curl`

### 1. Build and Run via CLI
```bash
# Run the automated test suite (builds, starts servers, and tests all scenarios)
./demo.sh test
```

### 2. Manual Server Management
```bash
# Start all 3 servers in the background
./demo.sh start

# Stop all servers
./demo.sh stop

# Restart servers
./demo.sh restart
```

### 3. Interactive Web Dashboard
Open your web browser and navigate to:
👉 **[http://localhost:8080](http://localhost:8080)**

Select any scenario, inspect the decoded token, and click **"Send Token to Both Servers & Compare"** to observe live side-by-side responses.

---

## Manual Verification via `curl`

### 1. Test "alg": "none" Bypass
```bash
# Generate the exploit token
TOKEN=$(curl -s "http://localhost:8080/api/generate-token?type=alg-none" | grep -o '"raw_token": "[^"]*' | cut -d'"' -f4)

# 1a. Send to Unsecured Server (Returns 200 OK - EXPLOITED!)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/admin/data

# 1b. Send to Secured Server (Returns 400 Bad Request - BLOCKED!)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/admin/data
```

### 2. Test Algorithm Confusion (RS256 → HS256)
```bash
TOKEN=$(curl -s "http://localhost:8080/api/generate-token?type=alg-confusion" | grep -o '"raw_token": "[^"]*' | cut -d'"' -f4)

# 2a. Unsecured Server: 200 OK (Public RSA key treated as HMAC secret)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/admin/data

# 2b. Secured Server: 401 Unauthorized (Algorithm 'HS256' not in allowlist [RS256])
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/admin/data
```

### 3. Test Confused Deputy (Worker Token Replay)
```bash
TOKEN=$(curl -s "http://localhost:8080/api/generate-token?type=confused-deputy" | grep -o '"raw_token": "[^"]*' | cut -d'"' -f4)

# 3a. Unsecured Server: 200 OK (Skips audience and type checks)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/admin/data

# 3b. Secured Server: 401 Unauthorized (Invalid token type / aud mismatch)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/admin/data
```

### 4. Test Delimiter Flood Pre-Parse DoS
```bash
TOKEN=$(curl -s "http://localhost:8080/api/generate-token?type=delimiter-flood" | grep -o '"raw_token": "[^"]*' | cut -d'"' -f4)

# 4a. Unsecured Server: Crashes or throws 500 error on naive split(".")
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/admin/data

# 4b. Secured Server: 400 Bad Request (Pre-parse header byte ceiling <= 4096 bytes enforced)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/admin/data
```

---

## Repository Structure
```
jwt-security-demo/
├── pom.xml                                      # Maven build file (Nimbus JOSE+JWT 10.0.2)
├── demo.sh                                      # CLI demonstration and test runner script
├── servers.log                                  # Runtime logs for the background servers
├── src/main/java/com/demo/jwt/
│   ├── DemoApplication.java                     # Main entrypoint launcher
│   ├── common/
│   │   ├── KeyManager.java                      # RSA 2048 key pair, PEM export, in-memory store
│   │   └── AttackTokenGenerator.java            # Generators for all 6 exploits + valid token
│   ├── unsecured/
│   │   └── UnsecuredServer.java                 # Vulnerable server implementation (:8081)
│   ├── secured/
│   │   └── SecuredServer.java                   # Hardened RFC 8725 compliant server (:8082)
│   └── web/
│       └── WebDashboard.java                    # Web dashboard HTTP server (:8080)
└── src/main/resources/
    └── static/
        └── index.html                           # Single-page interactive testing dashboard
```

---

## Defensive Code Highlights

In `SecuredServer.java`:
```java
// 1. Pre-Parse Envelope Protection (RFC 8725 §3.14)
if (authHeader.length() > 4096) {
    throw new SecurityException("Token header exceeds 4,096 bytes ceiling");
}
long dotCount = rawToken.chars().filter(ch -> ch == '.').count();
if (dotCount != 2) {
    throw new SecurityException("Invalid delimiter count; delimiter flood blocked");
}

// 2. Positive Algorithm Allowlist & Key Binding (RFC 8725 §3.1, §3.2)
if (!Set.of("RS256").contains(header.getAlgorithm().getName())) {
    throw new SecurityException("Algorithm not in positive allowlist");
}

// 3. Header Sanitization (RFC 8725 §3.10)
if (!SAFE_KID_PATTERN.matcher(kid).matches()) {
    throw new SecurityException("Malformed kid rejected");
}

// 4. Strict Type & Audience Enforcement (RFC 8725 §3.9, RFC 9068)
if (!"at+jwt".equalsIgnoreCase(header.getType().toString())) {
    throw new SecurityException("Expected typ: at+jwt");
}
if (!claims.getAudience().contains("secured-admin-api")) {
    throw new SecurityException("Audience mismatch; confused deputy blocked");
}
```
