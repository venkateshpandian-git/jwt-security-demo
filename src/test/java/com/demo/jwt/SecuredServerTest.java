package com.demo.jwt;

import com.demo.jwt.common.AttackTokenGenerator;
import com.demo.jwt.secured.SecuredServer;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Secured Server RFC 8725 Defense Tests")
public class SecuredServerTest {

    @Test
    @DisplayName("Defense 1: 'alg': 'none' is strictly rejected (RFC 8725 §3.1)")
    void testAlgNoneRejected() {
        String token = AttackTokenGenerator.createAlgNoneToken("attacker", "admin");
        SecurityException ex = assertThrows(SecurityException.class, () ->
            SecuredServer.verifyToken("Bearer " + token)
        );
        assertTrue(ex.getMessage().contains("none") || ex.getMessage().contains("forbidden"));
    }

    @Test
    @DisplayName("Defense 2: Algorithm Confusion (HS256) is rejected by allowlist [RS256] (RFC 8725 §3.1, §3.2)")
    void testAlgorithmConfusionRejected() {
        String token = AttackTokenGenerator.createAlgorithmConfusionToken("attacker", "admin", false);
        SecurityException ex = assertThrows(SecurityException.class, () ->
            SecuredServer.verifyToken("Bearer " + token)
        );
        assertTrue(ex.getMessage().contains("typ") || ex.getMessage().contains("Algorithm") || ex.getMessage().contains("RS256"));
    }

    @Test
    @DisplayName("Defense 3: Confused Deputy - worker token rejected due to wrong typ/audience (RFC 8725 §3.9, RFC 9068)")
    void testConfusedDeputyRejected() {
        String token = AttackTokenGenerator.createConfusedDeputyToken("low-privilege-worker");
        SecurityException ex = assertThrows(SecurityException.class, () ->
            SecuredServer.verifyToken("Bearer " + token)
        );
        assertTrue(ex.getMessage().contains("typ") || ex.getMessage().contains("at+jwt") || ex.getMessage().contains("Audience"));
    }

    @Test
    @DisplayName("Defense 4: kid path traversal rejected by alphanumeric regex (RFC 8725 §3.10)")
    void testKidPathTraversalRejected() {
        String token = AttackTokenGenerator.createKidPathTraversalToken("attacker", "admin");
        SecurityException ex = assertThrows(SecurityException.class, () ->
            SecuredServer.verifyToken("Bearer " + token)
        );
        assertTrue(ex.getMessage().contains("regex") || ex.getMessage().contains("kid") || ex.getMessage().contains("traversal"));
    }

    @Test
    @DisplayName("Defense 5: Expired token rejected by strict exp validation (RFC 8725 §3.8)")
    void testExpiredTokenRejected() {
        String token = AttackTokenGenerator.createExpiredToken("attacker", "admin");
        Exception ex = assertThrows(Exception.class, () ->
            SecuredServer.verifyToken("Bearer " + token)
        );
        assertTrue(ex.getMessage().toLowerCase().contains("expired"));
    }

    @Test
    @DisplayName("Defense 6: Delimiter flood rejected before split by period count pre-check (RFC 8725 §3.14)")
    void testDelimiterFloodRejected() {
        String token = AttackTokenGenerator.createDelimiterFloodToken(5000);
        SecurityException ex = assertThrows(SecurityException.class, () ->
            SecuredServer.verifyToken("Bearer " + token)
        );
        assertTrue(ex.getMessage().contains("delimiter") || ex.getMessage().contains("4,096"));
    }

    @Test
    @DisplayName("Baseline: Legitimate RFC 8725 & RFC 9068 admin token is successfully authenticated and authorized")
    void testLegitimateTokenAccepted() throws Exception {
        String token = AttackTokenGenerator.createValidSecuredToken("alice-admin", "admin");
        JWTClaimsSet claims = SecuredServer.verifyToken("Bearer " + token);

        assertNotNull(claims);
        assertEquals("alice-admin", claims.getSubject());
        assertEquals("admin", claims.getStringClaim("role"));
        assertTrue(claims.getAudience().contains("secured-admin-api"));
    }
}
