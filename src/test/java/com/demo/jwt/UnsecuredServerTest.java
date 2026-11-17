package com.demo.jwt;

import com.demo.jwt.common.AttackTokenGenerator;
import com.demo.jwt.unsecured.UnsecuredServer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Unsecured Server Vulnerability Verification Tests")
public class UnsecuredServerTest {

    @Test
    @DisplayName("Vulnerability 1: 'alg': 'none' signature stripping bypass accepted")
    void testAlgNoneAccepted() throws Exception {
        String token = AttackTokenGenerator.createAlgNoneToken("attacker", "admin");
        UnsecuredServer.VerificationResult result = UnsecuredServer.verifyToken("Bearer " + token);

        assertNotNull(result);
        assertEquals("admin", result.claims().get("role"));
        assertEquals("ALG_NONE_BYPASS", result.exploitDetected());
    }

    @Test
    @DisplayName("Vulnerability 2: Algorithm Confusion (RS256 public key as HS256 secret) accepted")
    void testAlgorithmConfusionAccepted() throws Exception {
        String token = AttackTokenGenerator.createAlgorithmConfusionToken("attacker", "admin", false);
        UnsecuredServer.VerificationResult result = UnsecuredServer.verifyToken("Bearer " + token);

        assertNotNull(result);
        assertEquals("admin", result.claims().get("role"));
        assertEquals("ALGORITHM_CONFUSION_RS256_TO_HS256", result.exploitDetected());
    }

    @Test
    @DisplayName("Vulnerability 3: Confused Deputy - worker token accepted without audience check")
    void testConfusedDeputyAccepted() throws Exception {
        String token = AttackTokenGenerator.createConfusedDeputyToken("low-privilege-worker");
        UnsecuredServer.VerificationResult result = UnsecuredServer.verifyToken("Bearer " + token);

        assertNotNull(result);
        assertEquals("low-privilege-worker", result.claims().get("sub"));
        assertEquals("CONFUSED_DEPUTY_AUDIENCE_IGNORED", result.exploitDetected());
    }

    @Test
    @DisplayName("Vulnerability 4: kid path traversal to /dev/null with empty HMAC key accepted")
    void testKidPathTraversalAccepted() throws Exception {
        String token = AttackTokenGenerator.createKidPathTraversalToken("attacker", "admin");
        UnsecuredServer.VerificationResult result = UnsecuredServer.verifyToken("Bearer " + token);

        assertNotNull(result);
        assertEquals("admin", result.claims().get("role"));
        assertEquals("KID_PATH_TRAVERSAL_EMPTY_KEY", result.exploitDetected());
    }

    @Test
    @DisplayName("Vulnerability 5: Expired token accepted because 'exp' claim is ignored")
    void testExpiredTokenAccepted() throws Exception {
        String token = AttackTokenGenerator.createExpiredToken("attacker", "admin");
        UnsecuredServer.VerificationResult result = UnsecuredServer.verifyToken("Bearer " + token);

        assertNotNull(result);
        assertEquals("admin", result.claims().get("role"));
        assertEquals("EXPIRED_TOKEN_ACCEPTED", result.exploitDetected());
    }
}
