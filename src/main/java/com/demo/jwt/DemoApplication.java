package com.demo.jwt;

import com.demo.jwt.secured.SecuredServer;
import com.demo.jwt.unsecured.UnsecuredServer;
import com.demo.jwt.web.WebDashboard;

import java.io.IOException;

/**
 * Main application entrypoint.
 *
 * Can start:
 * - All servers (Web Dashboard on 8080, Unsecured Server on 8081, Secured Server on 8082)
 * - Individual servers via command line args: "all", "unsecured", "secured", "web"
 */
public class DemoApplication {

    public static void main(String[] args) throws IOException {
        String mode = args.length > 0 ? args[0].toLowerCase() : "all";

        UnsecuredServer unsecuredServer = null;
        SecuredServer securedServer = null;
        WebDashboard webDashboard = null;

        System.out.println("==================================================================");
        System.out.println("  JWT Vulnerability & Defense Laboratory (RFC 8725 / BCP 225)     ");
        System.out.println("==================================================================");

        if ("all".equals(mode) || "unsecured".equals(mode)) {
            unsecuredServer = new UnsecuredServer(UnsecuredServer.DEFAULT_PORT);
            unsecuredServer.start();
        }

        if ("all".equals(mode) || "secured".equals(mode)) {
            securedServer = new SecuredServer(SecuredServer.DEFAULT_PORT);
            securedServer.start();
        }

        if ("all".equals(mode) || "web".equals(mode)) {
            webDashboard = new WebDashboard(WebDashboard.DEFAULT_PORT);
            webDashboard.start();
        }

        System.out.println("==================================================================");
        if (webDashboard != null) {
            System.out.println("  >> Interactive Web Dashboard: http://localhost:8080            ");
        }
        if (unsecuredServer != null) {
            System.out.println("  >> Unsecured Server (Vulnerable): http://localhost:8081        ");
        }
        if (securedServer != null) {
            System.out.println("  >> Secured Server (RFC 8725):     http://localhost:8082        ");
        }
        System.out.println("==================================================================");
        System.out.println("Press Ctrl+C to stop all servers.");

        final UnsecuredServer uRef = unsecuredServer;
        final SecuredServer sRef = securedServer;
        final WebDashboard wRef = webDashboard;

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nShutting down servers...");
            if (uRef != null) uRef.stop();
            if (sRef != null) sRef.stop();
            if (wRef != null) wRef.stop();
            System.out.println("All servers stopped successfully.");
        }));
    }
}
