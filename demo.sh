#!/usr/bin/env bash
# ==============================================================================
# JWT Vulnerability & Defense Demonstration Runner (RFC 8725 / BCP 225)
# ==============================================================================

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PID_FILE="$DIR/.demo_pids"
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

function print_banner() {
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${BOLD}     JWT Vulnerability & Defense Laboratory (RFC 8725 / BCP 225)      ${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "  Unsecured Server (Vulnerable):  ${RED}http://localhost:8081${NC}"
    echo -e "  Secured Server (RFC 8725):      ${GREEN}http://localhost:8082${NC}"
    echo -e "  Interactive Web Dashboard:      ${BLUE}http://localhost:8080${NC}"
    echo -e "${CYAN}======================================================================${NC}"
}

function build_app() {
    echo -e "\n${BLUE}[*] Building Java application with Maven...${NC}"
    cd "$DIR"
    mvn clean package -DskipTests
    echo -e "${GREEN}[+] Build complete: target/jwt-security-demo-1.0.0.jar${NC}"
}

function start_servers() {
    if [ -f "$PID_FILE" ]; then
        echo -e "${YELLOW}[!] Servers already running or PID file exists. Run './demo.sh stop' first.${NC}"
        return
    fi

    if [ ! -f "$DIR/target/jwt-security-demo-1.0.0.jar" ]; then
        build_app
    fi

    echo -e "\n${BLUE}[*] Starting servers...${NC}"
    java -jar "$DIR/target/jwt-security-demo-1.0.0.jar" all > "$DIR/servers.log" 2>&1 &
    APP_PID=$!
    echo "$APP_PID" > "$PID_FILE"

    echo -n "Waiting for servers to be ready..."
    for i in {1..20}; do
        if curl -s http://localhost:8080/api/config >/dev/null 2>&1 && \
           curl -s http://localhost:8081/api/status >/dev/null 2>&1 && \
           curl -s http://localhost:8082/api/status >/dev/null 2>&1; then
            echo -e " ${GREEN}READY!${NC}"
            echo -e "${GREEN}[+] Web Dashboard running at: http://localhost:8080${NC}"
            echo -e "${RED}[+] Unsecured Server running at: http://localhost:8081${NC}"
            echo -e "${GREEN}[+] Secured Server running at:   http://localhost:8082${NC}"
            return
        fi
        sleep 0.5
        echo -n "."
    done

    echo -e " ${RED}FAILED to start within 10 seconds! Check $DIR/servers.log${NC}"
}

function stop_servers() {
    echo -e "\n${BLUE}[*] Stopping servers...${NC}"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            echo -e "${GREEN}[+] Stopped process $PID${NC}"
        fi
        rm -f "$PID_FILE"
    fi

    # Kill any lingering instances on ports 8080, 8081, 8082
    for PORT in 8080 8081 8082; do
        PID=$(lsof -ti :$PORT 2>/dev/null || true)
        if [ -n "$PID" ]; then
            kill -9 "$PID" 2>/dev/null || true
            echo -e "${GREEN}[+] Killed lingering process on port $PORT (PID $PID)${NC}"
        fi
    done
    echo -e "${GREEN}[+] All servers stopped.${NC}"
}

function run_single_test() {
    local TYPE="$1"
    local TITLE="$2"
    local CVE="$3"

    echo -e "\n----------------------------------------------------------------------"
    echo -e "${BOLD}${YELLOW}TEST: ${TITLE}${NC} [${CYAN}${CVE}${NC}]"
    echo -e "----------------------------------------------------------------------"

    # Fetch attack token from WebDashboard API
    TOKEN_JSON=$(curl -s "http://localhost:8080/api/generate-token?type=$TYPE")
    TOKEN=$(echo "$TOKEN_JSON" | grep -o '"raw_token": "[^"]*' | cut -d'"' -f4)

    if [ -z "$TOKEN" ]; then
        echo -e "${RED}[!] Error generating token for $TYPE${NC}"
        return
    fi

    # 1. Send to Unsecured Server (8081)
    UNSEC_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/admin/data)
    UNSEC_STATUS=$(echo "$UNSEC_RESP" | grep "HTTP_STATUS:" | cut -d':' -f2)
    UNSEC_BODY=$(echo "$UNSEC_RESP" | grep -v "HTTP_STATUS:")

    # 2. Send to Secured Server (8082)
    SEC_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/admin/data)
    SEC_STATUS=$(echo "$SEC_RESP" | grep "HTTP_STATUS:" | cut -d':' -f2)
    SEC_BODY=$(echo "$SEC_RESP" | grep -v "HTTP_STATUS:")

    # Output Unsecured Result
    echo -n "  • Unsecured Server (Port 8081): "
    if [ "$UNSEC_STATUS" -eq 200 ]; then
        echo -e "${RED}${BOLD}[EXPLOITED! HTTP 200 OK]${NC}"
        echo -e "    ${RED}>> Admin access granted! Confidential ledger data compromised.${NC}"
    else
        echo -e "${YELLOW}[HTTP $UNSEC_STATUS]${NC}"
    fi

    # Output Secured Result
    echo -n "  • Secured Server   (Port 8082): "
    if [ "$TYPE" == "valid" ]; then
        if [ "$SEC_STATUS" -eq 200 ]; then
            echo -e "${GREEN}${BOLD}[AUTHENTICATED! HTTP 200 OK]${NC}"
            echo -e "    ${GREEN}>> Legitimate token fully verified under RFC 8725 standards.${NC}"
        else
            echo -e "${RED}[UNEXPECTED: HTTP $SEC_STATUS]${NC}"
        fi
    else
        if [ "$SEC_STATUS" -ne 200 ]; then
            echo -e "${GREEN}${BOLD}[BLOCKED! HTTP $SEC_STATUS]${NC}"
            DEFENSE_MSG=$(echo "$SEC_BODY" | grep -o '"defense_explanation": "[^"]*' | cut -d'"' -f4)
            if [ -n "$DEFENSE_MSG" ]; then
                echo -e "    ${GREEN}>> Defense Triggered: $DEFENSE_MSG${NC}"
            fi
        else
            echo -e "${RED}${BOLD}[FAILED: Server accepted exploit! HTTP 200]${NC}"
        fi
    fi
}

function run_all_tests() {
    print_banner

    # Ensure servers are running
    if ! curl -s http://localhost:8080/api/config >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Servers are not running. Launching now...${NC}"
        start_servers
    fi

    echo -e "\n${BOLD}${CYAN}=== EXECUTING JWT ATTACK SUITE AGAINST UNSECURED VS SECURED SERVERS ===${NC}"

    run_single_test "alg-none" "\"alg\": \"none\" Signature Stripping Bypass" "CVE-2022-23540 / RFC 8725 §3.1"
    run_single_test "alg-confusion" "Algorithm Confusion (RS256 Public Key as HS256 Secret)" "CVE-2022-29217 / RFC 8725 §3.1"
    run_single_test "confused-deputy" "Confused Deputy (Worker Token Replayed at Admin API)" "RFC 8725 §3.9 / RFC 9068"
    run_single_test "kid-traversal" "Unverified 'kid' Path Traversal to /dev/null" "RFC 8725 §3.10"
    run_single_test "expired" "Expired Token Replay Attack" "RFC 8725 §3.8"
    run_single_test "delimiter-flood" "Delimiter Flood Pre-Parse DoS" "CVE-2025-27144 / RFC 8725bis §3.14"
    run_single_test "embedded-jwk" "Embedded JWK Key Injection (jwt_tool -X i)" "CVE-2018-0114 / RFC 8725 §3.10"
    run_single_test "valid" "Baseline Legitimate Access Token" "RFC 8725 / RFC 9068 Compliant"

    echo -e "\n${CYAN}======================================================================${NC}"
    echo -e "${BOLD}${GREEN}✔ TEST RUN COMPLETE! All attack vectors successfully demonstrated.${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "You can also view the visual side-by-side dashboard in your browser:"
    echo -e "  👉  ${BOLD}${BLUE}http://localhost:8080${NC}\n"
}

case "$1" in
    build)
        build_app
        ;;
    start)
        print_banner
        start_servers
        ;;
    stop)
        stop_servers
        ;;
    restart)
        stop_servers
        start_servers
        ;;
    test)
        run_all_tests
        ;;
    *)
        print_banner
        echo -e "Usage: $0 {build|start|stop|restart|test}"
        echo -e ""
        echo -e "  build    - Compile and package Java app via Maven"
        echo -e "  start    - Start WebDashboard (8080), Unsecured (8081), and Secured (8082)"
        echo -e "  stop     - Stop all running demonstration servers"
        echo -e "  test     - Run the automated CLI attack suite and print side-by-side results"
        echo -e ""
        echo -e "Quickstart: run '$0 test' to build, start, and run the complete test suite!"
        ;;
esac
