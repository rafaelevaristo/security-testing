#!/bin/bash

# ISO 27001 Security Testing Framework
# Author: Security Testing Automation
# Version: 1.0
# Description: Automated security testing for web applications and HTTP configurations

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_DIR="${SCRIPT_DIR}/logs"
readonly REPORT_DIR="${SCRIPT_DIR}/reports"
readonly CONFIG_FILE="${SCRIPT_DIR}/config.conf"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Default configuration
DEFAULT_TIMEOUT=10
DEFAULT_USER_AGENT="SecurityTester/1.0"
VERBOSE=false
OUTPUT_FORMAT="text"

# Initialize directories
init_directories() {
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
}

# Logging functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_DIR/security_test.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_DIR/security_test.log"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_DIR/security_test.log"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_DIR/security_test.log"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_DIR/security_test.log"
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log_info "Configuration loaded from $CONFIG_FILE"
    else
        log_warning "No configuration file found, using defaults"
    fi
}

# HTTP Security Headers Test
test_security_headers() {
    local url="$1"
    local results_file="$2"
    
    log_info "Testing security headers for: $url"
    
    local response
    response=$(curl -s -I -m "$DEFAULT_TIMEOUT" -A "$DEFAULT_USER_AGENT" "$url" 2>/dev/null || echo "CURL_ERROR")
    
    if [[ "$response" == "CURL_ERROR" ]]; then
        echo "FAIL: Unable to connect to $url" >> "$results_file"
        return 1
    fi
    
    # Required security headers
    local required_headers=(
        "Strict-Transport-Security"
        "X-Content-Type-Options"
        "X-Frame-Options"
        "X-XSS-Protection"
        "Content-Security-Policy"
        "Referrer-Policy"
    )
    
    local missing_headers=()
    
    for header in "${required_headers[@]}"; do
        if ! echo "$response" | grep -qi "^$header:"; then
            missing_headers+=("$header")
        fi
    done
    
    if [[ ${#missing_headers[@]} -eq 0 ]]; then
        echo "PASS: All required security headers present" >> "$results_file"
        log_success "Security headers test passed for $url"
    else
        echo "FAIL: Missing security headers: ${missing_headers[*]}" >> "$results_file"
        log_warning "Missing headers for $url: ${missing_headers[*]}"
    fi
    
    # Check for insecure headers
    local insecure_headers=(
        "Server:"
        "X-Powered-By:"
        "X-AspNet-Version:"
    )
    
    local found_insecure=()
    for header in "${insecure_headers[@]}"; do
        if echo "$response" | grep -qi "^$header"; then
            found_insecure+=("$header")
        fi
    done
    
    if [[ ${#found_insecure[@]} -gt 0 ]]; then
        echo "WARNING: Information disclosure headers found: ${found_insecure[*]}" >> "$results_file"
        log_warning "Information disclosure headers found for $url: ${found_insecure[*]}"
    fi
}

# SSL/TLS Configuration Test
test_ssl_configuration() {
    local host="$1"
    local port="${2:-443}"
    local results_file="$3"
    
    log_info "Testing SSL/TLS configuration for: $host:$port"
    
    # Test SSL connection
    local ssl_info
    ssl_info=$(echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo "FAIL: Unable to establish SSL connection to $host:$port" >> "$results_file"
        return 1
    fi
    
    # Check protocol version
    local protocol
    protocol=$(echo "$ssl_info" | grep "Protocol" | head -1 | awk '{print $3}')
    
    case "$protocol" in
        "TLSv1.3"|"TLSv1.2")
            echo "PASS: Secure TLS protocol in use: $protocol" >> "$results_file"
            log_success "Secure TLS protocol for $host: $protocol"
            ;;
        "TLSv1.1"|"TLSv1"|"SSLv3"|"SSLv2")
            echo "FAIL: Insecure protocol in use: $protocol" >> "$results_file"
            log_error "Insecure protocol for $host: $protocol"
            ;;
        *)
            echo "WARNING: Unknown protocol: $protocol" >> "$results_file"
            log_warning "Unknown protocol for $host: $protocol"
            ;;
    esac
    
    # Check cipher suite
    local cipher
    cipher=$(echo "$ssl_info" | grep "Cipher" | head -1 | awk '{print $3}')
    
    # Weak ciphers to avoid
    local weak_ciphers=(
        "RC4"
        "MD5"
        "DES"
        "3DES"
        "NULL"
        "EXPORT"
        "ADH"
        "AECDH"
    )
    
    local is_weak=false
    for weak in "${weak_ciphers[@]}"; do
        if [[ "$cipher" == *"$weak"* ]]; then
            is_weak=true
            break
        fi
    done
    
    if [[ "$is_weak" == true ]]; then
        echo "FAIL: Weak cipher in use: $cipher" >> "$results_file"
        log_error "Weak cipher for $host: $cipher"
    else
        echo "PASS: Strong cipher in use: $cipher" >> "$results_file"
        log_success "Strong cipher for $host: $cipher"
    fi
    
    # Check certificate validity
    local cert_info
    cert_info=$(echo "$ssl_info" | openssl x509 -noout -dates 2>/dev/null)
    
    if [[ $? -eq 0 ]]; then
        echo "PASS: SSL certificate is valid" >> "$results_file"
        log_success "Valid SSL certificate for $host"
    else
        echo "FAIL: SSL certificate validation failed" >> "$results_file"
        log_error "Invalid SSL certificate for $host"
    fi
}

# Basic Web Application Security Tests
test_web_app_security() {
    local base_url="$1"
    local results_file="$2"
    
    log_info "Testing web application security for: $base_url"
    
    # Test for common vulnerabilities
    
    # 1. Directory traversal
    local traversal_payloads=(
        "../etc/passwd"
        "..\\windows\\system32\\drivers\\etc\\hosts"
        "....//....//etc/passwd"
    )
    
    for payload in "${traversal_payloads[@]}"; do
        local response
        response=$(curl -s -m "$DEFAULT_TIMEOUT" -A "$DEFAULT_USER_AGENT" "$base_url/$payload" 2>/dev/null || echo "CURL_ERROR")
        
        if [[ "$response" != "CURL_ERROR" ]] && [[ "$response" == *"root:"* ]] || [[ "$response" == *"localhost"* ]]; then
            echo "FAIL: Potential directory traversal vulnerability detected" >> "$results_file"
            log_error "Directory traversal vulnerability found for $base_url"
            break
        fi
    done
    
    # 2. SQL Injection basic test
    local sqli_payloads=(
        "'"
        "1' OR '1'='1"
        "1' UNION SELECT 1--"
    )
    
    for payload in "${sqli_payloads[@]}"; do
        local response
        response=$(curl -s -m "$DEFAULT_TIMEOUT" -A "$DEFAULT_USER_AGENT" "$base_url?id=$payload" 2>/dev/null || echo "CURL_ERROR")
        
        if [[ "$response" != "CURL_ERROR" ]] && [[ "$response" == *"SQL"* ]] || [[ "$response" == *"mysql"* ]] || [[ "$response" == *"syntax error"* ]]; then
            echo "FAIL: Potential SQL injection vulnerability detected" >> "$results_file"
            log_error "SQL injection vulnerability found for $base_url"
            break
        fi
    done
    
    # 3. XSS basic test
    local xss_payload="<script>alert('XSS')</script>"
    local response
    response=$(curl -s -m "$DEFAULT_TIMEOUT" -A "$DEFAULT_USER_AGENT" "$base_url?q=$xss_payload" 2>/dev/null || echo "CURL_ERROR")
    
    if [[ "$response" != "CURL_ERROR" ]] && [[ "$response" == *"<script>alert('XSS')</script>"* ]]; then
        echo "FAIL: Potential XSS vulnerability detected" >> "$results_file"
        log_error "XSS vulnerability found for $base_url"
    else
        echo "PASS: No obvious XSS vulnerability detected" >> "$results_file"
        log_success "XSS test passed for $base_url"
    fi
    
    # 4. Check for sensitive files
    local sensitive_files=(
        "robots.txt"
        ".git/config"
        ".env"
        "config.php"
        "wp-config.php"
        "web.config"
        ".htaccess"
    )
    
    local exposed_files=()
    for file in "${sensitive_files[@]}"; do
        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" -m "$DEFAULT_TIMEOUT" -A "$DEFAULT_USER_AGENT" "$base_url/$file" 2>/dev/null || echo "000")
        
        if [[ "$status_code" == "200" ]]; then
            exposed_files+=("$file")
        fi
    done
    
    if [[ ${#exposed_files[@]} -gt 0 ]]; then
        echo "WARNING: Sensitive files accessible: ${exposed_files[*]}" >> "$results_file"
        log_warning "Sensitive files accessible for $base_url: ${exposed_files[*]}"
    fi
}

# HTTP Methods Test
test_http_methods() {
    local url="$1"
    local results_file="$2"
    
    log_info "Testing HTTP methods for: $url"
    
    local dangerous_methods=("PUT" "DELETE" "TRACE" "CONNECT" "PATCH")
    local allowed_methods=()
    
    for method in "${dangerous_methods[@]}"; do
        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -m "$DEFAULT_TIMEOUT" -A "$DEFAULT_USER_AGENT" "$url" 2>/dev/null || echo "000")
        
        if [[ "$status_code" != "405" ]] && [[ "$status_code" != "501" ]] && [[ "$status_code" != "000" ]]; then
            allowed_methods+=("$method")
        fi
    done
    
    if [[ ${#allowed_methods[@]} -gt 0 ]]; then
        echo "WARNING: Potentially dangerous HTTP methods allowed: ${allowed_methods[*]}" >> "$results_file"
        log_warning "Dangerous HTTP methods allowed for $url: ${allowed_methods[*]}"
    else
        echo "PASS: No dangerous HTTP methods allowed" >> "$results_file"
        log_success "HTTP methods test passed for $url"
    fi
}

# Generate HTML report
generate_html_report() {
    local results_file="$1"
    local html_file="$REPORT_DIR/security_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        .test-section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Test Report</h1>
        <p>Generated on: $(date)</p>
    </div>
    <div class="test-section">
        <h2>Test Results</h2>
        <pre>
EOF

    while IFS= read -r line; do
        if [[ "$line" == *"PASS:"* ]]; then
            echo "<span class=\"pass\">$line</span>" >> "$html_file"
        elif [[ "$line" == *"FAIL:"* ]]; then
            echo "<span class=\"fail\">$line</span>" >> "$html_file"
        elif [[ "$line" == *"WARNING:"* ]]; then
            echo "<span class=\"warning\">$line</span>" >> "$html_file"
        else
            echo "$line" >> "$html_file"
        fi
    done < "$results_file"

    cat >> "$html_file" << EOF
        </pre>
    </div>
</body>
</html>
EOF

    log_info "HTML report generated: $html_file"
    echo "$html_file"
}

# Main testing function
run_security_tests() {
    local target_urls=("$@")
    
    if [[ ${#target_urls[@]} -eq 0 ]]; then
        log_error "No target URLs provided"
        exit 1
    fi
    
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local results_file="$REPORT_DIR/security_results_$timestamp.txt"
    
    echo "Security Test Results - $(date)" > "$results_file"
    echo "========================================" >> "$results_file"
    
    for url in "${target_urls[@]}"; do
        log_info "Starting security tests for: $url"
        echo "" >> "$results_file"
        echo "Testing: $url" >> "$results_file"
        echo "----------------------------------------" >> "$results_file"
        
        # Extract host and port for SSL testing
        local host
        local port=443
        host=$(echo "$url" | sed -E 's|https?://([^/:]+).*|\1|')
        
        if [[ "$url" == *":8080"* ]]; then
            port=8080
        elif [[ "$url" == *":80"* ]]; then
            port=80
        fi
        
        # Run tests
        test_security_headers "$url" "$results_file"
        
        if [[ "$url" == https://* ]]; then
            test_ssl_configuration "$host" "$port" "$results_file"
        fi
        
        test_web_app_security "$url" "$results_file"
        test_http_methods "$url" "$results_file"
        
        echo "" >> "$results_file"
    done
    
    log_success "Security testing completed. Results saved to: $results_file"
    
    # Generate HTML report if requested
    if [[ "$OUTPUT_FORMAT" == "html" ]]; then
        generate_html_report "$results_file"
    fi
    
    # Display summary
    local pass_count fail_count warning_count
    pass_count=$(grep -c "PASS:" "$results_file" || echo "0")
    fail_count=$(grep -c "FAIL:" "$results_file" || echo "0")
    warning_count=$(grep -c "WARNING:" "$results_file" || echo "0")
    
    echo ""
    log_info "Test Summary:"
    log_success "Passed: $pass_count"
    log_error "Failed: $fail_count"
    log_warning "Warnings: $warning_count"
    
    return $fail_count
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] URL1 [URL2 ...]

Options:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -t, --timeout SEC   Set timeout for requests (default: $DEFAULT_TIMEOUT)
    -f, --format FORMAT Output format: text or html (default: $OUTPUT_FORMAT)
    -c, --config FILE   Use custom configuration file

Examples:
    $0 https://example.com
    $0 -f html https://app1.com https://app2.com
    $0 -t 30 -v https://secure-app.com

EOF
}

# Parse command line arguments
parse_args() {
    local urls=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -t|--timeout)
                DEFAULT_TIMEOUT="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                urls+=("$1")
                shift
                ;;
        esac
    done
    
    if [[ ${#urls[@]} -eq 0 ]]; then
        log_error "At least one URL must be provided"
        show_usage
        exit 1
    fi
    
    echo "${urls[@]}"
}

# Main function
main() {
    local urls
    
    # Initialize
    init_directories
    load_config
    
    # Parse arguments
    urls=($(parse_args "$@"))
    
    # Run tests
    run_security_tests "${urls[@]}"
    
    exit $?
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi