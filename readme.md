# README.md
# ISO 27001 Security Testing Framework

A lightweight, containerized security testing framework designed for ISO 27001 compliance. This tool provides automated security testing without the complexity and false positives of tools like ZAP.

## Features

- **HTTP Security Headers Testing**: Validates presence of required security headers
- **SSL/TLS Configuration Testing**: Checks for weak protocols and ciphers  
- **Basic Web Application Security**: Tests for common vulnerabilities (XSS, SQLi, Directory Traversal)
- **HTTP Methods Testing**: Identifies dangerous HTTP methods
- **Containerized**: Runs in Docker for consistency and isolation
- **Scheduled Testing**: Supports cron-based automated testing
- **Multiple Output Formats**: Text and HTML reports
- **ISO 27001 Focused**: Designed specifically for compliance requirements

## Quick Start

1. **Build the container:**
   ```bash
   make build
   ```

2. **Run security tests:**
   ```bash
   URLS='https://your-app.com https://your-api.com' make test
   ```

3. **View reports:**
   ```bash
   make reports
   # Open http://localhost:8080 in your browser
   ```

## Configuration

Edit `config.conf` to customize:
- Timeout settings
- Custom security headers to check
- Output format preferences
- Test inclusion/exclusion

## Scheduled Testing

For continuous monitoring:
```bash
URLS='https://your-app.com' make cron
```

This sets up daily automated testing at 2 AM.

## Manual Usage

You can also run the script directly:
```bash
./security_test.sh -f html -t 30 https://example.com
```

## Output

The framework generates:
- Text reports with pass/fail results
- HTML reports with color-coded results
- Detailed logs for troubleshooting
- Summary statistics

## ISO 27001 Compliance

This tool addresses several ISO 27001 2022 controls:
- A.8.24 (Use of cryptography)
- A.8.25 (Secure system engineering principles)  
- A.8.26 (Application security requirements)
- A.8.29 (Security testing in development and acceptance)

## Extending the Framework

The modular design allows easy extension:
- Add new test functions following the existing pattern
- Extend configuration options
- Add notification capabilities
- Integrate with CI/CD pipelines