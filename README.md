# API Vulnerability Scanner

A simple Go-based API vulnerability scanner that checks for common security issues.

## Features

- Security header analysis
- HTTPS usage verification
- CORS configuration check
- Server information disclosure detection
- Content-Type validation
- Multiple output formats (console, JSON)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/api-vuln-scanner.git
cd api-vuln-scanner

# Initialize Go module and download dependencies
go mod init github.com/yourusername/api-vuln-scanner
go mod tidy

# Build the application
go build -o scanner.exe .

# Run the scanner
.\scanner.exe scan -u $URL
```

## Usage

### Basic scan
```bash
./api-vuln-scanner scan -u http://localhost:8080
```

### Scan with custom timeout
```bash
./api-vuln-scanner scan -u http://localhost:8080 -t 30
```

### Output as JSON
```bash
./api-vuln-scanner scan -u http://localhost:8080 -o json
```

### Help
```bash
./api-vuln-scanner --help
./api-vuln-scanner scan --help
```

## Example Output

```
=== API Vulnerability Scan Report ===
Target: http://localhost:8080
Scan Time: 2024-01-15 14:30:25

Summary:
  Total Issues Found: 3
  High: 1
  Medium: 2

Detailed Results:

[HIGH] HTTP Usage (SEC-002)
  Category: Transport
  Description: API is accessible over unencrypted HTTP
  Details: API should use HTTPS to encrypt data in transit

[MEDIUM] Missing Security Headers (SEC-001)
  Category: Headers
  Description: Important security headers are missing
  Details: Missing headers: Strict-Transport-Security, X-Content-Type-Options
```

## Vulnerability Checks

- **SEC-001**: Missing Security Headers
- **SEC-002**: HTTP Usage (non-HTTPS)
- **SEC-003**: Server Information Disclosure
- **SEC-004**: Permissive CORS Policy
- **SEC-005**: Missing Content-Type Header
- **SEC-006**: Missing X-Frame-Options
- **SEC-007**: Missing Content Security Policy

## Development

To run during development:
```bash
go run main.go scan -u http://localhost:8080
```

To add new vulnerability checks, implement a new function in `internal/scanner/checks.go` following the `VulnCheck` function signature.