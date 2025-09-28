package scanner

import (
    "fmt"
    "net/http"
    "strings"
)

func getVulnChecks() []VulnCheck {
    return []VulnCheck{
        checkMissingSecurityHeaders,
        checkHTTPSUsage,
        checkServerHeader,
        checkCORSConfiguration,
        checkContentType,
        checkXFrameOptions,
        checkCSP,
    }
}

func checkMissingSecurityHeaders(resp *http.Response, url string) Vulnerability {
    securityHeaders := []string{
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
    }

    var missing []string
    for _, header := range securityHeaders {
        if resp.Header.Get(header) == "" {
            missing = append(missing, header)
        }
    }

    vuln := Vulnerability{
        ID:          "SEC-001",
        Title:       "Missing Security Headers",
        Description: "Important security headers are missing",
        Category:    "Headers",
        Found:       len(missing) > 0,
    }

    if vuln.Found {
        vuln.Severity = SeverityMedium
        vuln.Details = fmt.Sprintf("Missing headers: %s", strings.Join(missing, ", "))
    }

    return vuln
}

func checkHTTPSUsage(resp *http.Response, url string) Vulnerability {
    vuln := Vulnerability{
        ID:          "SEC-002",
        Title:       "HTTP Usage",
        Description: "API is accessible over unencrypted HTTP",
        Category:    "Transport",
        Found:       strings.HasPrefix(url, "http://"),
    }

    if vuln.Found {
        vuln.Severity = SeverityHigh
        vuln.Details = "API should use HTTPS to encrypt data in transit"
    }

    return vuln
}

func checkServerHeader(resp *http.Response, url string) Vulnerability {
    serverHeader := resp.Header.Get("Server")
    
    vuln := Vulnerability{
        ID:          "SEC-003",
        Title:       "Server Information Disclosure",
        Description: "Server header reveals potentially sensitive information",
        Category:    "Information Disclosure",
        Found:       serverHeader != "",
    }

    if vuln.Found {
        vuln.Severity = SeverityLow
        vuln.Details = fmt.Sprintf("Server header: %s", serverHeader)
    }

    return vuln
}

func checkCORSConfiguration(resp *http.Response, url string) Vulnerability {
    corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
    
    vuln := Vulnerability{
        ID:          "SEC-004",
        Title:       "Permissive CORS Policy",
        Description: "CORS policy allows all origins",
        Category:    "CORS",
        Found:       corsOrigin == "*",
    }

    if vuln.Found {
        vuln.Severity = SeverityMedium
        vuln.Details = "Access-Control-Allow-Origin: * allows requests from any origin"
    }

    return vuln
}

func checkContentType(resp *http.Response, url string) Vulnerability {
    contentType := resp.Header.Get("Content-Type")
    
    vuln := Vulnerability{
        ID:          "SEC-005",
        Title:       "Missing Content-Type Header",
        Description: "Response lacks Content-Type header",
        Category:    "Headers",
        Found:       contentType == "",
    }

    if vuln.Found {
        vuln.Severity = SeverityLow
        vuln.Details = "Content-Type header is missing, which may lead to content sniffing attacks"
    }

    return vuln
}

func checkXFrameOptions(resp *http.Response, url string) Vulnerability {
    xFrameOptions := resp.Header.Get("X-Frame-Options")
    
    vuln := Vulnerability{
        ID:          "SEC-006",
        Title:       "Missing X-Frame-Options",
        Description: "X-Frame-Options header is missing",
        Category:    "Headers",
        Found:       xFrameOptions == "",
    }

    if vuln.Found {
        vuln.Severity = SeverityMedium
        vuln.Details = "Missing X-Frame-Options header allows the page to be embedded in frames, potentially leading to clickjacking attacks"
    }

    return vuln
}

func checkCSP(resp *http.Response, url string) Vulnerability {
    csp := resp.Header.Get("Content-Security-Policy")
    
    vuln := Vulnerability{
        ID:          "SEC-007",
        Title:       "Missing Content Security Policy",
        Description: "Content-Security-Policy header is missing",
        Category:    "Headers",
        Found:       csp == "",
    }

    if vuln.Found {
        vuln.Severity = SeverityMedium
        vuln.Details = "Missing CSP header increases risk of XSS attacks"
    }

    return vuln
}