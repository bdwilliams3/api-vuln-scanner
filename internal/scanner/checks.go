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
        checkPermissionsPolicy,
        checkReferrerPolicy,
        checkCacheControl,
        checkCookiesSecurity,
        checkHSTSPreload,
        checkXSSProtection,
        checkContentTypeOptions,
        checkCORSCredentials,
        checkExpectCT,
        checkFeaturePolicy,
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

func checkPermissionsPolicy(resp *http.Response, url string) Vulnerability {
    permissionsPolicy := resp.Header.Get("Permissions-Policy")
    
    vuln := Vulnerability{
        ID:          "SEC-008",
        Title:       "Missing Permissions Policy",
        Description: "Permissions-Policy header is missing",
        Category:    "Headers",
        Found:       permissionsPolicy == "",
    }

    if vuln.Found {
        vuln.Severity = SeverityLow
        vuln.Details = "Missing Permissions-Policy header allows all browser features by default"
    }

    return vuln
}

func checkReferrerPolicy(resp *http.Response, url string) Vulnerability {
    referrerPolicy := resp.Header.Get("Referrer-Policy")
    
    vuln := Vulnerability{
        ID:          "SEC-009",
        Title:       "Missing Referrer Policy",
        Description: "Referrer-Policy header is missing",
        Category:    "Headers",
        Found:       referrerPolicy == "",
    }

    if vuln.Found {
        vuln.Severity = SeverityLow
        vuln.Details = "Missing Referrer-Policy may leak sensitive information in URL parameters"
    }

    return vuln
}

func checkCacheControl(resp *http.Response, url string) Vulnerability {
    cacheControl := resp.Header.Get("Cache-Control")
    
    // Check if sensitive data might be cached
    isSensitive := strings.Contains(strings.ToLower(url), "login") ||
        strings.Contains(strings.ToLower(url), "auth") ||
        strings.Contains(strings.ToLower(url), "password") ||
        strings.Contains(strings.ToLower(url), "token")
    
    vuln := Vulnerability{
        ID:          "SEC-010",
        Title:       "Insecure Cache Configuration",
        Description: "Sensitive endpoint lacks proper cache controls",
        Category:    "Caching",
        Found:       isSensitive && !strings.Contains(strings.ToLower(cacheControl), "no-store"),
    }

    if vuln.Found {
        vuln.Severity = SeverityMedium
        vuln.Details = "Sensitive endpoints should use Cache-Control: no-store to prevent caching"
    }

    return vuln
}

func checkCookiesSecurity(resp *http.Response, url string) Vulnerability {
    var insecureCookies []string
    
    for _, cookie := range resp.Cookies() {
        if !cookie.Secure || !cookie.HttpOnly {
            insecureCookies = append(insecureCookies, cookie.Name)
        }
    }
    
    vuln := Vulnerability{
        ID:          "SEC-011",
        Title:       "Insecure Cookie Configuration",
        Description: "Cookies lack Secure or HttpOnly flags",
        Category:    "Cookies",
        Found:       len(insecureCookies) > 0,
    }

    if vuln.Found {
        vuln.Severity = SeverityMedium
        vuln.Details = fmt.Sprintf("Insecure cookies: %s. Cookies should have Secure and HttpOnly flags set", 
            strings.Join(insecureCookies, ", "))
    }

    return vuln
}

func checkHSTSPreload(resp *http.Response, url string) Vulnerability {
    hsts := resp.Header.Get("Strict-Transport-Security")
    
    hasPreload := strings.Contains(strings.ToLower(hsts), "preload")
    hasHSTS := hsts != ""
    
    vuln := Vulnerability{
        ID:          "SEC-012",
        Title:       "HSTS Without Preload",
        Description: "HSTS is configured but without preload directive",
        Category:    "Transport",
        Found:       hasHSTS && !hasPreload,
    }

    if vuln.Found {
        vuln.Severity = SeverityLow
        vuln.Details = "HSTS preload directive provides stronger protection against SSL stripping attacks"
    }

    return vuln
}

func checkXSSProtection(resp *http.Response, url string) Vulnerability {
    xssProtection := resp.Header.Get("X-XSS-Protection")
    
    // Check if it's disabled (0) or not set to block mode
    isInsecure := xssProtection == "0" || 
        (xssProtection != "" && !strings.Contains(xssProtection, "1; mode=block"))
    
    vuln := Vulnerability{
        ID:          "SEC-013",
        Title:       "Weak XSS Protection",
        Description: "X-XSS-Protection is disabled or not in block mode",
        Category:    "Headers",
        Found:       isInsecure,
    }

    if vuln.Found {
        vuln.Severity = SeverityLow
        vuln.Details = fmt.Sprintf("Current value: %s. Should be set to '1; mode=block'", xssProtection)
    }

    return vuln
}

func checkContentTypeOptions(resp *http.Response, url string) Vulnerability {
    contentTypeOptions := resp.Header.Get("X-Content-Type-Options")
    
    vuln := Vulnerability{
        ID:          "SEC-014",
        Title:       "Missing X-Content-Type-Options",
        Description: "X-Content-Type-Options header is not set to nosniff",
        Category:    "Headers",
        Found:       contentTypeOptions != "nosniff",
    }

    if vuln.Found {
        vuln.Severity = SeverityMedium
        vuln.Details = "Missing or incorrect X-Content-Type-Options allows MIME-type sniffing attacks"
    }

    return vuln
}

func checkCORSCredentials(resp *http.Response, url string) Vulnerability {
    corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
    corsCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
    
    // Wildcard origin with credentials is dangerous
    isVulnerable := corsOrigin == "*" && strings.ToLower(corsCredentials) == "true"
    
    vuln := Vulnerability{
        ID:          "SEC-015",
        Title:       "Dangerous CORS Configuration",
        Description: "CORS allows credentials with wildcard origin",
        Category:    "CORS",
        Found:       isVulnerable,
    }

    if vuln.Found {
        vuln.Severity = SeverityHigh
        vuln.Details = "Allowing credentials with wildcard origin exposes the API to credential theft"
    }

    return vuln
}

func checkExpectCT(resp *http.Response, url string) Vulnerability {
    expectCT := resp.Header.Get("Expect-CT")
    
    vuln := Vulnerability{
        ID:          "SEC-016",
        Title:       "Missing Expect-CT Header",
        Description: "Expect-CT header is missing",
        Category:    "Transport",
        Found:       expectCT == "",
    }

    if vuln.Found {
        vuln.Severity = SeverityLow
        vuln.Details = "Expect-CT header helps prevent certificate misissuance"
    }

    return vuln
}

func checkFeaturePolicy(resp *http.Response, url string) Vulnerability {
    featurePolicy := resp.Header.Get("Feature-Policy")
    permissionsPolicy := resp.Header.Get("Permissions-Policy")
    
    vuln := Vulnerability{
        ID:          "SEC-017",
        Title:       "Missing Feature/Permissions Policy",
        Description: "No feature or permissions policy is set",
        Category:    "Headers",
        Found:       featurePolicy == "" && permissionsPolicy == "",
    }

    if vuln.Found {
        vuln.Severity = SeverityLow
        vuln.Details = "Feature/Permissions policies control which browser features can be used"
    }

    return vuln
}