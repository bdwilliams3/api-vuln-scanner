package scanner

import (
    "fmt"
    "net/http"
    "time"
)

type Scanner struct {
    baseURL string
    client  *http.Client
    checks  []VulnCheck
}

type VulnCheck func(*http.Response, string) Vulnerability

func NewScanner(baseURL string, timeout int) *Scanner {
    client := &http.Client{
        Timeout: time.Duration(timeout) * time.Second,
    }

    return &Scanner{
        baseURL: baseURL,
        client:  client,
        checks:  getVulnChecks(),
    }
}

func (s *Scanner) Scan() (*ScanResults, error) {
    fmt.Println("Starting vulnerability scan...")
    
    resp, err := s.client.Get(s.baseURL)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to target: %w", err)
    }
    defer resp.Body.Close()

    var vulnerabilities []Vulnerability
    
    // Run all vulnerability checks
    for _, check := range s.checks {
        vuln := check(resp, s.baseURL)
        vulnerabilities = append(vulnerabilities, vuln)
    }

    // Calculate summary
    summary := calculateSummary(vulnerabilities)

    results := &ScanResults{
        URL:             s.baseURL,
        Timestamp:       time.Now(),
        Vulnerabilities: vulnerabilities,
        Summary:         summary,
    }

    return results, nil
}

func calculateSummary(vulnerabilities []Vulnerability) Summary {
    summary := Summary{}
    
    for _, vuln := range vulnerabilities {
        if !vuln.Found {
            continue
        }
        
        summary.Total++
        switch vuln.Severity {
        case SeverityCritical:
            summary.Critical++
        case SeverityHigh:
            summary.High++
        case SeverityMedium:
            summary.Medium++
        case SeverityLow:
            summary.Low++
        case SeverityInfo:
            summary.Info++
        }
    }
    
    return summary
}