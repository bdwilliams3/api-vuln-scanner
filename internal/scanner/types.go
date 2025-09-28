package scanner

import "time"

type Vulnerability struct {
    ID          string    `json:"id"`
    Title       string    `json:"title"`
    Description string    `json:"description"`
    Severity    Severity  `json:"severity"`
    Category    string    `json:"category"`
    Found       bool      `json:"found"`
    Details     string    `json:"details,omitempty"`
}

type Severity string

const (
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
    SeverityInfo     Severity = "INFO"
)

type ScanResults struct {
    URL             string          `json:"url"`
    Timestamp       time.Time       `json:"timestamp"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    Summary         Summary         `json:"summary"`
}

type Summary struct {
    Total    int `json:"total"`
    Critical int `json:"critical"`
    High     int `json:"high"`
    Medium   int `json:"medium"`
    Low      int `json:"low"`
    Info     int `json:"info"`
}