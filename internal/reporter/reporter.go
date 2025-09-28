package reporter

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/fatih/color"
    "github.com/bdwilliams3/api-vuln-scanner/internal/scanner"
)

type Reporter struct {
    format string
}

func NewReporter(format string) *Reporter {
    return &Reporter{format: format}
}

func (r *Reporter) Generate(results *scanner.ScanResults, targetURL string) error {
    switch r.format {
    case "json":
        return r.generateJSON(results)
    case "console":
        return r.generateConsole(results)
    default:
        return fmt.Errorf("unsupported output format: %s", r.format)
    }
}

func (r *Reporter) generateJSON(results *scanner.ScanResults) error {
    jsonData, err := json.MarshalIndent(results, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal results: %w", err)
    }

    fmt.Println(string(jsonData))
    return nil
}

func (r *Reporter) generateConsole(results *scanner.ScanResults) error {
    // Colors
    red := color.New(color.FgRed).SprintFunc()
    yellow := color.New(color.FgYellow).SprintFunc()
    green := color.New(color.FgGreen).SprintFunc()
    blue := color.New(color.FgBlue).SprintFunc()
    cyan := color.New(color.FgCyan).SprintFunc()

    fmt.Println("\n" + color.New(color.Bold).Sprint("=== API Vulnerability Scan Report ==="))
    fmt.Printf("Target: %s\n", results.URL)
    fmt.Printf("Scan Time: %s\n\n", results.Timestamp.Format("2006-01-02 15:04:05"))

    // Summary
    fmt.Println(color.New(color.Bold).Sprint("Summary:"))
    fmt.Printf("  Total Issues Found: %d\n", results.Summary.Total)
    if results.Summary.Critical > 0 {
        fmt.Printf("  Critical: %s\n", red(results.Summary.Critical))
    }
    if results.Summary.High > 0 {
        fmt.Printf("  High: %s\n", red(results.Summary.High))
    }
    if results.Summary.Medium > 0 {
        fmt.Printf("  Medium: %s\n", yellow(results.Summary.Medium))
    }
    if results.Summary.Low > 0 {
        fmt.Printf("  Low: %s\n", blue(results.Summary.Low))
    }
    if results.Summary.Info > 0 {
        fmt.Printf("  Info: %s\n", cyan(results.Summary.Info))
    }

    fmt.Println("\n" + color.New(color.Bold).Sprint("Detailed Results:"))

    foundIssues := false
    for _, vuln := range results.Vulnerabilities {
        if !vuln.Found {
            continue
        }
        
        foundIssues = true
        severityColor := getSeverityColor(vuln.Severity)
        
        fmt.Printf("\n[%s] %s (%s)\n", severityColor(vuln.Severity), vuln.Title, vuln.ID)
        fmt.Printf("  Category: %s\n", vuln.Category)
        fmt.Printf("  Description: %s\n", vuln.Description)
        if vuln.Details != "" {
            fmt.Printf("  Details: %s\n", vuln.Details)
        }
    }

    if !foundIssues {
        fmt.Println(green("\nNo vulnerabilities found! 🎉"))
    }

    return nil
}

func getSeverityColor(severity scanner.Severity) func(a ...interface{}) string {
    switch severity {
    case scanner.SeverityCritical, scanner.SeverityHigh:
        return color.New(color.FgRed).SprintFunc()
    case scanner.SeverityMedium:
        return color.New(color.FgYellow).SprintFunc()
    case scanner.SeverityLow:
        return color.New(color.FgBlue).SprintFunc()
    default:
        return color.New(color.FgCyan).SprintFunc()
    }
}