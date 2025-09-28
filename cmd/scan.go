package cmd

import (
    "fmt"
    "os"
    "path/filepath"
    "time"

    "github.com/spf13/cobra"
    "github.com/bdwilliams3/api-vuln-scanner/internal/reporter"
    "github.com/bdwilliams3/api-vuln-scanner/internal/scanner"
)

var (
    targetURL string
    outputFormat string
    timeout int
)

var rootCmd = &cobra.Command{
    Use:   "api-vuln-scanner",
    Short: "A simple API vulnerability scanner",
    Long:  "Scans APIs for common security vulnerabilities and generates reports",
}

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scan an API for vulnerabilities",
    Long:  "Performs a vulnerability scan on the specified API endpoint",
    RunE: func(cmd *cobra.Command, args []string) error {
        if targetURL == "" {
            return fmt.Errorf("target URL is required")
        }

        fmt.Printf("Scanning API: %s\n", targetURL)
        
        s := scanner.NewScanner(targetURL, timeout)
        results, err := s.Scan()
        if err != nil {
            return fmt.Errorf("scan failed: %w", err)
        }

        // Create reports directory if it doesn't exist
        if err := os.MkdirAll("reports", 0755); err != nil {
            return fmt.Errorf("failed to create reports directory: %w", err)
        }

        // Generate filename with timestamp
        timestamp := time.Now().Format("20060102_150405")
        var filename string
        if outputFormat == "csv" {
            filename = fmt.Sprintf("reports/scan_%s.csv", timestamp)
        } else {
            filename = fmt.Sprintf("reports/scan_%s.json", timestamp)
        }

        r := reporter.NewReporter(outputFormat)
        return r.Generate(results, targetURL, filename)
    },
}

func init() {
    rootCmd.AddCommand(scanCmd)
    
    scanCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Target API URL to scan (required)")
    scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format (json, csv)")
    scanCmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "Request timeout in seconds")
    
    scanCmd.MarkFlagRequired("url")
}

func Execute() error {
    return rootCmd.Execute()
}