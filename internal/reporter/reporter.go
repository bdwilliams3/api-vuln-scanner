package reporter

import (
    "encoding/csv"
    "encoding/json"
    "fmt"
    "os"
    "strconv"

    "github.com/bdwilliams3/api-vuln-scanner/internal/scanner"
)

type Reporter struct {
    format string
}

func NewReporter(format string) *Reporter {
    return &Reporter{format: format}
}

func (r *Reporter) Generate(results *scanner.ScanResults, targetURL string, filename string) error {
    switch r.format {
    case "csv":
        return r.generateCSV(results, filename)
    case "json":
        return r.generateJSON(results, filename)
    default:
        return fmt.Errorf("unsupported output format: %s", r.format)
    }
}

func (r *Reporter) generateJSON(results *scanner.ScanResults, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return fmt.Errorf("failed to create file: %w", err)
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    
    if err := encoder.Encode(results); err != nil {
        return fmt.Errorf("failed to write JSON: %w", err)
    }

    fmt.Printf("Report saved to: %s\n", filename)
    return nil
}

func (r *Reporter) generateCSV(results *scanner.ScanResults, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return fmt.Errorf("failed to create file: %w", err)
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    // Write header
    header := []string{"ID", "Title", "Category", "Severity", "Found", "Description", "Details"}
    if err := writer.Write(header); err != nil {
        return fmt.Errorf("failed to write CSV header: %w", err)
    }

    // Write vulnerability data
    for _, vuln := range results.Vulnerabilities {
        record := []string{
            vuln.ID,
            vuln.Title,
            vuln.Category,
            string(vuln.Severity),
            strconv.FormatBool(vuln.Found),
            vuln.Description,
            vuln.Details,
        }
        if err := writer.Write(record); err != nil {
            return fmt.Errorf("failed to write CSV record: %w", err)
        }
    }

    // Write summary as additional rows
    writer.Write([]string{}) // Empty row
    writer.Write([]string{"SUMMARY", "", "", "", "", "", ""})
    writer.Write([]string{"URL", results.URL, "", "", "", "", ""})
    writer.Write([]string{"Timestamp", results.Timestamp.Format("2006-01-02 15:04:05"), "", "", "", "", ""})
    writer.Write([]string{"Total Issues", strconv.Itoa(results.Summary.Total), "", "", "", "", ""})
    writer.Write([]string{"Critical", strconv.Itoa(results.Summary.Critical), "", "", "", "", ""})
    writer.Write([]string{"High", strconv.Itoa(results.Summary.High), "", "", "", "", ""})
    writer.Write([]string{"Medium", strconv.Itoa(results.Summary.Medium), "", "", "", "", ""})
    writer.Write([]string{"Low", strconv.Itoa(results.Summary.Low), "", "", "", "", ""})
    writer.Write([]string{"Info", strconv.Itoa(results.Summary.Info), "", "", "", "", ""})

    fmt.Printf("Report saved to: %s\n", filename)
    return nil
}