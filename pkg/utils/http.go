package utils

import (
    "crypto/tls"
    "net/http"
    "time"
)

// CreateInsecureClient creates an HTTP client that ignores SSL certificate errors
// Useful for testing against localhost with self-signed certificates
func CreateInsecureClient(timeout time.Duration) *http.Client {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    return &http.Client{
        Transport: tr,
        Timeout:   timeout,
    }
}

// CreateSecureClient creates an HTTP client with standard security settings
func CreateSecureClient(timeout time.Duration) *http.Client {
    return &http.Client{
        Timeout: timeout,
    }
}