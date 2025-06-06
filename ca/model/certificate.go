package model

import "time"

// Certificate represents a certificate with its details.
type Certificate struct {
	SerialNumber string `json:"serialNumber"`
	Subject      string `json:"subject"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	Raw          []byte `json:"-"`
}

type CertificateData struct {
	SerialNumber string
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	CertPEM      string // PEM-encoded certificate
}
