package model

import "time"

// Certificate represents a certificate with its details
type Certificate struct {
	SerialNumber string
	Subject      string
	NotBefore    string
	NotAfter     string
	Raw          []byte // DER-encoded certificate
}

type CertificateData struct {
	SerialNumber string
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	CertPEM      string // PEM-encoded certificate
}
