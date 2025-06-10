package model

import "time"

// Certificate represents a certificate with its details.
// type Certificate struct {
// 	SerialNumber string `json:"serialNumber"`
// 	Subject      string `json:"subject"`
// 	NotBefore    string `json:"notBefore"`
// 	NotAfter     string `json:"notAfter"`
// 	Raw          []byte `json:"-"`
// }

//	type CertificateData struct {
//		SerialNumber string
//		Subject      string
//		NotBefore    time.Time
//		NotAfter     time.Time
//		CertPEM      string // PEM-encoded certificate
//	}
type Certificate struct {
	SerialNumber string `json:"serial_number"`
	CAID         int    `json:"ca_id"` // Gắn với CA nào
	// CAKeyID      int    `json:"ca_key_id"` // Gắn với key nào
	// Usage        []KeyUsage        `json:"usage"`     // certSign, crlSign, ocspSign...
	Subject   string            `json:"subject"`
	NotBefore time.Time         `json:"not_before"`
	NotAfter  time.Time         `json:"not_after"`
	CertPEM   string            `json:"cert_pem"` // PEM-encoded cert
	Status    CertificateStatus `json:"status"`   // active, expired, revoked
}
