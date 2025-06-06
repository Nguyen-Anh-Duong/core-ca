package model

import "time"

type RevokedCertificate struct {
	SerialNumber   string
	RevocationDate time.Time
	Reason         string // Reason for revocation (e.g., "keyCompromise", "caCompromise", "affiliationChanged", etc.)
}

// type CertificateSatus struct {
// 	SerialNumber   string
// 	Status         string // "valid", "revoked", "expired"
// 	Revoked        bool
// 	RevocationDate time.Time
// 	Reason         string
// }
