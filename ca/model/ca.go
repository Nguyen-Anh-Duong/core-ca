package model

import "time"

type CA struct {
	ID   int    `json:"id"`
	Name string `json:"name"` // e.g., "RootCA"
	Type CAType `json:"type"` // "ROOT" or "INTERMEDIATE"
	// CryptoTokenID int       `json:"crypto_token_id"`
	// CertID     int       `json:"cert_id"` // ID of the certificate in the database
	ParentCAID *int      `json:"parent_ca_id,omitempty"`
	CreateAt   time.Time `json:"created_at"`
	Status     CAStatus  `json:"status"`   // "active" , "revoked", "expired", "unknown"
	CertPEM    string    `json:"cert_pem"` // PEM-encoded certificate
}
