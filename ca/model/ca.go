package model

import "time"

type CA struct {
	ID            int       `json:"id"`
	Name          string    `json:"name"` // e.g., "RootCA"
	Type          CAType    `json:"type"` // "ROOT" or "INTERMEDIATE"
	CryptoTokenID int       `json:"crypto_token_id"`
	SignKeyLabel  string    `json:"sign_key_label"`
	ParentCAID    *int      `json:"parent_ca_id,omitempty"`
	CertPEM       string    `json:"cert_pem"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Status        string    `json:"status"` // "active" or "revoked"
}
