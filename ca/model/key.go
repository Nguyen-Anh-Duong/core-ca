package model

type CryptoKey struct {
	ID        int    `json:"id"`
	Label     string `json:"label"` // e.g., "rootKey"
	Usage     string `json:"usage"` // "sign" or "encrypt"
	TokenID   string `json:"token_id"`
	CaID      *int   `json:"ca_id,omitempty"`
	PublicKey string `json:"public_key"` // PEM-encoded
	Status    string `json:"status"`     // "active" or "revoked"
}
