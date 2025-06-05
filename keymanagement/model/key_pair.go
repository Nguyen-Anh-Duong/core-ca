package model

import "crypto/rsa"

// KeyPair represents a public/private key pair
type KeyPair struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// KeyPairData for serializing metadata
type KeyPairData struct {
	ID        string
	PublicKey string // PEM-encoded public key
	KeyLabel  string // Label for the key
}
