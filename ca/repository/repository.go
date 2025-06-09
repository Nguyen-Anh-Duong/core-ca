package repository

import (
	"database/sql"
	"errors"
	"fmt"
)

type Repository interface {
	RevocationRepository
	CertificateRepository
	TokenRepository
	KeyRepository
	CARepository
}

type repository struct {
	*tokenRepository
	*keyRepository
	*caRepository
	*certificateRepository
	*revocationRepository
}

func NewRepository(db *sql.DB) (Repository, error) {
	if db == nil {
		return nil, errors.New("database is nil")
	}
	
	// Create certificate_authorities table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS certificate_authorities (
			id SERIAL PRIMARY KEY,
			name VARCHAR NOT NULL UNIQUE,
			type VARCHAR NOT NULL CHECK (type IN ('root', 'sub')),
			parent_ca_id INTEGER,
			cert_pem TEXT NOT NULL,
			status VARCHAR NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired', 'unknown')),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT fk_parent_ca_id FOREIGN KEY (parent_ca_id) REFERENCES certificate_authorities(id)
		);
	`)
	if err != nil {
		return nil, fmt.Errorf("NewRepository: failed to create certificate_authorities table: %w", err)
	}
	
	return &repository{
		tokenRepository:       &tokenRepository{db},
		keyRepository:         &keyRepository{db},
		caRepository:          &caRepository{db},
		certificateRepository: &certificateRepository{db},
		revocationRepository:  &revocationRepository{db},
	}, nil
}
