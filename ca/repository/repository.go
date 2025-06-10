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

	// Create certificates table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			serial_number VARCHAR PRIMARY KEY,
			subject VARCHAR NOT NULL,
			not_before TIMESTAMP NOT NULL,
			not_after TIMESTAMP NOT NULL,
			cert_pem TEXT NOT NULL,
			ca_id INTEGER,
			status VARCHAR NOT NULL DEFAULT 'valid' CHECK (status IN ('valid', 'revoked', 'expired', 'unknown')),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT fk_ca_id FOREIGN KEY (ca_id) REFERENCES certificate_authorities(id)
		);
	`)
	if err != nil {
		return nil, fmt.Errorf("NewRepository: failed to create certificates table: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS revoked_certificates(
			serial_number VARCHAR PRIMARY KEY,
			revocation_date TIMESTAMP NOT NULL,
			reason VARCHAR,
			is_ca BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY (serial_number) REFERENCES certificates(serial_number)
		)
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to create revoked_certificates table: %w", err)
	}

	return &repository{
		tokenRepository:       &tokenRepository{db},
		keyRepository:         &keyRepository{db},
		caRepository:          &caRepository{db},
		certificateRepository: &certificateRepository{db},
		revocationRepository:  &revocationRepository{db},
	}, nil
}
