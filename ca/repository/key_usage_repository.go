package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"fmt"
)

type KeyUsageRepository interface {
	// AddUsage adds a usage type to a key.
	AddUsage(ctx context.Context, keyID int, usage model.KeyUsage) error
	// RemoveUsage removes a usage type from a key.
	RemoveUsage(ctx context.Context, keyID int, usage model.KeyUsage) error
	// GetUsages retrieves all usage types for a key.
}

type keyUsageRepository struct {
	db *sql.DB
}

func NewKeyUsageRepository(db *sql.DB) (KeyUsageRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("NewKeyUsageRepository: database connection is nil")
	}

	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS key_usages (
		key_id INTEGER NOT NULL,
		usage VARCHAR NOT NULL CHECK (usage IN ('certSign', 'crlSign', 'ocspSign', 'encrypt', 'sign')),
		PRIMARY KEY (key_id, usage),
		CONSTRAINT fk_key_id FOREIGN KEY (key_id) REFERENCES crypto_keys(id)
	);
	`)
	if err != nil {
		return nil, err
	}

	return &keyUsageRepository{db: db}, nil
}

func (r *keyUsageRepository) AddUsage(ctx context.Context, keyID int, usage model.KeyUsage) error {
	return nil
}

func (r *keyUsageRepository) RemoveUsage(ctx context.Context, keyID int, usage model.KeyUsage) error {
	return nil
}
