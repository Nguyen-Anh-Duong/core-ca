package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"fmt"
)

type KeyRepository interface {
	SaveKey(ctx context.Context, key model.CryptoKey) (int, error)
	FindKeyByLabelAndTokenID(ctx context.Context, label string, tokenID int) (model.CryptoKey, error)
}

type keyRepository struct {
	db *sql.DB
}

func NewKeyRepository(db *sql.DB) (KeyRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("NewKeyRepository: database connection is nil")
	}

	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS crypto_keys (
		id SERIAL PRIMARY KEY,
		label VARCHAR NOT NULL,
		token_id INTEGER NOT NULL,
		ca_id INTEGER,
		public_key TEXT NOT NULL,
		status VARCHAR NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
		CONSTRAINT fk_token_id FOREIGN KEY (token_id) REFERENCES crypto_tokens(id),
		CONSTRAINT unique_label_token UNIQUE (label, token_id)
	);
	`)
	if err != nil {
		return nil, fmt.Errorf("NewKeyRepository: failed to create crypto_keys table: %w", err)
	}

	return &keyRepository{db: db}, nil
}

func (r *keyRepository) SaveKey(ctx context.Context, key model.CryptoKey) (int, error) {
	return 0, nil
}
func (r *keyRepository) FindKeyByLabelAndTokenID(ctx context.Context, label string, tokenID int) (model.CryptoKey, error) {
	return model.CryptoKey{}, nil
}
