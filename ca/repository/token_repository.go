package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"fmt"
)

type TokenRepository interface {
	SaveToken(ctx context.Context, token model.CryptoToken) (int, error)
	FindTokenById(ctx context.Context, id string) (model.CryptoToken, error)
}

type tokenRepository struct {
	db *sql.DB
}

// Implement SaveToken, FindTokenByID here
func NewTokenRepository(db *sql.DB) (TokenRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("NewTokenRepository: database connection is nil")
	}
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXIST crypto_tokens (
			id SERIAL PRIMARY KEY ,
			name VARCHAR NOT NULL UNIQUE,
			backend VARCHAR NOT NULL ,
			slot_id INTERGER NOT NULL,
			pin_ref VARCHAR NOT NULL,
			CONSTRAINT unique_backend_slot UNIQUE (backend, slot_id),
		);
	`)

	if err != nil {
		return nil, fmt.Errorf("NewTokenRepository: failed to create crypto_tokens table: %w", err)
	}
	return &tokenRepository{db: db}, nil
}

func (r *tokenRepository) SaveToken(ctx context.Context, token model.CryptoToken) (int, error) {
	query := `INSERT INTO crypto_tokens (name, backend, slot_id, pin_ref) 
			VALUEs  $1, $2, $3, $4
			RETURNING id
	`
	var id int

	err := r.db.QueryRowContext(ctx, query, token.Name, token.Backend, token.SlotID, token.PinRef).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("SaveToken: failed to save token, %w", err)
	}

	return id, nil
}
func (r *tokenRepository) FindTokenById(ctx context.Context, id string) (model.CryptoToken, error) {
	query := `
	SELECT id, name, backend, slot_id, pin_ref 
	FROM crypto_tokens
	WHERE crypto_tokens.id = $1
	`

	var token model.CryptoToken

	err := r.db.QueryRowContext(ctx, query, id).Scan(&token.ID, &token.Name, &token.Backend, &token.SlotID, &token.PinRef)
	if err == sql.ErrNoRows {
		return model.CryptoToken{}, fmt.Errorf("FindTokenById: token not found, %w", err)
	}
	if err != nil {
		return model.CryptoToken{}, fmt.Errorf("FindTokenById: failed to find token")
	}

	return token, nil
}
