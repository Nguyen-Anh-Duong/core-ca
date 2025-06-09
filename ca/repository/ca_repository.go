package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"fmt"
)

type CARepository interface {
	SaveCA(ctx context.Context, ca model.CA) (int, error)
	FindCAByID(ctx context.Context, id int) (model.CA, error)
	FindCABySerialNumber(ctx context.Context, serialNumber string) (model.CA, error)
	GetCAChain(ctx context.Context, caID int) ([]model.CA, error)
}

type caRepository struct {
	db *sql.DB
}

func NewCARepository(db *sql.DB) (CARepository, error) {
	if db == nil {
		return nil, fmt.Errorf("NewCARepository: database connection is nil")
	}

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS certificate_authorities (
			id SERIAL PRIMARY KEY,
			name VARCHAR NOT NULL UNIQUE,
			type VARCHAR NOT NULL CHECK (type IN ('root', 'sub')),
			parent_ca_id INTEGER,
			cert_id int NOT NULL,
			status VARCHAR NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired', 'unknown')),
			CONSTRAINT fk_crypto_token_id FOREIGN KEY (crypto_token_id) REFERENCES crypto_tokens(id),
			CONSTRAINT fk_parent_ca_id FOREIGN KEY (parent_ca_id) REFERENCES certificate_authorities(id),
			CONSTRAINT fk_cert_id FOREIGN KEY (cert_id) REFERENCES certificates(id)
		);
	`)

	if err != nil {
		return nil, fmt.Errorf("NewCARepository: failed to create certificate_authorities table: %w", err)
	}

	return &caRepository{db: db}, nil
}

func (r *caRepository) SaveCA(ctx context.Context, ca model.CA) (int, error) {
	return 0, nil
}
func (r *caRepository) FindCAByID(ctx context.Context, id int) (model.CA, error) {
	return model.CA{}, nil
}
func (r *caRepository) FindCABySerialNumber(ctx context.Context, serialNumber string) (model.CA, error) {
	return model.CA{}, nil
}
func (r *caRepository) GetCAChain(ctx context.Context, caID int) ([]model.CA, error) {
	return []model.CA{}, nil
}
