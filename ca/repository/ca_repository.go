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

func (r *caRepository) SaveCA(ctx context.Context, ca model.CA) (int, error) {
	query := `
		INSERT INTO certificate_authorities (name, type, parent_ca_id, cert_pem, status)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	var id int
	err := r.db.QueryRowContext(ctx, query, ca.Name, ca.Type, ca.ParentCAID, ca.CertPEM, ca.Status).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("SaveCA: failed to save CA: %w", err)
	}

	return id, nil
}

func (r *caRepository) FindCAByID(ctx context.Context, id int) (model.CA, error) {
	query := `
		SELECT id, name, type, parent_ca_id, cert_pem, status
		FROM certificate_authorities
		WHERE id = $1 AND status = 'active'
		AND type IN ('root', 'sub')
	`
	var caData model.CA
	row := r.db.QueryRowContext(ctx, query, id)
	err := row.Scan(&caData.ID, &caData.Name, &caData.Type, &caData.ParentCAID, &caData.CertPEM, &caData.Status)
	if err != nil {
		return model.CA{}, fmt.Errorf("FindCAByID: failed to find CA by ID %d: %w", id, err)
	}
	return caData, nil
}

func (r *caRepository) FindCABySerialNumber(ctx context.Context, serialNumber string) (model.CA, error) {
	return model.CA{}, nil
}
func (r *caRepository) GetCAChain(ctx context.Context, caID int) ([]model.CA, error) {
	return []model.CA{}, nil
}
