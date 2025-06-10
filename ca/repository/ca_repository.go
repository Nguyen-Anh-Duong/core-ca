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
	GetAllCAs(ctx context.Context) ([]model.CA, error)
	UpdateCAStatus(ctx context.Context, caID int, status string) error
	GetChildCAs(ctx context.Context, parentCAID int) ([]model.CA, error)
	GetCertificatesByCAID(ctx context.Context, caID int) ([]model.Certificate, error)
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
	query := `
		SELECT ca.id, ca.name, ca.type, ca.parent_ca_id, ca.cert_pem, ca.status, ca.created_at
		FROM certificate_authorities ca
		JOIN certificates c ON ca.id = c.ca_id
		WHERE c.serial_number = $1 AND ca.status != 'deleted'
	`
	var caData model.CA
	row := r.db.QueryRowContext(ctx, query, serialNumber)
	err := row.Scan(&caData.ID, &caData.Name, &caData.Type, &caData.ParentCAID, &caData.CertPEM, &caData.Status, &caData.CreateAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.CA{}, fmt.Errorf("FindCABySerialNumber: CA not found for certificate serial number %s", serialNumber)
		}
		return model.CA{}, fmt.Errorf("FindCABySerialNumber: failed to find CA by serial number %s: %w", serialNumber, err)
	}
	return caData, nil
}

func (r *caRepository) GetCAChain(ctx context.Context, caID int) ([]model.CA, error) {
	var chain []model.CA
	currentID := caID
	
	// Traverse từ CA hiện tại lên đến root CA
	for currentID != 0 {
		query := `
			SELECT id, name, type, parent_ca_id, cert_pem, status, created_at
			FROM certificate_authorities
			WHERE id = $1 AND status != 'deleted'
		`
		var ca model.CA
		row := r.db.QueryRowContext(ctx, query, currentID)
		err := row.Scan(&ca.ID, &ca.Name, &ca.Type, &ca.ParentCAID, &ca.CertPEM, &ca.Status, &ca.CreateAt)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("GetCAChain: CA with ID %d not found", currentID)
			}
			return nil, fmt.Errorf("GetCAChain: failed to get CA with ID %d: %w", currentID, err)
		}
		
		// Thêm CA vào chain
		chain = append(chain, ca)
		
		// Nếu đây là root CA (không có parent), dừng lại
		if ca.ParentCAID == nil {
			break
		}
		
		// Chuyển sang parent CA
		currentID = *ca.ParentCAID
		
		// Kiểm tra infinite loop (trong trường hợp có lỗi dữ liệu)
		if len(chain) > 10 {
			return nil, fmt.Errorf("GetCAChain: potential infinite loop detected, chain too long")
		}
	}
	
	return chain, nil
}

func (r *caRepository) GetAllCAs(ctx context.Context) ([]model.CA, error) {
	query := `
		SELECT id, name, type, parent_ca_id, cert_pem, status, created_at
		FROM certificate_authorities
		WHERE status != 'deleted'
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("GetAllCAs: failed to query CAs: %w", err)
	}
	defer rows.Close()

	var cas []model.CA
	for rows.Next() {
		var ca model.CA
		err := rows.Scan(&ca.ID, &ca.Name, &ca.Type, &ca.ParentCAID, &ca.CertPEM, &ca.Status, &ca.CreateAt)
		if err != nil {
			return nil, fmt.Errorf("GetAllCAs: failed to scan CA: %w", err)
		}
		cas = append(cas, ca)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAllCAs: rows error: %w", err)
	}

	return cas, nil
}

func (r *caRepository) UpdateCAStatus(ctx context.Context, caID int, status string) error {
	query := `
		UPDATE certificate_authorities
		SET status = $1
		WHERE id = $2
	`
	result, err := r.db.ExecContext(ctx, query, status, caID)
	if err != nil {
		return fmt.Errorf("UpdateCAStatus: failed to update CA status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("UpdateCAStatus: failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("UpdateCAStatus: CA with ID %d not found", caID)
	}

	return nil
}

func (r *caRepository) GetChildCAs(ctx context.Context, parentCAID int) ([]model.CA, error) {
	query := `
		SELECT id, name, type, parent_ca_id, cert_pem, status, created_at
		FROM certificate_authorities
		WHERE parent_ca_id = $1 AND status != 'deleted'
	`
	rows, err := r.db.QueryContext(ctx, query, parentCAID)
	if err != nil {
		return nil, fmt.Errorf("GetChildCAs: failed to query child CAs: %w", err)
	}
	defer rows.Close()

	var cas []model.CA
	for rows.Next() {
		var ca model.CA
		err := rows.Scan(&ca.ID, &ca.Name, &ca.Type, &ca.ParentCAID, &ca.CertPEM, &ca.Status, &ca.CreateAt)
		if err != nil {
			return nil, fmt.Errorf("GetChildCAs: failed to scan CA: %w", err)
		}
		cas = append(cas, ca)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("GetChildCAs: rows error: %w", err)
	}

	return cas, nil
}

func (r *caRepository) GetCertificatesByCAID(ctx context.Context, caID int) ([]model.Certificate, error) {
	query := `
		SELECT serial_number, subject, not_before, not_after, cert_pem, ca_id, status
		FROM certificates
		WHERE ca_id = $1 AND status != 'revoked'
	`
	rows, err := r.db.QueryContext(ctx, query, caID)
	if err != nil {
		return nil, fmt.Errorf("GetCertificatesByCAID: failed to query certificates: %w", err)
	}
	defer rows.Close()

	var certificates []model.Certificate
	for rows.Next() {
		var cert model.Certificate
		err := rows.Scan(&cert.SerialNumber, &cert.Subject, &cert.NotBefore, &cert.NotAfter, 
			&cert.CertPEM, &cert.CAID, &cert.Status)
		if err != nil {
			return nil, fmt.Errorf("GetCertificatesByCAID: failed to scan certificate: %w", err)
		}
		certificates = append(certificates, cert)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("GetCertificatesByCAID: rows error: %w", err)
	}

	return certificates, nil
}
