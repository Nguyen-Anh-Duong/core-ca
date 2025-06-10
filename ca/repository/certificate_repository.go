package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"fmt"
)

type CertificateRepository interface {
	SaveCert(ctx context.Context, certData model.Certificate) error
	FindBySerialNumber(ctx context.Context, serialNumber string) (model.Certificate, error)
	FindCertByCAID(ctx context.Context, id int) (model.Certificate, error)
}

type certificateRepository struct {
	db *sql.DB
}

func (r *certificateRepository) SaveCert(ctx context.Context, certData model.Certificate) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificates (serial_number, subject, not_before, not_after, cert_pem, ca_id, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, certData.SerialNumber, certData.Subject, certData.NotBefore, certData.NotAfter, string(certData.CertPEM), certData.CAID, string(certData.Status))
	return err
}

func (r *certificateRepository) FindBySerialNumber(ctx context.Context, serialNumber string) (model.Certificate, error) {
	var certData model.Certificate
	row := r.db.QueryRowContext(ctx, `
		SELECT serial_number, subject, not_before, not_after, cert_pem, ca_id, status
		FROM certificates
		WHERE serial_number = $1
	`, serialNumber)

	err := row.Scan(&certData.SerialNumber, &certData.Subject, &certData.NotBefore, &certData.NotAfter, &certData.CertPEM, &certData.CAID, &certData.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Certificate{}, nil // No certificate found
		}
		return model.Certificate{}, err // Other error
	}
	return certData, nil
}

func (r *certificateRepository) FindCertByCAID(ctx context.Context, caID int) (model.Certificate, error) {
	var certData model.Certificate
	row := r.db.QueryRowContext(ctx, `
		SELECT serial_number, subject, not_before, not_after, cert_pem, status, ca_id
		FROM certificates
		WHERE ca_id = $1 AND status = 'valid'
	`, caID)

	err := row.Scan(&certData.SerialNumber, &certData.Subject, &certData.NotBefore, &certData.NotAfter, &certData.CertPEM, &certData.Status, &certData.CAID)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Certificate{}, nil // No certificate found
		}
		return model.Certificate{}, fmt.Errorf("FindCertByCAID: %w", err) // Other error
	}
	return certData, nil
}
