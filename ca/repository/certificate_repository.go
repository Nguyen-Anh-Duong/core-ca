package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"errors"
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

func NewCertificateRepository(db *sql.DB) (CertificateRepository, error) {
	if db == nil {
		return nil, errors.New("database connection is nil")
	}
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS certificates (
			id SERIAL PRIMARY KEY,
            serial_number VARCHAR NOT NULL,
            subject VARCHAR NOT NULL,
            not_before TIMESTAMP NOT NULL,
            not_after TIMESTAMP NOT NULL,
            cert_pem TEXT NOT NULL,
			ca_id INTEGER,
			status VARCHAR NOT NULL DEFAULT 'valid' CHECK (status IN ('valid', 'revoked', 'expired', 'unknown')),
			CONSTRAINT fk_ca_id FOREIGN KEY (ca_id) REFERENCES certificate_authorities(id),
        )
    `)
	if err != nil {
		return nil, errors.New("failed to create certificates table: " + err.Error())
	}

	return &certificateRepository{db: db}, nil
}

func (r *certificateRepository) SaveCert(ctx context.Context, certData model.Certificate) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificates (serial_number, subject, not_before, not_after, cert_pem)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (serial_number) DO UPDATE SET
			subject = EXCLUDED.subject,
			not_before = EXCLUDED.not_before,
			not_after = EXCLUDED.not_after,
			cert_pem = EXCLUDED.cert_pem
	`, certData.SerialNumber, certData.Subject, certData.NotBefore, certData.NotAfter, string(certData.CertPEM))
	return err
}

func (r *certificateRepository) FindBySerialNumber(ctx context.Context, serialNumber string) (model.Certificate, error) {
	var certData model.Certificate
	row := r.db.QueryRowContext(ctx, `
		SELECT serial_number, subject, not_before, not_after, cert_pem
		FROM certificates
		WHERE serial_number = $1
	`, serialNumber)

	err := row.Scan(&certData.SerialNumber, &certData.Subject, &certData.NotBefore, &certData.NotAfter, &certData.CertPEM)
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
