package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"errors"
)

type CertificateRepository interface {
	Save(ctx context.Context, certData model.CertificateData) error
	FindBySerialNumber(ctx context.Context, serialNumber string) (model.CertificateData, error)
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
            serial_number VARCHAR PRIMARY KEY,
            subject VARCHAR NOT NULL,
            not_before TIMESTAMP NOT NULL,
            not_after TIMESTAMP NOT NULL,
            cert_pem TEXT NOT NULL
        )
    `)
	if err != nil {
		return nil, errors.New("failed to create certificates table: " + err.Error())
	}

	return &certificateRepository{db: db}, nil
}

func (r *certificateRepository) Save(ctx context.Context, certData model.CertificateData) error {
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

func (r *certificateRepository) FindBySerialNumber(ctx context.Context, serialNumber string) (model.CertificateData, error) {
	var certData model.CertificateData
	row := r.db.QueryRowContext(ctx, `
		SELECT serial_number, subject, not_before, not_after, cert_pem
		FROM certificates
		WHERE serial_number = $1
	`, serialNumber)

	err := row.Scan(&certData.SerialNumber, &certData.Subject, &certData.NotBefore, &certData.NotAfter, &certData.CertPEM)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.CertificateData{}, nil // No certificate found
		}
		return model.CertificateData{}, err // Other error
	}
	return certData, nil
}
