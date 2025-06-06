package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"errors"
	"time"
)

type CertificateRepository interface {
	Save(ctx context.Context, certData model.CertificateData) error
	FindBySerialNumber(ctx context.Context, serialNumber string) (model.CertificateData, error)
	Revoke(ctx context.Context, serialNumber string, reason string) error
	GetRevokedCertificate(ctx context.Context) ([]model.RevokedCertificate, error)
	IsRevoked(ctx context.Context, serialNumber string) (model.RevokedCertificate, bool, error)
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

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS revoked_certificates(
			serial_number VARCHAR PRIMARY KEY,
			revocation_date TIMESTAMP NOT NULL,
			reason VARCHAR,
			FOREIGN KEY (serial_number) REFERENCES certificates(serial_number)
		)
	`)

	if err != nil {
		return nil, errors.New("failed to create revoked_certificates table: " + err.Error())
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

func (r *certificateRepository) Revoke(ctx context.Context, serialNumber string, reason string) error {
	query := `INSERT INTO revoked_certificates (serial_number, revocation_date, reason)
				VALUES ($1, $2, $3)
	`
	_, err := r.db.ExecContext(ctx, query, serialNumber, time.Now(), reason)
	if err != nil {
		return errors.New("failed to revoke certificate: " + err.Error())
	}
	return nil
}

func (r *certificateRepository) GetRevokedCertificate(ctx context.Context) ([]model.RevokedCertificate, error) {
	query := "SELECT serial_number, revocation_date, reason FROM revoked_certificates"
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.New("failed to query revoked certificates: " + err.Error())
	}
	defer rows.Close()
	var revokedCerts []model.RevokedCertificate
	for rows.Next() {
		var cert model.RevokedCertificate
		var reason sql.NullString
		if err := rows.Scan(&cert.SerialNumber, &cert.RevocationDate, &reason); err != nil {
			return nil, errors.New("failed to scan revoked certificate: " + err.Error())
		}
		if reason.Valid {
			cert.Reason = reason.String
		}
		revokedCerts = append(revokedCerts, cert)
	}
	return revokedCerts, nil
}

func (r *certificateRepository) IsRevoked(ctx context.Context, serialNumber string) (model.RevokedCertificate, bool, error) {
	query := `SELECT serial_number, revocation_date, reason FROM revoked_certificates
	WHERE revoked_certificates.serial_number = $1
`
	var cert model.RevokedCertificate
	var reason sql.NullString
	err := r.db.QueryRowContext(ctx, query, serialNumber).Scan(&cert.SerialNumber, &cert.RevocationDate, &cert.Reason)
	if err != nil {
		return model.RevokedCertificate{}, false, errors.New("failed to check revocation status: " + err.Error())
	}
	if reason.Valid {
		cert.Reason = reason.String
	}
	return cert, true, nil
}
