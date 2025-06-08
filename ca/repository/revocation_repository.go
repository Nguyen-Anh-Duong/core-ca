package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
	"errors"
	"time"
)

type RevocationRepository interface {
	Revoke(ctx context.Context, serialNumber, reason string, isCA bool) error
	GetRevokedCertificates(ctx context.Context) ([]model.RevokedCertificate, error)
	IsRevoked(ctx context.Context, serialNumber string) (model.RevokedCertificate, bool, error)
}

type revocationRepository struct {
	db *sql.DB
}

func NewRevocationRepository(db *sql.DB) (RevocationRepository, error) {
	if db == nil {
		return nil, errors.New("database connection is nil")
	}
	_, err := db.Exec(`
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

	return &revocationRepository{db: db}, nil
}

func (r *revocationRepository) Revoke(ctx context.Context, serialNumber string, reason string, isCA bool) error {
	query := `INSERT INTO revoked_certificates (serial_number, revocation_date, reason, is_ca)
				VALUES ($1, $2, $3, $4)
	`
	_, err := r.db.ExecContext(ctx, query, serialNumber, time.Now(), reason, isCA)
	if err != nil {
		return errors.New("failed to revoke certificate: " + err.Error())
	}
	return nil
}

func (r *revocationRepository) GetRevokedCertificates(ctx context.Context) ([]model.RevokedCertificate, error) {
	query := "SELECT serial_number, revocation_date, reason. is_ca FROM revoked_certificates"
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.New("failed to query revoked certificates: " + err.Error())
	}
	defer rows.Close()
	var revokedCerts []model.RevokedCertificate
	for rows.Next() {
		var cert model.RevokedCertificate
		var reason sql.NullString
		if err := rows.Scan(&cert.SerialNumber, &cert.RevocationDate, &reason, &cert.IsCA); err != nil {
			return nil, errors.New("failed to scan revoked certificate: " + err.Error())
		}
		if reason.Valid {
			cert.Reason = model.RevocationReason(reason.String)
		}
		revokedCerts = append(revokedCerts, cert)
	}
	return revokedCerts, nil
}

func (r *revocationRepository) IsRevoked(ctx context.Context, serialNumber string) (model.RevokedCertificate, bool, error) {
	query := `SELECT serial_number, revocation_date, reason, is_ca FROM revoked_certificates
	WHERE revoked_certificates.serial_number = $1
`
	var cert model.RevokedCertificate
	var reason sql.NullString
	err := r.db.QueryRowContext(ctx, query, serialNumber).Scan(&cert.SerialNumber, &cert.RevocationDate, &reason, &cert.IsCA)
	if err != nil {
		return model.RevokedCertificate{}, false, errors.New("failed to check revocation status: " + err.Error())
	}
	if reason.Valid {
		cert.Reason = model.RevocationReason(reason.String)
	}
	return cert, true, nil
}
