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
	GetRevokedCertificates(ctx context.Context, caID int) ([]model.RevokedCertificate, error)
	IsRevoked(ctx context.Context, serialNumber string) (model.RevokedCertificate, bool, error)
}

type revocationRepository struct {
	db *sql.DB
}

func (r *revocationRepository) Revoke(ctx context.Context, serialNumber string, reason string, isCA bool) error {
	// Start transaction
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("failed to begin transaction: " + err.Error())
	}
	defer tx.Rollback()

	// Insert into revoked_certificates table
	query1 := `INSERT INTO revoked_certificates (serial_number, revocation_date, reason, is_ca)
				VALUES ($1, $2, $3, $4)`
	_, err = tx.ExecContext(ctx, query1, serialNumber, time.Now(), reason, isCA)
	if err != nil {
		return errors.New("failed to insert into revoked_certificates: " + err.Error())
	}

	// Update certificate status to 'revoked'
	query2 := `UPDATE certificates SET status = 'revoked' WHERE serial_number = $1`
	_, err = tx.ExecContext(ctx, query2, serialNumber)
	if err != nil {
		return errors.New("failed to update certificate status: " + err.Error())
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return errors.New("failed to commit transaction: " + err.Error())
	}

	return nil
}

func (r *revocationRepository) GetRevokedCertificates(ctx context.Context, caID int) ([]model.RevokedCertificate, error) {
	query := `SELECT rc.serial_number, rc.revocation_date, rc.reason, rc.is_ca 
			  FROM revoked_certificates rc
			  INNER JOIN certificates c ON rc.serial_number = c.serial_number
			  WHERE c.ca_id = $1`
	rows, err := r.db.QueryContext(ctx, query, caID)
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
