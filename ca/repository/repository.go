package repository

import (
	"database/sql"
	"errors"
)

type Repository interface {
	RevocationRepository
	CertificateRepository
	TokenRepository
	KeyRepository
	CARepository
}

type repository struct {
	*tokenRepository
	*keyRepository
	*caRepository
	*certificateRepository
	*revocationRepository
}

func NewRepository(db *sql.DB) (Repository, error) {
	if db == nil {
		return nil, errors.New("database is nil")
	}
	return &repository{
		tokenRepository:       &tokenRepository{db},
		keyRepository:         &keyRepository{db},
		caRepository:          &caRepository{db},
		certificateRepository: &certificateRepository{db},
		revocationRepository:  &revocationRepository{db},
	}, nil
}
