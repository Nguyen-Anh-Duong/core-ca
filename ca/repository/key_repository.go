package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
)

type KeyRepository interface {
	SaveKey(ctx context.Context, key model.CryptoKey) (int, error)
	FindKeyByLabelAndTokenID(ctx context.Context, label string, tokenID int) (model.CryptoKey, error)
}

type keyRepository struct {
	db *sql.DB
}
