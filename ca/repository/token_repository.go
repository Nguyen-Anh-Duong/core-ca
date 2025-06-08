package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
)

type TokenRepository interface {
	SaveToken(ctx context.Context, Token model.CryptoToken) (int error)
	FindTokenById(ctx context.Context, id string) (model.CryptoToken, error)
}

type tokenRepository struct {
	db *sql.DB
}

// Implement SaveToken, FindTokenByID ở đây
