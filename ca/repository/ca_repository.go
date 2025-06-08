package repository

import (
	"context"
	"core-ca/ca/model"
	"database/sql"
)

type CARepository interface {
	SaveCA(ctx context.Context, ca model.CA) (int, error)
	FindCAByID(ctx context.Context, id int) (model.CA, error)
	FindCABySerialNumber(ctx context.Context, serialNumber string) (model.CA, error)
	GetCAChain(ctx context.Context, caID int) ([]model.CA, error)
}

type caRepository struct {
	db *sql.DB
}
