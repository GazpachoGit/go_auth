package database

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5"
)

type Database struct {
	DB *pgx.Conn
}

func NewDatabase(connStr string) (*Database, error) {

	connConfig, err := pgx.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
		return nil, err
	}

	db, err := pgx.Connect(context.Background(), connConfig.ConnString())
	if err != nil {
		return nil, err
	}

	return &Database{DB: db}, nil
}
