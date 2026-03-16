package db

import (
	"context"
	"fmt"
	"time"

	"usermgr/internal/config"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

func Connect(cfg config.DatabaseConfig) (*sqlx.DB, error) {
	db, err := sqlx.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}

	return db, nil
}
