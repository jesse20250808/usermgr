.PHONY: run build migrate seed tidy lint

run:
	go run ./cmd/server

build:
	go build -o bin/server ./cmd/server

# Apply schema to the database defined by DATABASE_URL
migrate:
	psql "$(DATABASE_URL)" -f schema.sql

# Seed default roles, permissions, and admin user.
# Override defaults:  make seed ARGS="myadmin admin@co.com MyP@ss"
# Or via env:         SEED_ADMIN_USERNAME=myadmin SEED_ADMIN_PASSWORD=x make seed
seed:
	go run ./cmd/seed $(ARGS)

tidy:
	go mod tidy

lint:
	golangci-lint run ./...
