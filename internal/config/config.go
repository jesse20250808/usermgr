package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     AuthConfig
}

type ServerConfig struct {
	Port string
	Mode string // "debug" | "release"
}

type DatabaseConfig struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type AuthConfig struct {
	TokenLength int           // bytes of entropy (default 32)
	TokenTTL    time.Duration // 0 = non-expiring
}

func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port: getEnv("PORT", "8080"),
			Mode: getEnv("GIN_MODE", "debug"),
		},
		Database: DatabaseConfig{
			DSN:             getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/usermgr?sslmode=disable"),
			MaxOpenConns:    getEnvInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvInt("DB_MAX_IDLE_CONNS", 10),
			ConnMaxLifetime: getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		Auth: AuthConfig{
			TokenLength: getEnvInt("TOKEN_LENGTH", 32),
			TokenTTL:    getEnvDuration("TOKEN_TTL", 24*time.Hour*30), // 30 days
		},
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
