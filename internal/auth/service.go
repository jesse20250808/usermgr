package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"usermgr/internal/config"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// ─── Models ──────────────────────────────────────────────────────────────────

type Token struct {
	ID         uuid.UUID  `db:"id"`
	UserID     uuid.UUID  `db:"user_id"`
	TokenHash  string     `db:"token_hash"`
	Name       string     `db:"name"`
	ExpiresAt  *time.Time `db:"expires_at"`
	LastUsedAt *time.Time `db:"last_used_at"`
	CreatedAt  time.Time  `db:"created_at"`
}

type TokenInfo struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ─── Service ─────────────────────────────────────────────────────────────────

type Service struct {
	db  *sqlx.DB
	cfg config.AuthConfig
}

func NewService(db *sqlx.DB, cfg config.AuthConfig) *Service {
	return &Service{db: db, cfg: cfg}
}

// Issue creates a new opaque token for the given user.
// Returns the raw token (shown once) and its metadata.
func (s *Service) Issue(ctx context.Context, userID uuid.UUID, name string) (rawToken string, info TokenInfo, err error) {
	raw, err := generateToken(s.cfg.TokenLength)
	if err != nil {
		return "", TokenInfo{}, fmt.Errorf("generate token: %w", err)
	}

	hash := hashToken(raw)

	var expiresAt *time.Time
	if s.cfg.TokenTTL > 0 {
		t := time.Now().Add(s.cfg.TokenTTL)
		expiresAt = &t
	}

	var tok Token
	err = s.db.GetContext(ctx, &tok, `
		INSERT INTO tokens (user_id, token_hash, name, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING *`,
		userID, hash, name, expiresAt,
	)
	if err != nil {
		return "", TokenInfo{}, fmt.Errorf("insert token: %w", err)
	}

	return raw, TokenInfo{
		ID:        tok.ID,
		Name:      tok.Name,
		ExpiresAt: tok.ExpiresAt,
		CreatedAt: tok.CreatedAt,
	}, nil
}

// Validate looks up the token by hash, checks expiry, and touches last_used_at.
// Returns the user ID on success.
func (s *Service) Validate(ctx context.Context, rawToken string) (uuid.UUID, error) {
	hash := hashToken(rawToken)

	var tok Token
	err := s.db.GetContext(ctx, &tok, `
		SELECT * FROM tokens WHERE token_hash = $1`, hash)
	if err != nil {
		return uuid.Nil, fmt.Errorf("token not found")
	}

	if tok.ExpiresAt != nil && tok.ExpiresAt.Before(time.Now()) {
		return uuid.Nil, fmt.Errorf("token expired")
	}

	// Touch last_used_at asynchronously to avoid blocking the request
	go func() {
		_, _ = s.db.ExecContext(context.Background(),
			`UPDATE tokens SET last_used_at = NOW() WHERE id = $1`, tok.ID)
	}()

	return tok.UserID, nil
}

// Revoke deletes a token by ID, scoped to the owner.
func (s *Service) Revoke(ctx context.Context, tokenID, userID uuid.UUID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE id = $1 AND user_id = $2`, tokenID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token not found")
	}
	return nil
}

// ListByUser returns non-sensitive metadata for all tokens belonging to a user.
func (s *Service) ListByUser(ctx context.Context, userID uuid.UUID) ([]TokenInfo, error) {
	var tokens []Token
	err := s.db.SelectContext(ctx, &tokens,
		`SELECT * FROM tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}

	out := make([]TokenInfo, len(tokens))
	for i, t := range tokens {
		out[i] = TokenInfo{
			ID:         t.ID,
			Name:       t.Name,
			ExpiresAt:  t.ExpiresAt,
			LastUsedAt: t.LastUsedAt,
			CreatedAt:  t.CreatedAt,
		}
	}
	return out, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func generateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
