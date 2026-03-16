package user

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// ─── Models ──────────────────────────────────────────────────────────────────

type User struct {
	ID          uuid.UUID `db:"id"`
	Username    string    `db:"username"`
	Email       string    `db:"email"`
	Password    string    `db:"password"`
	DisplayName string    `db:"display_name"`
	IsActive    bool      `db:"is_active"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

// UserDTO is the public-safe representation (no password).
type UserDTO struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	IsActive    bool      `json:"is_active"`
	Roles       []string  `json:"roles"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (u User) ToDTO(roles []string) UserDTO {
	return UserDTO{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		IsActive:    u.IsActive,
		Roles:       roles,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// ─── Repository ───────────────────────────────────────────────────────────────

type Repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(ctx context.Context, u *User) error {
	return r.db.GetContext(ctx, u, `
		INSERT INTO users (username, email, password, display_name)
		VALUES ($1, $2, $3, $4)
		RETURNING *`,
		u.Username, u.Email, u.Password, u.DisplayName,
	)
}

func (r *Repository) FindByID(ctx context.Context, id uuid.UUID) (*User, error) {
	var u User
	err := r.db.GetContext(ctx, &u, `SELECT * FROM users WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return &u, nil
}

func (r *Repository) FindByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := r.db.GetContext(ctx, &u, `SELECT * FROM users WHERE username = $1`, username)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return &u, nil
}

func (r *Repository) List(ctx context.Context, limit, offset int) ([]User, int, error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT COUNT(*) FROM users`); err != nil {
		return nil, 0, err
	}

	var users []User
	err := r.db.SelectContext(ctx, &users,
		`SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	return users, total, err
}

func (r *Repository) Update(ctx context.Context, id uuid.UUID, email, displayName string, isActive bool) (*User, error) {
	var u User
	err := r.db.GetContext(ctx, &u, `
		UPDATE users
		SET email = $2, display_name = $3, is_active = $4, updated_at = NOW()
		WHERE id = $1
		RETURNING *`, id, email, displayName, isActive)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return &u, nil
}

func (r *Repository) UpdatePassword(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET password = $2, updated_at = NOW() WHERE id = $1`, id, hash)
	return err
}

func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// ─── Roles ────────────────────────────────────────────────────────────────────

func (r *Repository) GetRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var roles []string
	err := r.db.SelectContext(ctx, &roles, `
		SELECT ro.name FROM roles ro
		JOIN user_roles ur ON ur.role_id = ro.id
		WHERE ur.user_id = $1`, userID)
	return roles, err
}

func (r *Repository) AssignRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id FROM roles WHERE name = $2
		ON CONFLICT DO NOTHING`, userID, roleName)
	return err
}

func (r *Repository) RemoveRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM user_roles
		WHERE user_id = $1 AND role_id = (SELECT id FROM roles WHERE name = $2)`,
		userID, roleName)
	return err
}

// GetPermissions returns all (resource, action) pairs for the user via their roles.
func (r *Repository) GetPermissions(ctx context.Context, userID uuid.UUID) (map[string][]string, error) {
	var rows []struct {
		Resource string `db:"resource"`
		Action   string `db:"action"`
	}
	err := r.db.SelectContext(ctx, &rows, `
		SELECT DISTINCT p.resource, p.action
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN user_roles ur       ON ur.role_id = rp.role_id
		WHERE ur.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}

	perms := make(map[string][]string)
	for _, row := range rows {
		perms[row.Resource] = append(perms[row.Resource], row.Action)
	}
	return perms, nil
}
