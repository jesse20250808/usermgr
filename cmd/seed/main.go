package main

import (
	"context"
	"fmt"
	"os"

	"usermgr/internal/config"
	"usermgr/internal/db"
	"usermgr/pkg/password"
)

func main() {
	cfg := config.Load()

	database, err := db.Connect(cfg.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db connect: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	ctx := context.Background()

	// ── 从命令行或环境变量读取初始管理员信息 ──────────────────────────────
	adminUsername := getArg(1, getEnv("SEED_ADMIN_USERNAME", "admin"))
	adminEmail := getArg(2, getEnv("SEED_ADMIN_EMAIL", "admin@example.com"))
	adminPassword := getArg(3, getEnv("SEED_ADMIN_PASSWORD", "Admin@123456"))

	fmt.Println("=== usermgr seed ===")

	// ── 1. 确保 roles 存在 ───────────────────────────────────────────────
	fmt.Print("roles ... ")
	roles := []struct{ name, desc string }{
		{"admin", "Full access"},
		{"editor", "Read and write"},
		{"viewer", "Read only"},
	}
	for _, r := range roles {
		_, err := database.ExecContext(ctx, `
			INSERT INTO roles (name, description)
			VALUES ($1, $2)
			ON CONFLICT (name) DO NOTHING`, r.name, r.desc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\ninsert role %q: %v\n", r.name, err)
			os.Exit(1)
		}
	}
	fmt.Println("ok")

	// ── 2. 确保 permissions 存在 ─────────────────────────────────────────
	fmt.Print("permissions ... ")
	perms := []struct{ resource, action string }{
		{"users", "read"},
		{"users", "write"},
		{"users", "delete"},
		{"roles", "read"},
		{"roles", "write"},
		{"audit", "read"},
	}
	for _, p := range perms {
		_, err := database.ExecContext(ctx, `
			INSERT INTO permissions (resource, action)
			VALUES ($1, $2)
			ON CONFLICT (resource, action) DO NOTHING`, p.resource, p.action)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\ninsert permission %s:%s: %v\n", p.resource, p.action, err)
			os.Exit(1)
		}
	}
	fmt.Println("ok")

	// ── 3. 把所有权限绑定到 admin 角色 ───────────────────────────────────
	fmt.Print("role_permissions (admin) ... ")
	_, err = database.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id FROM roles r, permissions p
		WHERE r.name = 'admin'
		ON CONFLICT DO NOTHING`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nbind admin permissions: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok")

	// editor: users read/write
	fmt.Print("role_permissions (editor) ... ")
	_, err = database.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id FROM roles r
		JOIN permissions p ON p.resource = 'users' AND p.action IN ('read','write')
		WHERE r.name = 'editor'
		ON CONFLICT DO NOTHING`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nbind editor permissions: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok")

	// viewer: users read
	fmt.Print("role_permissions (viewer) ... ")
	_, err = database.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id FROM roles r
		JOIN permissions p ON p.resource = 'users' AND p.action = 'read'
		WHERE r.name = 'viewer'
		ON CONFLICT DO NOTHING`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nbind viewer permissions: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok")

	// ── 4. 创建管理员用户（已存在则跳过）────────────────────────────────
	fmt.Printf("admin user %q ... ", adminUsername)

	var exists bool
	_ = database.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, adminUsername,
	).Scan(&exists)

	if exists {
		fmt.Println("already exists, skipped")
	} else {
		hash, err := password.Hash(adminPassword)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nhash password: %v\n", err)
			os.Exit(1)
		}

		var userID string
		err = database.QueryRowContext(ctx, `
			INSERT INTO users (username, email, password, display_name)
			VALUES ($1, $2, $3, 'Administrator')
			RETURNING id`,
			adminUsername, adminEmail, hash,
		).Scan(&userID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\ncreate admin user: %v\n", err)
			os.Exit(1)
		}

		_, err = database.ExecContext(ctx, `
			INSERT INTO user_roles (user_id, role_id)
			SELECT $1, id FROM roles WHERE name = 'admin'`, userID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nassign admin role: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("created (id=%s)\n", userID)
	}

	// ── 完成 ─────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("seed completed successfully")
	fmt.Println()
	fmt.Printf("  username : %s\n", adminUsername)
	fmt.Printf("  email    : %s\n", adminEmail)
	if !exists {
		fmt.Printf("  password : %s\n", adminPassword)
	}
	fmt.Println()
	fmt.Println("login:")
	fmt.Printf("  curl -X POST http://localhost:8080/auth/login \\\n")
	fmt.Printf("    -H 'Content-Type: application/json' \\\n")
	fmt.Printf("    -d '{\"username\":\"%s\",\"password\":\"%s\"}'\n", adminUsername, adminPassword)
}

// getArg returns os.Args[i] if it exists, otherwise fallback.
func getArg(i int, fallback string) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return fallback
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
