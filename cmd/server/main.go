package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"usermgr/internal/audit"
	"usermgr/internal/auth"
	"usermgr/internal/config"
	"usermgr/internal/db"
	"usermgr/internal/middleware"
	"usermgr/internal/user"
)

func main() {
	// ── Logger ──────────────────────────────────────────────────────────────
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// ── Config ──────────────────────────────────────────────────────────────
	cfg := config.Load()
	gin.SetMode(cfg.Server.Mode)

	// ── Database ─────────────────────────────────────────────────────────────
	database, err := db.Connect(cfg.Database)
	if err != nil {
		logger.Fatal("database connection failed", zap.Error(err))
	}
	defer database.Close()
	logger.Info("database connected")

	// ── Services & Repositories ──────────────────────────────────────────────
	userRepo := user.NewRepository(database)
	authSvc := auth.NewService(database, cfg.Auth)
	auditSvc := audit.NewService(database, logger)

	// ── Handlers ─────────────────────────────────────────────────────────────
	authHandler := auth.NewHandler(authSvc, userRepo, auditSvc)
	userHandler := user.NewHandler(userRepo, auditSvc)
	auditHandler := audit.NewHandler(auditSvc)

	// ── Router ───────────────────────────────────────────────────────────────
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.Logger())

	// Health check (unauthenticated)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Auth routes
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/login", authHandler.Login)

		// Require authentication for the rest
		authed := authGroup.Group("")
		authed.Use(middleware.Authenticate(authSvc, userRepo))
		authed.POST("/logout", authHandler.Logout)
		authed.GET("/tokens", authHandler.ListTokens)
		authed.DELETE("/tokens/:id", authHandler.RevokeToken)
	}

	// User routes — all require authentication
	usersGroup := r.Group("/users")
	usersGroup.Use(middleware.Authenticate(authSvc, userRepo))
	{
		// List / create (admin or editor for write)
		usersGroup.GET("", middleware.RequirePermission("users", "read", userRepo), userHandler.List)
		usersGroup.POST("", middleware.RequirePermission("users", "write", userRepo), userHandler.Create)

		// Per-user operations
		usersGroup.GET("/:id", middleware.RequirePermission("users", "read", userRepo), userHandler.Get)
		usersGroup.PATCH("/:id", middleware.RequirePermission("users", "write", userRepo), userHandler.Update)
		usersGroup.DELETE("/:id", middleware.RequirePermission("users", "delete", userRepo), userHandler.Delete)
		usersGroup.PATCH("/:id/password", userHandler.ChangePassword) // self-service; handler checks ownership
		usersGroup.POST("/:id/roles", middleware.RequireAdmin(userRepo), userHandler.AssignRole)
		usersGroup.DELETE("/:id/roles/:role", middleware.RequireAdmin(userRepo), userHandler.RemoveRole)
	}

	// Audit log — admin only
	auditGroup := r.Group("/audit")
	auditGroup.Use(middleware.Authenticate(authSvc, userRepo))
	auditGroup.Use(middleware.RequirePermission("audit", "read", userRepo))
	{
		auditGroup.GET("", auditHandler.List)
	}

	// ── HTTP Server with graceful shutdown ────────────────────────────────────
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("server starting", zap.String("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("forced shutdown", zap.Error(err))
	}
	logger.Info("server stopped")
}
