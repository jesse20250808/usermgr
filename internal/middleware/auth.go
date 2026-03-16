package middleware

import (
	"usermgr/internal/auth"
	"usermgr/internal/user"
	"usermgr/pkg/response"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Authenticate validates the opaque bearer token.
// Sets in context: "user_id" (uuid.UUID), "user_obj" (*user.User).
func Authenticate(authSvc *auth.Service, userRepo *user.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := auth.ExtractBearerToken(c)
		if raw == "" {
			response.Unauthorized(c)
			return
		}

		userID, err := authSvc.Validate(c.Request.Context(), raw)
		if err != nil {
			response.Unauthorized(c)
			return
		}

		u, err := userRepo.FindByID(c.Request.Context(), userID)
		if err != nil || !u.IsActive {
			response.Unauthorized(c)
			return
		}

		c.Set("user_id", userID)
		c.Set("user_obj", u)
		c.Next()
	}
}

// RequirePermission checks that the authenticated user has resource:action via RBAC.
// Must be used after Authenticate.
func RequirePermission(resource, action string, userRepo *user.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.MustGet("user_id").(uuid.UUID)

		perms, err := userRepo.GetPermissions(c.Request.Context(), uid)
		if err != nil {
			response.Internal(c)
			return
		}

		for _, a := range perms[resource] {
			if a == action {
				c.Next()
				return
			}
		}

		response.Forbidden(c)
	}
}

// RequireAdmin checks that the caller has the "admin" role.
func RequireAdmin(userRepo *user.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		uid := c.MustGet("user_id").(uuid.UUID)
		roles, err := userRepo.GetRoles(c.Request.Context(), uid)
		if err != nil {
			response.Internal(c)
			return
		}
		for _, r := range roles {
			if r == "admin" {
				c.Next()
				return
			}
		}
		response.Forbidden(c)
	}
}

// Logger is a request logger that skips health-check endpoints.
func Logger() gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/health"},
	})
}
