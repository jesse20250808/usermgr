package auth

import (
	"net/http"
	"strings"

	"usermgr/internal/audit"
	"usermgr/internal/user"
	"usermgr/pkg/password"
	"usermgr/pkg/response"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	svc      *Service
	userRepo *user.Repository
	auditSvc *audit.Service
}

func NewHandler(svc *Service, userRepo *user.Repository, auditSvc *audit.Service) *Handler {
	return &Handler{svc: svc, userRepo: userRepo, auditSvc: auditSvc}
}

// POST /auth/login
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Name     string `json:"name"` // optional label for the token
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	u, err := h.userRepo.FindByUsername(c.Request.Context(), req.Username)
	if err != nil || !u.IsActive {
		response.Err(c, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := password.Verify(u.Password, req.Password); err != nil {
		response.Err(c, http.StatusUnauthorized, "invalid credentials")
		return
	}

	name := req.Name
	if name == "" {
		name = "web session"
	}

	raw, info, err := h.svc.Issue(c.Request.Context(), u.ID, name)
	if err != nil {
		response.Internal(c)
		return
	}

	h.auditSvc.Log(c, u.ID, "auth.login", "users", u.ID.String(), nil)

	response.OK(c, gin.H{
		"token":      raw, // shown only once
		"token_info": info,
		"user_id":    u.ID,
	})
}

// POST /auth/logout  (requires auth middleware)
func (h *Handler) Logout(c *gin.Context) {
	tokenID, _ := c.Get("token_id")
	userID, _ := c.Get("user_id")

	tid, ok1 := tokenID.(uuid.UUID)
	uid, ok2 := userID.(uuid.UUID)
	if !ok1 || !ok2 {
		response.Unauthorized(c)
		return
	}

	if err := h.svc.Revoke(c.Request.Context(), tid, uid); err != nil {
		response.Internal(c)
		return
	}

	h.auditSvc.Log(c, uid, "auth.logout", "tokens", tid.String(), nil)
	response.OK(c, gin.H{"message": "logged out"})
}

// GET /auth/tokens  (requires auth middleware)
func (h *Handler) ListTokens(c *gin.Context) {
	uid := c.MustGet("user_id").(uuid.UUID)
	tokens, err := h.svc.ListByUser(c.Request.Context(), uid)
	if err != nil {
		response.Internal(c)
		return
	}
	response.OK(c, tokens)
}

// DELETE /auth/tokens/:id  (requires auth middleware)
func (h *Handler) RevokeToken(c *gin.Context) {
	uid := c.MustGet("user_id").(uuid.UUID)
	tid, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid token id")
		return
	}

	if err := h.svc.Revoke(c.Request.Context(), tid, uid); err != nil {
		response.NotFound(c)
		return
	}

	h.auditSvc.Log(c, uid, "auth.token.revoke", "tokens", tid.String(), nil)
	response.OK(c, gin.H{"message": "token revoked"})
}

// ExtractBearerToken reads the raw token from "Authorization: Bearer <token>".
func ExtractBearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return parts[1]
	}
	return ""
}
