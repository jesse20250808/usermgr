package user

import (
	"net/http"
	"strconv"

	"usermgr/internal/audit"
	"usermgr/pkg/password"
	"usermgr/pkg/response"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	repo     *Repository
	auditSvc *audit.Service
}

func NewHandler(repo *Repository, auditSvc *audit.Service) *Handler {
	return &Handler{repo: repo, auditSvc: auditSvc}
}

// POST /users
func (h *Handler) Create(c *gin.Context) {
	var req struct {
		Username    string `json:"username"     binding:"required,min=3,max=64"`
		Email       string `json:"email"        binding:"required,email"`
		Password    string `json:"password"     binding:"required,min=8"`
		DisplayName string `json:"display_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	hash, err := password.Hash(req.Password)
	if err != nil {
		response.Internal(c)
		return
	}

	u := &User{
		Username:    req.Username,
		Email:       req.Email,
		Password:    hash,
		DisplayName: req.DisplayName,
	}
	if err := h.repo.Create(c.Request.Context(), u); err != nil {
		response.Err(c, http.StatusConflict, "username or email already taken")
		return
	}

	callerID, _ := c.Get("user_id")
	if cid, ok := callerID.(uuid.UUID); ok {
		h.auditSvc.Log(c, cid, "user.create", "users", u.ID.String(), nil)
	}

	response.Created(c, u.ToDTO(nil))
}

// GET /users
func (h *Handler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit > 100 {
		limit = 100
	}

	users, total, err := h.repo.List(c.Request.Context(), limit, offset)
	if err != nil {
		response.Internal(c)
		return
	}

	dtos := make([]UserDTO, len(users))
	for i, u := range users {
		roles, _ := h.repo.GetRoles(c.Request.Context(), u.ID)
		dtos[i] = u.ToDTO(roles)
	}

	response.OK(c, gin.H{
		"users":  dtos,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GET /users/:id
func (h *Handler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	u, err := h.repo.FindByID(c.Request.Context(), id)
	if err != nil {
		response.NotFound(c)
		return
	}

	roles, _ := h.repo.GetRoles(c.Request.Context(), u.ID)
	response.OK(c, u.ToDTO(roles))
}

// PATCH /users/:id
func (h *Handler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	var req struct {
		Email       string `json:"email"        binding:"omitempty,email"`
		DisplayName string `json:"display_name"`
		IsActive    *bool  `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	existing, err := h.repo.FindByID(c.Request.Context(), id)
	if err != nil {
		response.NotFound(c)
		return
	}

	email := existing.Email
	if req.Email != "" {
		email = req.Email
	}
	displayName := existing.DisplayName
	if req.DisplayName != "" {
		displayName = req.DisplayName
	}
	isActive := existing.IsActive
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	updated, err := h.repo.Update(c.Request.Context(), id, email, displayName, isActive)
	if err != nil {
		response.Internal(c)
		return
	}

	callerID := c.MustGet("user_id").(uuid.UUID)
	h.auditSvc.Log(c, callerID, "user.update", "users", id.String(), nil)

	roles, _ := h.repo.GetRoles(c.Request.Context(), updated.ID)
	response.OK(c, updated.ToDTO(roles))
}

// DELETE /users/:id
func (h *Handler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	if err := h.repo.Delete(c.Request.Context(), id); err != nil {
		response.NotFound(c)
		return
	}

	callerID := c.MustGet("user_id").(uuid.UUID)
	h.auditSvc.Log(c, callerID, "user.delete", "users", id.String(), nil)

	response.OK(c, gin.H{"message": "user deleted"})
}

// POST /users/:id/roles
func (h *Handler) AssignRole(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	var req struct {
		Role string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	if err := h.repo.AssignRole(c.Request.Context(), id, req.Role); err != nil {
		response.Internal(c)
		return
	}

	callerID := c.MustGet("user_id").(uuid.UUID)
	h.auditSvc.Log(c, callerID, "user.role.assign", "users", id.String(),
		map[string]any{"role": req.Role})

	response.OK(c, gin.H{"message": "role assigned"})
}

// DELETE /users/:id/roles/:role
func (h *Handler) RemoveRole(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	role := c.Param("role")
	if err := h.repo.RemoveRole(c.Request.Context(), id, role); err != nil {
		response.Internal(c)
		return
	}

	callerID := c.MustGet("user_id").(uuid.UUID)
	h.auditSvc.Log(c, callerID, "user.role.remove", "users", id.String(),
		map[string]any{"role": role})

	response.OK(c, gin.H{"message": "role removed"})
}

// PATCH /users/:id/password  (self-service or admin)
func (h *Handler) ChangePassword(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	callerID := c.MustGet("user_id").(uuid.UUID)
	// Only self or admin can change password
	if callerID != id {
		roles, _ := h.repo.GetRoles(c.Request.Context(), callerID)
		isAdmin := false
		for _, r := range roles {
			if r == "admin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			response.Forbidden(c)
			return
		}
	}

	var req struct {
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	hash, err := password.Hash(req.Password)
	if err != nil {
		response.Internal(c)
		return
	}

	if err := h.repo.UpdatePassword(c.Request.Context(), id, hash); err != nil {
		response.Internal(c)
		return
	}

	h.auditSvc.Log(c, callerID, "user.password.change", "users", id.String(), nil)
	response.OK(c, gin.H{"message": "password updated"})
}
