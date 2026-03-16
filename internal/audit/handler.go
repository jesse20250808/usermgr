package audit

import (
	"strconv"

	"usermgr/pkg/response"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// GET /audit  (admin only)
func (h *Handler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit > 200 {
		limit = 200
	}

	var filterUID *uuid.UUID
	if uidStr := c.Query("user_id"); uidStr != "" {
		if uid, err := uuid.Parse(uidStr); err == nil {
			filterUID = &uid
		}
	}

	logs, total, err := h.svc.List(c.Request.Context(), filterUID, limit, offset)
	if err != nil {
		response.Internal(c)
		return
	}

	response.OK(c, gin.H{
		"logs":   logs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
