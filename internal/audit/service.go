package audit

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

type Log struct {
	ID         int64      `db:"id"`
	UserID     *uuid.UUID `db:"user_id"`
	Action     string     `db:"action"`
	Resource   string     `db:"resource"`
	ResourceID string     `db:"resource_id"`
	IPAddress  string     `db:"ip_address"`
	UserAgent  string     `db:"user_agent"`
	Detail     []byte     `db:"detail"`
	CreatedAt  time.Time  `db:"created_at"`
}

type LogDTO struct {
	ID         int64          `json:"id"`
	UserID     *uuid.UUID     `json:"user_id,omitempty"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	ResourceID string         `json:"resource_id"`
	IPAddress  string         `json:"ip_address"`
	Detail     map[string]any `json:"detail,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

type Service struct {
	db     *sqlx.DB
	logger *zap.Logger
}

func NewService(db *sqlx.DB, logger *zap.Logger) *Service {
	return &Service{db: db, logger: logger}
}

// Log records an audit event. Runs asynchronously to avoid blocking handlers.
func (s *Service) Log(c *gin.Context, userID uuid.UUID, action, resource, resourceID string, detail map[string]any) {
	ip := clientIP(c)
	ua := c.GetHeader("User-Agent")

	var detailJSON []byte
	if detail != nil {
		detailJSON, _ = json.Marshal(detail)
	}

	go func() {
		ctx := context.Background()
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address, user_agent, detail)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			userID, action, resource, resourceID, ip, ua, detailJSON,
		)
		if err != nil {
			s.logger.Error("audit log write failed", zap.Error(err))
		}
	}()
}

// List returns paginated audit logs (admin only).
func (s *Service) List(ctx context.Context, userID *uuid.UUID, limit, offset int) ([]LogDTO, int, error) {
	var total int
	var logs []Log
	var err error

	if userID != nil {
		err = s.db.GetContext(ctx, &total,
			`SELECT COUNT(*) FROM audit_logs WHERE user_id = $1`, userID)
		if err != nil {
			return nil, 0, err
		}
		err = s.db.SelectContext(ctx, &logs, `
			SELECT * FROM audit_logs WHERE user_id = $1
			ORDER BY created_at DESC LIMIT $2 OFFSET $3`, userID, limit, offset)
	} else {
		err = s.db.GetContext(ctx, &total, `SELECT COUNT(*) FROM audit_logs`)
		if err != nil {
			return nil, 0, err
		}
		err = s.db.SelectContext(ctx, &logs,
			`SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	}
	if err != nil {
		return nil, 0, err
	}

	dtos := make([]LogDTO, len(logs))
	for i, l := range logs {
		var detail map[string]any
		if l.Detail != nil {
			_ = json.Unmarshal(l.Detail, &detail)
		}
		dtos[i] = LogDTO{
			ID:         l.ID,
			UserID:     l.UserID,
			Action:     l.Action,
			Resource:   l.Resource,
			ResourceID: l.ResourceID,
			IPAddress:  l.IPAddress,
			Detail:     detail,
			CreatedAt:  l.CreatedAt,
		}
	}
	return dtos, total, nil
}

func clientIP(c *gin.Context) string {
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		if ip := net.ParseIP(xff); ip != nil {
			return ip.String()
		}
	}
	host, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
	return host
}
