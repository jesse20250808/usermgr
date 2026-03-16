package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Response struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{Success: true, Data: data})
}

func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, Response{Success: true, Data: data})
}

func Err(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, Response{Success: false, Error: msg})
}

func BadRequest(c *gin.Context, msg string) { Err(c, http.StatusBadRequest, msg) }
func Unauthorized(c *gin.Context)           { Err(c, http.StatusUnauthorized, "unauthorized") }
func Forbidden(c *gin.Context)              { Err(c, http.StatusForbidden, "forbidden") }
func NotFound(c *gin.Context)               { Err(c, http.StatusNotFound, "not found") }
func Internal(c *gin.Context)               { Err(c, http.StatusInternalServerError, "internal server error") }
