package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// HealthHandler manages health check endpoints.
type HealthHandler struct {
	db  *gorm.DB
	rdb *redis.Client
}

// NewHealthHandler creates a new HealthHandler instance.
func NewHealthHandler(db *gorm.DB, rdb *redis.Client) *HealthHandler {
	return &HealthHandler{
		db:  db,
		rdb: rdb,
	}
}

// ServiceStatus represents the status of a specific service.
type ServiceStatus struct {
	Status  string `json:"status" example:"healthy"`
	Latency string `json:"latency,omitempty" example:"1.23ms"`
	Error   string `json:"error,omitempty" example:""`
}

// HealthDetailedResponse represents the detailed health check response.
type HealthDetailedResponse struct {
	Status    string                   `json:"status" example:"healthy"`
	Timestamp time.Time                `json:"timestamp"`
	Version   string                   `json:"version" example:"1.0.0"`
	Services  map[string]ServiceStatus `json:"services"`
}

// Health godoc
// @Summary      Detailed Health Check
// @Description  Checks the status of the service, database, and Redis.
// @Tags         health
// @Produce      json
// @Success      200 {object} HealthDetailedResponse "All services are healthy"
// @Failure      503 {object} HealthDetailedResponse "One or more services are unhealthy"
// @Router       /health [get]
func (h *HealthHandler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	response := HealthDetailedResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Services:  make(map[string]ServiceStatus),
	}

	// Check Database
	response.Services["database"] = h.checkDatabase(ctx)

	// Check Redis
	response.Services["redis"] = h.checkRedis(ctx)

	// If any service is unhealthy, the system is unhealthy
	for _, service := range response.Services {
		if service.Status != "healthy" {
			response.Status = "unhealthy"
			c.JSON(http.StatusServiceUnavailable, response)
			return
		}
	}

	c.JSON(http.StatusOK, response)
}

// checkDatabase verifies the database connection.
func (h *HealthHandler) checkDatabase(ctx context.Context) ServiceStatus {
	start := time.Now()

	sqlDB, err := h.db.DB()
	if err != nil {
		return ServiceStatus{
			Status: "unhealthy",
			Error:  "Failed to get DB connection: " + err.Error(),
		}
	}

	err = sqlDB.PingContext(ctx)
	latency := time.Since(start)

	if err != nil {
		return ServiceStatus{
			Status:  "unhealthy",
			Latency: latency.String(),
			Error:   "Ping failed: " + err.Error(),
		}
	}

	return ServiceStatus{
		Status:  "healthy",
		Latency: latency.String(),
	}
}

// checkRedis verifies the Redis connection.
func (h *HealthHandler) checkRedis(ctx context.Context) ServiceStatus {
	start := time.Now()

	_, err := h.rdb.Ping(ctx).Result()
	latency := time.Since(start)

	if err != nil {
		return ServiceStatus{
			Status:  "unhealthy",
			Latency: latency.String(),
			Error:   "Ping failed: " + err.Error(),
		}
	}

	return ServiceStatus{
		Status:  "healthy",
		Latency: latency.String(),
	}
}
