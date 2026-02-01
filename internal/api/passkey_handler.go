package api

import (
	"go-auth-core/internal/repository"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// PasskeyHandler handles CRUD operations for passkeys.
type PasskeyHandler struct {
	passkeyRepo *repository.PasskeyRepository
}

// NewPasskeyHandler creates a new instance of PasskeyHandler.
func NewPasskeyHandler(passkeyRepo *repository.PasskeyRepository) *PasskeyHandler {
	return &PasskeyHandler{
		passkeyRepo: passkeyRepo,
	}
}

// PasskeyResponse represents a passkey in the API response.
type PasskeyResponse struct {
	ID        uint      `json:"id" example:"1"`
	Name      string    `json:"name" example:"MacBook Pro"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

// RenamePasskeyRequest represents the request to rename a passkey.
type RenamePasskeyRequest struct {
	Name string `json:"name" binding:"required,min=1,max=100" example:"iPhone 15 Pro"`
}

// List godoc
// @Summary      List User Passkeys
// @Description  Returns all passkeys registered by the authenticated user.
// @Tags         passkeys
// @Security     CookieAuth
// @Produce      json
// @Success      200 {array} PasskeyResponse
// @Failure      401 {object} ErrorResponse "Not authenticated"
// @Router       /api/passkeys [get]
func (h *PasskeyHandler) List(c *gin.Context) {
	claims := GetUserClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	passkeys, err := h.passkeyRepo.FindByUserID(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve passkeys"})
		return
	}

	// Transform to response DTO
	response := make([]PasskeyResponse, len(passkeys))
	for i, p := range passkeys {
		response[i] = PasskeyResponse{
			ID:        p.ID,
			Name:      p.Name,
			CreatedAt: p.CreatedAt,
			// LastUsed could be added in the future
		}
	}

	c.JSON(http.StatusOK, response)
}

// Rename godoc
// @Summary      Rename Passkey
// @Description  Updates the name of a passkey. Users can only rename their own passkeys.
// @Tags         passkeys
// @Security     CookieAuth
// @Accept       json
// @Produce      json
// @Param        id path int true "Passkey ID"
// @Param        request body RenamePasskeyRequest true "New Name"
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse "Invalid data"
// @Failure      401 {object} ErrorResponse "Not authenticated"
// @Failure      403 {object} ErrorResponse "Not authorized to modify this passkey"
// @Failure      404 {object} ErrorResponse "Passkey not found"
// @Router       /api/passkeys/{id} [patch]
func (h *PasskeyHandler) Rename(c *gin.Context) {
	claims := GetUserClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Parse ID from path
	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid passkey ID"})
		return
	}

	// Parse body
	var req RenamePasskeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: name is required"})
		return
	}

	// Verify that the passkey exists and belongs to the user
	passkey, err := h.passkeyRepo.FindByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Passkey not found"})
		return
	}

	if passkey.UserID != claims.UserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized to modify this passkey"})
		return
	}

	// Update the name
	if err := h.passkeyRepo.Rename(uint(id), req.Name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rename passkey"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Passkey renamed successfully"})
}

// Delete godoc
// @Summary      Delete Passkey
// @Description  Deletes a passkey. Users can only delete their own passkeys and must keep at least one active.
// @Tags         passkeys
// @Security     CookieAuth
// @Produce      json
// @Param        id path int true "Passkey ID"
// @Success      200 {object} MessageResponse
// @Failure      400 {object} ErrorResponse "Cannot delete last passkey"
// @Failure      401 {object} ErrorResponse "Not authenticated"
// @Failure      403 {object} ErrorResponse "Not authorized to delete this passkey"
// @Failure      404 {object} ErrorResponse "Passkey not found"
// @Router       /api/passkeys/{id} [delete]
func (h *PasskeyHandler) Delete(c *gin.Context) {
	claims := GetUserClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Parse ID from path
	idParam := c.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid passkey ID"})
		return
	}

	// Verify that the passkey exists and belongs to the user
	passkey, err := h.passkeyRepo.FindByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Passkey not found"})
		return
	}

	if passkey.UserID != claims.UserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized to delete this passkey"})
		return
	}

	// Verify it's not the user's last passkey
	count, err := h.passkeyRepo.CountByUserID(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check passkey count"})
		return
	}

	if count <= 1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Cannot delete your last passkey. Register a new one first.",
		})
		return
	}

	// Delete the passkey
	if err := h.passkeyRepo.Delete(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete passkey"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Passkey deleted successfully"})
}
