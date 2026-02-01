package api

import "time"

// DTO (Data Transfer Objects) for API requests and responses.
// These models are also used for Swagger documentation.

// EmailRequest represents a request containing an email address.
// @Description Request body with user email
type EmailRequest struct {
	// User's email address
	// required: true
	// example: user@example.com
	Email string `json:"email" binding:"required,email" example:"user@example.com"`
}

// MessageResponse represents a generic success response.
// @Description Generic response message
type MessageResponse struct {
	// Response message
	// example: Operation successful
	Message string `json:"message" example:"Operation successful"`
}

// ErrorResponse represents an error response.
// @Description Error details
type ErrorResponse struct {
	// Error message
	// example: Invalid request format
	Error string `json:"error" example:"Invalid request format"`
	// Optional error code (e.g., TOKEN_EXPIRED)
	Code string `json:"code,omitempty" example:"TOKEN_EXPIRED"`
}

// UserInfo contains basic user information.
// @Description Authenticated user details
type UserInfo struct {
	// Unique user ID
	// example: 1
	ID uint `json:"id" example:"1"`
	// User email
	// example: user@example.com
	Email string `json:"email" example:"user@example.com"`
}

// LoginSuccessResponse represents a successful login response.
// @Description Response after successful authentication
type LoginSuccessResponse struct {
	// Success message
	// example: Login successful! 🔐
	Message string `json:"message" example:"Login successful! 🔐"`
	// User information
	User UserInfo `json:"user"`
}

// UserResponse wraps user information.
// @Description Response containing user info
type UserResponse struct {
	// Authenticated user info
	User UserInfo `json:"user"`
}

// HealthResponse represents the health check response.
// @Description Health check endpoint response
type HealthResponse struct {
	// Welcome message
	// example: Go Auth Core API 🚀
	Message string `json:"message" example:"Go Auth Core API 🚀"`
	// Service status
	// example: healthy
	Status string `json:"status" example:"healthy"`
}

// PasskeyListResponse represents a list of user passkeys.
// @Description List of registered passkeys
type PasskeyListResponse struct {
	// List of passkeys
	Passkeys []PasskeyInfo `json:"passkeys"`
}

// PasskeyInfo contains public information about a passkey.
// @Description Registered passkey details
type PasskeyInfo struct {
	// Passkey ID
	ID uint `json:"id" example:"1"`
	// Descriptive name
	Name string `json:"name" example:"MacBook Pro"`
	// Creation timestamp
	CreatedAt time.Time `json:"created_at"`
}

// RateLimitResponse represents the response when the rate limit is exceeded.
// @Description Response for too many requests
type RateLimitResponse struct {
	// Error message
	Error string `json:"error" example:"Too many requests"`
	// Seconds to wait before retrying
	RetryAfter int `json:"retry_after" example:"60"`
}
