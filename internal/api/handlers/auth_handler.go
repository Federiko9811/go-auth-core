package handlers

import (
	"go-auth-core/internal/api"
	"go-auth-core/internal/conf"
	"go-auth-core/internal/repository"
	"go-auth-core/internal/service"
	"go-auth-core/pkg/jwt"
	"go-auth-core/pkg/logger"
	"net/http"
	"strings"

	"regexp"
	"time"

	"github.com/gin-gonic/gin"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// AuthHandler handles HTTP requests related to authentication.
type AuthHandler struct {
	authService *service.AuthService
	userRepo    *repository.UserRepository
	redisRepo   *repository.RedisRepository
	cfg         *conf.Config
}

// NewAuthHandler is the constructor for AuthHandler.
func NewAuthHandler(authService *service.AuthService, userRepo *repository.UserRepository, redisRepo *repository.RedisRepository, cfg *conf.Config) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		userRepo:    userRepo,
		redisRepo:   redisRepo,
		cfg:         cfg,
	}
}

// --- REGISTRATION ---

// RegisterBegin godoc
// @Summary      Start Passkey Registration
// @Description  Initiates the WebAuthn registration flow. Returns options to be passed to navigator.credentials.create() in the browser.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body dtos.EmailRequest true "User Email"
// @Success      200 {object} object "PublicKeyCredentialCreationOptions for WebAuthn"
// @Failure      400 {object} dtos.ErrorResponse "Invalid or missing email"
// @Failure      500 {object} dtos.ErrorResponse "Internal server error"
// @Router       /auth/register/begin [post]
func (h *AuthHandler) RegisterBegin(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	// Double check with regex for strictness
	if !emailRegex.MatchString(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	options, requiresOTP, err := h.authService.RegisterBegin(c.Request.Context(), req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if requiresOTP {
		// New response format needed here? Or just use a specific field?
		// For now simple JSON:
		c.JSON(http.StatusOK, gin.H{
			"requires_otp": true,
			"message":      "User already exists. OTP sent to email.",
		})
		return
	}

	// Return options.Response directly to avoid the {"publicKey": {...}} wrapper
	c.JSON(http.StatusOK, gin.H{
		"requires_otp": false,
		"options":      options.Response,
	})
}

// RegisterVerifyOTP godoc
// @Summary      Verify OTP and Continue Registration
// @Description  Verifies the OTP sent to email and returns registration options.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body object true "Email and OTP"
// @Success      200 {object} object "PublicKeyCredentialCreationOptions"
// @Router       /auth/register/verify-otp [post]
func (h *AuthHandler) RegisterVerifyOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required,len=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	options, err := h.authService.VerifyOTP(c.Request.Context(), req.Email, req.OTP)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"options": options.Response,
	})
}

// RegisterFinish godoc
// @Summary      Complete Passkey Registration
// @Description  Completes the WebAuthn registration flow. The body must contain the raw response from navigator.credentials.create().
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        email query string true "User Email" example(user@example.com)
// @Param        request body object true "WebAuthn response from navigator.credentials.create()"
// @Success      200 {object} dtos.MessageResponse "Registration completed"
// @Failure      400 {object} dtos.ErrorResponse "Missing email"
// @Failure      401 {object} dtos.ErrorResponse "Registration failed"
// @Router       /auth/register/finish [post]
func (h *AuthHandler) RegisterFinish(c *gin.Context) {
	email := c.Query("email")
	if email == "" || !emailRegex.MatchString(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Valid email query parameter is required"})
		return
	}

	err := h.authService.RegisterFinish(c.Request.Context(), email, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Registration failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful! 🎉"})
}

// --- LOGIN ---

// LoginBegin godoc
// @Summary      Start Passkey Login
// @Description  Initiates the WebAuthn authentication flow. Returns options to be passed to navigator.credentials.get() in the browser.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body dtos.EmailRequest true "User Email"
// @Success      200 {object} object "PublicKeyCredentialRequestOptions for WebAuthn"
// @Failure      400 {object} dtos.ErrorResponse "Invalid email"
// @Failure      401 {object} dtos.ErrorResponse "Invalid credentials"
// @Router       /auth/login/begin [post]
func (h *AuthHandler) LoginBegin(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	if !emailRegex.MatchString(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	options, err := h.authService.LoginBegin(c.Request.Context(), req.Email)
	if err != nil {
		// Do not reveal if the user exists or not (security best practice)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Return options.Response directly to avoid the {"publicKey": {...}} wrapper
	c.JSON(http.StatusOK, options.Response)
}

// LoginFinish godoc
// @Summary      Complete Passkey Login
// @Description  Completes the WebAuthn authentication flow. If login is successful, sets two HttpOnly cookies: access_token (15 min) and refresh_token (7 days).
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        email query string true "User Email" example(user@example.com)
// @Param        request body object true "WebAuthn response from navigator.credentials.get()"
// @Success      200 {object} dtos.LoginSuccessResponse "Login completed, JWT cookies set"
// @Failure      400 {object} dtos.ErrorResponse "Missing email"
// @Failure      401 {object} dtos.ErrorResponse "Authentication failed"
// @Failure      500 {object} dtos.ErrorResponse "Token generation error"
// @Header       200 {string} Set-Cookie "access_token=<JWT>; Path=/; HttpOnly; SameSite=Lax"
// @Header       200 {string} Set-Cookie "refresh_token=<JWT>; Path=/auth; HttpOnly; SameSite=Lax"
// @Router       /auth/login/finish [post]
func (h *AuthHandler) LoginFinish(c *gin.Context) {
	email := c.Query("email")
	if email == "" || !emailRegex.MatchString(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Valid email query parameter is required"})
		return
	}

	user, err := h.authService.LoginFinish(c.Request.Context(), email, c.Request)
	if err != nil {
		// Log the actual error for debugging
		logger.Error("LoginFinish failed", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	// Generate access token (short-lived)
	accessToken, err := jwt.GenerateAccessToken(
		user.ID,
		user.Email,
		h.cfg.JWTSecret,
		h.cfg.RPDisplayName,
		h.cfg.AccessTokenExpireMinutes,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate refresh token (long-lived)
	refreshToken, err := jwt.GenerateRefreshToken(
		user.ID,
		h.cfg.JWTSecret,
		h.cfg.RPDisplayName,
		h.cfg.RefreshTokenExpireDays,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	secure := h.cfg.Env != "development"

	// Set access token cookie (valid for all routes)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"access_token",
		accessToken,
		h.cfg.AccessTokenExpireMinutes*60, // minutes -> seconds
		"/",
		h.cfg.CookieDomain, // Shared domain
		secure,
		true, // HttpOnly
	)

	// Set refresh token cookie (valid only for /auth)
	c.SetCookie(
		"refresh_token",
		refreshToken,
		h.cfg.RefreshTokenExpireDays*24*60*60, // days -> seconds
		"/auth",            // Only for auth endpoints
		h.cfg.CookieDomain, // Shared domain
		secure,
		true, // HttpOnly
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful! 🔐",
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
		},
	})
}

// --- TOKEN REFRESH ---

// RefreshToken godoc
// @Summary      Renew Access Token
// @Description  Uses the refresh token to obtain a new access token. The refresh token is rotated for security.
// @Tags         auth
// @Produce      json
// @Success      200 {object} dtos.MessageResponse "Token renewed"
// @Failure      401 {object} dtos.ErrorResponse "Missing, invalid, or expired refresh token"
// @Header       200 {string} Set-Cookie "access_token=<JWT>; Path=/; HttpOnly; SameSite=Lax"
// @Header       200 {string} Set-Cookie "refresh_token=<JWT>; Path=/auth; HttpOnly; SameSite=Lax"
// @Router       /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Read the refresh token from the cookie
	refreshTokenStr, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token not found"})
		return
	}

	// Validate the refresh token
	claims, err := jwt.ValidateRefreshToken(refreshTokenStr, h.cfg.JWTSecret)
	if err != nil {
		// Clear cookies if the token is invalid
		h.clearAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	// Check Blacklist
	blacklistKey := "blacklist:" + refreshTokenStr
	if _, err := h.redisRepo.Get(c.Request.Context(), blacklistKey); err == nil {
		// Key exists in blacklist
		h.clearAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
		return
	}

	// Retrieve the user from the database to get updated data
	user, err := h.userRepo.FindByID(claims.UserID)
	if err != nil || user == nil {
		h.clearAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Generate new tokens (token rotation)
	accessToken, err := jwt.GenerateAccessToken(
		user.ID,
		user.Email,
		h.cfg.JWTSecret,
		h.cfg.RPDisplayName,
		h.cfg.AccessTokenExpireMinutes,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Also rotate the refresh token (more secure)
	newRefreshToken, err := jwt.GenerateRefreshToken(
		user.ID,
		h.cfg.JWTSecret,
		h.cfg.RPDisplayName,
		h.cfg.RefreshTokenExpireDays,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	secure := h.cfg.Env != "development"

	// Set the new cookies
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"access_token",
		accessToken,
		h.cfg.AccessTokenExpireMinutes*60,
		"/",
		h.cfg.CookieDomain,
		secure,
		true,
	)

	c.SetCookie(
		"refresh_token",
		newRefreshToken,
		h.cfg.RefreshTokenExpireDays*24*60*60,
		"/auth",
		h.cfg.CookieDomain,
		secure,
		true,
	)

	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed successfully"})
}

// --- LOGOUT ---

// Logout godoc
// @Summary      User Logout
// @Description  Clears authentication cookies (access_token and refresh_token).
// @Tags         auth
// @Produce      json
// @Success      200 {object} dtos.MessageResponse "Logout completed"
// @Header       200 {string} Set-Cookie "access_token=; Path=/; Max-Age=0; HttpOnly"
// @Header       200 {string} Set-Cookie "refresh_token=; Path=/auth; Max-Age=0; HttpOnly"
// @Router       /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	// Blacklist the refresh token if present
	refreshTokenStr, err := c.Cookie("refresh_token")
	if err == nil && refreshTokenStr != "" {
		// We decode the token to find expiration, to set the blacklist TTL efficiently
		claims, err := jwt.ValidateRefreshToken(refreshTokenStr, h.cfg.JWTSecret)
		if err == nil {
			// Calculate remaining time
			expirationTime := claims.ExpiresAt.Time
			ttl := time.Until(expirationTime)
			if ttl > 0 {
				// Add to blacklist
				_ = h.redisRepo.Set(c.Request.Context(), "blacklist:"+refreshTokenStr, "revoked", ttl)
			}
		}
	}

	h.clearAuthCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// clearAuthCookies clears both authentication cookies.
func (h *AuthHandler) clearAuthCookies(c *gin.Context) {
	secure := h.cfg.Env != "development"

	// Common options for deletion
	c.SetSameSite(http.SameSiteLaxMode)

	// 1. Clear with configured domain
	c.SetCookie("access_token", "", -1, "/", h.cfg.CookieDomain, secure, true)
	c.SetCookie("refresh_token", "", -1, "/auth", h.cfg.CookieDomain, secure, true)

	// 2. Clear with empty domain (handles HostOnly cookies or domain mismatches)
	if h.cfg.CookieDomain != "" {
		c.SetCookie("access_token", "", -1, "/", "", secure, true)
		c.SetCookie("refresh_token", "", -1, "/auth", "", secure, true)
	}

	// 3. Clear with dot-prefixed domain if not already present (some browsers/configs behave differently)
	if h.cfg.CookieDomain != "" && !strings.HasPrefix(h.cfg.CookieDomain, ".") {
		dotDomain := "." + h.cfg.CookieDomain
		c.SetCookie("access_token", "", -1, "/", dotDomain, secure, true)
		c.SetCookie("refresh_token", "", -1, "/auth", dotDomain, secure, true)
	}
}

// --- PROTECTED ROUTES ---

// Me godoc
// @Description  Restituisce le informazioni dell'utente autenticato. Richiede un cookie access_token valido.
// @Tags         user
// @Security     CookieAuth
// @Produce      json
// @Success      200 {object} dtos.UserResponse "Informazioni utente"
// @Failure      401 {object} dtos.ErrorResponse "Non autenticato o token scaduto"
// @Router       /api/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	claims := api.GetUserClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":    claims.UserID,
			"email": claims.Email,
		},
	})
}
