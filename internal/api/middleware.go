package api

import (
	"go-auth-core/pkg/jwt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ContextKeyUser is the key used to store claims in Gin context.
// We use a custom string to avoid collisions.
const ContextKeyUser = "user_claims"

// JWTMiddleware protects routes requiring authentication.
//
// Logic:
// 1. Extracts JWT token from "access_token" HttpOnly cookie
// 2. Validates token with secret key
// 3. If valid, saves claims in context for later use
// 4. If invalid or missing, returns 401 Unauthorized
//
// Usage example:
//
//	protected := r.Group("/api")
//	protected.Use(api.JWTMiddleware(cfg.JWTSecret))
//	{
//	    protected.GET("/me", handler.Me)
//	}
func JWTMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Try extracting token from HttpOnly cookie
		token, err := c.Cookie("access_token")

		// If missing in cookie, try Authorization header (useful for testing)
		if err != nil || token == "" {
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		// 2. If token not found anywhere, error
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			return
		}

		// 3. Validate token
		claims, err := jwt.ValidateAccessToken(token, jwtSecret)
		if err != nil {
			// Distinguish between expired and invalid/malformed token
			// Allows frontend to handle cases differently
			if err == jwt.ErrExpiredToken {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "Token expired",
					"code":  "TOKEN_EXPIRED",
				})
				return
			}

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
				"code":  "INVALID_TOKEN",
			})
			return
		}

		// 4. Save claims to context
		// In protected routes, retrieve claims like this:
		//   claims := c.MustGet(api.ContextKeyUser).(*jwt.Claims)
		c.Set(ContextKeyUser, claims)

		// 5. Proceed to next handler
		c.Next()
	}
}

// GetUserClaims is a helper to safely retrieve claims from context.
// Returns nil if claims are not present (unprotected route).
func GetUserClaims(c *gin.Context) *jwt.Claims {
	claims, exists := c.Get(ContextKeyUser)
	if !exists {
		return nil
	}
	return claims.(*jwt.Claims)
}
