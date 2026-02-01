package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the payload of the access token.
// It contains complete user information.
type Claims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// RefreshClaims represents the payload of the refresh token.
// It contains only the user ID to minimize exposure.
type RefreshClaims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

// GenerateAccessToken creates a short-lived access token.
//
// Parameters:
//   - userID: Database user ID
//   - email: User's email
//   - secret: Secret key for signing
//   - issuer: Token issuer (App Name)
//   - expireMinutes: Validity duration in minutes (typically 15)
func GenerateAccessToken(userID uint, email string, secret string, issuer string, expireMinutes int) (string, error) {
	expiration := time.Now().Add(time.Duration(expireMinutes) * time.Minute)

	claims := &Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    issuer,
			Subject:   "access",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// GenerateRefreshToken creates a long-lived refresh token.
//
// Parameters:
//   - userID: Database user ID
//   - secret: Secret key for signing
//   - issuer: Token issuer (App Name)
//   - expireDays: Validity duration in days (typically 7)
func GenerateRefreshToken(userID uint, secret string, issuer string, expireDays int) (string, error) {
	expiration := time.Now().Add(time.Duration(expireDays) * 24 * time.Hour)

	claims := &RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    issuer,
			Subject:   "refresh",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateAccessToken verifies an access token and returns its claims.
func ValidateAccessToken(tokenString string, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Verify subject
	if claims.Subject != "access" {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ValidateRefreshToken verifies a refresh token and returns its claims.
func ValidateRefreshToken(tokenString string, secret string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*RefreshClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Verify subject
	if claims.Subject != "refresh" {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GenerateToken is kept for backward compatibility.
// Deprecated: use GenerateAccessToken
func GenerateToken(userID uint, email string, secret string, expiryHours int) (string, error) {
	// Use a default issuer for legacy calls
	return GenerateAccessToken(userID, email, secret, "go-auth-core-legacy", expiryHours*60)
}

// ValidateToken is kept for backward compatibility.
// Deprecated: use ValidateAccessToken
func ValidateToken(tokenString string, secret string) (*Claims, error) {
	// For backward compatibility, accepts tokens without subject check
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
