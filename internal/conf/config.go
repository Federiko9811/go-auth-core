package conf

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds the application configuration.
type Config struct {
	AppPort string
	Env     string

	// Database Config
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	// Redis Config
	RedisAddr     string
	RedisPassword string

	// Email Config
	MailHost     string
	MailPort     int
	MailUser     string
	MailPassword string
	MailFrom     string

	// WebAuthn Config
	RPDisplayName string
	RPID          string
	RPOrigins     []string

	// Token Config
	JWTSecret                string
	AccessTokenExpireMinutes int
	RefreshTokenExpireDays   int
	CookieDomain             string

	// Rate Limiting
	RateLimitRequests      int
	RateLimitWindowSeconds int

	// CORS
	CORSOrigins []string

	// Logging
	LogLevel  string
	LogFormat string
}

// LoadConfig reads the .env file and populates the Config struct.
func LoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️  Warning: .env file not found, using system environment variables")
	}

	cfg := &Config{
		AppPort: getEnv("APP_PORT", "8080"),
		Env:     getEnv("ENV", "development"),

		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", "go_auth_db"),
		DBSSLMode:  getEnv("DB_SSLMODE", "disable"),

		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),

		MailHost:     getEnv("MAIL_SERVER", "smtp.gmail.com"),
		MailPort:     getEnvInt("MAIL_PORT", 587),
		MailUser:     getEnv("MAIL_USERNAME", ""),
		MailPassword: getEnv("MAIL_PASSWORD", ""),
		MailFrom:     getEnv("MAIL_FROM", "noreply@example.com"),

		RPDisplayName: getEnv("RP_DISPLAY_NAME", "Go Auth Core"),
		RPID:          getEnv("RP_ID", "localhost"),
		RPOrigins:     splitAndTrim(getEnv("RP_ORIGINS", "http://localhost:3000")),

		JWTSecret:                getEnv("JWT_SECRET", "change-me-in-production"),
		AccessTokenExpireMinutes: getEnvInt("ACCESS_TOKEN_EXPIRE_MINUTES", 15),
		RefreshTokenExpireDays:   getEnvInt("REFRESH_TOKEN_EXPIRE_DAYS", 7),
		CookieDomain:             getEnv("COOKIE_DOMAIN", "localhost"),

		RateLimitRequests:      getEnvInt("RATE_LIMIT_REQUESTS", 100),
		RateLimitWindowSeconds: getEnvInt("RATE_LIMIT_WINDOW_SECONDS", 60),

		CORSOrigins: splitAndTrim(getEnv("CORS_ORIGINS", "http://localhost:3000")),

		LogLevel:  getEnv("LOG_LEVEL", "debug"),
		LogFormat: getEnv("LOG_FORMAT", "console"),
	}

	// Fail-Fast validation for production
	if cfg.Env == "production" {
		if cfg.JWTSecret == "change-me-in-production" || cfg.JWTSecret == "" {
			log.Fatal("CRITICAL: JWT_SECRET is not set or is using default value in production!")
		}
		if cfg.DBPassword == "" {
			log.Fatal("CRITICAL: DB_PASSWORD is required in production!")
		}
		if cfg.RedisPassword == "" {
			log.Fatal("CRITICAL: REDIS_PASSWORD is required in production!")
		}
	}

	return cfg
}

// getEnv reads an environment variable or uses a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// getEnvInt reads an environment variable as an integer.
func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return fallback
}

// splitAndTrim splits a string by commas and removes whitespace.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
