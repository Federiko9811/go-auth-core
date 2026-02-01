package database

import (
	"fmt"
	"log"
	"time"

	// 1. IMPORTANT: Add this import to see User and Passkey Structs
	"go-auth-core/internal/conf"
	"go-auth-core/internal/domain"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// NewPostgresDB initializes the connection to PostgreSQL.
func NewPostgresDB(cfg *conf.Config) (*gorm.DB, error) {
	// 1. Build connection string
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		cfg.DBHost,
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBName,
		cfg.DBPort,
		cfg.DBSSLMode,
	)

	// 2. Open connection with GORM
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// --- [NEW] AUTOMIGRATE BLOCK ---
	// This creates tables in DB based on structs in /internal/domain
	log.Println("🔄 Running AutoMigrate...")
	err = db.AutoMigrate(&domain.User{}, &domain.Passkey{})
	if err != nil {
		// If migration fails, app must not start
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}
	log.Println("✅ AutoMigrate completed")
	// ----------------------------------

	// 3. Advanced Connection Pool configuration
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	log.Println("✅ Database connection established successfully")
	return db, nil
}
