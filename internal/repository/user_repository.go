package repository

import (
	"errors"
	"go-auth-core/internal/domain"

	"gorm.io/gorm"
)

// UserRepository manages access to user data.
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new UserRepository instance.
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create saves a new user to the DB.
func (r *UserRepository) Create(user *domain.User) error {
	result := r.db.Create(user)
	return result.Error
}

// FindByEmail searches for a user by email.
// Returns (nil, nil) if the user does not exist, instead of returning an error.
// NOTE: Uses Preload to also load associated passkeys (required for WebAuthn).
func (r *UserRepository) FindByEmail(email string) (*domain.User, error) {
	var user domain.User

	// Searches for the first record matching the email.
	// Preload also loads the "Passkeys" relation in a single query.
	result := r.db.Preload("Passkeys").Where("email = ?", email).First(&user)

	if result.Error != nil {
		// If the error is "Record not found", we return nil (no user), not a system error.
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		// Otherwise, it's a real error (e.g., DB down).
		return nil, result.Error
	}

	return &user, nil
}

// FindByWebAuthnHandle searches for a user by their WebAuthn handle.
// This method is necessary during login to identify the user
// from the authenticator's response (which only contains the handle, not the email).
func (r *UserRepository) FindByWebAuthnHandle(handle string) (*domain.User, error) {
	var user domain.User

	result := r.db.Preload("Passkeys").Where("web_authn_handle = ?", handle).First(&user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}

	return &user, nil
}

// FindByID searches for a user by primary ID.
func (r *UserRepository) FindByID(id uint) (*domain.User, error) {
	var user domain.User
	result := r.db.First(&user, id)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}

	return &user, nil
}

// Update updates the user's data.
func (r *UserRepository) Update(user *domain.User) error {
	return r.db.Save(user).Error
}
