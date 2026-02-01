package repository

import (
	"go-auth-core/internal/domain"

	"gorm.io/gorm"
)

type PasskeyRepository struct {
	db *gorm.DB
}

func NewPasskeyRepository(db *gorm.DB) *PasskeyRepository {
	return &PasskeyRepository{db: db}
}

// Create saves a new passkey.
func (r *PasskeyRepository) Create(passkey *domain.Passkey) error {
	return r.db.Create(passkey).Error
}

// FindByUserID retrieves all passkeys for a user.
// (Useful for showing the user a list of their registered devices)
func (r *PasskeyRepository) FindByUserID(userID uint) ([]domain.Passkey, error) {
	var passkeys []domain.Passkey
	result := r.db.Where("user_id = ?", userID).Find(&passkeys)
	return passkeys, result.Error
}

// FindByCredentialID searches for a specific passkey using its binary ID.
// This is used during LOGIN to verify who is trying to log in.
func (r *PasskeyRepository) FindByCredentialID(credentialID []byte) (*domain.Passkey, error) {
	var passkey domain.Passkey

	// GORM automatically handles binary comparison
	result := r.db.Where("credential_id = ?", credentialID).First(&passkey)

	if result.Error != nil {
		return nil, result.Error
	}
	return &passkey, nil
}

// UpdateSignCount updates the anti-replay counter.
// Each time a passkey is used, the counter increases. If the DB has a higher counter
// than what the user sends, it means someone has cloned the key.
func (r *PasskeyRepository) UpdateSignCount(credentialID []byte, newCount uint32) error {
	return r.db.Model(&domain.Passkey{}).Where("credential_id = ?", credentialID).Update("sign_count", newCount).Error
}

// FindByID finds a specific passkey by its primary ID.
func (r *PasskeyRepository) FindByID(id uint) (*domain.Passkey, error) {
	var passkey domain.Passkey
	result := r.db.First(&passkey, id)

	if result.Error != nil {
		return nil, result.Error
	}
	return &passkey, nil
}

// Rename updates the name of a passkey.
func (r *PasskeyRepository) Rename(id uint, name string) error {
	return r.db.Model(&domain.Passkey{}).Where("id = ?", id).Update("name", name).Error
}

// Delete deletes (soft delete) a passkey.
func (r *PasskeyRepository) Delete(id uint) error {
	return r.db.Delete(&domain.Passkey{}, id).Error
}

// CountByUserID counts the active passkeys for a user.
func (r *PasskeyRepository) CountByUserID(userID uint) (int64, error) {
	var count int64
	result := r.db.Model(&domain.Passkey{}).Where("user_id = ?", userID).Count(&count)
	return count, result.Error
}
