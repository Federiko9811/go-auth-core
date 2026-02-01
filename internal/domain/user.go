package domain

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
)

// User represents a registered user in the system.
type User struct {
	gorm.Model
	Email string `Gorm:"uniqueIndex;not null" json:"email"`

	// WebAuthnHandle is the unique, stable User ID required by the WebAuthn specification.
	// It differs from the database ID to provide decoupling and security.
	// This value SHOULD NOT be displayed to the user.
	WebAuthnHandle string `Gorm:"uniqueIndex;not null" json:"-"`

	Passkeys []Passkey `Gorm:"constraint:OnDelete:CASCADE;" json:"passkeys,omitempty"`
}

// TableName overrides the default table name.
func (User) TableName() string {
	return "users"
}

// --- WebAuthn User Interface Implementation ---

// WebAuthnID returns the unique user ID (handle) as a byte slice.
func (u *User) WebAuthnID() []byte {
	return []byte(u.WebAuthnHandle)
}

// WebAuthnName returns the user's human-readable name (e.g., email or username).
// This is used by the authenticator to identify the user account.
func (u *User) WebAuthnName() string {
	return u.Email
}

// WebAuthnDisplayName returns the name displayed to the user by the authenticator.
func (u *User) WebAuthnDisplayName() string {
	return u.Email
}

// WebAuthnIcon returns the URL of the user's icon (optional).
func (u *User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns the list of WebAuthn credentials (passkeys) registered to this user.
// It maps the domain Passkey entities to the webauthn.Credential struct required by the library.
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	var credentials []webauthn.Credential

	for _, p := range u.Passkeys {
		credentials = append(credentials, webauthn.Credential{
			ID:              p.CredentialID,
			PublicKey:       p.PublicKey,
			AttestationType: "none",
			Transport:       []protocol.AuthenticatorTransport{},
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: p.BackupEligible,
				BackupState:    p.BackupState,
			},
			Authenticator: webauthn.Authenticator{SignCount: p.SignCount},
		})
	}

	return credentials
}
