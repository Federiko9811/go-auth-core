package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"go-auth-core/internal/conf"
	"go-auth-core/internal/domain"
	"go-auth-core/internal/repository"
	"go-auth-core/pkg/email"
	"go-auth-core/pkg/logger"
)

// AuthService manages authentication logic regarding WebAuthn and Passkeys.
type AuthService struct {
	userRepo    *repository.UserRepository
	passkeyRepo *repository.PasskeyRepository
	redisRepo   *repository.RedisRepository
	webAuthn    *webauthn.WebAuthn
	emailSender email.Sender
	cfg         *conf.Config
}

// NewAuthService creates a new instance of AuthService.
// It initializes the WebAuthn library with the provided configuration.
func NewAuthService(
	userRepo *repository.UserRepository,
	passkeyRepo *repository.PasskeyRepository,
	redisRepo *repository.RedisRepository,
	emailSender email.Sender,
	cfg *conf.Config,
) (*AuthService, error) {

	wconfig := &webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID, // Domain (without protocol/port)
		RPOrigins:     cfg.RPOrigins,
	}

	webAuthnInstance, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to init webauthn: %w", err)
	}

	return &AuthService{
		userRepo:    userRepo,
		passkeyRepo: passkeyRepo,
		redisRepo:   redisRepo,
		webAuthn:    webAuthnInstance,
		emailSender: emailSender,
		cfg:         cfg,
	}, nil
}

// --- REGISTRATION LOGIC ---

// RegisterBegin starts the WebAuthn registration flow.
// It creates a new user if one doesn't exist, and returns the creation options
// (including the challenge) to be sent to the frontend.
// If the user ALREADY exists, it triggers an OTP flow to verify identity before allowing additional passkey registration.
func (s *AuthService) RegisterBegin(ctx context.Context, email string) (*protocol.CredentialCreation, bool, error) {
	// 1. Check if user exists
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, false, fmt.Errorf("db error: %w", err)
	}

	// 2. If user exists, Trigger OTP Flow (Prevent Account Takeover)
	if user != nil {
		otp := s.generateOTP()

		// Store OTP in Redis (5 min TTL)
		otpKey := fmt.Sprintf("otp:reg:%s", email)
		if err := s.redisRepo.Set(ctx, otpKey, otp, 5*time.Minute); err != nil {
			return nil, false, fmt.Errorf("failed to store otp: %w", err)
		}

		// Send Email (Now Synchronous)
		if err := s.emailSender.SendOTP(email, otp); err != nil {
			logger.Error("failed to send otp email", err)
			return nil, false, fmt.Errorf("failed to send otp email")
		}

		return nil, true, nil // Returns true indicating OTP is required
	}

	// 3. If user doesn't exist, create a temporary user object (NOT saved to DB yet)
	// We defer creation to RegisterFinish to avoid orphan users if registration is abandoned.
	user = &domain.User{
		Email:          email,
		WebAuthnHandle: email, // In a real app complexity, might use UUID
	}

	options, err := s.generateRegistrationOptions(ctx, user)
	return options, false, err
}

// VerifyOTP checks the provided OTP and if valid, returns the WebAuthn registration options.
func (s *AuthService) VerifyOTP(ctx context.Context, email, otp string) (*protocol.CredentialCreation, error) {
	// 1. Rate Limiting Check
	attemptsKey := fmt.Sprintf("otp_attempts:%s", email)
	attempts, err := s.redisRepo.Incr(ctx, attemptsKey) // Increments and returns new value
	if err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	// Set expiration for the counter (window of 10 minutes)
	if attempts == 1 {
		_ = s.redisRepo.Expire(ctx, attemptsKey, 10*time.Minute)
	}

	if attempts > 5 {
		// Invalidate the OTP to force a new flow/wait
		otpKey := fmt.Sprintf("otp:reg:%s", email)
		_ = s.redisRepo.Delete(ctx, otpKey)
		return nil, fmt.Errorf("too many attempts, request a new OTP")
	}

	// 2. Verify OTP
	otpKey := fmt.Sprintf("otp:reg:%s", email)
	storedOTP, err := s.redisRepo.Get(ctx, otpKey)
	if err != nil {
		return nil, fmt.Errorf("otp expired or invalid")
	}

	if storedOTP != otp {
		return nil, fmt.Errorf("invalid otp")
	}

	// Consume OTP
	_ = s.redisRepo.Delete(ctx, otpKey)
	// Also clear attempts on success
	_ = s.redisRepo.Delete(ctx, attemptsKey)

	user, err := s.userRepo.FindByEmail(email)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found after otp verify")
	}

	return s.generateRegistrationOptions(ctx, user)
}

// generateRegistrationOptions helps reusing the options generation logic
func (s *AuthService) generateRegistrationOptions(ctx context.Context, user *domain.User) (*protocol.CredentialCreation, error) {
	// Prepare exclusions: we don't want to register the same authenticator twice.
	authCredentials := user.WebAuthnCredentials()
	excludeList := make([]protocol.CredentialDescriptor, len(authCredentials))
	for i, cred := range authCredentials {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
	}

	// Generate WebAuthn options
	options, sessionData, err := s.webAuthn.BeginRegistration(
		user,
		webauthn.WithExclusions(excludeList),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn begin error: %w", err)
	}

	// Serialize and save session data to Redis (short TTL)
	sessionKey := fmt.Sprintf("webauthn:reg:%s", user.WebAuthnHandle)
	if err := s.saveSession(ctx, sessionKey, sessionData); err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	return options, nil
}

// generateOTP creates a random 6-digit string using crypto/rand
func (s *AuthService) generateOTP() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		// Fallback to time-based if crypto fails (highly unlikely)
		// but safer to return something than crash or return empty
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// RegisterFinish completes the registration flow.
// It verifies the authenticator's response and saves the new credential to the DB.
func (s *AuthService) RegisterFinish(ctx context.Context, email string, req *http.Request) error {
	// 1. Check if user exists
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return fmt.Errorf("db error: %w", err)
	}

	var isNewUser bool
	if user == nil {
		isNewUser = true
		// Reconstruct user object for verification and eventual creation
		user = &domain.User{
			Email:          email,
			WebAuthnHandle: email,
		}
	}

	// Retrieve session data
	sessionKey := fmt.Sprintf("webauthn:reg:%s", user.WebAuthnHandle)
	sessionData, err := s.loadSession(ctx, sessionKey)
	if err != nil {
		return fmt.Errorf("session expired or invalid: %w", err)
	}

	// Verify the response
	credential, err := s.webAuthn.FinishRegistration(user, *sessionData, req)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Prepare passkey record
	newPasskey := &domain.Passkey{
		// UserID will be set automatically by GORM if we are creating the user,
		// otherwise we need to set it manually if it's an existing user.
		Name:           "Generic Passkey", // Default name, user can rename later
		CredentialID:   credential.ID,
		PublicKey:      credential.PublicKey,
		SignCount:      credential.Authenticator.SignCount,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	}

	if isNewUser {
		// Create User AND Passkey transactionally
		user.Passkeys = []domain.Passkey{*newPasskey}
		if err := s.userRepo.Create(user); err != nil {
			return fmt.Errorf("failed to create user and passkey: %w", err)
		}
	} else {
		// Append passkey to existing user
		newPasskey.UserID = user.ID
		if err := s.passkeyRepo.Create(newPasskey); err != nil {
			return fmt.Errorf("failed to save passkey: %w", err)
		}
	}

	return nil
}

// --- LOGIN LOGIC ---

// LoginBegin starts the authentication flow.
// It generates the assertion options (challenge) for the user to sign.
func (s *AuthService) LoginBegin(ctx context.Context, email string) (*protocol.CredentialAssertion, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("db error: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if len(user.Passkeys) == 0 {
		return nil, fmt.Errorf("no passkeys registered for this user")
	}

	options, sessionData, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("webauthn begin login error: %w", err)
	}

	sessionKey := fmt.Sprintf("webauthn:login:%s", user.WebAuthnHandle)
	if err := s.saveSession(ctx, sessionKey, sessionData); err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	return options, nil
}

// LoginFinish completes the authentication verification process.
func (s *AuthService) LoginFinish(ctx context.Context, email string, req *http.Request) (*domain.User, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	sessionKey := fmt.Sprintf("webauthn:login:%s", user.WebAuthnHandle)
	sessionData, err := s.loadSession(ctx, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("session expired or invalid: %w", err)
	}

	credential, err := s.webAuthn.FinishLogin(user, *sessionData, req)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Handles counter logic for cloning protection
	if credential.Authenticator.CloneWarning {
		return nil, fmt.Errorf("clone warning: authenticator might be cloned")
	}

	// Updates sign count
	if err := s.passkeyRepo.UpdateSignCount(credential.ID, credential.Authenticator.SignCount); err != nil {
		return nil, fmt.Errorf("failed to update sign count: %w", err)
	}

	return user, nil
}

// --- REDIS HELPERS ---

// saveSession stores WebAuthn session data in Redis with a short expiration TTL.
func (s *AuthService) saveSession(ctx context.Context, key string, data *webauthn.SessionData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	// Expires in 5 minutes
	return s.redisRepo.Set(ctx, key, string(jsonData), 5*time.Minute)
}

// loadSession retrieves and deserializes session data from Redis.
// It deletes the key after reading to prevent reuse (One-Time Use).
func (s *AuthService) loadSession(ctx context.Context, key string) (*webauthn.SessionData, error) {
	val, err := s.redisRepo.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var data webauthn.SessionData
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		return nil, err
	}

	// Delete after use
	_ = s.redisRepo.Delete(ctx, key)

	return &data, nil
}
