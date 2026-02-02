package email

import (
	"crypto/tls"
	"fmt"

	"go-auth-core/internal/conf"

	"gopkg.in/gomail.v2"
)

// Sender defines the interface for sending emails.
type Sender interface {
	SendOTP(to string, otp string) error
}

// GomailSender implements Sender using gomail.v2.
type GomailSender struct {
	dialer *gomail.Dialer
	from   string
}

// NewGomailSender creates a new instance of GomailSender.
func NewGomailSender(cfg *conf.Config) *GomailSender {
	// If no mail host is configured (e.g. testing), we can handle it gracefully or panic depending on philosophy.
	// Here we proceed, but SendOTP will fail if connection fails.
	d := gomail.NewDialer(cfg.MailHost, cfg.MailPort, cfg.MailUser, cfg.MailPassword)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: cfg.Env == "development"} // Useful for local mailhog/mailpit

	return &GomailSender{
		dialer: d,
		from:   cfg.MailFrom,
	}
}

// SendOTP sends an email with the verification code.
func (s *GomailSender) SendOTP(to string, otp string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Your Verification Code")

	htmlBody := fmt.Sprintf(`
		<h1>Verification Code</h1>
		<p>Your verification code is: <strong>%s</strong></p>
		<p>This code will expire in 5 minutes.</p>
		<p>If you did not request this, please ignore this email.</p>
	`, otp)

	m.SetBody("text/html", htmlBody)

	if err := s.dialer.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
