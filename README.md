# Go Auth Core

A production-ready **Go (Gin)** template with **passwordless authentication** using WebAuthn Passkeys.

## Features

- 🔑 **Passkeys (WebAuthn)**: Modern passwordless authentication using FIDO2 (library: `go-webauthn`)
- 🔐 **Secure Sessions**: JWT tokens stored in HttpOnly cookies (XSS protection)
- 🔄 **Token Refresh**: Automatic access token renewal via refresh tokens (Rotated)
- 🗄️ **Database**: PostgreSQL with GORM (ORM)
- 🐳 **Docker Ready**: Separate compose files for dev and production
- 📝 **Structured Logging**: JSON format for production using `zerolog`
- 🛡️ **Rate Limiting**: IP-based protection against DDoS attacks (Redis backed)
- 📧 **Email OTP**: Secure verification when adding passkeys to existing accounts (prevents Account Takeover)
- 📚 **Swagger Docs**: Auto-generated API documentation
- ⚡ **Redis Cache**: Session and OTP storage with automatic expiration

---

## 🔑 How Passkeys Work

Passkeys are a modern, phishing-resistant authentication method that replaces passwords. They use public-key cryptography and biometric verification (Face ID, Touch ID, Windows Hello, or a security key).

### Registration Flow

**New User:** Direct passkey registration

```
Browser                    Backend (Go)               Redis
   │                          │                          │
   │ POST /register/begin     │                          │
   │─────────────────────────>│                          │
   │                          │ Store challenge          │
   │                          │─────────────────────────>│
   │   {options: {...}}       │                          │
   │<─────────────────────────│                          │
   │                          │                          │
   │ User creates passkey     │                          │
   │ (biometric prompt)       │                          │
   │                          │                          │
   │ POST /register/finish    │                          │
   │─────────────────────────>│                          │
   │                          │                          │
   │   JWT cookies set        │                          │
   │<─────────────────────────│                          │
```

**Existing User:** OTP verification required to prevent Account Takeover (IDOR protection).

```
Browser                    Backend (Go)               Redis/Email
   │                          │                          │
   │ POST /register/begin     │                          │
   │─────────────────────────>│                          │
   │                          │ Generate OTP             │
   │                          │─────────────────────────>│ Redis + Email
   │   {requires_otp: true}   │                          │
   │<─────────────────────────│                          │
   │                          │                          │
   │ POST /register/verify-otp│                          │
   │─────────────────────────>│ Verify OTP               │
   │                          │<─────────────────────────│
   │   {options: {...}}       │                          │
   │<─────────────────────────│                          │
   │                          │                          │
   │ Continue with passkey... │                          │
```

---

## 🚀 Quick Start

### Prerequisites

- Go 1.22+
- Docker & Docker Compose
- Make (optional, for convenience)

### Local Development

```bash
# 1. Clone and configure
git clone https://github.com/Federiko9811/go-auth-core.git
cd go-auth-core
cp .env.example .env

# 2. Generate a secure secret key (for JWT)
openssl rand -hex 32
# Paste the output in .env at JWT_SECRET=

# 3. Setup and run
make up       # Start PostgreSQL + Redis
make run      # Run Go app locally (connects to local DB/Redis)

# App will run at http://localhost:8080
```

### Full Docker

```bash
# Run everything (App + DB + Redis) in containers
docker compose up -d
```

---

## 📡 API Endpoints

### Auth (`/auth`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register/begin` | Start passkey registration (sends OTP if user exists) |
| POST | `/register/verify-otp` | Verify OTP for existing user |
| POST | `/register/finish` | Complete registration & login |
| POST | `/login/begin` | Start authentication |
| POST | `/login/finish` | Complete login (Sets HttpOnly Cookies) |
| POST | `/refresh` | Refresh access token |
| POST | `/logout` | Clear cookies |

### Protected (`/api`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/me` | Current user profile (🔒) |
| GET | `/passkeys` | List user's passkeys (🔒) |
| PATCH | `/passkeys/:id` | Rename a passkey (🔒) |
| DELETE | `/passkeys/:id` | Delete a passkey (🔒) |

🔒 = Requires valid `access_token` cookie

### Documentation

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/swagger/index.html` | Interactive API documentation |

---

## 🛡️ Rate Limiting

The API includes IP-based rate limiting to protect against abuse:

- **Default**: 100 requests per 60 seconds per IP
- **Storage**: Redis
- **When exceeded**: Returns `429 Too Many Requests`

Configure in `.env`:
```bash
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60
```

---

## 📧 Email Configuration (OTP)

Email is required for OTP verification when users add passkeys to existing accounts.

**Gmail Example:**
1. Enable 2-Step Verification.
2. Create an App Password.
3. Add to `.env`:

```bash
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=abcdefghijklmnop
MAIL_FROM=noreply@yourdomain.com
```

---

## 🚀 Production Deployment

### Required Configuration

```bash
# Environment
ENV=production
APP_PORT=8080

# Security
JWT_SECRET=your-secure-random-key
COOKIE_SECURE=true  # Mandatory for HTTPS

# WebAuthn (cannot change after users register!)
RP_ID=yourdomain.com
RP_DISPLAY_NAME=Go Auth Core
RP_ORIGINS=https://yourdomain.com

# Database (use Docker service name in compose)
DB_HOST=db
REDIS_ADDR=redis:6379
```

### ⚠️ Important Notes

1. **RP_ID cannot change** after users create passkeys (domain bound).
2. **HTTPS is required** for passkeys in production browsers.
3. **COOKIE_SECURE=true** ensures cookies are not sent over HTTP.

---

## 🔧 Makefile Commands

| Command | Description |
|---------|-------------|
| `make up` | Start Infra (Postgres + Redis) |
| `make run` | Run App locally |
| `make build` | Compile binary |
| `make dev` | Start everything |
| `make down` | Stop containers |
| `make docs` | Generate Swagger docs (`swag init`) |
| `make test` | Run tests |

---

## 📁 Project Structure

```
go-auth-core/
├── cmd/
│   └── api/             # Entrypoint (main.go)
├── internal/
│   ├── api/             # API Handlers (Gin) & Middleware
│   ├── conf/            # Configuration loader
│   ├── domain/          # Data structs (User, Passkey)
│   ├── repository/      # DB access (Gorm, Redis)
│   └── service/         # Business Logic (WebAuthn, Auth)
├── pkg/
│   ├── database/        # Postgres connection
│   ├── email/           # Email sender (SMTP)
│   ├── jwt/             # JWT utilities
│   ├── logger/          # Structured logging
│   └── redis/           # Redis connection
├── docker-compose.yml   # Docker services
├── Dockerfile           # App container definition
└── Makefile             # Helpers
```

---

## 🧪 Frontend Integration

Example using `@simplewebauthn/browser`:

```javascript
import { startRegistration } from '@simplewebauthn/browser';

const email = 'user@example.com';

// 1. Start registration
const beginRes = await axios.post('/auth/register/begin', { email });

// 2. Check for OTP (Existing User)
if (beginRes.data.requires_otp) {
  // Ask user for OTP...
  const otpRes = await axios.post('/auth/register/verify-otp', {
    email,
    otp: userEnteredCode
  });
  // Use options from OTP response
  beginRes.data.options = otpRes.data.options;
}

// 3. Create Passkey
// Note: Go backend sends struct, browser needs JSON. 
const credential = await startRegistration({ 
  optionsJSON: beginRes.data.options 
});

// 4. Finish
// Go backend expects email as query param for finish!
await axios.post(
  `/auth/register/finish?email=${encodeURIComponent(email)}`, 
  credential
);
```

---

## License

MIT
