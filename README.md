# SecurityPatterns-Auth-Thesis

A highly reusable, decoupled .NET 9 library implementing the **Verifiable Token-based Authentication** security pattern with comprehensive test coverage, diagnostic demonstration, and an ASP.NET Core Web API — built for a university Bachelor's thesis.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Security Properties](#security-properties)
- [Technologies](#technologies)
- [Getting Started](#getting-started)
- [API Endpoints](#api-endpoints)
- [Test Coverage](#test-coverage)
- [Diagnostic Scenarios](#diagnostic-scenarios)

---

## Overview

This project demonstrates a production-quality implementation of JWT-based authentication that mitigates well-known vulnerabilities (CWE/CVE). The codebase follows **Clean Architecture** principles with strict layer separation, SOLID design, and academic-quality XML documentation.

### Key Design Decisions

- **Symmetric HMAC-SHA256** signing for token generation
- **Zero clock skew** — expired tokens are rejected immediately with no grace period
- **Algorithm whitelisting** — only HS256 is accepted; the `none` algorithm is rejected
- **Deterministic KeyId** — enables key resolution in IdentityModel 8.x
- **Sealed classes** — prevents inheritance-based tampering
- **Out-parameter pattern** — `ValidateToken` avoids allocations for validity-only checks

---

## Architecture

```
Clean Architecture (Dependency Rule → arrows point inward)

┌─────────────────────────────────────────────────────────────────┐
│  Presentation Layer                                             │
│  ┌─────────────────────┐   ┌─────────────────────────────────┐ │
│  │ SecurityPatterns.Api│──▶│ SecurityPatterns.Application    │ │
│  │ (ASP.NET Core Web)  │   │ (Use cases, DTOs, Interfaces)   │ │
│  └─────────┬───────────┘   └─────────────┬───────────────────┘ │
│            │                             │                     │
│            ▼                             ▼                     │
│  ┌─────────────────────┐   ┌─────────────────────────────────┐ │
│  │ SecurityPatterns.   │◀──│ SecurityPatterns.Core           │ │
│  │ VerifiableToken     │   │ (Abstractions: ITokenIssuer,    │ │
│  │ (JwtTokenIssuer,    │   │  ITokenVerifier, TokenResult)   │ │
│  │  JwtTokenVerifier)  │   └─────────────────────────────────┘ │
│  └─────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
              ┌─────────────────────────────────┐
              │ SecurityPatterns.Diagnostics    │
              │ (Console app for demos)         │
              └─────────────────────────────────┘
```

| Layer | Project | Responsibility |
|-------|---------|----------------|
| **Core** | `SecurityPatterns.Core` | Domain abstractions (`ITokenIssuer`, `ITokenVerifier`, `TokenResult`) — zero dependencies |
| **Infrastructure** | `SecurityPatterns.VerifiableToken` | JWT implementations with HMAC-SHA256 signing and verification |
| **Application** | `SecurityPatterns.Application` | Use case orchestration (`IAuthService`), DTOs, demo user store |
| **Presentation** | `SecurityPatterns.Api` | ASP.NET Core Web API with Swagger, JWT Bearer middleware |
| **Diagnostics** | `SecurityPatterns.Diagnostics` | Interactive console demonstrating attack scenarios |
| **Tests** | `SecurityPatterns.Tests` | 24 unit tests (xUnit + FluentAssertions) |

---

## Project Structure

```
SecurityPatterns.Solution/
├── src/
│   ├── SecurityPatterns.Core/
│   │   └── Abstractions/
│   │       ├── ITokenIssuer.cs          # Token generation contract
│   │       ├── ITokenVerifier.cs        # Token validation contract
│   │       └── TokenResult.cs           # Immutable token record
│   ├── SecurityPatterns.VerifiableToken/
│   │   └── Implementations/
│   │       ├── JwtTokenIssuer.cs        # Signs JWTs with HMAC-SHA256
│   │       └── JwtTokenVerifier.cs      # Validates JWT signatures & claims
│   ├── SecurityPatterns.Application/
│   │   ├── Interfaces/
│   │   │   └── IAuthService.cs          # Authentication use case
│   │   ├── Models/
│   │   │   ├── LoginRequest.cs          # DTO: username + password
│   │   │   ├── TokenResponse.cs         # DTO: token + expiry
│   │   │   ├── ProfileResponse.cs       # DTO: username + claims
│   │   │   └── DemoUsers.cs            # Hardcoded demo credentials
│   │   └── Services/
│   │       └── AuthService.cs           # Orchestrates authentication
│   ├── SecurityPatterns.Api/
│   │   ├── Controllers/
│   │   │   └── AuthController.cs        # POST /token, GET /profile
│   │   ├── Program.cs                   # Composition root, DI, middleware
│   │   ├── Properties/
│   │   │   └── launchSettings.json      # Ports and browser launch config
│   │   ├── appsettings.json             # JWT configuration
│   │   └── appsettings.Development.json
│   └── SecurityPatterns.Diagnostics/
│       └── Program.cs                   # 4 attack scenario demonstrations
└── tests/
    └── SecurityPatterns.Tests/
        ├── JwtTokenIssuerTests.cs       # 12 tests: token generation & validation
        └── JwtTokenVerifierTests.cs     # 12 tests: signature & claim verification
```

---

## Security Properties

### CWE/CVE Mitigations

| Vulnerability | Mitigation | Implementation |
|---|---|---|
| **CWE-347** (Improper Verification of Cryptographic Signature) | `ValidateIssuerSigningKey = true` forces HMAC-SHA256 signature verification | `JwtTokenVerifier.cs:118` |
| **CVE-2015-9235** (JWT "none" algorithm attack) | `RequireSignedTokens = true` + `ValidAlgorithms = [HmacSha256]` — tokens with `none` algorithm are rejected | `JwtTokenVerifier.cs:137-138` |
| **CWE-326** (Inadequate Encryption Strength) | Constructor enforces ≥256-bit key length at construction time; rejects weak keys | `JwtTokenIssuer.cs:84-92`, `JwtTokenVerifier.cs:98-106` |
| **CWE-287** (Improper Authentication) | Both issuer (`iss`) and audience (`aud`) claims are validated against expected values | `JwtTokenVerifier.cs:128-131` |
| **CWE-613** (Insufficient Session Expiration) | `ClockSkew = TimeSpan.Zero` — expired tokens rejected immediately with no grace period | `JwtTokenVerifier.cs:134` |

### Security Design Decisions

- **Sealed classes** — `JwtTokenIssuer` and `JwtTokenVerifier` are sealed to prevent inheritance-based tampering
- **Immutable state** — all configuration is set in constructors and treated as immutable
- **Deterministic KeyId** — `"signing-key-1"` is used on both issuer and verifier for IdentityModel 8.x key resolution
- **Out-parameter pattern** — `ValidateToken` uses `out IDictionary<string, string>? extractedClaims` to avoid allocations for validity-only checks

---

## Technologies

| Component | Technology |
|-----------|-----------|
| Runtime | .NET 9 |
| Language | C# 12 (file-scoped namespaces, nullable reference types) |
| Token Format | JWT (JSON Web Token) |
| Signing Algorithm | HMAC-SHA256 (symmetric) |
| Web Framework | ASP.NET Core |
| API Documentation | Swashbuckle / Swagger |
| Authentication | Microsoft.AspNetCore.Authentication.JwtBearer |
| Cryptography | System.IdentityModel.Tokens.Jwt 8.x |
| Test Framework | xUnit |
| Assertions | FluentAssertions 7.x |
| Architecture | Clean Architecture (Domain → Application → Infrastructure → Presentation) |
| Version Control | Git (conventional commits) |

---

## Getting Started

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- Git

### Clone and Run

```bash
git clone https://github.com/Moeinkhojaste/SecurityPatterns-Auth-Thesis.git
cd SecurityPatterns-Auth-Thesis
```

**Run the API (Web):**

```bash
dotnet run --project src/SecurityPatterns.Api
# Opens browser to http://localhost:5265/swagger
```

**Run the Diagnostics (Console):**

```bash
dotnet run --project src/SecurityPatterns.Diagnostics
```

**Run All Tests:**

```bash
dotnet test SecurityPatterns.sln
```

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/token` | Anonymous | Authenticate with username/password and receive a JWT |
| `GET` | `/api/auth/profile` | Bearer Token | Return the authenticated user's profile and claims |

### Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| `moein` | `Password123!` | Admin |
| `admin` | `Admin456!` | SuperAdmin |

### Example: Get Token

```bash
curl -X POST http://localhost:5265/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"moein","password":"Password123!"}'
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsImtpZCI6InNpZ25pbmcta2V5LTEi...",
  "expiresAt": "2026-07-04T12:00:00Z",
  "tokenType": "Bearer"
}
```

### Example: Get Profile

```bash
curl -X GET http://localhost:5265/api/auth/profile \
  -H "Authorization: Bearer <token>"
```

Response:

```json
{
  "username": "moein",
  "isAuthenticated": true,
  "claims": {
    "sub": "usr-001",
    "unique_name": "moein",
    "jti": "...",
    "role": "Admin",
    "scope": "thesis:read thesis:write",
    "iss": "SecurityPatterns-Thesis-Dev",
    "aud": "SecurityPatterns-Api-Dev"
  }
}
```

---

## Test Coverage

**24 tests passing** covering all critical security scenarios:

### JwtTokenIssuerTests (12 tests)

| Test | Description |
|------|-------------|
| `GenerateToken_ShouldProduceValidJwt_WithExpectedClaimsAndExpiry` | Verifies token contains correct claims and expiry |
| `GenerateToken_ShouldProduceUniqueTokenIds_WhenCalledMultipleTimes` | Each token has a unique `jti` claim |
| `Constructor_ShouldThrowArgumentException_WhenSecretKeyIsNullOrWhiteSpace` | Null/empty/whitespace keys are rejected |
| `Constructor_ShouldThrowArgumentException_WhenSecretKeyIsTooShort` | Keys < 256 bits are rejected (CWE-326) |
| `Constructor_ShouldThrowArgumentException_WhenIssuerIsNullOrWhiteSpace` | Null/empty issuer is rejected |
| `Constructor_ShouldThrowArgumentException_WhenAudienceIsNullOrWhiteSpace` | Null/empty audience is rejected |

### JwtTokenVerifierTests (12 tests)

| Test | Description |
|------|-------------|
| `ValidateToken_WithValidToken_ShouldReturnTrueAndExtractAllClaims` | Valid token accepted, all claims extracted |
| `ValidateToken_WithTamperedSignature_ShouldReturnFalse` | Tampered signature rejected (CWE-347) |
| `ValidateToken_WithExpiredToken_ShouldReturnFalse` | Expired token rejected (CWE-613) |
| `ValidateToken_WithWrongIssuer_ShouldReturnFalse` | Wrong issuer rejected (CWE-287) |
| `ValidateToken_WithWrongAudience_ShouldReturnFalse` | Wrong audience rejected (CWE-287) |
| `ValidateToken_WithNullOrEmptyToken_ShouldReturnFalse` | Null/empty tokens rejected |
| `ValidateToken_ShouldRejectNoneAlgorithmTokens` | `none` algorithm rejected (CVE-2015-9235) |
| `ValidateToken_WithWrongKey_ShouldReturnFalse` | Wrong signing key rejected |

---

## Diagnostic Scenarios

The `SecurityPatterns.Diagnostics` console app demonstrates 4 real-world attack scenarios:

| # | Scenario | Attack | Expected Result |
|---|----------|--------|-----------------|
| 1 | Successful authentication | Valid credentials | Token issued with correct claims |
| 2 | Token tampering | Modify token payload | Signature verification fails (CWE-347) |
| 3 | Algorithm downgrade | Change algorithm to `none` | Algorithm whitelist rejects token (CVE-2015-9235) |
| 4 | Expired token | Use token past `exp` claim | Lifetime validation rejects token (CWE-613) |

---

## Configuration

JWT settings are configured in `src/SecurityPatterns.Api/appsettings.json`:

```json
{
  "Jwt": {
    "SecretKey": "YXBpLXNlY3VyaXR5LXBhdHRlcm5zLXNlY3JldC1rZXktMjAyNg==",
    "Issuer": "SecurityPatterns-Thesis",
    "Audience": "SecurityPatterns-Api",
    "ExpiryMinutes": 30
  }
}
```

> **Note:** The same Base64-encoded secret key is shared across the Diagnostics, Tests, and API projects for token compatibility. In production, keys should be rotated and stored in a secrets manager.

---

## License

This project is developed as part of a university Bachelor's thesis at the University of [Your University Name].
