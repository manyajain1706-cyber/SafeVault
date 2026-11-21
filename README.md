# SafeVault — Secure Full-Stack API with ASP.NET Core Identity, JWT & RBAC

Capstone project for **Security and Authentication** demonstrating secure coding practices, authentication, role-based access control (RBAC), data protection, and vulnerability remediation assisted by **Microsoft Copilot**.

---

## Key Security Features Implemented

1. **Secure Input Validation & XSS/Injection Prevention (`InputSanitizationService.cs`)**
   - Enforces data annotations (`[Required]`, `[EmailAddress]`, `[StringLength]`, `[RegularExpression]`) on all incoming DTOs.
   - Detects and blocks common SQL injection and Cross-Site Scripting (XSS) payloads while HTML-encoding user-supplied text.
   - Uses Entity Framework Core parameterized queries and a unique index on user emails (`ApplicationDbContext.cs`).

2. **Authentication & Password Security (`AuthController.cs`, `Program.cs`)**
   - Uses **ASP.NET Core Identity** to automatically salt and hash passwords before database storage.
   - Enforces strong password complexity rules (minimum 10 characters, uppercase, lowercase, digit, special character) and account lockout after 5 failed login attempts.
   - Returns generic authentication failure messages to prevent user enumeration.

3. **Stateless JWT Authentication & RBAC (`JwtTokenService.cs`, `VaultController.cs`)**
   - Issues signed **JSON Web Tokens (JWT)** containing minimal essential claims (`sub`, `email`, `jti`, and `role`).
   - Loads signing keys from environment variables (`JWT_SECRET_KEY`) instead of hard-coding secrets in source control.
   - Enforces strict `TokenValidationParameters` (`ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, `ValidateIssuerSigningKey`, `ClockSkew = TimeSpan.Zero`).
   - Protects endpoints using `[Authorize]` and role-based policies (`RequireAdminRole`, `RequireUserOrAdmin`), and scopes user queries by `OwnerId` to prevent Broken Object Level Authorization (IDOR).

4. **Data Protection at Rest & in Transit (`DataProtectionService.cs`, `Program.cs`)**
   - Encrypts sensitive vault notes at rest using **AES-256-CBC** with a unique initialization vector (IV) per record.
   - Applies **dynamic data masking** so only the last four digits of account numbers are exposed.
   - Enforces HTTPS (`UseHttpsRedirection`, `UseHsts`) and HTTP security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`).

---

## Summary of Vulnerabilities Identified & Resolved with Microsoft Copilot

- **Hard-Coded JWT Secrets & Weak Validation:** Replaced hard-coded signing keys with environment-variable configuration and enabled strict issuer, audience, lifetime, and signature validation.
- **Cross-Site Scripting (XSS) & Injection Risks:** Added DTO regex/length validation, pattern filtering, and HTML encoding before persistence.
- **Broken Object Level Authorization (IDOR):** Scoped `GET /api/vault/my-records` strictly to the authenticated user's `NameIdentifier` claim so users cannot read other users' records.
- **Plain-Text Sensitive Data Exposure:** Implemented AES-256 encryption at rest for sensitive notes and masked account numbers in API responses.
- **Brute-Force & User Enumeration Risks:** Configured Identity account lockout and standardized login error responses.

---

## Getting Started

1. Set the `JWT_SECRET_KEY` environment variable (minimum 32 characters):
   ```bash
   export JWT_SECRET_KEY="YourStrong32CharacterMinimumSecretKey!"
   ```
2. Run the application:
   ```bash
   dotnet restore
   dotnet run
   ```
