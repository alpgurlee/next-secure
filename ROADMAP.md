# Roadmap

## v0.1.x - Rate Limiting ✅

### Completed
- [x] Sliding window algorithm
- [x] Fixed window algorithm
- [x] Token bucket algorithm
- [x] Memory store with LRU eviction
- [x] Redis store (ioredis compatible)
- [x] Upstash store (Edge/Serverless ready)
- [x] Custom identifier support (IP, API key, user ID)
- [x] Response customization (onLimit, skip, headers)
- [x] Duration parsing utilities
- [x] IP extraction utilities

### Future Enhancements
- [ ] Leaky bucket algorithm
- [ ] Multi-tier rate limiting (combine multiple limits)
- [ ] Rate limit by cost (weighted requests)
- [ ] Distributed rate limiting improvements

---

## v0.2.0 - CSRF Protection ✅

### Completed
- [x] Double submit cookie pattern
- [x] Signed token validation (HMAC-SHA256)
- [x] Token generation and validation
- [x] Configurable cookie settings
- [x] Header and body token support
- [x] Skip conditions
- [x] Custom error responses

### Usage
```typescript
import { withCSRF, generateCSRF } from 'nextjs-secure/csrf'

// Generate token
const { token, cookieHeader } = await generateCSRF()

// Protect endpoint
export const POST = withCSRF(handler, {
  cookie: { name: '__csrf', httpOnly: true, secure: true },
  headerName: 'x-csrf-token',
})
```

---

## v0.3.0 - Security Headers ✅

### Completed
- [x] Content-Security-Policy builder
- [x] Strict-Transport-Security
- [x] X-Frame-Options
- [x] X-Content-Type-Options
- [x] Referrer-Policy
- [x] Permissions-Policy
- [x] Cross-Origin headers (CORP, COEP, COOP)
- [x] Preset configurations (strict, relaxed, api)

### Usage
```typescript
import { withSecurityHeaders } from 'nextjs-secure/headers'

export const GET = withSecurityHeaders(handler, { preset: 'strict' })
```

---

## v0.4.0 - Authentication ✅

### Completed
- [x] JWT validation (HS256, RS256, ES256)
- [x] Claims validation (exp, nbf, iss, aud)
- [x] API Key authentication (header + query param)
- [x] Session/Cookie authentication
- [x] Role-Based Access Control (RBAC)
- [x] Permission-based access control
- [x] Combined multi-strategy auth (withAuth)
- [x] Optional auth (withOptionalAuth)
- [x] Custom token extraction
- [x] Custom user mapping

### Usage
```typescript
import { withJWT, withAPIKey, withAuth, withRoles } from 'nextjs-secure/auth'

// JWT auth
export const GET = withJWT(handler, { secret: process.env.JWT_SECRET })

// API Key auth
export const GET = withAPIKey(handler, { validate: (key) => db.findUser(key) })

// Combined auth with RBAC
export const GET = withAuth(handler, {
  jwt: { secret: process.env.JWT_SECRET },
  rbac: { roles: ['admin'] },
})
```

### Future Enhancements
- [ ] JWKS (JSON Web Key Set) support
- [ ] NextAuth.js provider
- [ ] Supabase provider
- [ ] Clerk provider
- [ ] Auth0 provider
- [ ] Firebase Auth provider

---

## v0.5.0 - Input Validation ✅

### Completed
- [x] Zod schema validation (compatible)
- [x] Custom schema validation (built-in)
- [x] Body/Query/Params validation
- [x] XSS sanitization (escape, strip, allow-safe modes)
- [x] XSS detection and blocking
- [x] SQL injection detection (high/medium/low severity)
- [x] SQL injection protection middleware
- [x] Path traversal prevention
- [x] Path/filename sanitization
- [x] File upload validation (size, type, magic numbers)
- [x] Content-Type validation
- [x] Combined security middleware (withSecureValidation)

### Usage
```typescript
import {
  withValidation,
  withSanitization,
  withXSSProtection,
  withSQLProtection,
  sanitize,
  detectXSS,
  detectSQLInjection,
  validatePath,
  sanitizeFilename
} from 'nextjs-secure/validation'

// Schema validation (works with Zod or custom schemas)
const schema = {
  email: { type: 'email', required: true },
  password: { type: 'string', minLength: 8 },
  age: { type: 'number', min: 18 }
}

export const POST = withValidation(handler, { body: schema })

// XSS sanitization middleware
export const POST = withSanitization(handler, {
  fields: ['content', 'bio'],
  mode: 'escape', // 'escape' | 'strip' | 'allow-safe'
})

// XSS protection (blocks malicious content)
export const POST = withXSSProtection(handler)

// SQL injection protection
export const POST = withSQLProtection(handler, {
  mode: 'block', // 'block' | 'detect'
})

// Manual sanitization
const cleanHtml = sanitize(userInput, {
  mode: 'allow-safe',
  allowedTags: ['b', 'i', 'em', 'strong'],
})

// File validation
export const POST = withFileValidation(handler, {
  maxSize: 5 * 1024 * 1024, // 5MB
  allowedTypes: ['image/jpeg', 'image/png'],
  validateMagicNumbers: true,
})
```

### Future Enhancements
- [ ] Rate limit per field (brute force protection)
- [ ] Content-based throttling
- [ ] GraphQL query validation

---

## v0.6.0 - Audit Logging

### Request Logging
```typescript
import { withAuditLog } from 'nextjs-secure/audit'

export const POST = withAuditLog(handler, {
  action: 'user.create',
  include: {
    ip: true,
    userAgent: true,
    userId: true,
    requestBody: false, // Careful with sensitive data
    responseStatus: true,
  },
  store: auditStore, // Custom storage
})
```

### Security Event Tracking
```typescript
import { trackSecurityEvent } from 'nextjs-secure/audit'

// Track failed login
await trackSecurityEvent({
  type: 'auth.failed',
  severity: 'warning',
  ip: getClientIp(request),
  metadata: { email: attemptedEmail },
})

// Track rate limit hit
await trackSecurityEvent({
  type: 'ratelimit.exceeded',
  severity: 'info',
  ip: getClientIp(request),
  metadata: { endpoint: '/api/login' },
})
```

### Planned Features
- [ ] Request/response logging
- [ ] Security event tracking
- [ ] Configurable log levels
- [ ] Multiple storage backends (console, file, external)
- [ ] PII redaction
- [ ] Log rotation
- [ ] Integration with logging services (Datadog, Sentry, etc.)

---

## Future Ideas (v1.0+)

### Bot Detection
- [ ] User-agent analysis
- [ ] Behavior analysis
- [ ] Honeypot fields
- [ ] Challenge-response (CAPTCHA integration)

### API Security
- [ ] Request signing
- [ ] Replay attack prevention
- [ ] Request timestamp validation
- [ ] API versioning helpers

### Geo-blocking
- [ ] Country-based blocking
- [ ] IP reputation checking
- [ ] VPN/Proxy detection

### DDoS Protection
- [ ] Adaptive rate limiting
- [ ] Request fingerprinting
- [ ] Automatic IP blocking

---

## Contributing

Want to help? Pick an unchecked item and submit a PR!

1. Fork the repo
2. Create feature branch
3. Write tests
4. Submit PR

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.
