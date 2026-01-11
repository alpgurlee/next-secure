# Roadmap

## v0.1.x - Rate Limiting (Current)

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

### Planned for v0.1.x
- [ ] Leaky bucket algorithm
- [ ] Multi-tier rate limiting (combine multiple limits)
- [ ] Rate limit by cost (weighted requests)
- [ ] Distributed rate limiting improvements

---

## v0.2.0 - Authentication Middleware

### JWT Validation
```typescript
import { withJWT } from 'nextjs-secure/auth'

export const GET = withJWT(handler, {
  secret: process.env.JWT_SECRET,
  algorithms: ['HS256', 'RS256'],
  issuer: 'https://myapp.com',
  audience: 'api',
})
```

### Auth Provider Integration
```typescript
import { withAuth } from 'nextjs-secure/auth'

// NextAuth.js
export const GET = withAuth(handler, {
  provider: 'next-auth',
})

// Supabase
export const GET = withAuth(handler, {
  provider: 'supabase',
  supabaseUrl: process.env.SUPABASE_URL,
  supabaseKey: process.env.SUPABASE_ANON_KEY,
})

// Clerk
export const GET = withAuth(handler, {
  provider: 'clerk',
})
```

### Role-Based Access Control (RBAC)
```typescript
import { withRole } from 'nextjs-secure/auth'

export const GET = withRole(handler, {
  roles: ['admin', 'moderator'],
  onUnauthorized: (req) => Response.json({ error: 'Forbidden' }, { status: 403 }),
})
```

### Planned Features
- [ ] JWT validation with JWKS support
- [ ] NextAuth.js provider
- [ ] Supabase provider
- [ ] Clerk provider
- [ ] Auth0 provider
- [ ] Firebase Auth provider
- [ ] RBAC middleware
- [ ] Permission-based access control
- [ ] Session validation
- [ ] API key authentication

---

## v0.3.0 - CSRF Protection

### Double Submit Cookie
```typescript
import { withCSRF } from 'nextjs-secure/csrf'

export const POST = withCSRF(handler, {
  cookie: {
    name: '__csrf',
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
  },
  header: 'x-csrf-token',
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
})
```

### Token Generation
```typescript
import { generateCSRFToken, validateCSRFToken } from 'nextjs-secure/csrf'

// In your form page
const token = await generateCSRFToken()

// In your API route
const isValid = await validateCSRFToken(request)
```

### Planned Features
- [ ] Double submit cookie pattern
- [ ] Signed token validation
- [ ] Origin/Referer validation
- [ ] Custom token storage
- [ ] Framework integration helpers

---

## v0.4.0 - Security Headers

### Preset Configurations
```typescript
import { withSecurityHeaders } from 'nextjs-secure/headers'

// Use preset
export const GET = withSecurityHeaders(handler, {
  preset: 'strict', // 'strict' | 'relaxed' | 'api'
})

// Or customize
export const GET = withSecurityHeaders(handler, {
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'https:'],
  },
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
  },
})
```

### Planned Features
- [ ] Content-Security-Policy builder
- [ ] Strict-Transport-Security
- [ ] X-Frame-Options
- [ ] X-Content-Type-Options
- [ ] Referrer-Policy
- [ ] Permissions-Policy
- [ ] Cross-Origin headers (CORP, COEP, COOP)
- [ ] Preset configurations (strict, relaxed, api)
- [ ] Next.js middleware integration

---

## v0.5.0 - Input Validation

### Zod Integration
```typescript
import { withValidation } from 'nextjs-secure/validation'
import { z } from 'zod'

const CreateUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(2).max(50),
})

export const POST = withValidation(handler, {
  body: CreateUserSchema,
  query: z.object({
    redirect: z.string().url().optional(),
  }),
})
```

### XSS Sanitization
```typescript
import { sanitize, withSanitization } from 'nextjs-secure/validation'

// Manual sanitization
const cleanHtml = sanitize(userInput, {
  allowedTags: ['b', 'i', 'em', 'strong'],
  allowedAttributes: {},
})

// Automatic sanitization middleware
export const POST = withSanitization(handler, {
  fields: ['content', 'bio', 'description'],
  mode: 'escape', // 'escape' | 'strip' | 'sanitize'
})
```

### Planned Features
- [ ] Zod schema validation
- [ ] Body/Query/Params validation
- [ ] XSS sanitization (DOMPurify-like)
- [ ] SQL injection detection
- [ ] Path traversal prevention
- [ ] File upload validation
- [ ] Content-Type validation

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
