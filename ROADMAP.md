# Roadmap

## Current Status

**Version:** 0.6.0
**Status:** All core features complete

---

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

### Usage
```typescript
import { withRateLimit, createMemoryStore } from 'nextjs-secure/rate-limit'

const store = createMemoryStore({ maxSize: 10000 })

export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  store,
  identifier: (req) => req.headers.get('x-api-key') || getIP(req),
})
```

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

// Use preset
export const GET = withSecurityHeaders(handler, { preset: 'strict' })

// Custom configuration
export const GET = withSecurityHeaders(handler, {
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
  },
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
})
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

// Permission-based
export const DELETE = withAuth(handler, {
  jwt: { secret: process.env.JWT_SECRET },
  rbac: { permissions: ['users:delete'] },
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

## v0.6.0 - Audit Logging ✅

### Completed
- [x] Request/response logging (withAuditLog)
- [x] Security event tracking (SecurityEventTracker)
- [x] Configurable log levels (debug, info, warn, error)
- [x] Multiple storage backends
  - [x] Memory store (MemoryStore) with LRU eviction
  - [x] Console store (ConsoleStore) with colorization
  - [x] External/HTTP store (ExternalStore) for webhooks
  - [x] Multi store (MultiStore) for fan-out
- [x] Log formatters
  - [x] JSON formatter (JSONFormatter)
  - [x] Text formatter (TextFormatter)
  - [x] Common Log Format (CLFFormatter)
  - [x] Structured key=value (StructuredFormatter)
- [x] PII redaction (mask, hash, remove modes)
- [x] Request ID middleware (withRequestId)
- [x] Response timing middleware (withTiming)
- [x] Datadog integration (createDatadogStore)
- [x] Custom redaction rules

### Usage
```typescript
import {
  withAuditLog,
  withRequestId,
  withTiming,
  createSecurityTracker,
  MemoryStore,
  ConsoleStore,
  createDatadogStore,
  redactObject,
  DEFAULT_PII_FIELDS
} from 'nextjs-secure/audit'

// Request logging with PII redaction
export const POST = withAuditLog(handler, {
  store: new MemoryStore({ maxEntries: 1000 }),
  include: {
    ip: true,
    userAgent: true,
    headers: false,
    query: true,
    response: true,
    duration: true,
  },
  pii: {
    fields: DEFAULT_PII_FIELDS,
    mode: 'mask', // 'mask' | 'hash' | 'remove'
  },
  exclude: {
    paths: ['/health', '/metrics'],
    methods: ['OPTIONS'],
  },
})

// Add request ID to all responses
export const GET = withRequestId(handler)

// Add response timing header
export const GET = withTiming(handler, { log: true })

// Security event tracking
const tracker = createSecurityTracker({
  store: new ConsoleStore({ colorize: true })
})

await tracker.authFailed({
  ip: '192.168.1.1',
  email: 'user@example.com',
  reason: 'Invalid password'
})

await tracker.rateLimitExceeded({
  ip: '192.168.1.1',
  endpoint: '/api/login',
  limit: 10,
  window: '15m'
})

await tracker.xssDetected({
  ip: '192.168.1.1',
  field: 'comment',
  endpoint: '/api/comments'
})

// Manual PII redaction
const safeData = redactObject(userData, {
  fields: ['password', 'ssn', 'creditCard'],
  mode: 'mask'
})

// Datadog integration
const datadogStore = createDatadogStore({
  apiKey: process.env.DATADOG_API_KEY,
  service: 'my-api',
  env: 'production',
})
```

### Future Enhancements
- [ ] Log rotation for file storage
- [ ] Sentry integration
- [ ] CloudWatch integration
- [ ] Elasticsearch integration

---

## v0.7.0 - Bot Detection (Planned)

### Features
- [ ] User-agent analysis and known bot detection
- [ ] Behavior analysis (request timing patterns)
- [ ] Honeypot fields for forms
- [ ] CAPTCHA integration (reCAPTCHA, hCaptcha, Turnstile)
- [ ] Browser fingerprinting
- [ ] Challenge-response verification

### Planned Usage
```typescript
import { withBotProtection } from 'nextjs-secure/bot'

export const POST = withBotProtection(handler, {
  honeypot: { fieldName: '_hp_field' },
  userAgent: {
    blockKnownBots: true,
    allowList: ['Googlebot', 'Bingbot'],
  },
  behavior: {
    minRequestInterval: 100, // ms
    maxRequestsPerSecond: 10,
  },
})

// With CAPTCHA
export const POST = withBotProtection(handler, {
  captcha: {
    provider: 'recaptcha',
    siteKey: process.env.RECAPTCHA_SITE_KEY,
    secretKey: process.env.RECAPTCHA_SECRET_KEY,
    threshold: 0.5,
  },
})
```

---

## v0.8.0 - API Security (Planned)

### Features
- [ ] Request signing (HMAC signatures)
- [ ] Replay attack prevention (nonce-based)
- [ ] Request timestamp validation
- [ ] API versioning helpers
- [ ] Request freshness validation
- [ ] Idempotency key support

### Planned Usage
```typescript
import { withRequestSigning, withReplayPrevention } from 'nextjs-secure/api'

// Request signing
export const POST = withRequestSigning(handler, {
  secret: process.env.API_SECRET,
  algorithm: 'sha256',
  headerName: 'x-signature',
  timestampTolerance: 300, // 5 minutes
})

// Replay prevention
export const POST = withReplayPrevention(handler, {
  store: redisStore,
  nonceHeader: 'x-nonce',
  ttl: '5m',
})

// API versioning
export const GET = withAPIVersion(handler, {
  header: 'x-api-version',
  supported: ['v1', 'v2'],
  current: 'v2',
  deprecated: ['v1'],
})
```

---

## v0.9.0 - Geo-blocking (Planned)

### Features
- [ ] Country-based blocking/allowing
- [ ] IP reputation checking
- [ ] VPN/Proxy detection
- [ ] Geo-based routing
- [ ] Region-specific rate limits
- [ ] Geo headers injection

### Planned Usage
```typescript
import { withGeoBlocking, withGeoHeaders } from 'nextjs-secure/geo'

// Block specific countries
export const GET = withGeoBlocking(handler, {
  blockCountries: ['CN', 'RU', 'KP'],
  allowCountries: null, // allow all except blocked
})

// Allow only specific countries
export const GET = withGeoBlocking(handler, {
  allowCountries: ['US', 'CA', 'GB', 'DE'],
  blockMessage: 'This service is not available in your region',
})

// VPN/Proxy detection
export const POST = withGeoBlocking(handler, {
  blockVPN: true,
  blockProxy: true,
  blockTor: true,
})

// Add geo headers to request
export const GET = withGeoHeaders(handler, {
  headers: {
    country: 'x-geo-country',
    region: 'x-geo-region',
    city: 'x-geo-city',
  },
})
```

---

## v1.0.0 - DDoS Protection (Planned)

### Features
- [ ] Adaptive rate limiting (dynamic limits based on server load)
- [ ] Request fingerprinting
- [ ] Automatic IP blocking
- [ ] Traffic analysis and anomaly detection
- [ ] Circuit breaker pattern
- [ ] Graceful degradation

### Planned Usage
```typescript
import { withDDoSProtection, withCircuitBreaker } from 'nextjs-secure/ddos'

// Adaptive rate limiting
export const GET = withDDoSProtection(handler, {
  baseLimit: 100,
  adaptiveMultiplier: {
    low: 1.5,    // 150 requests when load is low
    normal: 1.0, // 100 requests normal
    high: 0.5,   // 50 requests when load is high
  },
  fingerprint: true,
  autoBlock: {
    threshold: 1000, // requests per minute
    duration: '1h',
  },
})

// Circuit breaker
export const GET = withCircuitBreaker(handler, {
  failureThreshold: 5,
  successThreshold: 2,
  timeout: '30s',
  halfOpenRequests: 3,
  onOpen: () => console.log('Circuit opened'),
  onClose: () => console.log('Circuit closed'),
})
```

---

## v1.1.0 - Auth Provider Integrations (Planned)

### Features
- [ ] NextAuth.js session provider
- [ ] Clerk session provider
- [ ] Auth0 JWT provider
- [ ] Supabase session provider
- [ ] Firebase Auth provider
- [ ] JWKS (JSON Web Key Set) support
- [ ] OAuth 2.0 token introspection

### Planned Usage
```typescript
import {
  withNextAuth,
  withClerk,
  withAuth0,
  withSupabase,
  withFirebase,
  withJWKS
} from 'nextjs-secure/auth/providers'

// NextAuth.js
export const GET = withNextAuth(handler, {
  roles: ['admin'],
})

// Clerk
export const GET = withClerk(handler, {
  permissions: ['read:users'],
})

// Auth0 with JWKS
export const GET = withAuth0(handler, {
  domain: 'your-tenant.auth0.com',
  audience: 'https://api.example.com',
})

// Supabase
export const GET = withSupabase(handler, {
  roles: ['authenticated'],
})

// Firebase
export const GET = withFirebase(handler, {
  projectId: 'your-project',
})
```

---

## v1.2.0 - Observability Integrations (Planned)

### Features
- [ ] Sentry error tracking
- [ ] AWS CloudWatch logging
- [ ] Elasticsearch log aggregation
- [ ] Prometheus metrics export
- [ ] OpenTelemetry tracing
- [ ] Custom metrics

### Planned Usage
```typescript
import {
  createSentryStore,
  createCloudWatchStore,
  createElasticsearchStore,
  withPrometheusMetrics,
  withOpenTelemetry
} from 'nextjs-secure/observability'

// Sentry integration
const sentryStore = createSentryStore({
  dsn: process.env.SENTRY_DSN,
  environment: 'production',
})

// CloudWatch
const cloudwatchStore = createCloudWatchStore({
  region: 'us-east-1',
  logGroup: '/api/security',
})

// Prometheus metrics
export const GET = withPrometheusMetrics(handler, {
  prefix: 'api_',
  labels: ['method', 'path', 'status'],
})

// OpenTelemetry tracing
export const GET = withOpenTelemetry(handler, {
  serviceName: 'my-api',
  spanName: 'api.request',
})
```

---

## Future Ideas (Post v1.2.0)

### Advanced Security
- [ ] Web Application Firewall (WAF) rules
- [ ] Content Security Policy reporting
- [ ] Subresource Integrity (SRI) helpers
- [ ] Certificate pinning utilities

### Developer Experience
- [ ] Visual security dashboard
- [ ] Security audit reports
- [ ] Automated vulnerability scanning
- [ ] Security policy as code

### Performance
- [ ] Response caching with security headers
- [ ] Edge caching integration
- [ ] Compression with security

### Compliance
- [ ] GDPR compliance helpers
- [ ] HIPAA audit logging
- [ ] SOC 2 security controls
- [ ] PCI DSS requirements

---

## Contributing

Want to help? Pick an unchecked item and submit a PR!

1. Fork the repo
2. Create feature branch
3. Write tests (required)
4. Submit PR

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Version History

| Version | Release Date | Features |
|---------|--------------|----------|
| 0.1.0 | 2025-01-10 | Rate Limiting |
| 0.2.0 | 2025-01-10 | CSRF Protection |
| 0.3.0 | 2025-01-11 | Security Headers |
| 0.4.0 | 2025-01-11 | Authentication |
| 0.5.0 | 2025-01-11 | Input Validation |
| 0.6.0 | 2025-01-12 | Audit Logging |

---

**Last Updated:** 2025-01-12
