# nextjs-secure - Development Plan

> Production-ready security middleware for Next.js 13+ App Router

## Project Overview

**Goal:** Provide Next.js developers with enterprise-grade security out of the box. One `npm install` for complete API security.

**Package Name:** `nextjs-secure`

**Version:** 0.6.0

**Status:** All core features complete

---

## Completed Features

### v0.1.x - Rate Limiting

| Feature | Status | Description |
|---------|--------|-------------|
| Sliding Window Algorithm | Done | Accurate rate limiting with smooth distribution |
| Fixed Window Algorithm | Done | Simple time-based rate limiting |
| Token Bucket Algorithm | Done | Burst-friendly rate limiting |
| Memory Store | Done | In-memory with LRU eviction |
| Redis Store | Done | ioredis compatible for production |
| Upstash Store | Done | Edge/Serverless ready |
| Custom Identifiers | Done | IP, API key, user ID, composite |
| Response Customization | Done | onLimit, skip, headers |
| Duration Parsing | Done | Human-readable durations ('15m', '1h') |
| IP Extraction | Done | x-forwarded-for, x-real-ip support |

### v0.2.0 - CSRF Protection

| Feature | Status | Description |
|---------|--------|-------------|
| Double Submit Cookie | Done | Secure CSRF pattern |
| HMAC-SHA256 Signing | Done | Cryptographic token validation |
| Token Generation | Done | Secure random tokens |
| Cookie Configuration | Done | httpOnly, secure, sameSite options |
| Header/Body Support | Done | Flexible token extraction |
| Skip Conditions | Done | Conditional CSRF checks |

### v0.3.0 - Security Headers

| Feature | Status | Description |
|---------|--------|-------------|
| CSP Builder | Done | Content-Security-Policy configuration |
| HSTS | Done | Strict-Transport-Security |
| X-Frame-Options | Done | Clickjacking protection |
| X-Content-Type-Options | Done | MIME type sniffing protection |
| Referrer-Policy | Done | Referrer information control |
| Permissions-Policy | Done | Feature policy control |
| Cross-Origin Headers | Done | CORP, COEP, COOP support |
| Preset Configurations | Done | strict, relaxed, api presets |

### v0.4.0 - Authentication

| Feature | Status | Description |
|---------|--------|-------------|
| JWT Validation | Done | HS256, RS256, ES256 support |
| Claims Validation | Done | exp, nbf, iss, aud verification |
| API Key Auth | Done | Header and query parameter |
| Session Auth | Done | Cookie-based authentication |
| RBAC | Done | Role-Based Access Control |
| Permission ACL | Done | Fine-grained permissions |
| Multi-Strategy | Done | Combined auth (withAuth) |
| Optional Auth | Done | withOptionalAuth middleware |

### v0.5.0 - Input Validation

| Feature | Status | Description |
|---------|--------|-------------|
| Schema Validation | Done | Zod compatible + built-in |
| Body/Query/Params | Done | Full request validation |
| XSS Sanitization | Done | escape, strip, allow-safe modes |
| XSS Detection | Done | Pattern-based blocking |
| SQL Injection | Done | Detection and protection |
| Path Traversal | Done | Directory traversal prevention |
| File Validation | Done | Size, type, magic numbers |
| Content-Type | Done | Request validation |

### v0.6.0 - Audit Logging

| Feature | Status | Description |
|---------|--------|-------------|
| Request Logging | Done | withAuditLog middleware |
| Security Events | Done | Auth, rate limit, XSS tracking |
| Memory Store | Done | In-memory with LRU eviction |
| Console Store | Done | Colorized console output |
| External Store | Done | HTTP/webhook integration |
| Multi Store | Done | Fan-out to multiple stores |
| PII Redaction | Done | mask, hash, remove modes |
| Log Formatters | Done | JSON, Text, CLF, Structured |
| Request ID | Done | withRequestId middleware |
| Response Timing | Done | withTiming middleware |
| Datadog Integration | Done | createDatadogStore helper |

---

## Architecture

### Module Structure

```
src/
├── core/
│   ├── types.ts           # Core TypeScript types
│   └── errors.ts          # Custom error classes
│
├── middleware/
│   ├── rate-limit/        # Rate limiting module
│   │   ├── index.ts       # Main exports
│   │   ├── types.ts       # Types and interfaces
│   │   ├── algorithms/    # Rate limit algorithms
│   │   │   ├── sliding-window.ts
│   │   │   ├── fixed-window.ts
│   │   │   └── token-bucket.ts
│   │   └── stores/        # Storage backends
│   │       ├── memory.ts
│   │       ├── redis.ts
│   │       └── upstash.ts
│   │
│   ├── csrf/              # CSRF protection
│   │   ├── index.ts
│   │   └── types.ts
│   │
│   ├── headers/           # Security headers
│   │   ├── index.ts
│   │   └── types.ts
│   │
│   ├── auth/              # Authentication
│   │   ├── index.ts
│   │   ├── types.ts
│   │   ├── jwt.ts
│   │   ├── api-key.ts
│   │   ├── session.ts
│   │   └── rbac.ts
│   │
│   ├── validation/        # Input validation
│   │   ├── index.ts
│   │   ├── types.ts
│   │   ├── schema.ts
│   │   ├── sanitize.ts
│   │   ├── xss.ts
│   │   ├── sql.ts
│   │   ├── path.ts
│   │   └── file.ts
│   │
│   └── audit/             # Audit logging
│       ├── index.ts
│       ├── types.ts
│       ├── middleware.ts
│       ├── events.ts
│       ├── redaction.ts
│       ├── formatters.ts
│       └── stores/
│           ├── memory.ts
│           ├── console.ts
│           ├── external.ts
│           └── multi.ts
│
├── utils/
│   ├── ip.ts              # IP extraction utilities
│   └── time.ts            # Duration parsing
│
└── index.ts               # Main entry point
```

### Build Configuration

- **Build Tool:** tsup
- **Output:** ESM + CJS dual export
- **Type Definitions:** .d.ts and .d.cts
- **Target:** ES2020
- **Tree Shaking:** Enabled

### Module Entry Points

```typescript
// Main entry
import { withRateLimit, withCSRF, withAuth } from 'nextjs-secure'

// Individual modules (tree-shaking)
import { withRateLimit } from 'nextjs-secure/rate-limit'
import { withCSRF } from 'nextjs-secure/csrf'
import { withSecurityHeaders } from 'nextjs-secure/headers'
import { withJWT, withAuth } from 'nextjs-secure/auth'
import { withValidation, withXSSProtection } from 'nextjs-secure/validation'
import { withAuditLog, createSecurityTracker } from 'nextjs-secure/audit'
```

---

## Technical Specifications

### Runtime Support

| Environment | Support |
|-------------|---------|
| Node.js 18+ | Full |
| Edge Runtime | Full |
| Cloudflare Workers | Full |
| Vercel Edge | Full |
| AWS Lambda | Full |

### Dependencies

**Production:**
- `jose` - JWT handling (peer dependency, optional)

**Peer Dependencies:**
- `next` >= 13.0.0

**Optional:**
- `zod` - Schema validation
- `@upstash/redis` - Upstash store
- `ioredis` - Redis store

### Type Safety

- Full TypeScript support
- Generic handlers for typed context
- Strict mode enabled
- Complete JSDoc documentation

---

## Testing

### Test Framework

- **Runner:** Vitest
- **Coverage:** c8
- **Assertions:** Vitest built-in

### Test Statistics

| Category | Tests |
|----------|-------|
| Rate Limiting | ~100 |
| CSRF | ~30 |
| Security Headers | ~50 |
| Authentication | ~80 |
| Input Validation | ~120 |
| Audit Logging | ~90 |
| **Total** | **~470** |

### Running Tests

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific module
npm test -- --grep "rate-limit"

# Watch mode
npm run test:watch
```

---

## Future Roadmap (v1.0+)

### Bot Detection (v0.7.0)

| Feature | Priority | Description |
|---------|----------|-------------|
| User-Agent Analysis | High | Detect known bot patterns |
| Behavior Analysis | Medium | Request timing and patterns |
| Honeypot Fields | High | Hidden form fields for bots |
| CAPTCHA Integration | Medium | reCAPTCHA, hCaptcha support |
| Fingerprinting | Low | Browser fingerprint detection |

### API Security (v0.8.0)

| Feature | Priority | Description |
|---------|----------|-------------|
| Request Signing | High | HMAC request signatures |
| Replay Prevention | High | Nonce-based replay attacks |
| Timestamp Validation | High | Request freshness checks |
| API Versioning | Medium | Version header management |
| Request Validation | Medium | Schema-based request signing |

### Geo-blocking (v0.9.0)

| Feature | Priority | Description |
|---------|----------|-------------|
| Country Blocking | High | Block/allow by country code |
| IP Reputation | Medium | Known malicious IP detection |
| VPN Detection | Medium | Detect VPN/proxy usage |
| Geo Headers | Low | Add geo info to requests |
| Region-based Rules | Medium | Different rules per region |

### DDoS Protection (v1.0.0)

| Feature | Priority | Description |
|---------|----------|-------------|
| Adaptive Rate Limiting | High | Dynamic limits based on load |
| Request Fingerprinting | High | Identify attack patterns |
| Auto IP Blocking | Medium | Automatic threat response |
| Traffic Analysis | Medium | Real-time traffic monitoring |
| Circuit Breaker | High | Prevent cascade failures |

### Provider Integrations (v1.1.0)

| Provider | Type | Description |
|----------|------|-------------|
| NextAuth.js | Auth | Session-based authentication |
| Clerk | Auth | Clerk session support |
| Auth0 | Auth | Auth0 JWT validation |
| Supabase | Auth | Supabase session support |
| Firebase Auth | Auth | Firebase token validation |
| JWKS | Auth | JSON Web Key Set support |

### Observability (v1.2.0)

| Integration | Type | Description |
|-------------|------|-------------|
| Sentry | Error | Error tracking and alerting |
| CloudWatch | Logging | AWS logging integration |
| Elasticsearch | Logging | Log aggregation |
| Prometheus | Metrics | Metrics export |
| OpenTelemetry | Tracing | Distributed tracing |

---

## API Design Patterns

### Higher-Order Function Composition

```typescript
import { withAuth, withRateLimit } from 'nextjs-secure'

export const GET = withAuth(
  withRateLimit(
    async (req, ctx) => {
      return Response.json({ data: ctx.user })
    },
    { limit: 100, window: '15m' }
  ),
  { roles: ['admin'] }
)
```

### Middleware Stacking

```typescript
import { compose } from 'nextjs-secure'

export const GET = compose(
  withRateLimit({ limit: 100 }),
  withAuth({ roles: ['admin'] }),
  withAuditLog({ store: memoryStore }),
  handler
)
```

### Configuration-Based

```typescript
import { createSecureHandler } from 'nextjs-secure'

export const GET = createSecureHandler({
  rateLimit: { limit: 100, window: '15m' },
  auth: { roles: ['admin'] },
  audit: { enabled: true },
  handler: async (req, ctx) => {
    return Response.json({ users: [] })
  }
})
```

---

## Performance

### Benchmarks

| Operation | Time |
|-----------|------|
| Rate limit check (memory) | < 1ms |
| JWT validation | < 5ms |
| CSRF validation | < 1ms |
| XSS sanitization | < 2ms |
| SQL injection check | < 1ms |

### Optimization Techniques

- Lazy loading of optional dependencies
- Efficient regex compilation (cached)
- Minimal memory allocations
- No synchronous operations
- Edge Runtime compatible (no Node.js APIs)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development setup
- Code style guidelines
- Testing requirements
- Pull request process

---

## Resources

- [Next.js App Router](https://nextjs.org/docs/app)
- [jose (JWT)](https://github.com/panva/jose)
- [OWASP Security Headers](https://owasp.org/www-project-secure-headers/)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

**Last Updated:** 2025-01-12

**Current Version:** 0.6.0

**Status:** Core features complete, ready for production
