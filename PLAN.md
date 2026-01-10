# 🔐 next-secure - Development Plan

> Production-ready security middleware for Next.js 13+ App Router

## 📋 Project Overview

**Goal:** Provide Next.js developers with enterprise-grade security out of the box. One `npm install` for complete API security.

**Tagline:** *"Security middleware for Next.js that just works"*

**Target:** 1000+ GitHub stars, 10k+ weekly npm downloads

---

## 🎯 Core Features

### 1. Rate Limiting ⭐ (Priority 1)
- Sliding window algorithm
- Token bucket algorithm
- IP-based and User-based limiting
- Multiple stores: Memory, Redis, Upstash
- Edge Runtime compatible
- Customizable responses

### 2. Authentication Middleware
- JWT validation (jose library)
- Built-in providers: Supabase, NextAuth, Clerk
- Custom provider support
- Role-based access control (RBAC)
- Permission-based access control

### 3. Audit Logging
- Structured JSON logging
- Async/non-blocking
- Multiple adapters: Console, File, Database
- PII filtering
- Request/Response logging

### 4. CSRF Protection
- Token generation
- Double submit cookie pattern
- Automatic validation

### 5. Security Headers
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

### 6. Input Validation
- Zod integration
- XSS sanitization
- Request body validation

### 7. Protected Fields
- Whitelist-based filtering
- Mass assignment prevention

---

## 🏗️ API Design

### Approach 1: Functional Composition
```typescript
import { withAuth, withRateLimit } from 'next-secure'

export const GET = withAuth(
  withRateLimit(
    async (req, ctx) => {
      return Response.json({ data: [] })
    },
    { limit: 100, window: '15m' }
  ),
  { roles: ['admin'] }
)
```

### Approach 2: Builder Pattern
```typescript
import { secure } from 'next-secure'

export const GET = secure()
  .rateLimit({ limit: 100, window: '15m' })
  .auth({ roles: ['admin'] })
  .audit({ action: 'users.list' })
  .handle(async (req, ctx) => {
    return Response.json({ users: [] })
  })
```

### Approach 3: Config-based
```typescript
import { createHandler } from 'next-secure'

export const GET = createHandler({
  rateLimit: { limit: 100, window: '15m' },
  auth: { roles: ['admin'] },
  handler: async (req, ctx) => {
    return Response.json({ users: [] })
  }
})
```

---

## 📁 Project Structure

```
next-secure/
├── src/
│   ├── core/
│   │   ├── handler.ts
│   │   ├── context.ts
│   │   ├── errors.ts
│   │   └── types.ts
│   │
│   ├── middleware/
│   │   ├── rate-limit/
│   │   │   ├── index.ts
│   │   │   ├── types.ts
│   │   │   ├── algorithms/
│   │   │   │   ├── sliding-window.ts
│   │   │   │   ├── fixed-window.ts
│   │   │   │   └── token-bucket.ts
│   │   │   └── stores/
│   │   │       ├── memory.ts
│   │   │       ├── redis.ts
│   │   │       └── upstash.ts
│   │   │
│   │   ├── auth/
│   │   │   ├── index.ts
│   │   │   ├── jwt.ts
│   │   │   └── providers/
│   │   │       ├── supabase.ts
│   │   │       ├── next-auth.ts
│   │   │       ├── clerk.ts
│   │   │       └── custom.ts
│   │   │
│   │   ├── csrf/
│   │   │   └── index.ts
│   │   │
│   │   ├── headers/
│   │   │   └── index.ts
│   │   │
│   │   └── validation/
│   │       ├── index.ts
│   │       └── sanitize.ts
│   │
│   ├── logging/
│   │   ├── audit.ts
│   │   └── adapters/
│   │       ├── console.ts
│   │       ├── file.ts
│   │       └── database.ts
│   │
│   ├── utils/
│   │   ├── protected-fields.ts
│   │   ├── ip.ts
│   │   ├── time.ts
│   │   └── headers.ts
│   │
│   └── index.ts
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
├── examples/
│   ├── basic/
│   ├── with-supabase/
│   ├── with-prisma/
│   └── with-nextauth/
│
├── docs/
│   ├── getting-started.md
│   ├── rate-limiting.md
│   ├── authentication.md
│   └── ...
│
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── vitest.config.ts
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
└── SECURITY.md
```

---

## 📦 Dependencies

### Production (Minimal)
```json
{
  "dependencies": {
    "jose": "^5.0.0"
  },
  "peerDependencies": {
    "next": ">=13.0.0"
  },
  "peerDependenciesMeta": {
    "zod": { "optional": true },
    "@upstash/redis": { "optional": true },
    "ioredis": { "optional": true }
  }
}
```

### Development
- typescript, tsup, vitest
- eslint, prettier
- changesets (versioning)
- typedoc (API docs)

---

## 🔧 Technical Decisions

### Build
- ESM + CJS dual export
- Edge Runtime compatible
- Tree-shakeable
- Zero/minimal dependencies

### Error Handling
- Custom error classes (SecureError, RateLimitError, AuthError)
- Consistent error responses
- Detailed error messages in development

### Type Safety
- Full TypeScript
- Generic handlers for typed context
- Strict mode enabled

---

## 📅 Development Phases

### Phase 1: Foundation (Week 1-2) ✅ CURRENT
- [x] Project structure
- [x] Build tooling (tsup, vitest)
- [ ] Core handler and context
- [ ] Rate limiting (memory store)
- [ ] Rate limiting (sliding window)
- [ ] Rate limiting (Redis/Upstash)
- [ ] Unit tests
- [ ] Basic documentation

### Phase 2: Authentication (Week 3-4)
- [ ] JWT validation
- [ ] Auth middleware
- [ ] Supabase provider
- [ ] NextAuth provider
- [ ] Clerk provider
- [ ] RBAC support

### Phase 3: Additional Middleware (Week 5-6)
- [ ] CSRF protection
- [ ] Security headers
- [ ] Input validation (Zod)
- [ ] XSS sanitization
- [ ] Protected fields

### Phase 4: Logging & Polish (Week 7-8)
- [ ] Audit logging
- [ ] Multiple log adapters
- [ ] Builder pattern API
- [ ] Config-based API
- [ ] Performance benchmarks

### Phase 5: Documentation & Examples (Week 9-10)
- [ ] Comprehensive docs
- [ ] Example: Basic
- [ ] Example: Supabase
- [ ] Example: Prisma
- [ ] Example: NextAuth
- [ ] Migration guide

### Phase 6: Launch (Week 11)
- [ ] npm publish
- [ ] GitHub release
- [ ] Blog post
- [ ] Social media
- [ ] Hacker News / Reddit

---

## 🚀 Rate Limiting Module (Detailed)

### Features
1. **Algorithms**
   - Fixed Window: Simple, memory efficient
   - Sliding Window: Smoother, more accurate
   - Token Bucket: Burst-friendly

2. **Stores**
   - Memory: Development, single instance
   - Redis: Production, distributed
   - Upstash: Serverless, Edge compatible

3. **Identifiers**
   - IP address (default)
   - User ID (authenticated)
   - Custom function
   - Composite (IP + route)

4. **Configuration**
   ```typescript
   interface RateLimitConfig {
     // Limits
     limit: number
     window: string | number  // '15m', '1h', 60000

     // Algorithm
     algorithm?: 'sliding-window' | 'fixed-window' | 'token-bucket'

     // Identifier
     identifier?: 'ip' | 'user' | ((req: NextRequest) => string)

     // Store
     store?: RateLimitStore

     // Responses
     onLimit?: (req: NextRequest, info: RateLimitInfo) => Response

     // Headers
     headers?: boolean  // X-RateLimit-* headers

     // Skip
     skip?: (req: NextRequest) => boolean | Promise<boolean>

     // Key prefix
     prefix?: string
   }
   ```

5. **Response Headers**
   ```
   X-RateLimit-Limit: 100
   X-RateLimit-Remaining: 95
   X-RateLimit-Reset: 1699999999
   Retry-After: 60 (only when limited)
   ```

6. **Error Response**
   ```json
   {
     "error": "Too Many Requests",
     "message": "Rate limit exceeded. Try again in 60 seconds.",
     "retryAfter": 60
   }
   ```

### Implementation Priority
1. ✅ Types and interfaces
2. ✅ Time parsing utility
3. ✅ IP extraction utility
4. ⬜ Memory store
5. ⬜ Sliding window algorithm
6. ⬜ Core middleware
7. ⬜ Redis store
8. ⬜ Upstash store
9. ⬜ Token bucket algorithm
10. ⬜ Tests

---

## 📊 Success Metrics

| Metric | Target | Timeline |
|--------|--------|----------|
| GitHub Stars | 100 | Month 1 |
| GitHub Stars | 500 | Month 3 |
| GitHub Stars | 1000 | Month 6 |
| npm Weekly Downloads | 1000 | Month 1 |
| npm Weekly Downloads | 5000 | Month 3 |
| npm Weekly Downloads | 10000 | Month 6 |

---

## 🔗 Resources

- [Next.js App Router](https://nextjs.org/docs/app)
- [jose (JWT)](https://github.com/panva/jose)
- [Upstash Rate Limit](https://github.com/upstash/ratelimit)
- [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit)

---

**Last Updated:** 2025-01-11
**Status:** Phase 1 - Foundation
