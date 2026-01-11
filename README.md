# nextjs-secure

[![npm version](https://badge.fury.io/js/nextjs-secure.svg)](https://www.npmjs.com/package/nextjs-secure)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-13+-black.svg)](https://nextjs.org/)

Production-ready security middleware for Next.js App Router. Zero config, maximum protection.

```typescript
import { withRateLimit } from 'nextjs-secure'

export const GET = withRateLimit(
  async (req) => Response.json({ message: 'Hello!' }),
  { limit: 100, window: '15m' }
)
```

## Why nextjs-secure?

Building secure APIs in Next.js shouldn't require hours of boilerplate. Most projects end up with copy-pasted rate limiting code, inconsistent error handling, and security gaps.

**nextjs-secure** provides battle-tested security primitives that work out of the box:

- **Zero Configuration** - Sensible defaults, works immediately
- **Type Safe** - Full TypeScript support with generics
- **Edge Ready** - Works on Vercel Edge, Cloudflare Workers, Node.js
- **Flexible** - Memory, Redis, or Upstash storage backends
- **Lightweight** - No bloated dependencies, tree-shakeable

## Installation

```bash
npm install nextjs-secure
# or
yarn add nextjs-secure
# or
pnpm add nextjs-secure
```

## Table of Contents

- [Quick Start](#quick-start)
- [Rate Limiting](#rate-limiting)
  - [Basic Usage](#basic-usage)
  - [Algorithms](#algorithms)
  - [Storage Backends](#storage-backends)
  - [Custom Identifiers](#custom-identifiers)
  - [Response Customization](#response-customization)
- [CSRF Protection](#csrf-protection)
  - [Basic Setup](#basic-setup)
  - [Client-Side Usage](#client-side-usage)
  - [Configuration](#configuration-1)
  - [Manual Validation](#manual-validation)
- [Security Headers](#security-headers)
  - [Quick Start](#quick-start-1)
  - [Presets](#presets)
  - [Custom Configuration](#custom-configuration)
- [Authentication](#authentication)
  - [JWT Authentication](#jwt-authentication)
  - [API Key Authentication](#api-key-authentication)
  - [Session Authentication](#session-authentication)
  - [Role-Based Access Control](#role-based-access-control)
  - [Combined Authentication](#combined-authentication)
- [Utilities](#utilities)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

## Quick Start

### Protect an API Route

```typescript
// app/api/posts/route.ts
import { withRateLimit } from 'nextjs-secure'

export const GET = withRateLimit(
  async (request) => {
    const posts = await db.posts.findMany()
    return Response.json(posts)
  },
  {
    limit: 100,    // 100 requests
    window: '15m'  // per 15 minutes
  }
)
```

### Create a Reusable Limiter

```typescript
// lib/rate-limit.ts
import { createRateLimiter } from 'nextjs-secure'

export const apiLimiter = createRateLimiter({
  limit: 100,
  window: '15m',
})

export const strictLimiter = createRateLimiter({
  limit: 10,
  window: '1m',
})
```

```typescript
// app/api/users/route.ts
import { apiLimiter, strictLimiter } from '@/lib/rate-limit'

export const GET = apiLimiter(async (req) => {
  // ...
})

export const POST = strictLimiter(async (req) => {
  // ...
})
```

## Rate Limiting

### Basic Usage

The `withRateLimit` higher-order function wraps your route handler:

```typescript
import { withRateLimit } from 'nextjs-secure'

export const GET = withRateLimit(handler, {
  limit: 100,        // Max requests allowed
  window: '15m',     // Time window
})
```

**Window formats:**
- Seconds: `'30s'`, `'120s'`
- Minutes: `'15m'`, `'60m'`
- Hours: `'1h'`, `'24h'`
- Days: `'1d'`, `'7d'`
- Combined: `'1h 30m'`
- Milliseconds: `900000`

### Algorithms

#### Sliding Window (Default)

Prevents request bursts at window boundaries. Uses weighted counting between current and previous windows.

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  algorithm: 'sliding-window', // default
})
```

**How it works:**
```
Window 1: |----[80 requests]-----|
Window 2: |--[30 requests]-------|
                    ^ 50% through window 2

Weighted count = 30 + (80 × 0.5) = 70 requests
```

#### Fixed Window

Simple counter that resets at fixed intervals. Lower memory usage but allows bursts at boundaries.

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '1m',
  algorithm: 'fixed-window',
})
```

**Burst scenario:**
```
Window 1: |------------------[100]|  <- 100 requests at :59
Window 2: |[100]------------------|  <- 100 requests at :00
          200 requests in 2 seconds!
```

#### Token Bucket

Allows controlled bursts while maintaining average rate. Tokens refill continuously.

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,      // Bucket capacity
  window: '1m',    // Full refill time
  algorithm: 'token-bucket',
})
```

**Use case:** APIs where occasional bursts are acceptable but average rate must be controlled.

### Storage Backends

#### Memory Store (Default)

Built-in, zero-config. Perfect for development and single-instance deployments.

```typescript
import { withRateLimit, MemoryStore } from 'nextjs-secure'

const store = new MemoryStore({
  cleanupInterval: 60000,  // Cleanup every minute
  maxKeys: 10000,          // LRU eviction after 10k keys
})

export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  store,
})
```

**Limitations:**
- Data lost on restart
- Not shared between instances
- Not suitable for serverless (cold starts)

#### Redis Store

For distributed deployments. Works with ioredis, node-redis, or any compatible client.

```typescript
import Redis from 'ioredis'
import { withRateLimit, createRedisStore } from 'nextjs-secure/rate-limit'

const redis = new Redis(process.env.REDIS_URL)

const store = createRedisStore({
  client: redis,
  prefix: 'myapp:rl',  // Key prefix
})

export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  store,
})
```

**Features:**
- Atomic operations via Lua scripts
- Automatic key expiration
- Cluster-ready

#### Upstash Store

Optimized for serverless and edge. Uses HTTP-based Redis.

```typescript
import { withRateLimit, createUpstashStore } from 'nextjs-secure/rate-limit'

const store = createUpstashStore({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
})

export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  store,
})

// Or from environment variables
import { createUpstashStoreFromEnv } from 'nextjs-secure/rate-limit'
const store = createUpstashStoreFromEnv()
```

**Benefits:**
- No TCP connections
- Works on Edge Runtime
- Global distribution support

### Custom Identifiers

By default, rate limiting is per-IP. Customize with the `identifier` option:

#### By API Key

```typescript
export const GET = withRateLimit(handler, {
  limit: 1000,
  window: '1h',
  identifier: (req) => {
    return req.headers.get('x-api-key') ?? 'anonymous'
  },
})
```

#### By User ID

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  identifier: async (req) => {
    const session = await getSession(req)
    return session?.userId ?? getClientIp(req)
  },
})
```

#### By Route + IP

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  identifier: (req) => {
    const ip = req.headers.get('x-forwarded-for') ?? '127.0.0.1'
    return `${req.nextUrl.pathname}:${ip}`
  },
})
```

### Response Customization

#### Custom Error Response

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  onLimit: (req, info) => {
    return Response.json(
      {
        error: 'rate_limit_exceeded',
        message: `Too many requests. Try again in ${info.retryAfter} seconds.`,
        limit: info.limit,
        reset: new Date(info.reset * 1000).toISOString(),
      },
      { status: 429 }
    )
  },
})
```

#### Skip Certain Requests

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  skip: (req) => {
    // Skip for internal services
    const key = req.headers.get('x-internal-key')
    return key === process.env.INTERNAL_API_KEY
  },
})
```

#### Disable Headers

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  headers: false,  // Don't add X-RateLimit-* headers
})
```

### Response Headers

When `headers: true` (default), responses include:

| Header | Description | Example |
|--------|-------------|---------|
| `X-RateLimit-Limit` | Maximum requests allowed | `100` |
| `X-RateLimit-Remaining` | Requests remaining | `95` |
| `X-RateLimit-Reset` | Unix timestamp when limit resets | `1699999999` |
| `Retry-After` | Seconds until retry (only on 429) | `60` |

### Manual Rate Limit Check

For existing handlers or complex logic:

```typescript
import { checkRateLimit } from 'nextjs-secure'

export async function GET(request: NextRequest) {
  const { success, info, headers } = await checkRateLimit(request, {
    limit: 100,
    window: '15m',
  })

  if (!success) {
    return Response.json(
      { error: 'Rate limited' },
      { status: 429, headers }
    )
  }

  // Your logic here
  return Response.json({ data: '...' }, { headers })
}
```

## CSRF Protection

Protect your forms against Cross-Site Request Forgery attacks using the double submit cookie pattern.

### Basic Setup

```typescript
// app/api/csrf/route.ts - Token endpoint
import { generateCSRF } from 'nextjs-secure/csrf'

export async function GET() {
  const { token, cookieHeader } = await generateCSRF()

  return Response.json(
    { csrfToken: token },
    { headers: { 'Set-Cookie': cookieHeader } }
  )
}
```

```typescript
// app/api/submit/route.ts - Protected endpoint
import { withCSRF } from 'nextjs-secure/csrf'

export const POST = withCSRF(async (req) => {
  const data = await req.json()
  // Safe to process - CSRF validated
  return Response.json({ success: true })
})
```

### Client-Side Usage

```typescript
// Fetch token on page load
const { csrfToken } = await fetch('/api/csrf').then(r => r.json())

// Include in form submissions
fetch('/api/submit', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-csrf-token': csrfToken  // Token in header
  },
  body: JSON.stringify({ data: '...' })
})
```

Or include in form body:

```typescript
fetch('/api/submit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    _csrf: csrfToken,  // Token in body
    data: '...'
  })
})
```

### Configuration

```typescript
import { withCSRF } from 'nextjs-secure/csrf'

export const POST = withCSRF(handler, {
  // Cookie settings
  cookie: {
    name: '__csrf',        // Cookie name
    httpOnly: true,        // Not accessible via JS
    secure: true,          // HTTPS only
    sameSite: 'strict',    // Strict same-site policy
    maxAge: 86400          // 24 hours
  },

  // Where to look for token
  headerName: 'x-csrf-token',  // Header name
  fieldName: '_csrf',          // Body field name

  // Token settings
  secret: process.env.CSRF_SECRET,  // Signing secret
  tokenLength: 32,                   // Token size in bytes

  // Protected methods (default: POST, PUT, PATCH, DELETE)
  protectedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],

  // Skip protection conditionally
  skip: (req) => req.headers.get('x-api-key') === 'trusted',

  // Custom error response
  onError: (req, reason) => {
    return new Response(`CSRF failed: ${reason}`, { status: 403 })
  }
})
```

### Manual Validation

```typescript
import { validateCSRF } from 'nextjs-secure/csrf'

export async function POST(req) {
  const result = await validateCSRF(req)

  if (!result.valid) {
    console.log('CSRF failed:', result.reason)
    // reason: 'missing_cookie' | 'invalid_cookie' | 'missing_token' | 'token_mismatch'
    return Response.json({ error: result.reason }, { status: 403 })
  }

  // Continue processing
}
```

### Environment Variable

Set `CSRF_SECRET` in your environment:

```env
CSRF_SECRET=your-secret-key-min-32-chars-recommended
```

## Security Headers

Add security headers to your responses with pre-configured presets or custom configuration.

### Quick Start

```typescript
import { withSecurityHeaders } from 'nextjs-secure/headers'

// Use strict preset (default)
export const GET = withSecurityHeaders(async (req) => {
  return Response.json({ data: 'protected' })
})
```

### Presets

Three presets available: `strict`, `relaxed`, `api`

```typescript
// Strict: Maximum security (default)
export const GET = withSecurityHeaders(handler, { preset: 'strict' })

// Relaxed: Development-friendly, allows inline scripts
export const GET = withSecurityHeaders(handler, { preset: 'relaxed' })

// API: Optimized for JSON APIs
export const GET = withSecurityHeaders(handler, { preset: 'api' })
```

### Custom Configuration

```typescript
import { withSecurityHeaders } from 'nextjs-secure/headers'

export const GET = withSecurityHeaders(handler, {
  config: {
    // Content-Security-Policy
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
    },

    // Strict-Transport-Security
    strictTransportSecurity: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },

    // Other headers
    xFrameOptions: 'DENY',           // or 'SAMEORIGIN'
    xContentTypeOptions: true,        // X-Content-Type-Options: nosniff
    referrerPolicy: 'strict-origin-when-cross-origin',

    // Cross-Origin headers
    crossOriginOpenerPolicy: 'same-origin',
    crossOriginEmbedderPolicy: 'require-corp',
    crossOriginResourcePolicy: 'same-origin',

    // Permissions-Policy (disable features)
    permissionsPolicy: {
      camera: [],
      microphone: [],
      geolocation: [],
    },
  }
})
```

### Disable Specific Headers

```typescript
export const GET = withSecurityHeaders(handler, {
  config: {
    contentSecurityPolicy: false,  // Disable CSP
    xFrameOptions: false,          // Disable X-Frame-Options
  }
})
```

### Manual Header Creation

```typescript
import { createSecurityHeaders } from 'nextjs-secure/headers'

export async function GET() {
  const headers = createSecurityHeaders({ preset: 'api' })

  return new Response(JSON.stringify({ ok: true }), {
    headers,
  })
}
```

### Available Headers

| Header | Description |
|--------|-------------|
| Content-Security-Policy | Controls resources the page can load |
| Strict-Transport-Security | Forces HTTPS connections |
| X-Frame-Options | Prevents clickjacking |
| X-Content-Type-Options | Prevents MIME sniffing |
| Referrer-Policy | Controls referrer information |
| Permissions-Policy | Disables browser features |
| Cross-Origin-Opener-Policy | Isolates browsing context |
| Cross-Origin-Embedder-Policy | Controls embedding |
| Cross-Origin-Resource-Policy | Controls resource sharing |

## Authentication

Flexible authentication middleware supporting JWT, API keys, session cookies, and role-based access control.

### JWT Authentication

```typescript
import { withJWT } from 'nextjs-secure/auth'

export const GET = withJWT(
  async (req, ctx) => {
    // ctx.user contains the authenticated user
    return Response.json({ user: ctx.user })
  },
  {
    secret: process.env.JWT_SECRET,
    // or use publicKey for RS256/ES256
  }
)
```

#### Configuration

```typescript
export const GET = withJWT(handler, {
  // Secret for HMAC algorithms (HS256, HS384, HS512)
  secret: process.env.JWT_SECRET,

  // Public key for RSA/ECDSA (RS256, ES256, etc.)
  publicKey: process.env.JWT_PUBLIC_KEY,

  // Allowed algorithms (default: ['HS256'])
  algorithms: ['HS256', 'RS256'],

  // Validate issuer
  issuer: 'https://myapp.com',
  // or multiple issuers
  issuer: ['https://auth.myapp.com', 'https://api.myapp.com'],

  // Validate audience
  audience: 'my-api',

  // Clock tolerance in seconds (for exp/nbf claims)
  clockTolerance: 30,

  // Custom token extraction
  getToken: (req) => req.headers.get('x-auth-token'),

  // Custom user mapping from JWT payload
  mapUser: (payload) => ({
    id: payload.sub,
    email: payload.email,
    roles: payload.roles || [],
  }),
})
```

### API Key Authentication

```typescript
import { withAPIKey } from 'nextjs-secure/auth'

export const GET = withAPIKey(
  async (req, ctx) => {
    return Response.json({ user: ctx.user })
  },
  {
    validate: async (apiKey, req) => {
      // Return user object if valid, null if invalid
      const user = await db.users.findByApiKey(apiKey)
      return user || null
    },
  }
)
```

#### Configuration

```typescript
export const GET = withAPIKey(handler, {
  // Required: validation function
  validate: async (apiKey, req) => {
    // Lookup API key and return user or null
    return db.apiKeys.findUser(apiKey)
  },

  // Header name (default: 'x-api-key')
  headerName: 'x-api-key',

  // Query parameter name (default: 'api_key')
  queryParam: 'api_key',
})
```

API keys can be sent via header or query parameter:
```bash
# Via header
curl -H "x-api-key: YOUR_API_KEY" https://api.example.com/data

# Via query parameter
curl https://api.example.com/data?api_key=YOUR_API_KEY
```

### Session Authentication

```typescript
import { withSession } from 'nextjs-secure/auth'

export const GET = withSession(
  async (req, ctx) => {
    return Response.json({ user: ctx.user })
  },
  {
    validate: async (sessionId, req) => {
      // Return user object if session valid, null if invalid
      const session = await db.sessions.find(sessionId)
      return session?.user || null
    },
  }
)
```

#### Configuration

```typescript
export const GET = withSession(handler, {
  // Required: session validation function
  validate: async (sessionId, req) => {
    const session = await redis.get(`session:${sessionId}`)
    if (!session) return null
    return JSON.parse(session)
  },

  // Cookie name (default: 'session')
  cookieName: 'session',
})
```

### Role-Based Access Control

Use `withRoles` after an authentication middleware to enforce role/permission requirements.

```typescript
import { withJWT, withRoles } from 'nextjs-secure/auth'

// Chain with JWT auth
const authenticatedHandler = withJWT(
  withRoles(
    async (req, ctx) => {
      return Response.json({ admin: true })
    },
    { roles: ['admin'] }
  ),
  { secret: process.env.JWT_SECRET }
)

export const GET = authenticatedHandler
```

#### Configuration

```typescript
withRoles(handler, {
  // Required roles (any match = authorized)
  roles: ['admin', 'moderator'],

  // Required permissions (all must match)
  permissions: ['read', 'write'],

  // Custom role extraction
  getUserRoles: (user) => user.roles || [],

  // Custom permission extraction
  getUserPermissions: (user) => user.permissions || [],

  // Custom authorization logic
  authorize: async (user, req) => {
    // Return true if authorized, false otherwise
    return user.subscriptionTier === 'pro'
  },
})
```

### Combined Authentication

Use `withAuth` for flexible multi-strategy authentication:

```typescript
import { withAuth } from 'nextjs-secure/auth'

export const GET = withAuth(
  async (req, ctx) => {
    // Authenticated via any method
    return Response.json({ user: ctx.user })
  },
  {
    // Try JWT first
    jwt: {
      secret: process.env.JWT_SECRET,
    },

    // Fall back to API key
    apiKey: {
      validate: (key) => db.apiKeys.findUser(key),
    },

    // Fall back to session
    session: {
      validate: (id) => db.sessions.findUser(id),
    },

    // Optional RBAC
    rbac: {
      roles: ['user', 'admin'],
    },

    // Callbacks
    onSuccess: async (req, user) => {
      // Log successful auth
      console.log(`Authenticated: ${user.id}`)
    },

    onError: (req, error) => {
      // Custom error response
      return Response.json({ error: error.message }, { status: error.status })
    },
  }
)
```

### Optional Authentication

For routes that work with or without authentication:

```typescript
import { withOptionalAuth } from 'nextjs-secure/auth'

export const GET = withOptionalAuth(
  async (req, ctx) => {
    if (ctx.user) {
      // Authenticated user
      return Response.json({ user: ctx.user })
    }
    // Anonymous access
    return Response.json({ guest: true })
  },
  {
    jwt: { secret: process.env.JWT_SECRET },
  }
)
```

### JWT Utilities

```typescript
import { verifyJWT, decodeJWT, extractBearerToken } from 'nextjs-secure/auth'

// Verify and decode JWT
const { payload, error } = await verifyJWT(token, {
  secret: process.env.JWT_SECRET,
  issuer: 'myapp',
})

if (error) {
  console.log(error.code) // 'expired_token', 'invalid_signature', etc.
}

// Decode without verification (for inspection only)
const decoded = decodeJWT(token)
// { header, payload, signature }

// Extract token from Authorization header
const token = extractBearerToken(req.headers.get('authorization'))
// 'Bearer xxx' -> 'xxx'
```

## Utilities

### Duration Parsing

```typescript
import { parseDuration, formatDuration } from 'nextjs-secure'

parseDuration('15m')        // 900000
parseDuration('1h 30m')     // 5400000
parseDuration('2d')         // 172800000

formatDuration(900000)      // '15m'
formatDuration(5400000)     // '1h 30m'
formatDuration(90061000)    // '1d 1h 1m 1s'
```

### IP Utilities

```typescript
import { getClientIp, anonymizeIp, isPrivateIp } from 'nextjs-secure'

// Extract client IP from request
const ip = getClientIp(request)

// Handles: cf-connecting-ip, x-real-ip, x-forwarded-for, etc.
const ip = getClientIp(request, {
  trustProxy: true,
  customHeaders: ['x-custom-ip'],
  fallback: '0.0.0.0',
})

// Anonymize for logging (GDPR compliant)
anonymizeIp('192.168.1.100')  // '192.168.1.xxx'

// Check if private
isPrivateIp('192.168.1.1')    // true
isPrivateIp('8.8.8.8')        // false
```

## API Reference

### `withRateLimit(handler, config)`

Wraps a route handler with rate limiting.

```typescript
interface RateLimitConfig {
  limit: number
  window: string | number
  algorithm?: 'sliding-window' | 'fixed-window' | 'token-bucket'
  identifier?: 'ip' | 'user' | ((req: NextRequest) => string | Promise<string>)
  store?: RateLimitStore
  headers?: boolean
  skip?: (req: NextRequest) => boolean | Promise<boolean>
  onLimit?: (req: NextRequest, info: RateLimitInfo) => Response | Promise<Response>
  prefix?: string
  message?: string
  statusCode?: number
}
```

### `createRateLimiter(config)`

Creates a reusable rate limiter function.

### `checkRateLimit(request, config)`

Manually check rate limit without wrapping.

Returns:
```typescript
{
  success: boolean
  info: RateLimitInfo
  headers: Headers
  response?: Response  // Only if rate limited
}
```

### `RateLimitInfo`

```typescript
interface RateLimitInfo {
  limit: number      // Max requests
  remaining: number  // Requests left
  reset: number      // Unix timestamp
  limited: boolean   // Whether rate limited
  retryAfter?: number // Seconds until retry
}
```

## Examples

### Different Limits per HTTP Method

```typescript
// app/api/posts/route.ts
import { withRateLimit } from 'nextjs-secure'

// Generous limit for reads
export const GET = withRateLimit(getHandler, {
  limit: 1000,
  window: '15m',
})

// Strict limit for writes
export const POST = withRateLimit(postHandler, {
  limit: 10,
  window: '1m',
})

// Very strict for deletes
export const DELETE = withRateLimit(deleteHandler, {
  limit: 5,
  window: '1h',
})
```

### Tiered Rate Limiting

```typescript
// lib/rate-limit.ts
import { createRateLimiter, createUpstashStore } from 'nextjs-secure/rate-limit'

const store = createUpstashStore({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
})

// Free tier: 100 req/day
export const freeLimiter = createRateLimiter({
  limit: 100,
  window: '1d',
  store,
  identifier: async (req) => {
    const apiKey = req.headers.get('x-api-key')
    return `free:${apiKey}`
  },
})

// Pro tier: 10000 req/day
export const proLimiter = createRateLimiter({
  limit: 10000,
  window: '1d',
  store,
  identifier: async (req) => {
    const apiKey = req.headers.get('x-api-key')
    return `pro:${apiKey}`
  },
})
```

### With Authentication

```typescript
import { withRateLimit } from 'nextjs-secure'
import { getServerSession } from 'next-auth'

export const GET = withRateLimit(
  async (req, ctx) => {
    const session = await getServerSession()

    if (!session) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 })
    }

    return Response.json({ user: session.user })
  },
  {
    limit: 100,
    window: '15m',
    identifier: async (req) => {
      const session = await getServerSession()
      return session?.user?.id ?? 'anonymous'
    },
  }
)
```

### Webhook Endpoint

```typescript
import { withRateLimit } from 'nextjs-secure'
import { headers } from 'next/headers'
import crypto from 'crypto'

export const POST = withRateLimit(
  async (req) => {
    const body = await req.text()
    const signature = headers().get('x-webhook-signature')

    // Verify signature
    const expected = crypto
      .createHmac('sha256', process.env.WEBHOOK_SECRET!)
      .update(body)
      .digest('hex')

    if (signature !== expected) {
      return Response.json({ error: 'Invalid signature' }, { status: 401 })
    }

    // Process webhook
    const data = JSON.parse(body)
    await processWebhook(data)

    return Response.json({ received: true })
  },
  {
    limit: 1000,
    window: '1m',
    identifier: (req) => {
      // Rate limit by webhook source
      return req.headers.get('x-webhook-source') ?? 'unknown'
    },
  }
)
```

## Roadmap

- [x] Rate Limiting (v0.1.0)
  - [x] Sliding window algorithm
  - [x] Fixed window algorithm
  - [x] Token bucket algorithm
  - [x] Memory store
  - [x] Redis store
  - [x] Upstash store
- [x] CSRF Protection (v0.2.0)
  - [x] Double submit cookie pattern
  - [x] Token generation/validation
  - [x] Configurable cookie settings
- [x] Security Headers (v0.3.0)
  - [x] Content-Security-Policy
  - [x] Strict-Transport-Security
  - [x] X-Frame-Options, X-Content-Type-Options
  - [x] Permissions-Policy
  - [x] COOP, COEP, CORP
  - [x] Presets (strict, relaxed, api)
- [x] Authentication (v0.4.0)
  - [x] JWT validation (HS256, RS256, ES256)
  - [x] API Key authentication
  - [x] Session/Cookie authentication
  - [x] Role-Based Access Control (RBAC)
  - [x] Combined multi-strategy auth
- [ ] Input Validation (v0.5.0)
- [ ] Audit Logging (v0.6.0)

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

```bash
# Clone
git clone https://github.com/alpgurlee/next-secure.git
cd next-secure

# Install
npm install

# Test
npm test

# Build
npm run build
```

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Star this repo** if you find it useful!
