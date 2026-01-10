# next-secure

[![npm version](https://badge.fury.io/js/next-secure.svg)](https://www.npmjs.com/package/next-secure)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-13+-black.svg)](https://nextjs.org/)

Production-ready security middleware for Next.js App Router. Zero config, maximum protection.

```typescript
import { withRateLimit } from 'next-secure'

export const GET = withRateLimit(
  async (req) => Response.json({ message: 'Hello!' }),
  { limit: 100, window: '15m' }
)
```

## Why next-secure?

Building secure APIs in Next.js shouldn't require hours of boilerplate. Most projects end up with copy-pasted rate limiting code, inconsistent error handling, and security gaps.

**next-secure** provides battle-tested security primitives that work out of the box:

- **Zero Configuration** - Sensible defaults, works immediately
- **Type Safe** - Full TypeScript support with generics
- **Edge Ready** - Works on Vercel Edge, Cloudflare Workers, Node.js
- **Flexible** - Memory, Redis, or Upstash storage backends
- **Lightweight** - No bloated dependencies, tree-shakeable

## Installation

```bash
npm install next-secure
# or
yarn add next-secure
# or
pnpm add next-secure
```

## Table of Contents

- [Quick Start](#quick-start)
- [Rate Limiting](#rate-limiting)
  - [Basic Usage](#basic-usage)
  - [Algorithms](#algorithms)
  - [Storage Backends](#storage-backends)
  - [Custom Identifiers](#custom-identifiers)
  - [Response Customization](#response-customization)
- [Utilities](#utilities)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

## Quick Start

### Protect an API Route

```typescript
// app/api/posts/route.ts
import { withRateLimit } from 'next-secure'

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
import { createRateLimiter } from 'next-secure'

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
import { withRateLimit } from 'next-secure'

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
import { withRateLimit, MemoryStore } from 'next-secure'

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
import { withRateLimit, createRedisStore } from 'next-secure/rate-limit'

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
import { withRateLimit, createUpstashStore } from 'next-secure/rate-limit'

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
import { createUpstashStoreFromEnv } from 'next-secure/rate-limit'
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
import { checkRateLimit } from 'next-secure'

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

## Utilities

### Duration Parsing

```typescript
import { parseDuration, formatDuration } from 'next-secure'

parseDuration('15m')        // 900000
parseDuration('1h 30m')     // 5400000
parseDuration('2d')         // 172800000

formatDuration(900000)      // '15m'
formatDuration(5400000)     // '1h 30m'
formatDuration(90061000)    // '1d 1h 1m 1s'
```

### IP Utilities

```typescript
import { getClientIp, anonymizeIp, isPrivateIp } from 'next-secure'

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
import { withRateLimit } from 'next-secure'

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
import { createRateLimiter, createUpstashStore } from 'next-secure/rate-limit'

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
import { withRateLimit } from 'next-secure'
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
import { withRateLimit } from 'next-secure'
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
- [ ] Authentication (v0.2.0)
  - [ ] JWT validation
  - [ ] Supabase provider
  - [ ] NextAuth provider
  - [ ] Clerk provider
  - [ ] RBAC support
- [ ] CSRF Protection (v0.3.0)
- [ ] Security Headers (v0.4.0)
- [ ] Input Validation (v0.5.0)
- [ ] Audit Logging (v0.6.0)

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

```bash
# Clone
git clone https://github.com/alpgu/next-secure.git
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
