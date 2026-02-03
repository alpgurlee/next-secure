# nextjs-secure

[![npm version](https://badge.fury.io/js/nextjs-secure.svg)](https://www.npmjs.com/package/nextjs-secure)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-13+-black.svg)](https://nextjs.org/)
[![Tests](https://img.shields.io/badge/tests-709%20passing-brightgreen.svg)]()

Production-ready security middleware for Next.js 13+ App Router. Zero config, maximum protection.

```typescript
import { withRateLimit, withJWT, withValidation } from 'nextjs-secure'

export const POST = withRateLimit(
  withJWT(
    withValidation(handler, { body: schema }),
    { secret: process.env.JWT_SECRET }
  ),
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
- **Complete** - Rate limiting, auth, CSRF, headers, validation, audit logging

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
- [CSRF Protection](#csrf-protection)
- [Security Headers](#security-headers)
- [Authentication](#authentication)
- [Input Validation](#input-validation)
- [Audit Logging](#audit-logging)
- [Bot Detection](#bot-detection)
- [API Security](#api-security)
- [Utilities](#utilities)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

---

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
  { limit: 100, window: '15m' }
)
```

### Full Security Stack

```typescript
// app/api/admin/users/route.ts
import { withRateLimit, withJWT, withRoles, withValidation, withAuditLog } from 'nextjs-secure'
import { MemoryStore } from 'nextjs-secure/audit'

const auditStore = new MemoryStore({ maxEntries: 1000 })

const schema = {
  email: { type: 'email', required: true },
  role: { type: 'string', enum: ['user', 'admin'] }
}

export const POST = withAuditLog(
  withRateLimit(
    withJWT(
      withRoles(
        withValidation(
          async (req, ctx) => {
            // ctx.user = authenticated user
            // ctx.validated = validated body
            return Response.json({ success: true })
          },
          { body: schema }
        ),
        { roles: ['admin'] }
      ),
      { secret: process.env.JWT_SECRET }
    ),
    { limit: 10, window: '1m' }
  ),
  { store: auditStore }
)
```

---

## Rate Limiting

Protect your APIs from abuse with configurable rate limiting.

### Basic Usage

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
Prevents request bursts at window boundaries.

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  algorithm: 'sliding-window',
})
```

#### Fixed Window
Simple counter that resets at fixed intervals.

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '1m',
  algorithm: 'fixed-window',
})
```

#### Token Bucket
Allows controlled bursts while maintaining average rate.

```typescript
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '1m',
  algorithm: 'token-bucket',
})
```

### Storage Backends

#### Memory Store (Default)

```typescript
import { withRateLimit, MemoryStore } from 'nextjs-secure'

const store = new MemoryStore({
  cleanupInterval: 60000,
  maxKeys: 10000,
})

export const GET = withRateLimit(handler, { limit: 100, window: '15m', store })
```

#### Redis Store

```typescript
import Redis from 'ioredis'
import { withRateLimit, createRedisStore } from 'nextjs-secure/rate-limit'

const redis = new Redis(process.env.REDIS_URL)
const store = createRedisStore({ client: redis, prefix: 'myapp:rl' })

export const GET = withRateLimit(handler, { limit: 100, window: '15m', store })
```

#### Upstash Store (Edge/Serverless)

```typescript
import { withRateLimit, createUpstashStore } from 'nextjs-secure/rate-limit'

const store = createUpstashStore({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
})

export const GET = withRateLimit(handler, { limit: 100, window: '15m', store })
```

### Custom Identifiers

```typescript
// By API Key
export const GET = withRateLimit(handler, {
  limit: 1000,
  window: '1h',
  identifier: (req) => req.headers.get('x-api-key') ?? 'anonymous',
})

// By User ID
export const GET = withRateLimit(handler, {
  limit: 100,
  window: '15m',
  identifier: async (req) => {
    const session = await getSession(req)
    return session?.userId ?? getClientIp(req)
  },
})
```

### Response Headers

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed |
| `X-RateLimit-Remaining` | Requests remaining |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |
| `Retry-After` | Seconds until retry (only on 429) |

---

## CSRF Protection

Protect forms against Cross-Site Request Forgery attacks.

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
    'x-csrf-token': csrfToken
  },
  body: JSON.stringify({ data: '...' })
})
```

### Configuration

```typescript
export const POST = withCSRF(handler, {
  cookie: {
    name: '__csrf',
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 86400
  },
  headerName: 'x-csrf-token',
  fieldName: '_csrf',
  secret: process.env.CSRF_SECRET,
  skip: (req) => req.headers.get('x-api-key') === 'trusted',
})
```

---

## Security Headers

Add security headers to protect against common attacks.

### Quick Start

```typescript
import { withSecurityHeaders } from 'nextjs-secure/headers'

export const GET = withSecurityHeaders(handler)
```

### Presets

```typescript
// Strict: Maximum security (default)
export const GET = withSecurityHeaders(handler, { preset: 'strict' })

// Relaxed: Development-friendly
export const GET = withSecurityHeaders(handler, { preset: 'relaxed' })

// API: Optimized for JSON APIs
export const GET = withSecurityHeaders(handler, { preset: 'api' })
```

### Custom Configuration

```typescript
export const GET = withSecurityHeaders(handler, {
  config: {
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
    xContentTypeOptions: true,
    referrerPolicy: 'strict-origin-when-cross-origin',
    permissionsPolicy: {
      camera: [],
      microphone: [],
      geolocation: [],
    },
  }
})
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

---

## Authentication

Flexible authentication supporting JWT, API keys, sessions, and RBAC.

### JWT Authentication

```typescript
import { withJWT } from 'nextjs-secure/auth'

export const GET = withJWT(
  async (req, ctx) => {
    return Response.json({ user: ctx.user })
  },
  {
    secret: process.env.JWT_SECRET,
    algorithms: ['HS256', 'RS256'],
    issuer: 'https://myapp.com',
    audience: 'my-api',
  }
)
```

### API Key Authentication

```typescript
import { withAPIKey } from 'nextjs-secure/auth'

export const GET = withAPIKey(
  async (req, ctx) => {
    return Response.json({ user: ctx.user })
  },
  {
    validate: async (apiKey) => {
      const user = await db.users.findByApiKey(apiKey)
      return user || null
    },
    headerName: 'x-api-key',
    queryParam: 'api_key',
  }
)
```

### Session Authentication

```typescript
import { withSession } from 'nextjs-secure/auth'

export const GET = withSession(
  async (req, ctx) => {
    return Response.json({ user: ctx.user })
  },
  {
    validate: async (sessionId) => {
      const session = await db.sessions.find(sessionId)
      return session?.user || null
    },
    cookieName: 'session',
  }
)
```

### Role-Based Access Control

```typescript
import { withJWT, withRoles } from 'nextjs-secure/auth'

export const GET = withJWT(
  withRoles(
    async (req, ctx) => {
      return Response.json({ admin: true })
    },
    {
      roles: ['admin', 'moderator'],
      permissions: ['users:read', 'users:write'],
    }
  ),
  { secret: process.env.JWT_SECRET }
)
```

### Combined Authentication

```typescript
import { withAuth } from 'nextjs-secure/auth'

export const GET = withAuth(
  async (req, ctx) => {
    return Response.json({ user: ctx.user })
  },
  {
    jwt: { secret: process.env.JWT_SECRET },
    apiKey: { validate: (key) => db.apiKeys.findUser(key) },
    session: { validate: (id) => db.sessions.findUser(id) },
    rbac: { roles: ['user', 'admin'] },
  }
)
```

### Optional Authentication

```typescript
import { withOptionalAuth } from 'nextjs-secure/auth'

export const GET = withOptionalAuth(
  async (req, ctx) => {
    if (ctx.user) {
      return Response.json({ user: ctx.user })
    }
    return Response.json({ guest: true })
  },
  { jwt: { secret: process.env.JWT_SECRET } }
)
```

---

## Input Validation

Validate and sanitize user input to prevent attacks.

### Schema Validation

```typescript
import { withValidation } from 'nextjs-secure/validation'

// Built-in schema
const schema = {
  email: { type: 'email', required: true },
  password: { type: 'string', minLength: 8, maxLength: 100 },
  age: { type: 'number', min: 18, max: 120 },
  role: { type: 'string', enum: ['user', 'admin'] },
}

export const POST = withValidation(handler, { body: schema })

// Or use Zod
import { z } from 'zod'

const zodSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
})

export const POST = withValidation(handler, { body: zodSchema })
```

### XSS Protection

```typescript
import { withXSSProtection, withSanitization, sanitize, detectXSS } from 'nextjs-secure/validation'

// Block XSS attempts
export const POST = withXSSProtection(handler)

// Sanitize specific fields
export const POST = withSanitization(handler, {
  fields: ['content', 'bio'],
  mode: 'escape', // 'escape' | 'strip' | 'allow-safe'
})

// Manual sanitization
const clean = sanitize(userInput, {
  mode: 'allow-safe',
  allowedTags: ['b', 'i', 'em', 'strong'],
})

// Detection only
const { hasXSS, matches } = detectXSS(input)
```

### SQL Injection Protection

```typescript
import { withSQLProtection, detectSQLInjection, hasSQLInjection } from 'nextjs-secure/validation'

// Block SQL injection
export const POST = withSQLProtection(handler, {
  mode: 'block', // 'block' | 'detect'
  minSeverity: 'medium', // 'low' | 'medium' | 'high'
})

// Manual detection
const result = detectSQLInjection(input)
// { hasSQLi: true, severity: 'high', patterns: ['UNION SELECT'] }

// Simple check
if (hasSQLInjection(input)) {
  // Block request
}
```

### Path Traversal Prevention

```typescript
import { validatePath, sanitizePath, sanitizeFilename } from 'nextjs-secure/validation'

// Validate path
const result = validatePath(userPath, {
  basePath: '/uploads',
  allowedExtensions: ['.jpg', '.png'],
  maxDepth: 3,
})

if (!result.valid) {
  console.log(result.reason) // 'traversal_detected', 'invalid_extension', etc.
}

// Sanitize
const safePath = sanitizePath('../../../etc/passwd') // 'etc/passwd'
const safeFilename = sanitizeFilename('../../evil.exe') // 'evil.exe'
```

### File Validation

```typescript
import { withFileValidation, validateFile } from 'nextjs-secure/validation'

export const POST = withFileValidation(handler, {
  maxSize: 5 * 1024 * 1024, // 5MB
  allowedTypes: ['image/jpeg', 'image/png', 'application/pdf'],
  validateMagicNumbers: true, // Check actual file content
  maxFiles: 10,
})

// Manual validation
const result = await validateFile(file, {
  maxSize: 5 * 1024 * 1024,
  allowedTypes: ['image/jpeg'],
})
```

### Combined Security Validation

```typescript
import { withSecureValidation } from 'nextjs-secure/validation'

export const POST = withSecureValidation(handler, {
  xss: true,
  sql: { minSeverity: 'medium' },
  contentType: ['application/json'],
})
```

---

## Audit Logging

Track requests and security events for monitoring and compliance.

### Request Logging

```typescript
import { withAuditLog, MemoryStore, ConsoleStore } from 'nextjs-secure/audit'

const store = new MemoryStore({ maxEntries: 1000 })

export const POST = withAuditLog(handler, {
  store,
  include: {
    ip: true,
    userAgent: true,
    headers: false,
    query: true,
    response: true,
    duration: true,
  },
  exclude: {
    paths: ['/health', '/metrics'],
    methods: ['OPTIONS'],
    statusCodes: [304],
  },
  pii: {
    fields: ['password', 'token', 'ssn', 'creditCard'],
    mode: 'mask', // 'mask' | 'hash' | 'remove'
  },
})
```

### Storage Backends

```typescript
import { MemoryStore, ConsoleStore, createDatadogStore, MultiStore } from 'nextjs-secure/audit'

// Memory (development)
const memoryStore = new MemoryStore({ maxEntries: 1000, ttl: 3600000 })

// Console (development)
const consoleStore = new ConsoleStore({ colorize: true, level: 'info' })

// Datadog (production)
const datadogStore = createDatadogStore({
  apiKey: process.env.DATADOG_API_KEY,
  service: 'my-api',
  environment: 'production',
})

// Multiple stores
const multiStore = new MultiStore([consoleStore, datadogStore])
```

### Security Event Tracking

```typescript
import { createSecurityTracker, trackSecurityEvent } from 'nextjs-secure/audit'

const tracker = createSecurityTracker({ store })

// Authentication failures
await tracker.authFailed({
  ip: '192.168.1.1',
  email: 'user@example.com',
  reason: 'Invalid password',
})

// Rate limit exceeded
await tracker.rateLimitExceeded({
  ip: '192.168.1.1',
  endpoint: '/api/login',
  limit: 10,
  window: '15m',
})

// XSS detected
await tracker.xssDetected({
  ip: '192.168.1.1',
  field: 'comment',
  endpoint: '/api/comments',
})

// SQL injection detected
await tracker.sqliDetected({
  ip: '192.168.1.1',
  field: 'username',
  pattern: 'UNION SELECT',
  severity: 'high',
  endpoint: '/api/users',
})

// CSRF validation failure
await tracker.csrfInvalid({
  ip: '192.168.1.1',
  endpoint: '/api/transfer',
  reason: 'Token mismatch',
})

// IP blocked
await tracker.ipBlocked({
  ip: '192.168.1.1',
  reason: 'Too many failed attempts',
  duration: 3600,
})

// Custom events
await tracker.custom({
  message: 'Suspicious activity detected',
  severity: 'high',
  details: { pattern: 'automated_scanning' },
})
```

### PII Redaction

```typescript
import { redactObject, redactEmail, redactCreditCard, redactIP, DEFAULT_PII_FIELDS } from 'nextjs-secure/audit'

// Redact object
const safeData = redactObject(userData, {
  fields: DEFAULT_PII_FIELDS,
  mode: 'mask',
})

// Specific redactors
redactEmail('john@example.com')     // '****@example.com'
redactCreditCard('4111111111111111') // '**** **** **** 1111'
redactIP('192.168.1.100')           // '192.168.*.*'
```

### Request ID & Timing

```typescript
import { withRequestId, withTiming } from 'nextjs-secure/audit'

// Add request ID to responses
export const GET = withRequestId(handler, {
  headerName: 'x-request-id',
  generateId: () => `req_${Date.now()}`,
})

// Add response timing
export const GET = withTiming(handler, {
  headerName: 'x-response-time',
  log: true,
})
```

### Log Formatters

```typescript
import { JSONFormatter, TextFormatter, CLFFormatter, StructuredFormatter } from 'nextjs-secure/audit'

// JSON (default)
const jsonFormatter = new JSONFormatter({ pretty: true })

// Human-readable text
const textFormatter = new TextFormatter({
  template: '{timestamp} [{level}] {message}',
})

// Apache/Nginx Common Log Format
const clfFormatter = new CLFFormatter()

// Key=value (ELK/Splunk)
const structuredFormatter = new StructuredFormatter({
  delimiter: ' ',
  kvSeparator: '=',
})
```

---

## Bot Detection

Protect your endpoints from automated bots, scrapers, and spam.

### Basic Usage

```typescript
import { withBotProtection } from 'nextjs-secure/bot'

export const POST = withBotProtection(handler, {
  userAgent: {
    blockAllBots: false,
    allowList: ['Googlebot', 'Bingbot'],
  },
  honeypot: true,
  behavior: {
    maxRequestsPerSecond: 10,
  },
})
```

### Presets

```typescript
import { withBotProtectionPreset } from 'nextjs-secure/bot'

// Relaxed: Only blocks obvious bots
export const GET = withBotProtectionPreset(handler, 'relaxed')

// Standard: Good balance (default)
export const GET = withBotProtectionPreset(handler, 'standard')

// Strict: Maximum protection
export const GET = withBotProtectionPreset(handler, 'strict')

// API: Optimized for API endpoints
export const GET = withBotProtectionPreset(handler, 'api')
```

### User-Agent Detection

```typescript
import { withUserAgentProtection, analyzeUserAgent, KNOWN_BOT_PATTERNS } from 'nextjs-secure/bot'

// Middleware
export const GET = withUserAgentProtection(handler, {
  blockAllBots: true,
  allowCategories: ['search_engine', 'social_media'],
  allowList: ['Googlebot', 'Twitterbot'],
  blockList: ['BadBot'],
})

// Manual detection
const result = analyzeUserAgent('Googlebot/2.1')
// { isBot: true, category: 'search_engine', name: 'Googlebot', confidence: 0.95 }
```

### Honeypot Protection

```typescript
import { withHoneypotProtection, generateHoneypotHTML, generateHoneypotCSS } from 'nextjs-secure/bot'

// Middleware
export const POST = withHoneypotProtection(handler, {
  fieldName: '_hp_email',
  additionalFields: ['_hp_name', '_hp_phone'],
})

// Generate HTML for forms
const honeypotHTML = generateHoneypotHTML({ fieldName: '_hp_email' })
// Returns hidden input fields

// Generate CSS
const honeypotCSS = generateHoneypotCSS({ fieldName: '_hp_email' })
// Returns CSS to hide fields
```

### Behavior Analysis

```typescript
import { withBehaviorProtection, MemoryBehaviorStore } from 'nextjs-secure/bot'

const store = new MemoryBehaviorStore()

export const GET = withBehaviorProtection(handler, {
  store,
  minRequestInterval: 100,    // Min ms between requests
  maxRequestsPerSecond: 10,   // Max requests per second
  patterns: {
    sequentialAccess: true,   // Detect sequential URL patterns
    regularTiming: true,      // Detect bot-like timing
    missingHeaders: true,     // Detect missing browser headers
  },
})
```

### CAPTCHA Integration

```typescript
import { withCaptchaProtection, verifyCaptcha } from 'nextjs-secure/bot'

// reCAPTCHA v3
export const POST = withCaptchaProtection(handler, {
  provider: 'recaptcha-v3',
  siteKey: process.env.RECAPTCHA_SITE_KEY,
  secretKey: process.env.RECAPTCHA_SECRET_KEY,
  threshold: 0.5,
})

// hCaptcha
export const POST = withCaptchaProtection(handler, {
  provider: 'hcaptcha',
  siteKey: process.env.HCAPTCHA_SITE_KEY,
  secretKey: process.env.HCAPTCHA_SECRET_KEY,
})

// Cloudflare Turnstile
export const POST = withCaptchaProtection(handler, {
  provider: 'turnstile',
  siteKey: process.env.TURNSTILE_SITE_KEY,
  secretKey: process.env.TURNSTILE_SECRET_KEY,
})

// Manual verification
const result = await verifyCaptcha(token, {
  provider: 'recaptcha-v3',
  secretKey: process.env.RECAPTCHA_SECRET_KEY,
})
```

### Manual Bot Detection

```typescript
import { detectBot } from 'nextjs-secure/bot'

const result = await detectBot(request, {
  userAgent: { blockAllBots: true },
  honeypot: true,
  behavior: { maxRequestsPerSecond: 10 },
})

if (result.isBot) {
  console.log(`Bot detected: ${result.reason}`)
  console.log(`Category: ${result.category}`)
  console.log(`Confidence: ${result.confidence}`)
}
```

### Bot Categories

| Category | Examples |
|----------|----------|
| `search_engine` | Googlebot, Bingbot, Yandex |
| `social_media` | Twitterbot, FacebookBot, LinkedInBot |
| `ai_crawler` | GPTBot, Claude-Web, Anthropic |
| `monitoring` | UptimeRobot, Pingdom |
| `feed_reader` | Feedly, Feedbin |
| `preview` | Slackbot, Discord |
| `scraper` | Scrapy, DataMiner |
| `spam` | Spam bots, malicious crawlers |
| `unknown` | Unidentified automated traffic |

---

## API Security

Protect your APIs with request signing, replay prevention, and versioning.

### Request Signing (HMAC)

Sign and verify requests using HMAC to prevent tampering.

```typescript
import { withRequestSigning, generateSignature } from 'nextjs-secure/api'

// Server: Verify signed requests
export const POST = withRequestSigning(handler, {
  secret: process.env.API_SECRET,
  algorithm: 'sha256', // or 'sha512'
  timestampTolerance: 300, // 5 minutes
})

// Client: Sign outgoing requests
const timestamp = Math.floor(Date.now() / 1000).toString()
const signature = await generateSignature(request, {
  secret: API_SECRET,
  algorithm: 'sha256',
})

fetch('/api/data', {
  method: 'POST',
  headers: {
    'x-timestamp': timestamp,
    'x-signature': signature,
  },
  body: JSON.stringify(data),
})
```

### Custom Signing Components

```typescript
export const POST = withRequestSigning(handler, {
  secret: process.env.API_SECRET,
  components: {
    method: true,
    path: true,
    query: true,
    body: true,
    timestamp: true,
  },
  signatureHeader: 'x-signature',
  timestampHeader: 'x-timestamp',
})
```

### Replay Prevention

Prevent replay attacks using nonces.

```typescript
import { withReplayPrevention, MemoryNonceStore, generateNonce } from 'nextjs-secure/api'

const store = new MemoryNonceStore({ maxSize: 10000, ttl: 300000 })

// Server: Block replay attacks
export const POST = withReplayPrevention(handler, {
  store,
  ttl: 300000, // 5 minutes
  required: true,
  nonceHeader: 'x-nonce',
})

// Client: Generate unique nonce
const nonce = generateNonce(32)
fetch('/api/payment', {
  method: 'POST',
  headers: { 'x-nonce': nonce },
  body: JSON.stringify(data),
})
```

### Timestamp Validation

Reject old or future-dated requests.

```typescript
import { withTimestamp, validateTimestamp } from 'nextjs-secure/api'

export const POST = withTimestamp(handler, {
  maxAge: 300, // 5 minutes
  format: 'unix', // 'unix' | 'unix-ms' | 'iso8601'
  required: true,
  allowFuture: false,
  timestampHeader: 'x-timestamp',
})

// Manual validation
const result = validateTimestamp(request, { maxAge: 300 })
if (!result.valid) {
  console.log(result.reason) // 'Timestamp too old'
}
```

### API Versioning

Manage API versions with deprecation support.

```typescript
import { withAPIVersion, createVersionRouter, extractVersion } from 'nextjs-secure/api'

// Single version validation
export const GET = withAPIVersion(handler, {
  current: 'v2',
  supported: ['v1', 'v2', 'v3'],
  deprecated: ['v1'],
  sunset: ['v0'],
  source: 'header', // 'header' | 'query' | 'path' | 'accept'
  addDeprecationHeaders: true,
})

// Version-based routing
const router = createVersionRouter({
  v1: v1Handler,
  v2: v2Handler,
  v3: v3Handler,
}, { default: 'v2' })

export const GET = router
```

### Idempotency Keys

Ensure safe retries for payment and critical operations.

```typescript
import { withIdempotency, MemoryIdempotencyStore, generateIdempotencyKey } from 'nextjs-secure/api'

const store = new MemoryIdempotencyStore({ maxSize: 10000 })

// Server: Handle idempotent requests
export const POST = withIdempotency(handler, {
  store,
  ttl: 86400000, // 24 hours
  required: true,
  keyHeader: 'idempotency-key',
  hashRequestBody: true, // Detect body mismatches
})

// Client: Use idempotency key
const key = generateIdempotencyKey()
fetch('/api/payment', {
  method: 'POST',
  headers: { 'idempotency-key': key },
  body: JSON.stringify(payment),
})
```

### Combined API Protection

Use presets for common security profiles.

```typescript
import { withAPIProtection, withAPIProtectionPreset } from 'nextjs-secure/api'

// Full configuration
export const POST = withAPIProtection(handler, {
  signing: {
    secret: process.env.API_SECRET,
    algorithm: 'sha256',
  },
  replay: {
    store: nonceStore,
    ttl: 300000,
  },
  timestamp: {
    maxAge: 300,
    required: true,
  },
  versioning: {
    current: 'v2',
    supported: ['v1', 'v2'],
  },
  idempotency: {
    store: idempotencyStore,
    required: true,
  },
})

// Presets
export const POST = withAPIProtectionPreset(handler, 'basic')    // Minimal
export const POST = withAPIProtectionPreset(handler, 'standard') // Balanced
export const POST = withAPIProtectionPreset(handler, 'strict')   // Maximum
export const POST = withAPIProtectionPreset(handler, 'financial') // Banking/Payment
```

### Preset Comparison

| Feature | Basic | Standard | Strict | Financial |
|---------|-------|----------|--------|-----------|
| Signing | ❌ | ❌ | SHA-256 | SHA-512 |
| Replay Prevention | ❌ | ✅ (5min) | ✅ (5min) | ✅ (24h) |
| Timestamp Validation | ✅ (10min) | ✅ (5min) | ✅ (5min) | ✅ (1min) |
| Idempotency | ❌ | ❌ | ✅ (1h) | ✅ (24h) |
| Versioning | ❌ | ❌ | ✅ | ✅ |

---

## Utilities

### Duration Parsing

```typescript
import { parseDuration, formatDuration } from 'nextjs-secure'

parseDuration('15m')        // 900000
parseDuration('1h 30m')     // 5400000
parseDuration('2d')         // 172800000

formatDuration(900000)      // '15m'
formatDuration(5400000)     // '1h 30m'
```

### IP Utilities

```typescript
import { getClientIp, anonymizeIp, isPrivateIp, isLocalhost } from 'nextjs-secure'

// Extract client IP
const ip = getClientIp(request, {
  trustProxy: true,
  customHeaders: ['x-custom-ip'],
})

// Anonymize for GDPR
anonymizeIp('192.168.1.100')  // '192.168.1.xxx'

// Check IP type
isPrivateIp('192.168.1.1')    // true
isPrivateIp('8.8.8.8')        // false
isLocalhost('127.0.0.1')      // true
```

---

## API Reference

### Rate Limiting

| Function | Description |
|----------|-------------|
| `withRateLimit(handler, config)` | Wrap handler with rate limiting |
| `createRateLimiter(config)` | Create reusable rate limiter |
| `checkRateLimit(request, config)` | Manual rate limit check |
| `getRateLimitStatus(key, config)` | Get current status without incrementing |
| `resetRateLimit(key, config)` | Reset rate limit for key |

### CSRF

| Function | Description |
|----------|-------------|
| `withCSRF(handler, config)` | Wrap handler with CSRF protection |
| `generateCSRF(config)` | Generate CSRF token and cookie |
| `validateCSRF(request, config)` | Manual CSRF validation |

### Security Headers

| Function | Description |
|----------|-------------|
| `withSecurityHeaders(handler, config)` | Add security headers |
| `createSecurityHeaders(config)` | Create headers object |
| `buildCSP(config)` | Build CSP header string |
| `getPreset(name)` | Get preset configuration |

### Authentication

| Function | Description |
|----------|-------------|
| `withJWT(handler, config)` | JWT authentication |
| `withAPIKey(handler, config)` | API key authentication |
| `withSession(handler, config)` | Session authentication |
| `withAuth(handler, config)` | Combined authentication |
| `withRoles(handler, config)` | Role-based access control |
| `withOptionalAuth(handler, config)` | Optional authentication |
| `verifyJWT(token, config)` | Verify JWT token |
| `decodeJWT(token)` | Decode JWT without verification |

### Validation

| Function | Description |
|----------|-------------|
| `withValidation(handler, config)` | Schema validation |
| `withXSSProtection(handler)` | Block XSS attempts |
| `withSanitization(handler, config)` | Sanitize input |
| `withSQLProtection(handler, config)` | Block SQL injection |
| `withFileValidation(handler, config)` | File upload validation |
| `sanitize(input, config)` | Manual sanitization |
| `detectXSS(input)` | Detect XSS patterns |
| `detectSQLInjection(input)` | Detect SQL injection |
| `validatePath(path, config)` | Validate file path |

### Audit Logging

| Function | Description |
|----------|-------------|
| `withAuditLog(handler, config)` | Request logging |
| `withRequestId(handler, config)` | Add request ID |
| `withTiming(handler, config)` | Add response timing |
| `createSecurityTracker(config)` | Create event tracker |
| `trackSecurityEvent(store, event)` | Track single event |
| `redactObject(obj, config)` | Redact PII from object |

### Bot Detection

| Function | Description |
|----------|-------------|
| `withBotProtection(handler, config)` | Combined bot protection |
| `withUserAgentProtection(handler, config)` | User-agent only protection |
| `withHoneypotProtection(handler, config)` | Honeypot only protection |
| `withBehaviorProtection(handler, config)` | Behavior analysis only |
| `withCaptchaProtection(handler, config)` | CAPTCHA verification |
| `withBotProtectionPreset(handler, preset)` | Use preset configuration |
| `detectBot(request, config)` | Manual bot detection |
| `analyzeUserAgent(userAgent, config)` | Analyze user-agent string |
| `checkHoneypot(request, config)` | Check honeypot fields |
| `checkBehavior(request, config)` | Check request behavior |
| `verifyCaptcha(token, config)` | Verify CAPTCHA token |
| `generateHoneypotHTML(config)` | Generate honeypot HTML |
| `generateHoneypotCSS(config)` | Generate honeypot CSS |

### API Security

| Function | Description |
|----------|-------------|
| `withRequestSigning(handler, config)` | HMAC request signing |
| `withReplayPrevention(handler, config)` | Nonce-based replay prevention |
| `withTimestamp(handler, config)` | Timestamp validation |
| `withAPIVersion(handler, config)` | API version validation |
| `withIdempotency(handler, config)` | Idempotency key support |
| `withAPIProtection(handler, config)` | Combined API protection |
| `withAPIProtectionPreset(handler, preset)` | Use preset configuration |
| `generateSignature(request, config)` | Generate HMAC signature |
| `verifySignature(request, config)` | Verify HMAC signature |
| `generateNonce(length)` | Generate secure nonce |
| `checkReplay(request, config)` | Check for replay attack |
| `validateTimestamp(request, config)` | Validate request timestamp |
| `extractVersion(request, config)` | Extract API version |
| `createVersionRouter(handlers, config)` | Create version-based router |
| `generateIdempotencyKey(length)` | Generate idempotency key |
| `checkIdempotency(request, config)` | Check idempotency status |

---

## Examples

### Complete API with All Security Features

```typescript
// lib/security.ts
import { createRateLimiter, MemoryStore } from 'nextjs-secure/rate-limit'
import { createSecurityTracker, MemoryStore as AuditStore } from 'nextjs-secure/audit'

export const apiLimiter = createRateLimiter({
  limit: 100,
  window: '15m',
  store: new MemoryStore(),
})

export const strictLimiter = createRateLimiter({
  limit: 5,
  window: '1m',
})

export const auditStore = new AuditStore({ maxEntries: 10000 })
export const securityTracker = createSecurityTracker({ store: auditStore })
```

```typescript
// app/api/users/route.ts
import { withJWT, withRoles } from 'nextjs-secure/auth'
import { withValidation } from 'nextjs-secure/validation'
import { withAuditLog } from 'nextjs-secure/audit'
import { apiLimiter, auditStore, securityTracker } from '@/lib/security'

const createUserSchema = {
  email: { type: 'email', required: true },
  name: { type: 'string', minLength: 2, maxLength: 100 },
  role: { type: 'string', enum: ['user', 'admin'] },
}

async function createUser(req, ctx) {
  const { email, name, role } = ctx.validated
  const user = await db.users.create({ email, name, role })
  return Response.json(user, { status: 201 })
}

export const POST = withAuditLog(
  apiLimiter(
    withJWT(
      withRoles(
        withValidation(createUser, { body: createUserSchema }),
        { roles: ['admin'] }
      ),
      { secret: process.env.JWT_SECRET }
    )
  ),
  {
    store: auditStore,
    include: { ip: true, userAgent: true },
    pii: { fields: ['password'], mode: 'remove' },
  }
)
```

### Tiered Rate Limiting

```typescript
import { createRateLimiter, createUpstashStore } from 'nextjs-secure/rate-limit'

const store = createUpstashStore({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
})

const freeLimiter = createRateLimiter({
  limit: 100,
  window: '1d',
  store,
  identifier: (req) => `free:${req.headers.get('x-api-key')}`,
})

const proLimiter = createRateLimiter({
  limit: 10000,
  window: '1d',
  store,
  identifier: (req) => `pro:${req.headers.get('x-api-key')}`,
})

export async function GET(req) {
  const tier = await getUserTier(req)
  const limiter = tier === 'pro' ? proLimiter : freeLimiter
  return limiter(handler)(req)
}
```

---

## Roadmap

- [x] **v0.1.x** - Rate Limiting
- [x] **v0.2.0** - CSRF Protection
- [x] **v0.3.0** - Security Headers
- [x] **v0.4.0** - Authentication
- [x] **v0.5.0** - Input Validation
- [x] **v0.6.0** - Audit Logging
- [x] **v0.7.0** - Bot Detection
- [x] **v0.8.0** - API Security

See [ROADMAP.md](ROADMAP.md) for detailed progress and future plans.

---

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

### Running Tests

```bash
npm run test        # Watch mode
npm run test:run    # Single run
npm run test:coverage  # With coverage
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Made with security in mind for the Next.js community.**
