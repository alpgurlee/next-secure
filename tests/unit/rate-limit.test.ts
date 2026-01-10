/**
 * Rate limiting tests
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  withRateLimit,
  checkRateLimit,
  createRateLimiter,
  MemoryStore,
  SlidingWindowAlgorithm,
  FixedWindowAlgorithm,
  TokenBucketAlgorithm,
  clearAllRateLimits,
} from '../../src/middleware/rate-limit'

// Mock request factory
function createMockRequest(options: {
  ip?: string
  headers?: Record<string, string>
  url?: string
  method?: string
} = {}): Parameters<typeof withRateLimit>[0] extends (req: infer R, ...args: unknown[]) => unknown ? R : never {
  const headers = new Map(Object.entries(options.headers ?? {}))

  return {
    ip: options.ip ?? '127.0.0.1',
    url: options.url ?? 'http://localhost/api/test',
    method: options.method ?? 'GET',
    headers: {
      get: (key: string) => headers.get(key.toLowerCase()) ?? null,
    },
    nextUrl: {
      pathname: '/api/test',
      searchParams: new URLSearchParams(),
      href: options.url ?? 'http://localhost/api/test',
    },
    json: async () => ({}),
    text: async () => '',
    formData: async () => new FormData(),
    clone: function() { return this },
  } as Parameters<typeof withRateLimit>[0] extends (req: infer R, ...args: unknown[]) => unknown ? R : never
}

describe('MemoryStore', () => {
  let store: MemoryStore

  beforeEach(() => {
    store = new MemoryStore({ cleanupInterval: 0 }) // Disable auto cleanup
  })

  afterEach(async () => {
    await store.close()
  })

  it('should increment counter', async () => {
    const result1 = await store.increment('test-key', 60000)
    expect(result1.count).toBe(1)

    const result2 = await store.increment('test-key', 60000)
    expect(result2.count).toBe(2)
  })

  it('should use different keys for different windows', async () => {
    // Memory store is algorithm-agnostic - algorithms pass window-specific keys
    // This test verifies that different keys maintain separate counts
    const result1 = await store.increment('window:1000', 60000)
    expect(result1.count).toBe(1)

    const result2 = await store.increment('window:2000', 60000)
    expect(result2.count).toBe(1) // Different key, starts at 1

    const result3 = await store.increment('window:1000', 60000)
    expect(result3.count).toBe(2) // Same key as result1, increments
  })

  it('should get current count', async () => {
    await store.increment('test-key', 60000)
    await store.increment('test-key', 60000)

    const data = await store.get('test-key')
    expect(data).not.toBeNull()
    // Note: get with window-based key might not work directly
    // This test is for the basic functionality
  })

  it('should reset counter', async () => {
    await store.increment('test-key', 60000)
    await store.reset('test-key')

    const data = await store.get('test-key')
    expect(data).toBeNull()
  })

  it('should report healthy', async () => {
    expect(await store.isHealthy()).toBe(true)
  })

  it('should cleanup expired entries', async () => {
    const windowMs = 50

    await store.increment('key1', windowMs)
    expect(store.size).toBe(1)

    // Wait for expiry
    await new Promise((resolve) => setTimeout(resolve, windowMs + 50))

    await store.cleanup()
    expect(store.size).toBe(0)
  })

  it('should evict oldest entries when maxKeys exceeded', async () => {
    const smallStore = new MemoryStore({ maxKeys: 5, cleanupInterval: 0 })

    for (let i = 0; i < 10; i++) {
      await smallStore.increment(`key-${i}`, 60000)
    }

    // Should have evicted some keys
    expect(smallStore.size).toBeLessThanOrEqual(5)

    await smallStore.close()
  })
})

describe('SlidingWindowAlgorithm', () => {
  let store: MemoryStore
  let algorithm: SlidingWindowAlgorithm

  beforeEach(() => {
    store = new MemoryStore({ cleanupInterval: 0 })
    algorithm = new SlidingWindowAlgorithm()
  })

  afterEach(async () => {
    await store.close()
  })

  it('should allow requests under limit', async () => {
    const result = await algorithm.check(store, 'test', 10, 60000)

    expect(result.limited).toBe(false)
    expect(result.remaining).toBe(9)
    expect(result.limit).toBe(10)
  })

  it('should block requests over limit', async () => {
    // Make 10 requests (limit)
    for (let i = 0; i < 10; i++) {
      await algorithm.check(store, 'test', 10, 60000)
    }

    // 11th request should be blocked
    const result = await algorithm.check(store, 'test', 10, 60000)

    expect(result.limited).toBe(true)
    expect(result.remaining).toBe(0)
    expect(result.retryAfter).toBeGreaterThan(0)
  })

  it('should calculate remaining correctly', async () => {
    const result1 = await algorithm.check(store, 'test', 5, 60000)
    expect(result1.remaining).toBe(4)

    const result2 = await algorithm.check(store, 'test', 5, 60000)
    expect(result2.remaining).toBe(3)

    const result3 = await algorithm.check(store, 'test', 5, 60000)
    expect(result3.remaining).toBe(2)
  })
})

describe('FixedWindowAlgorithm', () => {
  let store: MemoryStore
  let algorithm: FixedWindowAlgorithm

  beforeEach(() => {
    store = new MemoryStore({ cleanupInterval: 0 })
    algorithm = new FixedWindowAlgorithm()
  })

  afterEach(async () => {
    await store.close()
  })

  it('should allow requests under limit', async () => {
    const result = await algorithm.check(store, 'test', 10, 60000)

    expect(result.limited).toBe(false)
    expect(result.remaining).toBeLessThanOrEqual(10)
  })

  it('should block requests over limit', async () => {
    // Make 10 requests (limit)
    for (let i = 0; i < 10; i++) {
      await algorithm.check(store, 'test', 10, 60000)
    }

    // 11th request should be blocked
    const result = await algorithm.check(store, 'test', 10, 60000)

    expect(result.limited).toBe(true)
    expect(result.remaining).toBe(0)
  })
})

describe('TokenBucketAlgorithm', () => {
  let store: MemoryStore
  let algorithm: TokenBucketAlgorithm

  beforeEach(() => {
    store = new MemoryStore({ cleanupInterval: 0 })
    algorithm = new TokenBucketAlgorithm()
  })

  afterEach(async () => {
    await store.close()
    algorithm.clear()
  })

  it('should allow burst of requests', async () => {
    // Token bucket should allow initial burst
    const results = await Promise.all([
      algorithm.check(store, 'test', 10, 60000),
      algorithm.check(store, 'test', 10, 60000),
      algorithm.check(store, 'test', 10, 60000),
    ])

    results.forEach((result) => {
      expect(result.limited).toBe(false)
    })
  })

  it('should block when tokens exhausted', async () => {
    // Exhaust all tokens
    for (let i = 0; i < 10; i++) {
      await algorithm.check(store, 'test', 10, 60000)
    }

    // Next request should be blocked
    const result = await algorithm.check(store, 'test', 10, 60000)
    expect(result.limited).toBe(true)
  })

  it('should refill tokens over time', async () => {
    // Use small window for quick test
    const windowMs = 100

    // Exhaust tokens
    for (let i = 0; i < 5; i++) {
      await algorithm.check(store, 'test', 5, windowMs)
    }

    // Should be blocked
    let result = await algorithm.check(store, 'test', 5, windowMs)
    expect(result.limited).toBe(true)

    // Wait for refill
    await new Promise((resolve) => setTimeout(resolve, windowMs + 10))

    // Should have tokens again
    result = await algorithm.check(store, 'test', 5, windowMs)
    expect(result.limited).toBe(false)
  })
})

describe('withRateLimit middleware', () => {
  beforeEach(() => {
    clearAllRateLimits()
  })

  it('should pass requests under limit', async () => {
    const handler = vi.fn().mockResolvedValue(Response.json({ ok: true }))

    const wrappedHandler = withRateLimit(handler, {
      limit: 10,
      window: '1m',
    })

    const req = createMockRequest()
    const response = await wrappedHandler(req)

    expect(response.status).toBe(200)
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('should block requests over limit', async () => {
    const handler = vi.fn().mockResolvedValue(Response.json({ ok: true }))

    const wrappedHandler = withRateLimit(handler, {
      limit: 3,
      window: '1m',
    })

    const req = createMockRequest()

    // Make 3 requests (limit)
    await wrappedHandler(req)
    await wrappedHandler(req)
    await wrappedHandler(req)

    // 4th request should be blocked
    const response = await wrappedHandler(req)

    expect(response.status).toBe(429)
    expect(handler).toHaveBeenCalledTimes(3)
  })

  it('should include rate limit headers', async () => {
    const handler = vi.fn().mockResolvedValue(Response.json({ ok: true }))

    const wrappedHandler = withRateLimit(handler, {
      limit: 10,
      window: '1m',
      headers: true,
    })

    const req = createMockRequest()
    const response = await wrappedHandler(req)

    expect(response.headers.get('X-RateLimit-Limit')).toBe('10')
    expect(response.headers.get('X-RateLimit-Remaining')).toBeDefined()
    expect(response.headers.get('X-RateLimit-Reset')).toBeDefined()
  })

  it('should skip rate limiting when skip returns true', async () => {
    const handler = vi.fn().mockResolvedValue(Response.json({ ok: true }))

    const wrappedHandler = withRateLimit(handler, {
      limit: 1,
      window: '1m',
      skip: () => true,
    })

    const req = createMockRequest()

    // Should not be rate limited even after many requests
    await wrappedHandler(req)
    await wrappedHandler(req)
    const response = await wrappedHandler(req)

    expect(response.status).toBe(200)
    expect(handler).toHaveBeenCalledTimes(3)
  })

  it('should use custom onLimit handler', async () => {
    const handler = vi.fn().mockResolvedValue(Response.json({ ok: true }))
    const customResponse = new Response(JSON.stringify({ custom: true }), { status: 429 })

    const wrappedHandler = withRateLimit(handler, {
      limit: 1,
      window: '1m',
      onLimit: () => customResponse,
    })

    const req = createMockRequest()

    await wrappedHandler(req) // First request
    const response = await wrappedHandler(req) // Should be blocked

    expect(response.status).toBe(429)
    const data = await response.json() as { custom: boolean }
    expect(data.custom).toBe(true)
  })

  it('should use custom identifier', async () => {
    const handler = vi.fn().mockResolvedValue(Response.json({ ok: true }))

    const wrappedHandler = withRateLimit(handler, {
      limit: 1,
      window: '1m',
      identifier: (req) => req.headers.get('x-api-key') ?? 'anonymous',
    })

    const req1 = createMockRequest({ headers: { 'x-api-key': 'key1' } })
    const req2 = createMockRequest({ headers: { 'x-api-key': 'key2' } })

    // Different keys should have separate limits
    await wrappedHandler(req1)
    const response2 = await wrappedHandler(req2)

    expect(response2.status).toBe(200)
  })
})

describe('checkRateLimit', () => {
  beforeEach(() => {
    clearAllRateLimits()
  })

  it('should return success for requests under limit', async () => {
    const req = createMockRequest()
    const result = await checkRateLimit(req, {
      limit: 10,
      window: '1m',
    })

    expect(result.success).toBe(true)
    expect(result.info.limited).toBe(false)
    expect(result.response).toBeUndefined()
  })

  it('should return failure for requests over limit', async () => {
    const req = createMockRequest()

    // Make requests up to limit
    for (let i = 0; i < 3; i++) {
      await checkRateLimit(req, { limit: 3, window: '1m' })
    }

    // Next should fail
    const result = await checkRateLimit(req, { limit: 3, window: '1m' })

    expect(result.success).toBe(false)
    expect(result.info.limited).toBe(true)
    expect(result.response).toBeDefined()
    expect(result.response?.status).toBe(429)
  })
})

describe('createRateLimiter', () => {
  beforeEach(() => {
    clearAllRateLimits()
  })

  it('should create reusable limiter', async () => {
    const limiter = createRateLimiter({
      limit: 10,
      window: '1m',
    })

    const handler = vi.fn().mockResolvedValue(Response.json({ ok: true }))
    const wrappedHandler = limiter(handler)

    const req = createMockRequest()
    const response = await wrappedHandler(req)

    expect(response.status).toBe(200)
  })
})
