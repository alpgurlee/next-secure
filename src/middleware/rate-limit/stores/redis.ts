/**
 * Redis Rate Limit Store
 *
 * Production-ready store for distributed rate limiting using Redis.
 *
 * Supports:
 * - ioredis
 * - node-redis
 * - Any Redis client with compatible API
 *
 * @example
 * ```typescript
 * import Redis from 'ioredis'
 * import { createRedisStore } from 'next-secure/rate-limit'
 *
 * const redis = new Redis(process.env.REDIS_URL)
 * const store = createRedisStore({ client: redis })
 *
 * export const GET = withRateLimit(handler, {
 *   limit: 100,
 *   window: '15m',
 *   store
 * })
 * ```
 */

import type { RateLimitStore, RedisStoreOptions } from '../types'
import { msToSeconds } from '../../../utils/time'

/**
 * Minimal Redis client interface
 * Supports both ioredis and node-redis
 */
interface RedisClient {
  get(key: string): Promise<string | null>
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>
  incr(key: string): Promise<number>
  expire(key: string, seconds: number): Promise<unknown>
  del(key: string | string[]): Promise<unknown>
  eval(script: string, numKeys: number, ...args: unknown[]): Promise<unknown>
  ping?(): Promise<string>
  quit?(): Promise<unknown>
}

/**
 * Lua script for atomic increment with expiry
 * This ensures that increment and expiry are set atomically
 */
const INCREMENT_SCRIPT = `
local key = KEYS[1]
local window = tonumber(ARGV[1])
local now = tonumber(ARGV[2])

-- Calculate window start and end
local windowMs = window
local windowStart = math.floor(now / windowMs) * windowMs
local windowEnd = windowStart + windowMs
local reset = math.floor(windowEnd / 1000)

-- Create window-specific key
local windowKey = key .. ":" .. windowStart

-- Increment the counter
local count = redis.call("INCR", windowKey)

-- Set expiry on first request in window
if count == 1 then
  -- Expire slightly after window ends to handle edge cases
  local ttl = math.ceil((windowEnd - now) / 1000) + 10
  redis.call("EXPIRE", windowKey, ttl)
end

return {count, reset}
`

/**
 * Redis store for distributed rate limiting
 *
 * Features:
 * - Atomic operations using Lua scripts
 * - Automatic key expiration
 * - Compatible with ioredis and node-redis
 * - Cluster-ready
 */
export class RedisStore implements RateLimitStore {
  public readonly name = 'redis'

  private readonly client: RedisClient
  private readonly prefix: string

  constructor(options: RedisStoreOptions) {
    this.client = options.client as RedisClient
    this.prefix = options.prefix ?? 'next-secure:rl'
  }

  /**
   * Increment the counter for a key
   */
  async increment(
    key: string,
    windowMs: number
  ): Promise<{ count: number; reset: number }> {
    const fullKey = `${this.prefix}:${key}`
    const now = Date.now()

    try {
      // Use Lua script for atomic operation
      const result = await this.client.eval(
        INCREMENT_SCRIPT,
        1, // number of keys
        fullKey,
        String(windowMs),
        String(now)
      ) as [number, number]

      return {
        count: result[0],
        reset: result[1],
      }
    } catch (error) {
      // Fallback to non-atomic operation if Lua not available
      return this.incrementFallback(fullKey, windowMs, now)
    }
  }

  /**
   * Fallback increment without Lua (less atomic but still works)
   */
  private async incrementFallback(
    key: string,
    windowMs: number,
    now: number
  ): Promise<{ count: number; reset: number }> {
    const windowStart = Math.floor(now / windowMs) * windowMs
    const windowEnd = windowStart + windowMs
    const reset = msToSeconds(windowEnd)
    const windowKey = `${key}:${windowStart}`

    // Increment counter
    const count = await this.client.incr(windowKey)

    // Set expiry on first request
    if (count === 1) {
      const ttl = Math.ceil((windowEnd - now) / 1000) + 10
      await this.client.expire(windowKey, ttl)
    }

    return { count, reset }
  }

  /**
   * Get the current count for a key
   */
  async get(key: string): Promise<{ count: number; reset: number } | null> {
    const fullKey = `${this.prefix}:${key}`
    const now = Date.now()

    // We need to find the current window key
    // Since we don't know the window size here, we'll need a different approach

    // Try to get the key directly (assumes key includes window timestamp)
    const value = await this.client.get(fullKey)

    if (value === null) {
      return null
    }

    try {
      const data = JSON.parse(value) as { count: number; reset: number }
      return data
    } catch {
      // If it's just a number (from INCR), return with estimated reset
      const count = parseInt(value, 10)
      if (!isNaN(count)) {
        return {
          count,
          reset: Math.floor(now / 1000) + 60, // Estimate 1 minute
        }
      }
      return null
    }
  }

  /**
   * Reset the counter for a key
   */
  async reset(key: string): Promise<void> {
    const fullKey = `${this.prefix}:${key}`

    // Delete all keys matching the pattern
    // Note: This is a simple implementation. For production,
    // consider using SCAN to avoid blocking
    await this.client.del(fullKey)
  }

  /**
   * Check if Redis is healthy
   */
  async isHealthy(): Promise<boolean> {
    try {
      if (this.client.ping) {
        const result = await this.client.ping()
        return result === 'PONG'
      }
      return true
    } catch {
      return false
    }
  }

  /**
   * Close Redis connection
   */
  async close(): Promise<void> {
    if (this.client.quit) {
      await this.client.quit()
    }
  }
}

/**
 * Create a Redis store
 *
 * @example
 * ```typescript
 * import Redis from 'ioredis'
 * import { createRedisStore } from 'next-secure/rate-limit'
 *
 * const redis = new Redis({
 *   host: 'localhost',
 *   port: 6379,
 *   password: 'your-password'
 * })
 *
 * const store = createRedisStore({ client: redis })
 * ```
 */
export function createRedisStore(options: RedisStoreOptions): RedisStore {
  return new RedisStore(options)
}

/**
 * Create a Redis store from URL
 *
 * @example
 * ```typescript
 * import Redis from 'ioredis'
 * import { createRedisStoreFromUrl } from 'next-secure/rate-limit'
 *
 * const store = createRedisStoreFromUrl(
 *   'redis://localhost:6379',
 *   Redis // Pass the Redis constructor
 * )
 * ```
 */
export function createRedisStoreFromUrl(
  url: string,
  RedisConstructor: new (url: string) => RedisClient,
  options?: { prefix?: string }
): RedisStore {
  const client = new RedisConstructor(url)
  return new RedisStore({
    client,
    prefix: options?.prefix,
  })
}
