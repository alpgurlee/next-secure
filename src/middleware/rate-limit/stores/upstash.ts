/**
 * Upstash Redis Rate Limit Store
 *
 * Optimized for serverless and edge environments.
 * Uses HTTP-based Redis client for maximum compatibility.
 *
 * @example
 * ```typescript
 * import { createUpstashStore } from 'next-secure/rate-limit'
 *
 * const store = createUpstashStore({
 *   url: process.env.UPSTASH_REDIS_REST_URL!,
 *   token: process.env.UPSTASH_REDIS_REST_TOKEN!
 * })
 *
 * export const GET = withRateLimit(handler, {
 *   limit: 100,
 *   window: '15m',
 *   store
 * })
 * ```
 */

import type { RateLimitStore, UpstashStoreOptions } from '../types'
import { msToSeconds } from '../../../utils/time'

/**
 * Upstash REST API response
 */
interface UpstashResponse<T = unknown> {
  result: T
  error?: string
}

/**
 * Upstash store for serverless rate limiting
 *
 * Features:
 * - HTTP-based (no TCP connections)
 * - Edge Runtime compatible
 * - Automatic connection pooling
 * - Global distribution support
 */
export class UpstashStore implements RateLimitStore {
  public readonly name = 'upstash'

  private readonly url: string
  private readonly token: string
  private readonly prefix: string

  constructor(options: UpstashStoreOptions) {
    this.url = options.url.replace(/\/$/, '') // Remove trailing slash
    this.token = options.token
    this.prefix = options.prefix ?? 'next-secure:rl'
  }

  /**
   * Execute an Upstash command via REST API
   */
  private async execute<T>(command: string[]): Promise<T> {
    const response = await fetch(`${this.url}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(command),
    })

    if (!response.ok) {
      throw new Error(`Upstash error: ${response.status} ${response.statusText}`)
    }

    const data = await response.json() as UpstashResponse<T>

    if (data.error) {
      throw new Error(`Upstash error: ${data.error}`)
    }

    return data.result
  }

  /**
   * Execute a pipeline of commands
   */
  private async pipeline<T>(commands: string[][]): Promise<T[]> {
    const response = await fetch(`${this.url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(commands),
    })

    if (!response.ok) {
      throw new Error(`Upstash error: ${response.status} ${response.statusText}`)
    }

    const data = await response.json() as UpstashResponse<T>[]

    // Check for errors in any response
    for (const item of data) {
      if (item.error) {
        throw new Error(`Upstash error: ${item.error}`)
      }
    }

    return data.map((item) => item.result)
  }

  /**
   * Increment the counter for a key
   */
  async increment(
    key: string,
    windowMs: number
  ): Promise<{ count: number; reset: number }> {
    const now = Date.now()
    const windowStart = Math.floor(now / windowMs) * windowMs
    const windowEnd = windowStart + windowMs
    const reset = msToSeconds(windowEnd)

    const windowKey = `${this.prefix}:${key}:${windowStart}`
    const ttl = Math.ceil((windowEnd - now) / 1000) + 10

    // Use pipeline for atomic increment + expire
    const results = await this.pipeline<number | null>([
      ['INCR', windowKey],
      ['EXPIRE', windowKey, String(ttl)],
    ])

    const count = results[0] ?? 1

    return { count, reset }
  }

  /**
   * Get the current count for a key
   */
  async get(key: string): Promise<{ count: number; reset: number } | null> {
    const fullKey = `${this.prefix}:${key}`

    try {
      const value = await this.execute<string | null>(['GET', fullKey])

      if (value === null) {
        return null
      }

      const count = parseInt(value, 10)
      if (isNaN(count)) {
        return null
      }

      // Estimate reset time (we don't have exact info)
      const now = Date.now()
      return {
        count,
        reset: Math.floor(now / 1000) + 60,
      }
    } catch {
      return null
    }
  }

  /**
   * Reset the counter for a key
   */
  async reset(key: string): Promise<void> {
    const fullKey = `${this.prefix}:${key}`
    await this.execute(['DEL', fullKey])
  }

  /**
   * Check if Upstash is healthy
   */
  async isHealthy(): Promise<boolean> {
    try {
      const result = await this.execute<string>(['PING'])
      return result === 'PONG'
    } catch {
      return false
    }
  }

  /**
   * Cleanup is handled automatically by Redis TTL
   */
  async cleanup(): Promise<void> {
    // No-op: Upstash handles cleanup via TTL
  }

  /**
   * No connection to close for HTTP-based client
   */
  async close(): Promise<void> {
    // No-op: HTTP-based, no persistent connection
  }
}

/**
 * Create an Upstash store
 *
 * @example
 * ```typescript
 * const store = createUpstashStore({
 *   url: process.env.UPSTASH_REDIS_REST_URL!,
 *   token: process.env.UPSTASH_REDIS_REST_TOKEN!
 * })
 * ```
 */
export function createUpstashStore(options: UpstashStoreOptions): UpstashStore {
  return new UpstashStore(options)
}

/**
 * Create an Upstash store from environment variables
 *
 * Expects:
 * - UPSTASH_REDIS_REST_URL
 * - UPSTASH_REDIS_REST_TOKEN
 *
 * @example
 * ```typescript
 * const store = createUpstashStoreFromEnv()
 * // or with custom prefix
 * const store = createUpstashStoreFromEnv({ prefix: 'my-app:rl' })
 * ```
 */
export function createUpstashStoreFromEnv(options?: { prefix?: string }): UpstashStore {
  const url = process.env.UPSTASH_REDIS_REST_URL
  const token = process.env.UPSTASH_REDIS_REST_TOKEN

  if (!url) {
    throw new Error('UPSTASH_REDIS_REST_URL environment variable is required')
  }

  if (!token) {
    throw new Error('UPSTASH_REDIS_REST_TOKEN environment variable is required')
  }

  return new UpstashStore({
    url,
    token,
    prefix: options?.prefix,
  })
}

/**
 * Sliding window rate limiter using Upstash's native implementation
 *
 * This uses Upstash's @upstash/ratelimit package internally for better performance.
 * Only use this if you have @upstash/ratelimit installed.
 *
 * @example
 * ```typescript
 * import { Ratelimit } from '@upstash/ratelimit'
 * import { Redis } from '@upstash/redis'
 *
 * const ratelimit = new Ratelimit({
 *   redis: Redis.fromEnv(),
 *   limiter: Ratelimit.slidingWindow(100, '15m'),
 * })
 *
 * const store = createUpstashRatelimitStore(ratelimit)
 * ```
 */
export interface UpstashRatelimitResult {
  success: boolean
  limit: number
  remaining: number
  reset: number
  pending: Promise<unknown>
}

export interface UpstashRatelimitInstance {
  limit(identifier: string): Promise<UpstashRatelimitResult>
}

export class UpstashRatelimitStore implements RateLimitStore {
  public readonly name = 'upstash-ratelimit'

  constructor(private readonly ratelimit: UpstashRatelimitInstance) {}

  async increment(
    key: string,
    _windowMs: number
  ): Promise<{ count: number; reset: number }> {
    const result = await this.ratelimit.limit(key)

    // Upstash ratelimit returns remaining, we need to calculate count
    const count = result.limit - result.remaining

    return {
      count,
      reset: result.reset,
    }
  }

  async get(_key: string): Promise<{ count: number; reset: number } | null> {
    // Upstash ratelimit doesn't support get without increment
    return null
  }

  async reset(_key: string): Promise<void> {
    // Upstash ratelimit doesn't support reset
    // The key will expire naturally
  }

  async isHealthy(): Promise<boolean> {
    return true
  }
}

/**
 * Create a store from an existing @upstash/ratelimit instance
 */
export function createUpstashRatelimitStore(
  ratelimit: UpstashRatelimitInstance
): UpstashRatelimitStore {
  return new UpstashRatelimitStore(ratelimit)
}
