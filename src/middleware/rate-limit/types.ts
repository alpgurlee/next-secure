/**
 * Rate limiting types and interfaces
 */

import type { Duration, NextRequest, RateLimitAlgorithm, RateLimitInfo } from '../../core/types'

/**
 * Rate limit store interface
 * Implement this interface to create custom stores (Redis, Upstash, etc.)
 */
export interface RateLimitStore {
  /**
   * Unique identifier for this store
   */
  readonly name: string

  /**
   * Increment the counter for a key
   *
   * @param key - Unique identifier for the rate limit bucket
   * @param windowMs - Window duration in milliseconds
   * @returns Current count and reset timestamp
   */
  increment(
    key: string,
    windowMs: number
  ): Promise<{ count: number; reset: number }>

  /**
   * Get the current count for a key
   *
   * @param key - Unique identifier for the rate limit bucket
   * @returns Current count and reset timestamp, or null if not found
   */
  get(key: string): Promise<{ count: number; reset: number } | null>

  /**
   * Reset the counter for a key
   *
   * @param key - Unique identifier for the rate limit bucket
   */
  reset(key: string): Promise<void>

  /**
   * Check if the store is healthy/connected
   */
  isHealthy?(): Promise<boolean>

  /**
   * Cleanup expired entries (optional, for memory stores)
   */
  cleanup?(): Promise<void>

  /**
   * Close connections (optional, for external stores)
   */
  close?(): Promise<void>
}

/**
 * Rate limit algorithm interface
 */
export interface RateLimitAlgorithmImpl {
  /**
   * Algorithm name
   */
  readonly name: RateLimitAlgorithm

  /**
   * Check if the request should be rate limited
   *
   * @param store - Storage backend
   * @param key - Rate limit key
   * @param limit - Maximum requests allowed
   * @param windowMs - Window duration in milliseconds
   * @returns Rate limit info
   */
  check(
    store: RateLimitStore,
    key: string,
    limit: number,
    windowMs: number
  ): Promise<RateLimitInfo>
}

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  /**
   * Maximum number of requests allowed within the window
   */
  limit: number

  /**
   * Time window for rate limiting
   * Can be a duration string ('15m', '1h', '30s') or milliseconds
   */
  window: Duration | string

  /**
   * Algorithm to use for rate limiting
   * @default 'sliding-window'
   */
  algorithm?: RateLimitAlgorithm

  /**
   * How to identify clients
   * - 'ip': Use client IP address (default)
   * - 'user': Use authenticated user ID (requires auth middleware)
   * - function: Custom identifier function
   * @default 'ip'
   */
  identifier?: 'ip' | 'user' | ((request: NextRequest) => string | Promise<string>)

  /**
   * Storage backend for rate limit data
   * @default MemoryStore
   */
  store?: RateLimitStore

  /**
   * Include rate limit headers in response
   * - X-RateLimit-Limit
   * - X-RateLimit-Remaining
   * - X-RateLimit-Reset
   * @default true
   */
  headers?: boolean

  /**
   * Custom handler when rate limit is exceeded
   * Return a Response to override the default 429 response
   */
  onLimit?: (request: NextRequest, info: RateLimitInfo) => Response | Promise<Response>

  /**
   * Skip rate limiting for certain requests
   * Return true to skip rate limiting
   */
  skip?: (request: NextRequest) => boolean | Promise<boolean>

  /**
   * Key prefix for storage
   * @default 'rl'
   */
  prefix?: string

  /**
   * Custom message when rate limited
   * @default 'Too Many Requests'
   */
  message?: string

  /**
   * Status code when rate limited
   * @default 429
   */
  statusCode?: number

  /**
   * Enable debug logging
   * @default false
   */
  debug?: boolean
}

/**
 * Rate limit result returned by the middleware
 */
export interface RateLimitResult {
  /**
   * Whether the request is allowed
   */
  success: boolean

  /**
   * Rate limit information
   */
  info: RateLimitInfo

  /**
   * Headers to include in the response
   */
  headers: Headers
}

/**
 * Sliding window log entry
 */
export interface SlidingWindowEntry {
  /**
   * Timestamp of the request (ms)
   */
  timestamp: number

  /**
   * Weight of this request (for weighted rate limiting)
   */
  weight?: number
}

/**
 * Token bucket state
 */
export interface TokenBucketState {
  /**
   * Current number of tokens
   */
  tokens: number

  /**
   * Last refill timestamp (ms)
   */
  lastRefill: number
}

/**
 * Rate limit headers
 */
export interface RateLimitHeaders {
  'X-RateLimit-Limit': string
  'X-RateLimit-Remaining': string
  'X-RateLimit-Reset': string
  'Retry-After'?: string
}

/**
 * Memory store options
 */
export interface MemoryStoreOptions {
  /**
   * Cleanup interval in milliseconds
   * @default 60000 (1 minute)
   */
  cleanupInterval?: number

  /**
   * Maximum number of keys to store
   * When exceeded, oldest keys are removed
   * @default 10000
   */
  maxKeys?: number
}

/**
 * Redis store options
 */
export interface RedisStoreOptions {
  /**
   * Redis client instance
   */
  client: unknown // Will be typed properly when implementing

  /**
   * Key prefix
   * @default 'next-secure:rl'
   */
  prefix?: string
}

/**
 * Upstash store options
 */
export interface UpstashStoreOptions {
  /**
   * Upstash Redis URL
   */
  url: string

  /**
   * Upstash Redis token
   */
  token: string

  /**
   * Key prefix
   * @default 'next-secure:rl'
   */
  prefix?: string
}
