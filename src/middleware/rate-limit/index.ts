/**
 * Rate Limiting Module
 *
 * Production-ready rate limiting for Next.js App Router.
 *
 * @example
 * ```typescript
 * import { withRateLimit, createRateLimiter } from 'next-secure/rate-limit'
 *
 * // Simple usage
 * export const GET = withRateLimit(
 *   async (req) => Response.json({ ok: true }),
 *   { limit: 100, window: '15m' }
 * )
 *
 * // Reusable limiter
 * const apiLimiter = createRateLimiter({ limit: 100, window: '15m' })
 * export const POST = apiLimiter(async (req) => Response.json({ ok: true }))
 * ```
 *
 * @packageDocumentation
 */

// Main middleware
export {
  withRateLimit,
  createRateLimiter,
  checkRateLimit,
  resetRateLimit,
  getRateLimitStatus,
  clearAllRateLimits,
} from './middleware'

// Types
export type {
  RateLimitConfig,
  RateLimitStore,
  RateLimitAlgorithmImpl,
  RateLimitResult,
  RateLimitHeaders,
  MemoryStoreOptions,
  RedisStoreOptions,
  UpstashStoreOptions,
  SlidingWindowEntry,
  TokenBucketState,
} from './types'

// Stores
export { MemoryStore, createMemoryStore, getGlobalMemoryStore } from './stores/memory'

// Algorithms
export {
  SlidingWindowAlgorithm,
  SlidingWindowLogAlgorithm,
  createSlidingWindowAlgorithm,
} from './algorithms/sliding-window'

export {
  FixedWindowAlgorithm,
  FixedWindowWithBurstProtection,
  createFixedWindowAlgorithm,
  createFixedWindowWithBurstProtection,
} from './algorithms/fixed-window'

export {
  TokenBucketAlgorithm,
  LeakyBucketAlgorithm,
  createTokenBucketAlgorithm,
  createLeakyBucketAlgorithm,
} from './algorithms/token-bucket'

// Re-export common types from core
export type { RateLimitInfo, Duration, RateLimitAlgorithm } from '../../core/types'
