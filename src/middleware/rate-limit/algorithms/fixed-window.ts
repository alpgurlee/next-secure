/**
 * Fixed Window Rate Limiting Algorithm
 *
 * The simplest rate limiting algorithm. Divides time into fixed windows
 * and counts requests within each window.
 *
 * How it works:
 * 1. Divide time into fixed windows (e.g., every minute starting at :00)
 * 2. Count requests within the current window
 * 3. Reset counter when new window starts
 *
 * Example (100 req/min limit):
 * - Window 1 (12:00:00 - 12:00:59): 80 requests -> allowed
 * - Window 2 (12:01:00 - 12:01:59): 0 requests (fresh start)
 *
 * Pros:
 * - Simple to implement
 * - Memory efficient (only 1 counter per key)
 * - Fast (O(1) operations)
 *
 * Cons:
 * - Burst problem: 200 requests possible in 2 seconds at window boundary
 *   - 100 requests at 12:00:59 (end of window 1)
 *   - 100 requests at 12:01:00 (start of window 2)
 * - Not smooth
 *
 * Use when:
 * - Simplicity is preferred
 * - Burst at boundaries is acceptable
 * - Memory/CPU is very constrained
 */

import type { RateLimitStore, RateLimitAlgorithmImpl } from '../types'
import type { RateLimitInfo } from '../../../core/types'
import { msToSeconds } from '../../../utils/time'

/**
 * Fixed window algorithm implementation
 */
export class FixedWindowAlgorithm implements RateLimitAlgorithmImpl {
  public readonly name = 'fixed-window' as const

  /**
   * Check if the request should be rate limited
   */
  async check(
    store: RateLimitStore,
    key: string,
    limit: number,
    windowMs: number
  ): Promise<RateLimitInfo> {
    const now = Date.now()

    // Calculate window boundaries
    const windowStart = Math.floor(now / windowMs) * windowMs
    const windowEnd = windowStart + windowMs
    const reset = msToSeconds(windowEnd)

    // Create window-specific key
    const windowKey = `${key}:${windowStart}`

    // Get current count
    const data = await store.get(windowKey)
    const currentCount = data?.count ?? 0

    // Check if limit exceeded
    if (currentCount >= limit) {
      const retryAfter = Math.ceil((windowEnd - now) / 1000)

      return {
        limit,
        remaining: 0,
        reset,
        limited: true,
        retryAfter: Math.max(1, retryAfter),
      }
    }

    // Increment counter
    const { count } = await store.increment(windowKey, windowMs)

    // Double-check after increment (race condition protection)
    if (count > limit) {
      const retryAfter = Math.ceil((windowEnd - now) / 1000)

      return {
        limit,
        remaining: 0,
        reset,
        limited: true,
        retryAfter: Math.max(1, retryAfter),
      }
    }

    return {
      limit,
      remaining: Math.max(0, limit - count),
      reset,
      limited: false,
    }
  }
}

/**
 * Create a fixed window algorithm instance
 */
export function createFixedWindowAlgorithm(): FixedWindowAlgorithm {
  return new FixedWindowAlgorithm()
}

/**
 * Fixed window with burst protection
 *
 * Adds a secondary limit to prevent bursts at window boundaries.
 * For example: 100 req/min with max 20 req/10sec burst.
 */
export class FixedWindowWithBurstProtection implements RateLimitAlgorithmImpl {
  public readonly name = 'fixed-window' as const

  constructor(
    private readonly burstLimit: number,
    private readonly burstWindowMs: number
  ) {}

  async check(
    store: RateLimitStore,
    key: string,
    limit: number,
    windowMs: number
  ): Promise<RateLimitInfo> {
    const now = Date.now()

    // Check burst limit first (smaller window)
    const burstWindowStart = Math.floor(now / this.burstWindowMs) * this.burstWindowMs
    const burstKey = `${key}:burst:${burstWindowStart}`
    const burstData = await store.get(burstKey)
    const burstCount = burstData?.count ?? 0

    if (burstCount >= this.burstLimit) {
      const burstWindowEnd = burstWindowStart + this.burstWindowMs
      const retryAfter = Math.ceil((burstWindowEnd - now) / 1000)

      return {
        limit: this.burstLimit,
        remaining: 0,
        reset: msToSeconds(burstWindowEnd),
        limited: true,
        retryAfter: Math.max(1, retryAfter),
      }
    }

    // Check main limit
    const windowStart = Math.floor(now / windowMs) * windowMs
    const windowEnd = windowStart + windowMs
    const windowKey = `${key}:${windowStart}`
    const data = await store.get(windowKey)
    const currentCount = data?.count ?? 0

    if (currentCount >= limit) {
      const retryAfter = Math.ceil((windowEnd - now) / 1000)

      return {
        limit,
        remaining: 0,
        reset: msToSeconds(windowEnd),
        limited: true,
        retryAfter: Math.max(1, retryAfter),
      }
    }

    // Increment both counters
    await Promise.all([
      store.increment(windowKey, windowMs),
      store.increment(burstKey, this.burstWindowMs),
    ])

    return {
      limit,
      remaining: Math.max(0, limit - currentCount - 1),
      reset: msToSeconds(windowEnd),
      limited: false,
    }
  }
}

/**
 * Create a fixed window with burst protection
 *
 * @example
 * ```typescript
 * // 100 req/min with max 20 req/10sec burst
 * const algorithm = createFixedWindowWithBurstProtection(20, 10000)
 * ```
 */
export function createFixedWindowWithBurstProtection(
  burstLimit: number,
  burstWindowMs: number
): FixedWindowWithBurstProtection {
  return new FixedWindowWithBurstProtection(burstLimit, burstWindowMs)
}
