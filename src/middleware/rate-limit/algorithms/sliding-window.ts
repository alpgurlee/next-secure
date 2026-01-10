/**
 * Sliding Window Rate Limiting Algorithm
 *
 * This algorithm provides a smoother rate limiting experience compared to fixed windows.
 * It uses a weighted calculation based on the previous and current window counts.
 *
 * How it works:
 * 1. Divide time into fixed windows (e.g., 1 minute each)
 * 2. Track request counts for current and previous windows
 * 3. Calculate weighted count based on position within current window
 *
 * Example (100 req/min limit):
 * - Previous window: 80 requests
 * - Current window: 30 requests
 * - 30 seconds into current window (50% through)
 * - Weighted count = 30 + (80 * 0.5) = 70
 * - Since 70 < 100, request is allowed
 *
 * Pros:
 * - Smoother than fixed window
 * - Prevents burst attacks at window boundaries
 * - Memory efficient (only stores 2 counters per key)
 *
 * Cons:
 * - Slightly more complex than fixed window
 * - Not perfectly accurate (approximation)
 */

import type { RateLimitStore, RateLimitAlgorithmImpl } from '../types'
import type { RateLimitInfo } from '../../../core/types'
import { msToSeconds } from '../../../utils/time'

/**
 * Sliding window counter algorithm implementation
 */
export class SlidingWindowAlgorithm implements RateLimitAlgorithmImpl {
  public readonly name = 'sliding-window' as const

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
    const previousWindowStart = windowStart - windowMs

    // Position within current window (0 to 1)
    const windowPosition = (now - windowStart) / windowMs

    // Keys for current and previous windows
    const currentKey = `${key}:${windowStart}`
    const previousKey = `${key}:${previousWindowStart}`

    // Get counts from both windows
    const [currentData, previousData] = await Promise.all([
      store.get(currentKey),
      store.get(previousKey),
    ])

    const currentCount = currentData?.count ?? 0
    const previousCount = previousData?.count ?? 0

    // Calculate weighted count using sliding window formula
    // Weight of previous window decreases as we move through current window
    const previousWeight = 1 - windowPosition
    const weightedCount = currentCount + Math.floor(previousCount * previousWeight)

    // Calculate reset time (end of current window)
    const reset = msToSeconds(windowEnd)

    // Check if limit exceeded
    if (weightedCount >= limit) {
      // Calculate retry time based on when enough requests will "expire"
      const retryAfter = this.calculateRetryAfter(
        currentCount,
        previousCount,
        limit,
        windowMs,
        windowPosition
      )

      return {
        limit,
        remaining: 0,
        reset,
        limited: true,
        retryAfter,
      }
    }

    // Increment current window counter
    await store.increment(currentKey, windowMs)

    // Calculate remaining
    const remaining = Math.max(0, limit - weightedCount - 1)

    return {
      limit,
      remaining,
      reset,
      limited: false,
    }
  }

  /**
   * Calculate how long until the client can make another request
   */
  private calculateRetryAfter(
    currentCount: number,
    previousCount: number,
    limit: number,
    windowMs: number,
    windowPosition: number
  ): number {
    // If previous window is empty, wait until current window resets
    if (previousCount === 0) {
      return Math.ceil((1 - windowPosition) * windowMs / 1000)
    }

    // Calculate when the weighted count will drop below limit
    // We need: currentCount + previousCount * (1 - newPosition) < limit
    // Solving for newPosition: newPosition > 1 - (limit - currentCount) / previousCount

    const requiredPosition = 1 - (limit - currentCount) / previousCount

    if (requiredPosition <= windowPosition) {
      // Should already be under limit, but we got here so add small delay
      return 1
    }

    if (requiredPosition >= 1) {
      // Need to wait until next window
      const remainingInCurrentWindow = (1 - windowPosition) * windowMs
      return Math.ceil(remainingInCurrentWindow / 1000)
    }

    // Calculate time until we reach required position
    const timeToWait = (requiredPosition - windowPosition) * windowMs
    return Math.ceil(timeToWait / 1000)
  }
}

/**
 * Create a sliding window algorithm instance
 */
export function createSlidingWindowAlgorithm(): SlidingWindowAlgorithm {
  return new SlidingWindowAlgorithm()
}

/**
 * Sliding Window Log Algorithm (more accurate but uses more memory)
 *
 * This stores individual request timestamps instead of just counters.
 * More accurate but not recommended for high-traffic scenarios.
 */
export class SlidingWindowLogAlgorithm implements RateLimitAlgorithmImpl {
  public readonly name = 'sliding-window' as const

  /**
   * In-memory log of request timestamps per key
   * For production, this should be stored externally (Redis sorted sets, etc.)
   */
  private logs: Map<string, number[]> = new Map()

  /**
   * Maximum log size before cleanup
   */
  private readonly maxLogSize = 10000

  async check(
    _store: RateLimitStore,
    key: string,
    limit: number,
    windowMs: number
  ): Promise<RateLimitInfo> {
    const now = Date.now()
    const windowStart = now - windowMs

    // Get or create log for this key
    let log = this.logs.get(key) ?? []

    // Remove expired entries
    log = log.filter((timestamp) => timestamp > windowStart)

    // Calculate reset (when oldest entry expires)
    const oldestTimestamp = log[0] ?? now
    const reset = msToSeconds(oldestTimestamp + windowMs)

    // Check if limit exceeded
    if (log.length >= limit) {
      const retryAfter = Math.ceil((oldestTimestamp + windowMs - now) / 1000)

      return {
        limit,
        remaining: 0,
        reset,
        limited: true,
        retryAfter: Math.max(1, retryAfter),
      }
    }

    // Add current request
    log.push(now)
    this.logs.set(key, log)

    // Cleanup if too many keys
    if (this.logs.size > this.maxLogSize) {
      this.cleanup()
    }

    return {
      limit,
      remaining: Math.max(0, limit - log.length),
      reset,
      limited: false,
    }
  }

  /**
   * Remove oldest entries when log size exceeded
   */
  private cleanup(): void {
    const keysToDelete: string[] = []
    const now = Date.now()

    for (const [key, log] of this.logs) {
      // Delete empty or very old logs
      if (log.length === 0 || log[log.length - 1]! < now - 3600000) {
        keysToDelete.push(key)
      }
    }

    for (const key of keysToDelete) {
      this.logs.delete(key)
    }
  }

  /**
   * Clear all logs
   */
  clear(): void {
    this.logs.clear()
  }
}
