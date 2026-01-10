/**
 * Token Bucket Rate Limiting Algorithm
 *
 * A bucket holds tokens that are consumed by requests. Tokens are refilled
 * at a constant rate. This allows for controlled bursts while maintaining
 * an average rate.
 *
 * How it works:
 * 1. Bucket starts full with 'limit' tokens
 * 2. Each request consumes 1 token (or more for weighted requests)
 * 3. Tokens are refilled at 'limit / window' rate
 * 4. Request is allowed if tokens >= 1
 *
 * Example (100 tokens, refill 100/min = 1.67/sec):
 * - Initial: 100 tokens
 * - 50 requests instantly: 50 tokens remaining (burst allowed)
 * - Wait 30 seconds: 50 + (50 * 1.67) = 100 tokens (refilled)
 * - 100 requests instantly: 0 tokens
 * - Next request: denied until tokens refill
 *
 * Pros:
 * - Allows controlled bursts
 * - Smooth average rate
 * - Good for APIs with sporadic traffic
 *
 * Cons:
 * - More complex state management
 * - Requires storing last refill time
 *
 * Use when:
 * - You want to allow bursts
 * - Traffic is sporadic
 * - User experience matters (can handle burst then wait)
 */

import type { RateLimitStore, RateLimitAlgorithmImpl, TokenBucketState } from '../types'
import type { RateLimitInfo } from '../../../core/types'
import { msToSeconds } from '../../../utils/time'

/**
 * Token bucket algorithm implementation
 */
export class TokenBucketAlgorithm implements RateLimitAlgorithmImpl {
  public readonly name = 'token-bucket' as const

  /**
   * In-memory bucket states
   * For distributed systems, this should be stored in Redis
   */
  private buckets: Map<string, TokenBucketState> = new Map()

  /**
   * Maximum number of buckets to store before cleanup
   */
  private readonly maxBuckets = 10000

  /**
   * Check if the request should be rate limited
   *
   * @param store - Not used directly, state stored in memory
   * @param key - Rate limit key
   * @param limit - Maximum tokens (bucket capacity)
   * @param windowMs - Time to refill bucket completely
   */
  async check(
    _store: RateLimitStore,
    key: string,
    limit: number,
    windowMs: number
  ): Promise<RateLimitInfo> {
    const now = Date.now()

    // Get or create bucket state
    let bucket = this.buckets.get(key)

    if (!bucket) {
      // New bucket, start full
      bucket = {
        tokens: limit,
        lastRefill: now,
      }
    } else {
      // Refill tokens based on time elapsed
      bucket = this.refillTokens(bucket, limit, windowMs, now)
    }

    // Calculate reset time (when bucket would be full again)
    const tokensNeeded = limit - bucket.tokens
    const refillRate = limit / windowMs // tokens per ms
    const timeToFull = tokensNeeded / refillRate
    const reset = msToSeconds(now + timeToFull)

    // Check if we have tokens
    if (bucket.tokens < 1) {
      // Calculate when we'll have 1 token
      const timeToOneToken = (1 - bucket.tokens) / refillRate
      const retryAfter = Math.ceil(timeToOneToken / 1000)

      return {
        limit,
        remaining: 0,
        reset,
        limited: true,
        retryAfter: Math.max(1, retryAfter),
      }
    }

    // Consume a token
    bucket.tokens -= 1
    this.buckets.set(key, bucket)

    // Cleanup if too many buckets
    if (this.buckets.size > this.maxBuckets) {
      this.cleanup()
    }

    return {
      limit,
      remaining: Math.floor(bucket.tokens),
      reset,
      limited: false,
    }
  }

  /**
   * Refill tokens based on time elapsed
   */
  private refillTokens(
    bucket: TokenBucketState,
    limit: number,
    windowMs: number,
    now: number
  ): TokenBucketState {
    const elapsed = now - bucket.lastRefill
    const refillRate = limit / windowMs // tokens per ms
    const tokensToAdd = elapsed * refillRate

    return {
      tokens: Math.min(limit, bucket.tokens + tokensToAdd),
      lastRefill: now,
    }
  }

  /**
   * Remove old buckets
   */
  private cleanup(): void {
    const now = Date.now()
    const staleThreshold = 3600000 // 1 hour

    const keysToDelete: string[] = []

    for (const [key, bucket] of this.buckets) {
      if (now - bucket.lastRefill > staleThreshold) {
        keysToDelete.push(key)
      }
    }

    for (const key of keysToDelete) {
      this.buckets.delete(key)
    }
  }

  /**
   * Get current bucket state (for testing/debugging)
   */
  getBucketState(key: string): TokenBucketState | undefined {
    return this.buckets.get(key)
  }

  /**
   * Clear all buckets
   */
  clear(): void {
    this.buckets.clear()
  }
}

/**
 * Create a token bucket algorithm instance
 */
export function createTokenBucketAlgorithm(): TokenBucketAlgorithm {
  return new TokenBucketAlgorithm()
}

/**
 * Leaky Bucket Algorithm (variation of token bucket)
 *
 * Instead of refilling tokens, requests "leak" out of the bucket
 * at a constant rate. This enforces a strict output rate.
 *
 * Think of it as a bucket with a hole at the bottom:
 * - Requests are added to the bucket
 * - Requests leak out at a constant rate
 * - If bucket overflows, request is rejected
 *
 * Use when:
 * - You need strict rate enforcement
 * - Bursts should be queued, not rejected
 * - Output rate must be constant
 */
export class LeakyBucketAlgorithm implements RateLimitAlgorithmImpl {
  public readonly name = 'token-bucket' as const // Grouped with token bucket

  /**
   * In-memory bucket states
   * Stores the "water level" and last leak time
   */
  private buckets: Map<string, { level: number; lastLeak: number }> = new Map()

  /**
   * Maximum number of buckets
   */
  private readonly maxBuckets = 10000

  async check(
    _store: RateLimitStore,
    key: string,
    limit: number,
    windowMs: number
  ): Promise<RateLimitInfo> {
    const now = Date.now()

    // Get or create bucket
    let bucket = this.buckets.get(key) ?? { level: 0, lastLeak: now }

    // Calculate how much has leaked since last check
    const elapsed = now - bucket.lastLeak
    const leakRate = limit / windowMs // requests per ms
    const leaked = elapsed * leakRate

    // Update level (can't go below 0)
    bucket.level = Math.max(0, bucket.level - leaked)
    bucket.lastLeak = now

    // Calculate reset time
    const timeToEmpty = bucket.level / leakRate
    const reset = msToSeconds(now + timeToEmpty)

    // Check if bucket would overflow
    if (bucket.level + 1 > limit) {
      // Calculate when there's room for 1 more request
      const overflow = bucket.level + 1 - limit
      const timeToRoom = overflow / leakRate
      const retryAfter = Math.ceil(timeToRoom / 1000)

      return {
        limit,
        remaining: 0,
        reset,
        limited: true,
        retryAfter: Math.max(1, retryAfter),
      }
    }

    // Add request to bucket
    bucket.level += 1
    this.buckets.set(key, bucket)

    // Cleanup if needed
    if (this.buckets.size > this.maxBuckets) {
      this.cleanup(now)
    }

    return {
      limit,
      remaining: Math.floor(limit - bucket.level),
      reset,
      limited: false,
    }
  }

  private cleanup(now: number): void {
    const staleThreshold = 3600000

    for (const [key, bucket] of this.buckets) {
      if (now - bucket.lastLeak > staleThreshold) {
        this.buckets.delete(key)
      }
    }
  }

  clear(): void {
    this.buckets.clear()
  }
}

/**
 * Create a leaky bucket algorithm instance
 */
export function createLeakyBucketAlgorithm(): LeakyBucketAlgorithm {
  return new LeakyBucketAlgorithm()
}
