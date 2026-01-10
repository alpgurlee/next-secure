/**
 * In-memory rate limit store
 *
 * Suitable for:
 * - Development
 * - Single-instance deployments
 * - Testing
 *
 * Not suitable for:
 * - Multi-instance/distributed deployments (use Redis/Upstash)
 * - Serverless (data lost between invocations)
 */

import type { RateLimitStore, MemoryStoreOptions } from '../types'
import { msToSeconds } from '../../../utils/time'

/**
 * Entry stored in memory
 */
interface MemoryEntry {
  count: number
  reset: number // Unix timestamp (seconds)
  createdAt: number // Timestamp (ms)
}

/**
 * LRU-style memory store for rate limiting
 *
 * Features:
 * - Automatic cleanup of expired entries
 * - LRU eviction when max keys exceeded
 * - Zero dependencies
 * - Edge Runtime compatible
 *
 * @example
 * ```typescript
 * import { MemoryStore } from 'next-secure/rate-limit'
 *
 * const store = new MemoryStore({
 *   cleanupInterval: 60000, // 1 minute
 *   maxKeys: 10000
 * })
 * ```
 */
export class MemoryStore implements RateLimitStore {
  public readonly name = 'memory'

  private store: Map<string, MemoryEntry>
  private cleanupTimer: ReturnType<typeof setInterval> | null = null
  private readonly maxKeys: number
  private readonly cleanupInterval: number

  constructor(options: MemoryStoreOptions = {}) {
    const { cleanupInterval = 60000, maxKeys = 10000 } = options

    this.store = new Map()
    this.maxKeys = maxKeys
    this.cleanupInterval = cleanupInterval

    // Start cleanup timer (only in long-running environments)
    if (typeof setInterval !== 'undefined' && cleanupInterval > 0) {
      this.startCleanupTimer()
    }
  }

  /**
   * Increment the counter for a key
   *
   * Note: The key should already include window information if needed.
   * This store is algorithm-agnostic - algorithms handle windowing logic.
   */
  async increment(
    key: string,
    windowMs: number
  ): Promise<{ count: number; reset: number }> {
    const now = Date.now()
    const defaultReset = msToSeconds(now + windowMs)

    const existing = this.store.get(key)

    if (existing) {
      // Increment existing entry
      existing.count++
      // Move to end (LRU update)
      this.store.delete(key)
      this.store.set(key, existing)
      return { count: existing.count, reset: existing.reset }
    }

    // New entry
    const entry: MemoryEntry = {
      count: 1,
      reset: defaultReset,
      createdAt: now,
    }

    // Check if we need to evict
    if (this.store.size >= this.maxKeys) {
      this.evictOldest()
    }

    this.store.set(key, entry)
    return { count: 1, reset: defaultReset }
  }

  /**
   * Get the current count for a key
   */
  async get(key: string): Promise<{ count: number; reset: number } | null> {
    const entry = this.store.get(key)

    if (!entry) {
      return null
    }

    // Check if expired
    const now = Math.floor(Date.now() / 1000)
    if (entry.reset <= now) {
      this.store.delete(key)
      return null
    }

    return { count: entry.count, reset: entry.reset }
  }

  /**
   * Reset the counter for a key
   */
  async reset(key: string): Promise<void> {
    this.store.delete(key)
  }

  /**
   * Check if the store is healthy
   */
  async isHealthy(): Promise<boolean> {
    return true
  }

  /**
   * Cleanup expired entries
   */
  async cleanup(): Promise<void> {
    const now = Math.floor(Date.now() / 1000)
    const keysToDelete: string[] = []

    for (const [key, entry] of this.store) {
      if (entry.reset <= now) {
        keysToDelete.push(key)
      }
    }

    for (const key of keysToDelete) {
      this.store.delete(key)
    }
  }

  /**
   * Close the store (stop cleanup timer)
   */
  async close(): Promise<void> {
    this.stopCleanupTimer()
    this.store.clear()
  }

  /**
   * Get the current size of the store
   */
  get size(): number {
    return this.store.size
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.store.clear()
  }

  /**
   * Start the cleanup timer
   */
  private startCleanupTimer(): void {
    if (this.cleanupTimer) return

    this.cleanupTimer = setInterval(() => {
      void this.cleanup()
    }, this.cleanupInterval)

    // Unref to not keep the process alive
    if (typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
      (this.cleanupTimer as NodeJS.Timeout).unref()
    }
  }

  /**
   * Stop the cleanup timer
   */
  private stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
      this.cleanupTimer = null
    }
  }

  /**
   * Evict oldest entries when max keys exceeded
   */
  private evictOldest(): void {
    // Map maintains insertion order, so first key is oldest
    const keysToDelete = Math.ceil(this.maxKeys * 0.1) // Delete 10%

    let deleted = 0
    for (const key of this.store.keys()) {
      if (deleted >= keysToDelete) break
      this.store.delete(key)
      deleted++
    }
  }
}

/**
 * Create a memory store with default options
 */
export function createMemoryStore(options?: MemoryStoreOptions): MemoryStore {
  return new MemoryStore(options)
}

/**
 * Global memory store instance (singleton)
 * Useful for serverless environments where you want to reuse across requests
 */
let globalStore: MemoryStore | null = null

/**
 * Get or create the global memory store
 */
export function getGlobalMemoryStore(options?: MemoryStoreOptions): MemoryStore {
  if (!globalStore) {
    globalStore = new MemoryStore(options)
  }
  return globalStore
}

/**
 * Reset the global memory store (useful for testing)
 */
export function resetGlobalMemoryStore(): void {
  if (globalStore) {
    void globalStore.close()
    globalStore = null
  }
}
