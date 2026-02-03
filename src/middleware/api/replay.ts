/**
 * Replay Attack Prevention for API Security
 * @module nextjs-secure/api
 */

import type { NextRequest } from 'next/server'
import type { NonceStore, ReplayPreventionOptions, ReplayCheckResult } from './types'

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_REPLAY_OPTIONS: Required<Omit<ReplayPreventionOptions, 'store' | 'validate' | 'onReplay' | 'skip'>> = {
  nonceHeader: 'x-nonce',
  nonceQuery: '',
  ttl: 300000, // 5 minutes
  required: true,
  minLength: 16,
  maxLength: 128,
}

// ============================================================================
// Memory Nonce Store
// ============================================================================

interface NonceEntry {
  timestamp: number
  expiresAt: number
}

/**
 * In-memory nonce store with LRU eviction
 */
export class MemoryNonceStore implements NonceStore {
  private nonces: Map<string, NonceEntry> = new Map()
  private maxSize: number
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  constructor(options: { maxSize?: number; autoCleanup?: boolean; cleanupIntervalMs?: number } = {}) {
    const { maxSize = 100000, autoCleanup = true, cleanupIntervalMs = 60000 } = options
    this.maxSize = maxSize

    if (autoCleanup) {
      this.cleanupInterval = setInterval(() => {
        this.cleanup()
      }, cleanupIntervalMs)

      // Prevent interval from keeping the process alive
      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref()
      }
    }
  }

  async exists(nonce: string): Promise<boolean> {
    const entry = this.nonces.get(nonce)
    if (!entry) {
      return false
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      this.nonces.delete(nonce)
      return false
    }

    return true
  }

  async set(nonce: string, ttl: number): Promise<void> {
    // Evict oldest entries if at capacity
    if (this.nonces.size >= this.maxSize) {
      this.evictOldest()
    }

    const now = Date.now()
    this.nonces.set(nonce, {
      timestamp: now,
      expiresAt: now + ttl,
    })
  }

  async cleanup(): Promise<void> {
    const now = Date.now()
    for (const [nonce, entry] of this.nonces.entries()) {
      if (now > entry.expiresAt) {
        this.nonces.delete(nonce)
      }
    }
  }

  getStats(): { size: number; oldestTimestamp?: number } {
    let oldestTimestamp: number | undefined

    for (const entry of this.nonces.values()) {
      if (!oldestTimestamp || entry.timestamp < oldestTimestamp) {
        oldestTimestamp = entry.timestamp
      }
    }

    return {
      size: this.nonces.size,
      oldestTimestamp,
    }
  }

  private evictOldest(): void {
    // Find and remove oldest entries (10% of max size)
    const toRemove = Math.ceil(this.maxSize * 0.1)
    const entries = Array.from(this.nonces.entries())
      .sort((a, b) => a[1].timestamp - b[1].timestamp)
      .slice(0, toRemove)

    for (const [nonce] of entries) {
      this.nonces.delete(nonce)
    }
  }

  /**
   * Clear all nonces
   */
  clear(): void {
    this.nonces.clear()
  }

  /**
   * Stop auto cleanup
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
  }
}

// ============================================================================
// Global Store
// ============================================================================

let globalNonceStore: MemoryNonceStore | null = null

/**
 * Get global nonce store (singleton)
 */
export function getGlobalNonceStore(): MemoryNonceStore {
  if (!globalNonceStore) {
    globalNonceStore = new MemoryNonceStore()
  }
  return globalNonceStore
}

// ============================================================================
// Nonce Utilities
// ============================================================================

/**
 * Generate a cryptographically secure nonce
 */
export function generateNonce(length: number = 32): string {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Validate nonce format
 */
export function isValidNonceFormat(nonce: string, minLength: number = 16, maxLength: number = 128): boolean {
  if (!nonce || typeof nonce !== 'string') {
    return false
  }

  if (nonce.length < minLength || nonce.length > maxLength) {
    return false
  }

  // Check for valid characters (alphanumeric, dash, underscore)
  return /^[a-zA-Z0-9_-]+$/.test(nonce)
}

// ============================================================================
// Replay Check
// ============================================================================

/**
 * Extract nonce from request
 */
export function extractNonce(req: NextRequest, options: ReplayPreventionOptions = {}): string | null {
  const {
    nonceHeader = DEFAULT_REPLAY_OPTIONS.nonceHeader,
    nonceQuery = DEFAULT_REPLAY_OPTIONS.nonceQuery,
  } = options

  // Try header first
  const headerNonce = req.headers.get(nonceHeader)
  if (headerNonce) {
    return headerNonce
  }

  // Try query param
  if (nonceQuery) {
    const url = new URL(req.url)
    const queryNonce = url.searchParams.get(nonceQuery)
    if (queryNonce) {
      return queryNonce
    }
  }

  return null
}

/**
 * Check request for replay attack
 */
export async function checkReplay(
  req: NextRequest,
  options: ReplayPreventionOptions = {}
): Promise<ReplayCheckResult> {
  const {
    store = getGlobalNonceStore(),
    nonceHeader = DEFAULT_REPLAY_OPTIONS.nonceHeader,
    nonceQuery = DEFAULT_REPLAY_OPTIONS.nonceQuery,
    ttl = DEFAULT_REPLAY_OPTIONS.ttl,
    required = DEFAULT_REPLAY_OPTIONS.required,
    minLength = DEFAULT_REPLAY_OPTIONS.minLength,
    maxLength = DEFAULT_REPLAY_OPTIONS.maxLength,
    validate,
  } = options

  // Extract nonce
  const nonce = extractNonce(req, { nonceHeader, nonceQuery })

  // Check if nonce is required
  if (!nonce) {
    if (required) {
      return {
        isReplay: false, // Not a replay, but missing
        nonce: null as unknown as undefined,
        reason: 'Missing nonce',
      }
    }
    return {
      isReplay: false,
    }
  }

  // Validate nonce format
  if (!isValidNonceFormat(nonce, minLength, maxLength)) {
    return {
      isReplay: false,
      nonce,
      reason: `Invalid nonce format (length must be ${minLength}-${maxLength}, alphanumeric)`,
    }
  }

  // Custom validation
  if (validate) {
    const isValid = await validate(nonce)
    if (!isValid) {
      return {
        isReplay: false,
        nonce,
        reason: 'Nonce failed custom validation',
      }
    }
  }

  // Check if nonce has been used
  const exists = await store.exists(nonce)
  if (exists) {
    return {
      isReplay: true,
      nonce,
      reason: 'Nonce has already been used',
    }
  }

  // Store the nonce
  await store.set(nonce, ttl)

  return {
    isReplay: false,
    nonce,
  }
}

// ============================================================================
// Replay Prevention Middleware
// ============================================================================

/**
 * Default response for replay attack
 */
function defaultReplayResponse(nonce: string): Response {
  return new Response(
    JSON.stringify({
      error: 'Forbidden',
      message: 'Request replay detected',
      code: 'REPLAY_DETECTED',
      nonce,
    }),
    {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Default response for missing/invalid nonce
 */
function defaultMissingNonceResponse(reason: string): Response {
  return new Response(
    JSON.stringify({
      error: 'Bad Request',
      message: reason,
      code: 'INVALID_NONCE',
    }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Create replay prevention middleware
 */
export function withReplayPrevention<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: ReplayPreventionOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  return async (req: NextRequest, ctx: T): Promise<Response> => {
    // Check if should skip
    if (options.skip && await options.skip(req)) {
      return handler(req, ctx)
    }

    // Check for replay
    const result = await checkReplay(req, options)

    // Handle replay attack
    if (result.isReplay) {
      const onReplay = options.onReplay || defaultReplayResponse
      return onReplay(result.nonce!)
    }

    // Handle missing/invalid nonce
    if (result.reason && options.required !== false) {
      return defaultMissingNonceResponse(result.reason)
    }

    return handler(req, ctx)
  }
}

// ============================================================================
// Request Helper
// ============================================================================

/**
 * Add nonce header to outgoing request headers
 */
export function addNonceHeader(
  headers: Record<string, string> = {},
  options: { headerName?: string; length?: number } = {}
): Record<string, string> {
  const { headerName = 'x-nonce', length = 32 } = options
  return {
    ...headers,
    [headerName]: generateNonce(length),
  }
}
