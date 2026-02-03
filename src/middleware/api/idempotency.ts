/**
 * Idempotency Support for API Security
 * @module nextjs-secure/api
 */

import type { NextRequest } from 'next/server'
import type { IdempotencyStore, CachedResponse, IdempotencyOptions, IdempotencyResult } from './types'

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_IDEMPOTENCY_OPTIONS: Required<Omit<IdempotencyOptions, 'store' | 'validateKey' | 'onError' | 'skip' | 'onCacheHit'>> = {
  keyHeader: 'idempotency-key',
  ttl: 86400000, // 24 hours
  required: false,
  methods: ['POST', 'PUT', 'PATCH'],
  minKeyLength: 16,
  maxKeyLength: 256,
  hashRequestBody: true,
  lockTimeout: 30000, // 30 seconds
  waitForLock: true,
  maxWaitTime: 10000, // 10 seconds
}

// ============================================================================
// Memory Idempotency Store
// ============================================================================

interface IdempotencyEntry {
  response: CachedResponse
  expiresAt: number
}

interface ProcessingEntry {
  startedAt: number
  expiresAt: number
}

/**
 * In-memory idempotency store
 */
export class MemoryIdempotencyStore implements IdempotencyStore {
  private cache: Map<string, IdempotencyEntry> = new Map()
  private processing: Map<string, ProcessingEntry> = new Map()
  private maxSize: number
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  constructor(options: { maxSize?: number; autoCleanup?: boolean; cleanupIntervalMs?: number } = {}) {
    const { maxSize = 10000, autoCleanup = true, cleanupIntervalMs = 60000 } = options
    this.maxSize = maxSize

    if (autoCleanup) {
      this.cleanupInterval = setInterval(() => {
        this.cleanup()
      }, cleanupIntervalMs)

      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref()
      }
    }
  }

  async get(key: string): Promise<CachedResponse | null> {
    const entry = this.cache.get(key)
    if (!entry) {
      return null
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key)
      return null
    }

    return entry.response
  }

  async set(key: string, response: CachedResponse, ttl: number): Promise<void> {
    // Evict oldest if at capacity
    if (this.cache.size >= this.maxSize) {
      this.evictOldest()
    }

    this.cache.set(key, {
      response,
      expiresAt: Date.now() + ttl,
    })
  }

  async isProcessing(key: string): Promise<boolean> {
    const entry = this.processing.get(key)
    if (!entry) {
      return false
    }

    // Check if lock expired
    if (Date.now() > entry.expiresAt) {
      this.processing.delete(key)
      return false
    }

    return true
  }

  async startProcessing(key: string, timeout: number): Promise<boolean> {
    // Check if already processing
    if (await this.isProcessing(key)) {
      return false
    }

    const now = Date.now()
    this.processing.set(key, {
      startedAt: now,
      expiresAt: now + timeout,
    })

    return true
  }

  async endProcessing(key: string): Promise<void> {
    this.processing.delete(key)
  }

  async delete(key: string): Promise<void> {
    this.cache.delete(key)
    this.processing.delete(key)
  }

  async cleanup(): Promise<void> {
    const now = Date.now()

    // Cleanup expired cache entries
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key)
      }
    }

    // Cleanup expired processing locks
    for (const [key, entry] of this.processing.entries()) {
      if (now > entry.expiresAt) {
        this.processing.delete(key)
      }
    }
  }

  getStats(): { cacheSize: number; processingSize: number } {
    return {
      cacheSize: this.cache.size,
      processingSize: this.processing.size,
    }
  }

  private evictOldest(): void {
    // Remove 10% of oldest entries
    const toRemove = Math.ceil(this.maxSize * 0.1)
    const entries = Array.from(this.cache.entries())
      .sort((a, b) => a[1].response.cachedAt - b[1].response.cachedAt)
      .slice(0, toRemove)

    for (const [key] of entries) {
      this.cache.delete(key)
    }
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.cache.clear()
    this.processing.clear()
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

let globalIdempotencyStore: MemoryIdempotencyStore | null = null

/**
 * Get global idempotency store (singleton)
 */
export function getGlobalIdempotencyStore(): MemoryIdempotencyStore {
  if (!globalIdempotencyStore) {
    globalIdempotencyStore = new MemoryIdempotencyStore()
  }
  return globalIdempotencyStore
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Generate a cryptographically secure idempotency key
 */
export function generateIdempotencyKey(length: number = 32): string {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Hash request body using SHA-256
 */
export async function hashRequestBody(body: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(body)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = new Uint8Array(hashBuffer)
  return Array.from(hashArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Validate idempotency key format
 */
export function isValidIdempotencyKey(
  key: string,
  minLength: number = 16,
  maxLength: number = 256
): boolean {
  if (!key || typeof key !== 'string') {
    return false
  }

  if (key.length < minLength || key.length > maxLength) {
    return false
  }

  // Check for valid characters (alphanumeric, dash, underscore)
  return /^[a-zA-Z0-9_-]+$/.test(key)
}

/**
 * Create cache key from idempotency key and request hash
 */
export async function createCacheKey(
  idempotencyKey: string,
  req: NextRequest,
  hashBody: boolean = true
): Promise<string> {
  const parts = [idempotencyKey, req.method, new URL(req.url).pathname]

  if (hashBody) {
    try {
      const cloned = req.clone()
      const body = await cloned.text()
      if (body) {
        const bodyHash = await hashRequestBody(body)
        parts.push(bodyHash)
      }
    } catch {
      // Ignore body hash errors
    }
  }

  return parts.join(':')
}

// ============================================================================
// Idempotency Check
// ============================================================================

/**
 * Extract idempotency key from request
 */
export function extractIdempotencyKey(
  req: NextRequest,
  options: IdempotencyOptions = {}
): string | null {
  const { keyHeader = DEFAULT_IDEMPOTENCY_OPTIONS.keyHeader } = options
  return req.headers.get(keyHeader)
}

/**
 * Check idempotency for request
 */
export async function checkIdempotency(
  req: NextRequest,
  options: IdempotencyOptions = {}
): Promise<IdempotencyResult> {
  const {
    store = getGlobalIdempotencyStore(),
    keyHeader = DEFAULT_IDEMPOTENCY_OPTIONS.keyHeader,
    required = DEFAULT_IDEMPOTENCY_OPTIONS.required,
    methods = DEFAULT_IDEMPOTENCY_OPTIONS.methods,
    minKeyLength = DEFAULT_IDEMPOTENCY_OPTIONS.minKeyLength,
    maxKeyLength = DEFAULT_IDEMPOTENCY_OPTIONS.maxKeyLength,
    hashRequestBody: hashBody = DEFAULT_IDEMPOTENCY_OPTIONS.hashRequestBody,
    validateKey,
  } = options

  // Check if method requires idempotency
  const method = req.method.toUpperCase()
  if (!methods.includes(method)) {
    return {
      key: null,
      fromCache: false,
      isProcessing: false,
    }
  }

  // Extract key
  const key = req.headers.get(keyHeader)

  // Check if required
  if (!key) {
    if (required) {
      return {
        key: null,
        fromCache: false,
        isProcessing: false,
        reason: 'Missing idempotency key',
      }
    }
    return {
      key: null,
      fromCache: false,
      isProcessing: false,
    }
  }

  // Validate key format
  if (!isValidIdempotencyKey(key, minKeyLength, maxKeyLength)) {
    return {
      key,
      fromCache: false,
      isProcessing: false,
      reason: `Invalid idempotency key format (length must be ${minKeyLength}-${maxKeyLength}, alphanumeric)`,
    }
  }

  // Custom validation
  if (validateKey) {
    const isValid = await validateKey(key)
    if (!isValid) {
      return {
        key,
        fromCache: false,
        isProcessing: false,
        reason: 'Idempotency key failed custom validation',
      }
    }
  }

  // Create cache key
  const cacheKey = await createCacheKey(key, req, hashBody)

  // Check cache
  const cached = await store.get(cacheKey)
  if (cached) {
    return {
      key,
      fromCache: true,
      cachedResponse: cached,
      isProcessing: false,
    }
  }

  // Check if processing
  const isProcessing = await store.isProcessing(cacheKey)

  return {
    key,
    fromCache: false,
    isProcessing,
    reason: isProcessing ? 'Request is currently being processed' : undefined,
  }
}

// ============================================================================
// Response Caching
// ============================================================================

/**
 * Cache response for idempotency key
 */
export async function cacheResponse(
  key: string,
  req: NextRequest,
  response: Response,
  options: IdempotencyOptions = {}
): Promise<void> {
  const {
    store = getGlobalIdempotencyStore(),
    ttl = DEFAULT_IDEMPOTENCY_OPTIONS.ttl,
    hashRequestBody: hashBody = DEFAULT_IDEMPOTENCY_OPTIONS.hashRequestBody,
  } = options

  // Create cache key
  const cacheKey = await createCacheKey(key, req, hashBody)

  // Clone response to read body
  const cloned = response.clone()
  const body = await cloned.text()

  // Convert headers to object
  const headers: Record<string, string> = {}
  response.headers.forEach((value, name) => {
    headers[name] = value
  })

  // Store cached response
  const cachedResponse: CachedResponse = {
    status: response.status,
    headers,
    body,
    cachedAt: Date.now(),
  }

  await store.set(cacheKey, cachedResponse, ttl)

  // End processing lock
  await store.endProcessing(cacheKey)
}

/**
 * Create response from cached data
 */
export function createResponseFromCache(cached: CachedResponse): Response {
  const headers = new Headers(cached.headers)

  // Add header to indicate this is a cached response
  headers.set('x-idempotency-replayed', 'true')
  headers.set('x-idempotency-cached-at', new Date(cached.cachedAt).toISOString())

  return new Response(cached.body, {
    status: cached.status,
    headers,
  })
}

// ============================================================================
// Idempotency Middleware
// ============================================================================

/**
 * Default error response
 */
function defaultErrorResponse(reason: string): Response {
  return new Response(
    JSON.stringify({
      error: 'Bad Request',
      message: reason,
      code: 'IDEMPOTENCY_ERROR',
    }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Wait for lock with polling
 */
async function waitForLock(
  store: IdempotencyStore,
  cacheKey: string,
  maxWaitTime: number,
  pollInterval: number = 100
): Promise<CachedResponse | null> {
  const startTime = Date.now()

  while (Date.now() - startTime < maxWaitTime) {
    // Check if response is now cached
    const cached = await store.get(cacheKey)
    if (cached) {
      return cached
    }

    // Check if still processing
    const isProcessing = await store.isProcessing(cacheKey)
    if (!isProcessing) {
      // Processing ended but no cached response - might be an error
      return null
    }

    // Wait before next poll
    await new Promise(resolve => setTimeout(resolve, pollInterval))
  }

  return null
}

/**
 * Create idempotency middleware
 */
export function withIdempotency<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: IdempotencyOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  return async (req: NextRequest, ctx: T): Promise<Response> => {
    // Check if should skip
    if (options.skip && await options.skip(req)) {
      return handler(req, ctx)
    }

    const {
      store = getGlobalIdempotencyStore(),
      methods = DEFAULT_IDEMPOTENCY_OPTIONS.methods,
      hashRequestBody: hashBody = DEFAULT_IDEMPOTENCY_OPTIONS.hashRequestBody,
      lockTimeout = DEFAULT_IDEMPOTENCY_OPTIONS.lockTimeout,
      waitForLock: shouldWait = DEFAULT_IDEMPOTENCY_OPTIONS.waitForLock,
      maxWaitTime = DEFAULT_IDEMPOTENCY_OPTIONS.maxWaitTime,
      onError,
      onCacheHit,
    } = options

    // Check if method requires idempotency
    const method = req.method.toUpperCase()
    if (!methods.includes(method)) {
      return handler(req, ctx)
    }

    // Check idempotency
    const result = await checkIdempotency(req, options)

    // Handle errors
    if (result.reason && !result.isProcessing) {
      const errorHandler = onError || defaultErrorResponse
      return errorHandler(result.reason)
    }

    // Return cached response
    if (result.fromCache && result.cachedResponse) {
      if (onCacheHit) {
        onCacheHit(result.key!, result.cachedResponse)
      }
      return createResponseFromCache(result.cachedResponse)
    }

    // No key provided and not required
    if (!result.key) {
      return handler(req, ctx)
    }

    // Create cache key for lock
    const cacheKey = await createCacheKey(result.key, req, hashBody)

    // Handle concurrent request
    if (result.isProcessing) {
      if (shouldWait) {
        const cached = await waitForLock(store, cacheKey, maxWaitTime)
        if (cached) {
          if (onCacheHit) {
            onCacheHit(result.key, cached)
          }
          return createResponseFromCache(cached)
        }
      }

      return new Response(
        JSON.stringify({
          error: 'Conflict',
          message: 'Request with this idempotency key is currently being processed',
          code: 'IDEMPOTENCY_CONFLICT',
        }),
        {
          status: 409,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }

    // Acquire processing lock
    const acquired = await store.startProcessing(cacheKey, lockTimeout)
    if (!acquired) {
      // Race condition - another request got the lock
      if (shouldWait) {
        const cached = await waitForLock(store, cacheKey, maxWaitTime)
        if (cached) {
          if (onCacheHit) {
            onCacheHit(result.key, cached)
          }
          return createResponseFromCache(cached)
        }
      }

      return new Response(
        JSON.stringify({
          error: 'Conflict',
          message: 'Request with this idempotency key is currently being processed',
          code: 'IDEMPOTENCY_CONFLICT',
        }),
        {
          status: 409,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }

    try {
      // Execute handler
      const response = await handler(req, ctx)

      // Cache response (only for successful responses 2xx)
      if (response.status >= 200 && response.status < 300) {
        await cacheResponse(result.key, req, response, options)
      } else {
        // End processing without caching for error responses
        await store.endProcessing(cacheKey)
      }

      return response
    } catch (error) {
      // End processing lock on error
      await store.endProcessing(cacheKey)
      throw error
    }
  }
}

// ============================================================================
// Request Helper
// ============================================================================

/**
 * Add idempotency key header to outgoing request headers
 */
export function addIdempotencyHeader(
  headers: Record<string, string> = {},
  options: { headerName?: string; key?: string } = {}
): Record<string, string> {
  const { headerName = 'idempotency-key', key = generateIdempotencyKey() } = options
  return {
    ...headers,
    [headerName]: key,
  }
}
