/**
 * Rate Limiting Middleware for Next.js App Router
 *
 * @example
 * ```typescript
 * // Basic usage
 * import { withRateLimit } from 'next-secure/rate-limit'
 *
 * export const GET = withRateLimit(
 *   async (req) => Response.json({ data: [] }),
 *   { limit: 100, window: '15m' }
 * )
 *
 * // With custom identifier
 * export const GET = withRateLimit(handler, {
 *   limit: 100,
 *   window: '15m',
 *   identifier: (req) => req.headers.get('x-api-key') ?? 'anonymous'
 * })
 *
 * // With Redis store
 * import { createRedisStore } from 'next-secure/rate-limit'
 *
 * const store = createRedisStore({ client: redis })
 *
 * export const GET = withRateLimit(handler, {
 *   limit: 100,
 *   window: '15m',
 *   store
 * })
 * ```
 */

import type { NextRequest, RateLimitInfo, SecureContext } from '../../core/types'
import { RateLimitError } from '../../core/errors'
import { parseDuration } from '../../utils/time'
import { getClientIp } from '../../utils/ip'
import type { RateLimitConfig, RateLimitStore, RateLimitAlgorithmImpl } from './types'
import { MemoryStore } from './stores/memory'
import { SlidingWindowAlgorithm } from './algorithms/sliding-window'
import { FixedWindowAlgorithm } from './algorithms/fixed-window'
import { TokenBucketAlgorithm } from './algorithms/token-bucket'

/**
 * Default configuration values
 */
const DEFAULT_CONFIG: Partial<RateLimitConfig> = {
  algorithm: 'sliding-window',
  identifier: 'ip',
  headers: true,
  prefix: 'rl',
  message: 'Too Many Requests',
  statusCode: 429,
  debug: false,
}

/**
 * Global default store (shared across handlers)
 */
let defaultStore: RateLimitStore | null = null

/**
 * Get or create the default memory store
 */
function getDefaultStore(): RateLimitStore {
  if (!defaultStore) {
    defaultStore = new MemoryStore()
  }
  return defaultStore
}

/**
 * Get algorithm instance by name
 */
function getAlgorithm(name: RateLimitConfig['algorithm']): RateLimitAlgorithmImpl {
  switch (name) {
    case 'fixed-window':
      return new FixedWindowAlgorithm()
    case 'token-bucket':
      return new TokenBucketAlgorithm()
    case 'sliding-window':
    default:
      return new SlidingWindowAlgorithm()
  }
}

/**
 * Create rate limit headers
 */
function createRateLimitHeaders(info: RateLimitInfo): Headers {
  const headers = new Headers()

  headers.set('X-RateLimit-Limit', String(info.limit))
  headers.set('X-RateLimit-Remaining', String(info.remaining))
  headers.set('X-RateLimit-Reset', String(info.reset))

  if (info.limited && info.retryAfter) {
    headers.set('Retry-After', String(info.retryAfter))
  }

  return headers
}

/**
 * Merge headers from multiple sources
 */
function mergeHeaders(target: Headers, source: Headers): void {
  source.forEach((value, key) => {
    target.set(key, value)
  })
}

/**
 * Get client identifier from request
 */
async function getIdentifier(
  request: NextRequest,
  identifier: RateLimitConfig['identifier'],
  prefix: string,
  context?: SecureContext
): Promise<string> {
  if (typeof identifier === 'function') {
    const id = await identifier(request)
    return `${prefix}:custom:${id}`
  }

  if (identifier === 'user') {
    // Requires auth middleware to have run first
    const userId = context?.user
      ? (context.user as { id?: string }).id ?? 'anonymous'
      : 'anonymous'
    return `${prefix}:user:${userId}`
  }

  // Default: IP-based
  const ip = getClientIp(request)
  return `${prefix}:ip:${ip}`
}

/**
 * Rate limiting middleware wrapper
 *
 * @example
 * ```typescript
 * // Simple usage
 * export const GET = withRateLimit(
 *   async (req) => Response.json({ ok: true }),
 *   { limit: 100, window: '15m' }
 * )
 *
 * // With all options
 * export const POST = withRateLimit(
 *   async (req, ctx) => {
 *     // ctx.rateLimit contains info
 *     return Response.json({ remaining: ctx.rateLimit?.remaining })
 *   },
 *   {
 *     limit: 10,
 *     window: '1m',
 *     algorithm: 'sliding-window',
 *     identifier: 'ip',
 *     headers: true,
 *     onLimit: (req, info) => new Response(
 *       JSON.stringify({ error: 'Slow down!' }),
 *       { status: 429 }
 *     ),
 *     skip: (req) => req.headers.get('x-bypass') === 'secret'
 *   }
 * )
 * ```
 */
export function withRateLimit<TUser = unknown>(
  handler: (
    request: NextRequest,
    context: SecureContext<TUser> & { rateLimit?: RateLimitInfo }
  ) => Promise<Response> | Response,
  config: RateLimitConfig
): (request: NextRequest, context?: SecureContext<TUser>) => Promise<Response> {
  // Merge config with defaults
  const finalConfig: Required<RateLimitConfig> = {
    ...DEFAULT_CONFIG,
    ...config,
    store: config.store ?? getDefaultStore(),
  } as Required<RateLimitConfig>

  // Parse window duration once
  const windowMs = parseDuration(finalConfig.window)

  // Get algorithm once
  const algorithm = getAlgorithm(finalConfig.algorithm)

  // Debug logging
  const debug = finalConfig.debug
    ? (msg: string, data?: unknown) => {
        // eslint-disable-next-line no-console
        console.log(`[next-secure:rate-limit] ${msg}`, data ?? '')
      }
    : () => {}

  debug('Initialized', {
    limit: finalConfig.limit,
    window: finalConfig.window,
    algorithm: finalConfig.algorithm,
  })

  return async (
    request: NextRequest,
    context?: SecureContext<TUser>
  ): Promise<Response> => {
    // Create context if not provided
    const ctx: SecureContext<TUser> & { rateLimit?: RateLimitInfo } = context ?? {
      user: null,
      requestId: crypto.randomUUID(),
      ip: getClientIp(request),
      userAgent: request.headers.get('user-agent') ?? '',
      startTime: Date.now(),
      metadata: {},
    }

    try {
      // Check if we should skip rate limiting
      if (finalConfig.skip) {
        const shouldSkip = await finalConfig.skip(request)
        if (shouldSkip) {
          debug('Skipping rate limit check')
          return handler(request, ctx)
        }
      }

      // Get identifier
      const key = await getIdentifier(
        request,
        finalConfig.identifier,
        finalConfig.prefix,
        ctx
      )
      debug('Rate limit key', key)

      // Check rate limit
      const info = await algorithm.check(
        finalConfig.store,
        key,
        finalConfig.limit,
        windowMs
      )
      debug('Rate limit info', info)

      // Add rate limit info to context
      ctx.rateLimit = info

      // Check if limited
      if (info.limited) {
        debug('Request rate limited')

        // Custom handler
        if (finalConfig.onLimit) {
          const response = await finalConfig.onLimit(request, info)

          // Add headers to custom response
          if (finalConfig.headers) {
            const rateLimitHeaders = createRateLimitHeaders(info)
            mergeHeaders(response.headers, rateLimitHeaders)
          }

          return response
        }

        // Default rate limit response
        const error = new RateLimitError({
          retryAfter: info.retryAfter ?? 60,
          resetAt: info.reset * 1000,
          message: finalConfig.message,
        })

        const response = error.toResponse()

        if (finalConfig.headers) {
          const rateLimitHeaders = createRateLimitHeaders(info)
          mergeHeaders(response.headers, rateLimitHeaders)
        }

        return response
      }

      // Call the handler
      const response = await handler(request, ctx)

      // Add rate limit headers to successful response
      if (finalConfig.headers) {
        // Clone response to modify headers
        const newResponse = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: new Headers(response.headers),
        })

        const rateLimitHeaders = createRateLimitHeaders(info)
        mergeHeaders(newResponse.headers, rateLimitHeaders)

        return newResponse
      }

      return response
    } catch (error) {
      debug('Error in rate limit middleware', error)

      // Re-throw RateLimitError
      if (error instanceof RateLimitError) {
        throw error
      }

      // For other errors, let the request through (fail open)
      // This prevents rate limiting from blocking all requests on errors
      // eslint-disable-next-line no-console
      console.error('[next-secure:rate-limit] Error:', error)
      return handler(request, ctx)
    }
  }
}

/**
 * Create a rate limiter instance for reuse
 *
 * @example
 * ```typescript
 * const apiLimiter = createRateLimiter({
 *   limit: 100,
 *   window: '15m'
 * })
 *
 * export const GET = apiLimiter(async (req) => Response.json({ ok: true }))
 * export const POST = apiLimiter(async (req) => Response.json({ ok: true }))
 * ```
 */
export function createRateLimiter(config: RateLimitConfig) {
  return <TUser = unknown>(
    handler: (
      request: NextRequest,
      context: SecureContext<TUser> & { rateLimit?: RateLimitInfo }
    ) => Promise<Response> | Response
  ) => withRateLimit(handler, config)
}

/**
 * Check rate limit without wrapping a handler
 * Useful for checking rate limit in existing code
 *
 * @example
 * ```typescript
 * export async function GET(req: NextRequest) {
 *   const result = await checkRateLimit(req, {
 *     limit: 100,
 *     window: '15m'
 *   })
 *
 *   if (!result.success) {
 *     return result.response
 *   }
 *
 *   // Continue with normal logic
 *   return Response.json({ ok: true })
 * }
 * ```
 */
export async function checkRateLimit(
  request: NextRequest,
  config: RateLimitConfig
): Promise<{
  success: boolean
  info: RateLimitInfo
  response?: Response
  headers: Headers
}> {
  const finalConfig = {
    ...DEFAULT_CONFIG,
    ...config,
    store: config.store ?? getDefaultStore(),
  } as Required<RateLimitConfig>

  const windowMs = parseDuration(finalConfig.window)
  const algorithm = getAlgorithm(finalConfig.algorithm)

  // Check if should skip
  if (finalConfig.skip) {
    const shouldSkip = await finalConfig.skip(request)
    if (shouldSkip) {
      const info: RateLimitInfo = {
        limit: finalConfig.limit,
        remaining: finalConfig.limit,
        reset: Math.floor(Date.now() / 1000) + Math.floor(windowMs / 1000),
        limited: false,
      }
      return { success: true, info, headers: new Headers() }
    }
  }

  const key = await getIdentifier(request, finalConfig.identifier, finalConfig.prefix)
  const info = await algorithm.check(finalConfig.store, key, finalConfig.limit, windowMs)
  const headers = finalConfig.headers ? createRateLimitHeaders(info) : new Headers()

  if (info.limited) {
    let response: Response

    if (finalConfig.onLimit) {
      response = await finalConfig.onLimit(request, info)
    } else {
      const error = new RateLimitError({
        retryAfter: info.retryAfter ?? 60,
        resetAt: info.reset * 1000,
        message: finalConfig.message,
      })
      response = error.toResponse()
    }

    if (finalConfig.headers) {
      mergeHeaders(response.headers, headers)
    }

    return { success: false, info, response, headers }
  }

  return { success: true, info, headers }
}

/**
 * Reset rate limit for a specific key
 *
 * @example
 * ```typescript
 * // Reset rate limit for an IP
 * await resetRateLimit('ip', '192.168.1.1')
 *
 * // Reset for a user
 * await resetRateLimit('user', 'user-123')
 * ```
 */
export async function resetRateLimit(
  type: 'ip' | 'user' | 'custom',
  identifier: string,
  options?: {
    store?: RateLimitStore
    prefix?: string
  }
): Promise<void> {
  const store = options?.store ?? getDefaultStore()
  const prefix = options?.prefix ?? 'rl'
  const key = `${prefix}:${type}:${identifier}`

  await store.reset(key)
}

/**
 * Get current rate limit status for a key (without incrementing)
 */
export async function getRateLimitStatus(
  type: 'ip' | 'user' | 'custom',
  identifier: string,
  options?: {
    store?: RateLimitStore
    prefix?: string
  }
): Promise<{ count: number; reset: number } | null> {
  const store = options?.store ?? getDefaultStore()
  const prefix = options?.prefix ?? 'rl'
  const key = `${prefix}:${type}:${identifier}`

  return store.get(key)
}

/**
 * Clear all rate limits (useful for testing)
 */
export function clearAllRateLimits(): void {
  if (defaultStore && 'clear' in defaultStore) {
    (defaultStore as MemoryStore).clear()
  }
}
