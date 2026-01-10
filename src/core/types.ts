/**
 * Core types for next-secure
 */

/**
 * Standard Next.js request type (compatible with App Router)
 */
export interface NextRequest {
  url: string
  method: string
  headers: Headers
  ip?: string
  geo?: {
    city?: string
    country?: string
    region?: string
    latitude?: string
    longitude?: string
  }
  nextUrl: {
    pathname: string
    searchParams: URLSearchParams
    href: string
  }
  json: () => Promise<unknown>
  text: () => Promise<string>
  formData: () => Promise<FormData>
  clone: () => NextRequest
}

/**
 * Security context passed to handlers
 */
export interface SecureContext<TUser = unknown> {
  /**
   * Authenticated user (if auth middleware is used)
   */
  user: TUser | null

  /**
   * Unique request ID for tracing
   */
  requestId: string

  /**
   * Client IP address
   */
  ip: string

  /**
   * User agent string
   */
  userAgent: string

  /**
   * Request start timestamp
   */
  startTime: number

  /**
   * Additional metadata
   */
  metadata: Record<string, unknown>
}

/**
 * Handler function type
 */
export type SecureHandler<TUser = unknown> = (
  request: NextRequest,
  context: SecureContext<TUser>
) => Promise<Response> | Response

/**
 * Middleware function type
 */
export type Middleware<TUser = unknown> = (
  request: NextRequest,
  context: SecureContext<TUser>,
  next: () => Promise<Response>
) => Promise<Response>

/**
 * Error response format
 */
export interface ErrorResponse {
  error: string
  message: string
  code?: string
  details?: Record<string, unknown>
}

/**
 * Rate limit info included in context
 */
export interface RateLimitInfo {
  /**
   * Maximum number of requests allowed
   */
  limit: number

  /**
   * Remaining requests in current window
   */
  remaining: number

  /**
   * Unix timestamp when the limit resets
   */
  reset: number

  /**
   * Whether the request is rate limited
   */
  limited: boolean

  /**
   * Seconds until rate limit resets (only when limited)
   */
  retryAfter?: number
}

/**
 * Duration string format (e.g., '15m', '1h', '30s')
 */
export type Duration = `${number}${'s' | 'm' | 'h' | 'd'}` | number

/**
 * Algorithm types for rate limiting
 */
export type RateLimitAlgorithm = 'sliding-window' | 'fixed-window' | 'token-bucket'

/**
 * Identifier types for rate limiting
 */
export type RateLimitIdentifier = 'ip' | 'user' | ((request: NextRequest) => string | Promise<string>)
