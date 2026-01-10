/**
 * Custom error classes for next-secure
 */

/**
 * Base error class for all next-secure errors
 */
export class SecureError extends Error {
  /**
   * HTTP status code
   */
  public readonly statusCode: number

  /**
   * Error code for programmatic handling
   */
  public readonly code: string

  /**
   * Additional error details
   */
  public readonly details?: Record<string, unknown>

  constructor(
    message: string,
    options: {
      statusCode?: number
      code?: string
      details?: Record<string, unknown>
      cause?: Error
    } = {}
  ) {
    super(message, { cause: options.cause })
    this.name = 'SecureError'
    this.statusCode = options.statusCode ?? 500
    this.code = options.code ?? 'SECURE_ERROR'
    this.details = options.details

    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor)
    }
  }

  /**
   * Convert error to JSON response
   */
  toJSON(): Record<string, unknown> {
    return {
      error: this.name,
      message: this.message,
      code: this.code,
      ...(this.details && { details: this.details }),
    }
  }

  /**
   * Create a Response object from this error
   */
  toResponse(headers?: HeadersInit): Response {
    return new Response(JSON.stringify(this.toJSON()), {
      status: this.statusCode,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    })
  }
}

/**
 * Rate limit exceeded error
 */
export class RateLimitError extends SecureError {
  /**
   * Seconds until rate limit resets
   */
  public readonly retryAfter: number

  /**
   * Unix timestamp when limit resets
   */
  public readonly resetAt: number

  constructor(
    options: {
      retryAfter: number
      resetAt: number
      message?: string
      details?: Record<string, unknown>
    }
  ) {
    super(options.message ?? 'Too Many Requests', {
      statusCode: 429,
      code: 'RATE_LIMIT_EXCEEDED',
      details: options.details,
    })
    this.name = 'RateLimitError'
    this.retryAfter = options.retryAfter
    this.resetAt = options.resetAt
  }

  override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      retryAfter: this.retryAfter,
    }
  }

  override toResponse(headers?: HeadersInit): Response {
    return new Response(JSON.stringify(this.toJSON()), {
      status: this.statusCode,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(this.retryAfter),
        ...headers,
      },
    })
  }
}

/**
 * Authentication error
 */
export class AuthenticationError extends SecureError {
  constructor(
    message = 'Authentication required',
    options: {
      code?: string
      details?: Record<string, unknown>
      cause?: Error
    } = {}
  ) {
    super(message, {
      statusCode: 401,
      code: options.code ?? 'AUTHENTICATION_REQUIRED',
      details: options.details,
      cause: options.cause,
    })
    this.name = 'AuthenticationError'
  }
}

/**
 * Authorization error (authenticated but not permitted)
 */
export class AuthorizationError extends SecureError {
  constructor(
    message = 'Access denied',
    options: {
      code?: string
      details?: Record<string, unknown>
      cause?: Error
    } = {}
  ) {
    super(message, {
      statusCode: 403,
      code: options.code ?? 'ACCESS_DENIED',
      details: options.details,
      cause: options.cause,
    })
    this.name = 'AuthorizationError'
  }
}

/**
 * Validation error
 */
export class ValidationError extends SecureError {
  /**
   * Field-level validation errors
   */
  public readonly errors: Array<{
    field: string
    message: string
    code?: string
  }>

  constructor(
    errors: Array<{ field: string; message: string; code?: string }>,
    message = 'Validation failed'
  ) {
    super(message, {
      statusCode: 400,
      code: 'VALIDATION_ERROR',
      details: { errors },
    })
    this.name = 'ValidationError'
    this.errors = errors
  }

  override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      errors: this.errors,
    }
  }
}

/**
 * CSRF token error
 */
export class CsrfError extends SecureError {
  constructor(
    message = 'Invalid or missing CSRF token',
    options: {
      details?: Record<string, unknown>
    } = {}
  ) {
    super(message, {
      statusCode: 403,
      code: 'CSRF_TOKEN_INVALID',
      details: options.details,
    })
    this.name = 'CsrfError'
  }
}

/**
 * Configuration error
 */
export class ConfigurationError extends SecureError {
  constructor(
    message: string,
    options: {
      details?: Record<string, unknown>
      cause?: Error
    } = {}
  ) {
    super(message, {
      statusCode: 500,
      code: 'CONFIGURATION_ERROR',
      details: options.details,
      cause: options.cause,
    })
    this.name = 'ConfigurationError'
  }
}

/**
 * Check if an error is a SecureError
 */
export function isSecureError(error: unknown): error is SecureError {
  return error instanceof SecureError
}

/**
 * Convert unknown error to SecureError
 */
export function toSecureError(error: unknown): SecureError {
  if (error instanceof SecureError) {
    return error
  }

  if (error instanceof Error) {
    return new SecureError(error.message, {
      cause: error,
    })
  }

  return new SecureError(String(error))
}
