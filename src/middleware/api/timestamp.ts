/**
 * Timestamp Validation for API Security
 * @module nextjs-secure/api
 */

import type { NextRequest } from 'next/server'
import type { TimestampOptions, TimestampResult, TimestampFormat } from './types'

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_TIMESTAMP_OPTIONS: Required<Omit<TimestampOptions, 'timestampQuery' | 'onInvalid' | 'skip'>> = {
  timestampHeader: 'x-timestamp',
  format: 'unix',
  maxAge: 300, // 5 minutes
  allowFuture: false,
  maxFuture: 60, // 1 minute
  required: true,
}

// ============================================================================
// Timestamp Parsing
// ============================================================================

/**
 * Parse timestamp string to Unix timestamp (seconds)
 */
export function parseTimestamp(value: string, format: TimestampFormat = 'unix'): number | null {
  if (!value || typeof value !== 'string') {
    return null
  }

  try {
    switch (format) {
      case 'unix': {
        const num = parseInt(value, 10)
        if (isNaN(num) || num <= 0) {
          return null
        }
        return num
      }

      case 'unix-ms': {
        const num = parseInt(value, 10)
        if (isNaN(num) || num <= 0) {
          return null
        }
        return Math.floor(num / 1000)
      }

      case 'iso8601': {
        const date = new Date(value)
        if (isNaN(date.getTime())) {
          return null
        }
        return Math.floor(date.getTime() / 1000)
      }

      default:
        return null
    }
  } catch {
    return null
  }
}

/**
 * Format current timestamp
 */
export function formatTimestamp(format: TimestampFormat = 'unix'): string {
  const now = Date.now()

  switch (format) {
    case 'unix':
      return Math.floor(now / 1000).toString()
    case 'unix-ms':
      return now.toString()
    case 'iso8601':
      return new Date(now).toISOString()
    default:
      return Math.floor(now / 1000).toString()
  }
}

// ============================================================================
// Timestamp Extraction
// ============================================================================

/**
 * Extract timestamp from request
 */
export function extractTimestamp(req: NextRequest, options: TimestampOptions = {}): string | null {
  const {
    timestampHeader = DEFAULT_TIMESTAMP_OPTIONS.timestampHeader,
    timestampQuery,
  } = options

  // Try header first
  const headerTimestamp = req.headers.get(timestampHeader)
  if (headerTimestamp) {
    return headerTimestamp
  }

  // Try query param
  if (timestampQuery) {
    const url = new URL(req.url)
    const queryTimestamp = url.searchParams.get(timestampQuery)
    if (queryTimestamp) {
      return queryTimestamp
    }
  }

  return null
}

// ============================================================================
// Timestamp Validation
// ============================================================================

/**
 * Validate request timestamp
 */
export function validateTimestamp(
  req: NextRequest,
  options: TimestampOptions = {}
): TimestampResult {
  const {
    timestampHeader = DEFAULT_TIMESTAMP_OPTIONS.timestampHeader,
    timestampQuery,
    format = DEFAULT_TIMESTAMP_OPTIONS.format,
    maxAge = DEFAULT_TIMESTAMP_OPTIONS.maxAge,
    allowFuture = DEFAULT_TIMESTAMP_OPTIONS.allowFuture,
    maxFuture = DEFAULT_TIMESTAMP_OPTIONS.maxFuture,
    required = DEFAULT_TIMESTAMP_OPTIONS.required,
  } = options

  // Extract timestamp
  const timestampStr = extractTimestamp(req, { timestampHeader, timestampQuery })

  // Check if required
  if (!timestampStr) {
    if (required) {
      return {
        valid: false,
        reason: 'Missing timestamp',
      }
    }
    return {
      valid: true,
    }
  }

  // Parse timestamp
  const timestamp = parseTimestamp(timestampStr, format)
  if (timestamp === null) {
    return {
      valid: false,
      reason: `Invalid timestamp format (expected: ${format})`,
    }
  }

  // Get current time
  const now = Math.floor(Date.now() / 1000)
  const age = now - timestamp

  // Check if too old
  if (age > maxAge) {
    return {
      valid: false,
      timestamp,
      age,
      reason: `Timestamp too old (age: ${age}s, max: ${maxAge}s)`,
    }
  }

  // Check if in future
  if (age < 0) {
    if (!allowFuture) {
      return {
        valid: false,
        timestamp,
        age,
        reason: 'Timestamp is in the future',
      }
    }

    // Check if too far in future
    const futureAge = Math.abs(age)
    if (futureAge > maxFuture) {
      return {
        valid: false,
        timestamp,
        age,
        reason: `Timestamp too far in future (${futureAge}s, max: ${maxFuture}s)`,
      }
    }
  }

  return {
    valid: true,
    timestamp,
    age,
  }
}

/**
 * Quick check if timestamp is valid
 */
export function isTimestampValid(
  timestampStr: string,
  options: { format?: TimestampFormat; maxAge?: number; allowFuture?: boolean; maxFuture?: number } = {}
): boolean {
  const {
    format = 'unix',
    maxAge = 300,
    allowFuture = false,
    maxFuture = 60,
  } = options

  const timestamp = parseTimestamp(timestampStr, format)
  if (timestamp === null) {
    return false
  }

  const now = Math.floor(Date.now() / 1000)
  const age = now - timestamp

  // Check if too old
  if (age > maxAge) {
    return false
  }

  // Check if in future
  if (age < 0) {
    if (!allowFuture) {
      return false
    }
    if (Math.abs(age) > maxFuture) {
      return false
    }
  }

  return true
}

// ============================================================================
// Timestamp Middleware
// ============================================================================

/**
 * Default response for invalid timestamp
 */
function defaultInvalidResponse(reason: string): Response {
  return new Response(
    JSON.stringify({
      error: 'Bad Request',
      message: reason,
      code: 'INVALID_TIMESTAMP',
    }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Create timestamp validation middleware
 */
export function withTimestamp<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: TimestampOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  return async (req: NextRequest, ctx: T): Promise<Response> => {
    // Check if should skip
    if (options.skip && await options.skip(req)) {
      return handler(req, ctx)
    }

    // Validate timestamp
    const result = validateTimestamp(req, options)

    if (!result.valid) {
      const onInvalid = options.onInvalid || defaultInvalidResponse
      return onInvalid(result.reason || 'Invalid timestamp')
    }

    return handler(req, ctx)
  }
}

// ============================================================================
// Request Helper
// ============================================================================

/**
 * Add timestamp header to outgoing request headers
 */
export function addTimestampHeader(
  headers: Record<string, string> = {},
  options: { headerName?: string; format?: TimestampFormat } = {}
): Record<string, string> {
  const { headerName = 'x-timestamp', format = 'unix' } = options
  return {
    ...headers,
    [headerName]: formatTimestamp(format),
  }
}

/**
 * Get request age in seconds (for monitoring/logging)
 */
export function getRequestAge(req: NextRequest, options: TimestampOptions = {}): number | null {
  const timestampStr = extractTimestamp(req, options)
  if (!timestampStr) {
    return null
  }

  const timestamp = parseTimestamp(timestampStr, options.format)
  if (timestamp === null) {
    return null
  }

  const now = Math.floor(Date.now() / 1000)
  return now - timestamp
}
