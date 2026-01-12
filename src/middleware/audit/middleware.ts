import type { NextRequest } from 'next/server'
import type {
  AuditConfig,
  RequestLogEntry,
  LogLevel,
  PIIConfig,
} from './types'
import { redactObject, redactHeaders, redactQuery, DEFAULT_PII_FIELDS } from './redaction'

type RouteHandler = (req: NextRequest) => Response | Promise<Response>

/**
 * Generate unique request ID
 */
function generateRequestId(): string {
  return `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`
}

/**
 * Get client IP from request
 */
function getClientIP(req: NextRequest): string | undefined {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    req.headers.get('cf-connecting-ip') ||
    undefined
  )
}

/**
 * Convert headers to record
 */
function headersToRecord(headers: Headers, includeHeaders?: boolean | string[]): Record<string, string> {
  if (!includeHeaders) return {}

  const result: Record<string, string> = {}

  if (includeHeaders === true) {
    headers.forEach((value, key) => {
      result[key] = value
    })
  } else if (Array.isArray(includeHeaders)) {
    for (const key of includeHeaders) {
      const value = headers.get(key)
      if (value) result[key] = value
    }
  }

  return result
}

/**
 * Parse query parameters from URL
 */
function parseQuery(url: string): Record<string, string> {
  const result: Record<string, string> = {}

  try {
    const urlObj = new URL(url)
    urlObj.searchParams.forEach((value, key) => {
      result[key] = value
    })
  } catch {
    // Invalid URL
  }

  return result
}

/**
 * Determine log level from status code
 */
function statusToLevel(status: number): LogLevel {
  if (status >= 500) return 'error'
  if (status >= 400) return 'warn'
  return 'info'
}

/**
 * Should skip logging for this request
 */
function shouldSkip(
  req: NextRequest,
  status: number,
  exclude?: AuditConfig['exclude']
): boolean {
  if (!exclude) return false

  const url = new URL(req.url)

  // Check path
  if (exclude.paths?.length) {
    const matchesPath = exclude.paths.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$')
        return regex.test(url.pathname)
      }
      return url.pathname === pattern || url.pathname.startsWith(pattern)
    })
    if (matchesPath) return true
  }

  // Check method
  if (exclude.methods?.includes(req.method)) {
    return true
  }

  // Check status code
  if (exclude.statusCodes?.includes(status)) {
    return true
  }

  return false
}

/**
 * Audit logging middleware
 */
export function withAuditLog(
  handler: RouteHandler,
  config: AuditConfig
): RouteHandler {
  const {
    enabled = true,
    store,
    include = {},
    exclude,
    pii,
    getUser,
    requestIdHeader = 'x-request-id',
    generateRequestId: customGenerateId,
    onError,
    skip,
  } = config

  // Default include settings
  const includeSettings = {
    ip: include.ip ?? true,
    userAgent: include.userAgent ?? true,
    headers: include.headers ?? false,
    query: include.query ?? true,
    body: include.body ?? false,
    response: include.response ?? true,
    responseBody: include.responseBody ?? false,
    duration: include.duration ?? true,
    user: include.user ?? true,
  }

  // PII config
  const piiConfig: PIIConfig = pii || {
    fields: DEFAULT_PII_FIELDS,
    mode: 'mask',
  }

  return async (req: NextRequest): Promise<Response> => {
    // Check if logging is enabled
    if (!enabled) {
      return handler(req)
    }

    // Check skip condition
    if (skip && await skip(req)) {
      return handler(req)
    }

    const startTime = Date.now()
    const requestId = req.headers.get(requestIdHeader) ||
      (customGenerateId ? customGenerateId() : generateRequestId())

    const url = new URL(req.url)

    // Build request info
    let requestInfo: RequestLogEntry['request'] = {
      id: requestId,
      method: req.method,
      url: req.url,
      path: url.pathname,
    }

    if (includeSettings.ip) {
      requestInfo.ip = getClientIP(req)
    }

    if (includeSettings.userAgent) {
      requestInfo.userAgent = req.headers.get('user-agent') || undefined
    }

    if (includeSettings.headers) {
      let headers = headersToRecord(req.headers, includeSettings.headers)
      headers = redactHeaders(headers)
      requestInfo.headers = headers
    }

    if (includeSettings.query) {
      let query = parseQuery(req.url)
      query = redactQuery(query)
      requestInfo.query = query
    }

    requestInfo.contentType = req.headers.get('content-type') || undefined
    requestInfo.contentLength = parseInt(req.headers.get('content-length') || '0', 10) || undefined

    // Get user if configured
    let user: RequestLogEntry['user']
    if (includeSettings.user && getUser) {
      try {
        user = await getUser(req) || undefined
      } catch {
        // Ignore user extraction errors
      }
    }

    // Execute handler
    let response: Response
    let error: Error | undefined

    try {
      response = await handler(req)
    } catch (err) {
      error = err instanceof Error ? err : new Error(String(err))
      // Re-throw to let error propagate
      throw err
    } finally {
      const duration = Date.now() - startTime
      const status = response!?.status || 500

      // Check if we should skip this request
      if (!shouldSkip(req, status, exclude)) {
        // Build log entry
        const entry: RequestLogEntry = {
          id: requestId,
          timestamp: new Date(),
          type: 'request',
          level: error ? 'error' : statusToLevel(status),
          message: `${req.method} ${url.pathname} ${status} ${duration}ms`,
          request: requestInfo,
          user,
        }

        // Add response info
        if (includeSettings.response && response!) {
          entry.response = {
            status: response.status,
            duration,
          }

          if (includeSettings.headers) {
            entry.response.headers = headersToRecord(response.headers, includeSettings.headers)
          }
        }

        // Add error info
        if (error) {
          entry.error = {
            name: error.name,
            message: error.message,
            stack: error.stack,
          }
        }

        // Redact PII
        const redactedEntry = redactObject(entry, piiConfig)

        // Write to store
        try {
          await store.write(redactedEntry)
        } catch (writeError) {
          if (onError) {
            onError(writeError instanceof Error ? writeError : new Error(String(writeError)), entry)
          } else {
            console.error('[AuditLog] Failed to write log:', writeError)
          }
        }
      }
    }

    return response!
  }
}

/**
 * Create audit middleware with default console logging
 */
export function createAuditMiddleware(
  config: Partial<AuditConfig> & { store: AuditConfig['store'] }
): (handler: RouteHandler) => RouteHandler {
  return (handler: RouteHandler) => withAuditLog(handler, config as AuditConfig)
}

/**
 * Request logger that adds request ID to response headers
 */
export function withRequestId(
  handler: RouteHandler,
  options: {
    headerName?: string
    generateId?: () => string
  } = {}
): RouteHandler {
  const { headerName = 'x-request-id', generateId = generateRequestId } = options

  return async (req: NextRequest): Promise<Response> => {
    const requestId = req.headers.get(headerName) || generateId()

    const response = await handler(req)

    // Clone response to add header
    const newResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    })

    newResponse.headers.set(headerName, requestId)

    return newResponse
  }
}

/**
 * Simple request timing middleware
 */
export function withTiming(
  handler: RouteHandler,
  options: {
    headerName?: string
    log?: boolean
  } = {}
): RouteHandler {
  const { headerName = 'x-response-time', log = false } = options

  return async (req: NextRequest): Promise<Response> => {
    const start = Date.now()

    const response = await handler(req)

    const duration = Date.now() - start

    // Clone response to add header
    const newResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    })

    newResponse.headers.set(headerName, `${duration}ms`)

    if (log) {
      const url = new URL(req.url)
      console.log(`${req.method} ${url.pathname} ${response.status} ${duration}ms`)
    }

    return newResponse
  }
}
