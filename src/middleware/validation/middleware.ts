import type { NextRequest } from 'next/server'
import type {
  ValidationConfig,
  ValidatedContext,
  ValidationError,
  SanitizationMiddlewareConfig,
  SanitizationChange,
  SQLProtectionConfig,
  ContentTypeConfig,
  FileValidationConfig,
  FileInfo,
  Schema,
  CustomSchema,
} from './types'
import { validateRequest, defaultValidationErrorResponse } from './validators/schema'
import { validateContentType, defaultContentTypeErrorResponse } from './validators/content-type'
import { validateFilesFromRequest, defaultFileErrorResponse } from './validators/file'
import { sanitize, detectXSS } from './sanitizers/xss'
import { detectSQLInjectionInObject } from './sanitizers/sql'
import { walkObject } from './utils'

type RouteHandler = (req: NextRequest) => Response | Promise<Response>

/**
 * Validation middleware
 * Validates request body, query, and params against schemas
 */
export function withValidation<
  TBody = unknown,
  TQuery = unknown,
  TParams = unknown
>(
  handler: (
    req: NextRequest,
    ctx: { validated: ValidatedContext<TBody, TQuery, TParams> }
  ) => Response | Promise<Response>,
  config: ValidationConfig<TBody, TQuery, TParams> & {
    routeParams?: Record<string, string | string[]>
  }
): RouteHandler {
  const onError = config.onError || ((_, errors) => defaultValidationErrorResponse(errors))

  return async (req: NextRequest): Promise<Response> => {
    const result = await validateRequest<TBody, TQuery, TParams>(req, {
      body: config.body as Schema<TBody> | CustomSchema | undefined,
      query: config.query as Schema<TQuery> | CustomSchema | undefined,
      params: config.params as Schema<TParams> | CustomSchema | undefined,
      routeParams: config.routeParams,
    })

    if (!result.success) {
      return onError(req, result.errors || [])
    }

    return handler(req, { validated: result.data! })
  }
}

/**
 * XSS Sanitization middleware
 * Sanitizes string values in request body
 */
export function withSanitization(
  handler: (
    req: NextRequest,
    ctx: { sanitized: unknown; changes: SanitizationChange[] }
  ) => Response | Promise<Response>,
  config: SanitizationMiddlewareConfig = {}
): RouteHandler {
  const {
    fields,
    mode = 'escape',
    allowedTags,
    skip,
    onSanitized,
  } = config

  return async (req: NextRequest): Promise<Response> => {
    // Check skip condition
    if (skip && await skip(req)) {
      return handler(req, { sanitized: null, changes: [] })
    }

    let body: unknown
    try {
      body = await req.json()
    } catch {
      return handler(req, { sanitized: null, changes: [] })
    }

    const changes: SanitizationChange[] = []

    const sanitized = walkObject(body, (value, path) => {
      // If specific fields are specified, only sanitize those
      if (fields && fields.length > 0) {
        const fieldName = path.split('.').pop() || path
        if (!fields.includes(fieldName)) {
          return value
        }
      }

      const cleaned = sanitize(value, { mode, allowedTags })

      if (cleaned !== value) {
        changes.push({
          field: path,
          original: value,
          sanitized: cleaned,
        })
      }

      return cleaned
    }, '')

    // Callback for tracking
    if (onSanitized && changes.length > 0) {
      onSanitized(req, changes)
    }

    return handler(req, { sanitized, changes })
  }
}

/**
 * XSS Detection middleware
 * Blocks requests with potential XSS payloads in body and query parameters
 */
export function withXSSProtection(
  handler: RouteHandler,
  config: {
    fields?: string[]
    deep?: boolean
    checkQuery?: boolean
    onDetection?: (req: NextRequest, field: string, value: string) => Response | void | Promise<Response | void>
  } = {}
): RouteHandler {
  const { fields, onDetection, checkQuery = true } = config

  return async (req: NextRequest): Promise<Response> => {
    const detections: { field: string; value: string }[] = []

    // Check query parameters for XSS
    if (checkQuery) {
      const url = new URL(req.url)
      for (const [key, value] of url.searchParams.entries()) {
        if (detectXSS(value)) {
          detections.push({ field: `query.${key}`, value })
        }
      }
    }

    // Check body
    let body: unknown
    try {
      body = await req.json()
    } catch {
      // No body or invalid JSON, skip body check
      body = null
    }

    if (body) {
      walkObject(body, (value, path) => {
        // If specific fields are specified, only check those
        if (fields && fields.length > 0) {
          const fieldName = path.split('.').pop() || path
          if (!fields.includes(fieldName)) {
            return value
          }
        }

        if (detectXSS(value)) {
          detections.push({ field: path, value })
        }

        return value
      }, '')
    }

    if (detections.length > 0) {
      if (onDetection) {
        for (const { field, value } of detections) {
          const result = await onDetection(req, field, value)
          if (result instanceof Response) {
            return result
          }
        }
      }

      // Default: block request
      return new Response(
        JSON.stringify({
          error: 'xss_detected',
          message: 'Potentially malicious content detected',
          fields: detections.map(d => d.field),
        }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }

    return handler(req)
  }
}

/**
 * SQL Injection Protection middleware
 */
export function withSQLProtection(
  handler: RouteHandler,
  config: SQLProtectionConfig = {}
): RouteHandler {
  const {
    fields,
    deep = true,
    mode = 'block',
    customPatterns,
    allowList = [],
    onDetection,
  } = config

  return async (req: NextRequest): Promise<Response> => {
    let body: unknown
    try {
      body = await req.json()
    } catch {
      return handler(req)
    }

    const detections = detectSQLInjectionInObject(body, {
      fields,
      deep,
      customPatterns,
      minSeverity: mode === 'detect' ? 'low' : 'medium',
    })

    // Filter out allowed values
    const filtered = detections.filter(d => !allowList.includes(d.value))

    if (filtered.length > 0) {
      if (onDetection) {
        const result = await onDetection(req, filtered)
        if (result instanceof Response) {
          return result
        }
      }

      if (mode === 'block') {
        return new Response(
          JSON.stringify({
            error: 'sql_injection_detected',
            message: 'Potentially malicious SQL detected',
            detections: filtered.map(d => ({
              field: d.field,
              pattern: d.pattern,
              severity: d.severity,
            })),
          }),
          {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          }
        )
      }
    }

    return handler(req)
  }
}

/**
 * Content-Type validation middleware
 */
export function withContentType(
  handler: RouteHandler,
  config: ContentTypeConfig
): RouteHandler {
  const onInvalid = config.onInvalid || ((_, contentType) =>
    defaultContentTypeErrorResponse(contentType, `Content-Type '${contentType}' is not allowed`)
  )

  return async (req: NextRequest): Promise<Response> => {
    const result = validateContentType(req, config)

    if (!result.valid) {
      return onInvalid(req, result.contentType)
    }

    return handler(req)
  }
}

/**
 * File upload validation middleware
 */
export function withFileValidation(
  handler: (
    req: NextRequest,
    ctx: { files: Map<string, FileInfo[]> }
  ) => Response | Promise<Response>,
  config: FileValidationConfig = {}
): RouteHandler {
  const onInvalid = config.onInvalid || ((_, errors) => defaultFileErrorResponse(errors))

  return async (req: NextRequest): Promise<Response> => {
    const result = await validateFilesFromRequest(req, config)

    if (!result.valid) {
      return onInvalid(req, result.errors)
    }

    return handler(req, { files: result.files })
  }
}

/**
 * Combined validation middleware
 * Combines schema validation, sanitization, and protection
 */
export function withSecureValidation<
  TBody = unknown,
  TQuery = unknown,
  TParams = unknown
>(
  handler: (
    req: NextRequest,
    ctx: {
      validated: ValidatedContext<TBody, TQuery, TParams>
      files?: Map<string, FileInfo[]>
    }
  ) => Response | Promise<Response>,
  config: {
    schema?: ValidationConfig<TBody, TQuery, TParams>
    routeParams?: Record<string, string | string[]>
    contentType?: ContentTypeConfig
    files?: FileValidationConfig
    sanitize?: SanitizationMiddlewareConfig
    xss?: { enabled: boolean; fields?: string[] }
    sql?: SQLProtectionConfig
    onError?: (req: NextRequest, errors: ValidationError[]) => Response | Promise<Response>
  }
): RouteHandler {
  return async (req: NextRequest): Promise<Response> => {
    const allErrors: ValidationError[] = []

    // 1. Content-Type validation
    if (config.contentType) {
      const ctResult = validateContentType(req, config.contentType)
      if (!ctResult.valid) {
        allErrors.push({
          field: 'Content-Type',
          code: 'invalid_content_type',
          message: ctResult.reason || 'Invalid Content-Type',
        })
      }
    }

    // 2. File validation (if multipart)
    let files: Map<string, FileInfo[]> | undefined
    if (config.files) {
      const fileResult = await validateFilesFromRequest(req, config.files)
      if (!fileResult.valid) {
        allErrors.push(...fileResult.errors.map(e => ({
          field: e.field || e.filename,
          code: e.code,
          message: e.message,
        })))
      } else {
        files = fileResult.files
      }
    }

    // Early return on content errors
    if (allErrors.length > 0) {
      const onError = config.onError || ((_, errors) => defaultValidationErrorResponse(errors))
      return onError(req, allErrors)
    }

    // 3. Schema validation
    let validated: ValidatedContext<TBody, TQuery, TParams> | undefined
    if (config.schema) {
      const schemaResult = await validateRequest<TBody, TQuery, TParams>(req, {
        body: config.schema.body as Schema<TBody> | CustomSchema | undefined,
        query: config.schema.query as Schema<TQuery> | CustomSchema | undefined,
        params: config.schema.params as Schema<TParams> | CustomSchema | undefined,
        routeParams: config.routeParams,
      })

      if (!schemaResult.success) {
        allErrors.push(...(schemaResult.errors || []))
      } else {
        validated = schemaResult.data
      }
    } else {
      validated = {
        body: {} as TBody,
        query: {} as TQuery,
        params: {} as TParams,
      }
    }

    // 4. SQL injection detection
    if (config.sql && validated?.body) {
      const sqlDetections = detectSQLInjectionInObject(validated.body, {
        fields: config.sql.fields,
        deep: config.sql.deep,
        customPatterns: config.sql.customPatterns,
      })

      if (sqlDetections.length > 0 && config.sql.mode !== 'detect') {
        allErrors.push(...sqlDetections.map(d => ({
          field: d.field,
          code: 'sql_injection',
          message: `Potential SQL injection detected: ${d.pattern}`,
        })))
      }
    }

    // 5. XSS detection
    if (config.xss?.enabled && validated?.body) {
      walkObject(validated.body, (value, path) => {
        if (config.xss?.fields && config.xss.fields.length > 0) {
          const fieldName = path.split('.').pop() || path
          if (!config.xss.fields.includes(fieldName)) {
            return value
          }
        }

        if (detectXSS(value)) {
          allErrors.push({
            field: path,
            code: 'xss_detected',
            message: 'Potentially malicious content detected',
          })
        }

        return value
      }, '')
    }

    // Return errors
    if (allErrors.length > 0) {
      const onError = config.onError || ((_, errors) => defaultValidationErrorResponse(errors))
      return onError(req, allErrors)
    }

    return handler(req, { validated: validated!, files })
  }
}
