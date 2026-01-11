import type { NextRequest } from 'next/server'
import type {
  Schema,
  CustomSchema,
  ValidationResult,
  ValidationError,
  ValidatedContext,
} from '../types'
import { isZodSchema, isCustomSchema, validateCustomSchema, validateZodSchema, parseQueryString } from '../utils'

/**
 * Validate data against a schema (Zod or custom)
 */
export function validate<T>(
  data: unknown,
  schema: Schema<T> | CustomSchema
): ValidationResult<T> {
  if (isZodSchema(schema)) {
    return validateZodSchema(data, schema)
  }

  if (isCustomSchema(schema)) {
    return validateCustomSchema<T>(data, schema)
  }

  // Unknown schema type
  return {
    success: false,
    errors: [{
      field: '_schema',
      code: 'invalid_schema',
      message: 'Invalid schema provided',
    }],
  }
}

/**
 * Extract and validate request body
 */
export async function validateBody<T>(
  request: NextRequest,
  schema: Schema<T> | CustomSchema
): Promise<ValidationResult<T>> {
  let body: unknown

  try {
    const contentType = request.headers.get('content-type') || ''

    if (contentType.includes('application/json')) {
      body = await request.json()
    } else if (contentType.includes('application/x-www-form-urlencoded')) {
      const text = await request.text()
      body = Object.fromEntries(new URLSearchParams(text))
    } else if (contentType.includes('multipart/form-data')) {
      const formData = await request.formData()
      const obj: Record<string, unknown> = {}
      formData.forEach((value, key) => {
        // Skip File objects for validation, only include strings
        if (typeof value === 'string') {
          obj[key] = value
        }
      })
      body = obj
    } else {
      // Try JSON as fallback
      try {
        body = await request.json()
      } catch {
        body = {}
      }
    }
  } catch (error) {
    return {
      success: false,
      errors: [{
        field: '_body',
        code: 'parse_error',
        message: 'Failed to parse request body',
      }],
    }
  }

  return validate<T>(body, schema)
}

/**
 * Extract and validate query parameters
 */
export function validateQuery<T>(
  request: NextRequest,
  schema: Schema<T> | CustomSchema
): ValidationResult<T> {
  const query = parseQueryString(request.url)
  return validate<T>(query, schema)
}

/**
 * Validate path parameters (from URL pattern)
 */
export function validateParams<T>(
  params: Record<string, string | string[]>,
  schema: Schema<T> | CustomSchema
): ValidationResult<T> {
  return validate<T>(params, schema)
}

/**
 * Combined request validation
 */
export async function validateRequest<
  TBody = unknown,
  TQuery = unknown,
  TParams = unknown
>(
  request: NextRequest,
  config: {
    body?: Schema<TBody> | CustomSchema
    query?: Schema<TQuery> | CustomSchema
    params?: Schema<TParams> | CustomSchema
    routeParams?: Record<string, string | string[]>
  }
): Promise<{
  success: boolean
  data?: ValidatedContext<TBody, TQuery, TParams>
  errors?: ValidationError[]
}> {
  const allErrors: ValidationError[] = []
  const data: Partial<ValidatedContext<TBody, TQuery, TParams>> = {}

  // Validate body
  if (config.body) {
    const bodyResult = await validateBody<TBody>(request, config.body)
    if (!bodyResult.success) {
      allErrors.push(...(bodyResult.errors || []).map(e => ({
        ...e,
        field: `body.${e.field}`.replace('body._root', 'body'),
      })))
    } else {
      data.body = bodyResult.data
    }
  } else {
    data.body = {} as TBody
  }

  // Validate query
  if (config.query) {
    const queryResult = validateQuery<TQuery>(request, config.query)
    if (!queryResult.success) {
      allErrors.push(...(queryResult.errors || []).map(e => ({
        ...e,
        field: `query.${e.field}`.replace('query._root', 'query'),
      })))
    } else {
      data.query = queryResult.data
    }
  } else {
    data.query = {} as TQuery
  }

  // Validate params
  if (config.params && config.routeParams) {
    const paramsResult = validateParams<TParams>(config.routeParams, config.params)
    if (!paramsResult.success) {
      allErrors.push(...(paramsResult.errors || []).map(e => ({
        ...e,
        field: `params.${e.field}`.replace('params._root', 'params'),
      })))
    } else {
      data.params = paramsResult.data
    }
  } else {
    data.params = {} as TParams
  }

  if (allErrors.length > 0) {
    return { success: false, errors: allErrors }
  }

  return {
    success: true,
    data: data as ValidatedContext<TBody, TQuery, TParams>,
  }
}

/**
 * Default validation error response
 */
export function defaultValidationErrorResponse(
  errors: ValidationError[]
): Response {
  return new Response(
    JSON.stringify({
      error: 'validation_error',
      message: 'Request validation failed',
      details: errors.map(e => ({
        field: e.field,
        code: e.code,
        message: e.message,
      })),
    }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Create a validation function for a schema
 */
export function createValidator<T>(
  schema: Schema<T> | CustomSchema
): (data: unknown) => ValidationResult<T> {
  return (data: unknown) => validate<T>(data, schema)
}

/**
 * Check if all validation results are successful
 */
export function allValid(...results: ValidationResult[]): boolean {
  return results.every(r => r.success)
}

/**
 * Merge validation errors from multiple results
 */
export function mergeErrors(...results: ValidationResult[]): ValidationError[] {
  const errors: ValidationError[] = []
  for (const result of results) {
    if (result.errors) {
      errors.push(...result.errors)
    }
  }
  return errors
}
