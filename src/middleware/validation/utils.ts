import type { Schema, CustomSchema, FieldRule, ValidationError, ValidationResult } from './types'

/**
 * Check if a schema is a Zod-like schema (has safeParse method)
 */
export function isZodSchema(schema: unknown): schema is Schema {
  return (
    typeof schema === 'object' &&
    schema !== null &&
    'safeParse' in schema &&
    typeof (schema as Schema).safeParse === 'function'
  )
}

/**
 * Check if a schema is a custom schema (plain object with field rules)
 */
export function isCustomSchema(schema: unknown): schema is CustomSchema {
  if (typeof schema !== 'object' || schema === null) return false
  if ('safeParse' in schema) return false

  const entries = Object.entries(schema)
  if (entries.length === 0) return false

  return entries.every(([_, rule]) => {
    return typeof rule === 'object' && rule !== null && 'type' in rule
  })
}

/**
 * Email regex pattern (RFC 5322 simplified)
 */
const EMAIL_PATTERN = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

/**
 * URL regex pattern (supports domain names, localhost, and IP addresses)
 */
const URL_PATTERN = /^https?:\/\/(?:(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}|localhost|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)$/

/**
 * UUID regex pattern (v4)
 */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

/**
 * ISO date pattern
 */
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:?\d{2})?)?$/

/**
 * Validate a single field with a rule
 */
export function validateField(value: unknown, rule: FieldRule, fieldName: string): ValidationError | null {
  // Handle required
  if (value === undefined || value === null || value === '') {
    if (rule.required) {
      return {
        field: fieldName,
        code: 'required',
        message: rule.message || `${fieldName} is required`,
        received: value,
      }
    }
    return null // Optional field with no value
  }

  // Type validation
  switch (rule.type) {
    case 'string':
      if (typeof value !== 'string') {
        return {
          field: fieldName,
          code: 'invalid_type',
          message: rule.message || `${fieldName} must be a string`,
          expected: 'string',
          received: typeof value,
        }
      }
      // String length validation
      if (rule.minLength !== undefined && value.length < rule.minLength) {
        return {
          field: fieldName,
          code: 'too_short',
          message: rule.message || `${fieldName} must be at least ${rule.minLength} characters`,
          received: value.length,
        }
      }
      if (rule.maxLength !== undefined && value.length > rule.maxLength) {
        return {
          field: fieldName,
          code: 'too_long',
          message: rule.message || `${fieldName} must be at most ${rule.maxLength} characters`,
          received: value.length,
        }
      }
      // Pattern validation
      if (rule.pattern && !rule.pattern.test(value)) {
        return {
          field: fieldName,
          code: 'invalid_pattern',
          message: rule.message || `${fieldName} has invalid format`,
          received: value,
        }
      }
      break

    case 'number':
      const num = typeof value === 'number' ? value : Number(value)
      if (isNaN(num)) {
        return {
          field: fieldName,
          code: 'invalid_type',
          message: rule.message || `${fieldName} must be a number`,
          expected: 'number',
          received: typeof value,
        }
      }
      if (rule.integer && !Number.isInteger(num)) {
        return {
          field: fieldName,
          code: 'invalid_integer',
          message: rule.message || `${fieldName} must be an integer`,
          received: num,
        }
      }
      if (rule.min !== undefined && num < rule.min) {
        return {
          field: fieldName,
          code: 'too_small',
          message: rule.message || `${fieldName} must be at least ${rule.min}`,
          received: num,
        }
      }
      if (rule.max !== undefined && num > rule.max) {
        return {
          field: fieldName,
          code: 'too_large',
          message: rule.message || `${fieldName} must be at most ${rule.max}`,
          received: num,
        }
      }
      break

    case 'boolean':
      if (typeof value !== 'boolean' && value !== 'true' && value !== 'false') {
        return {
          field: fieldName,
          code: 'invalid_type',
          message: rule.message || `${fieldName} must be a boolean`,
          expected: 'boolean',
          received: typeof value,
        }
      }
      break

    case 'email':
      if (typeof value !== 'string' || !EMAIL_PATTERN.test(value)) {
        return {
          field: fieldName,
          code: 'invalid_email',
          message: rule.message || `${fieldName} must be a valid email address`,
          received: value,
        }
      }
      break

    case 'url':
      if (typeof value !== 'string' || !URL_PATTERN.test(value)) {
        return {
          field: fieldName,
          code: 'invalid_url',
          message: rule.message || `${fieldName} must be a valid URL`,
          received: value,
        }
      }
      break

    case 'uuid':
      if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
        return {
          field: fieldName,
          code: 'invalid_uuid',
          message: rule.message || `${fieldName} must be a valid UUID`,
          received: value,
        }
      }
      break

    case 'date':
      if (typeof value !== 'string' || !DATE_PATTERN.test(value)) {
        const parsed = new Date(value as string)
        if (isNaN(parsed.getTime())) {
          return {
            field: fieldName,
            code: 'invalid_date',
            message: rule.message || `${fieldName} must be a valid date`,
            received: value,
          }
        }
      }
      break

    case 'array':
      if (!Array.isArray(value)) {
        return {
          field: fieldName,
          code: 'invalid_type',
          message: rule.message || `${fieldName} must be an array`,
          expected: 'array',
          received: typeof value,
        }
      }
      if (rule.minItems !== undefined && value.length < rule.minItems) {
        return {
          field: fieldName,
          code: 'too_few_items',
          message: rule.message || `${fieldName} must have at least ${rule.minItems} items`,
          received: value.length,
        }
      }
      if (rule.maxItems !== undefined && value.length > rule.maxItems) {
        return {
          field: fieldName,
          code: 'too_many_items',
          message: rule.message || `${fieldName} must have at most ${rule.maxItems} items`,
          received: value.length,
        }
      }
      // Validate items if rule provided
      if (rule.items) {
        for (let i = 0; i < value.length; i++) {
          const itemError = validateField(value[i], rule.items, `${fieldName}[${i}]`)
          if (itemError) return itemError
        }
      }
      break

    case 'object':
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return {
          field: fieldName,
          code: 'invalid_type',
          message: rule.message || `${fieldName} must be an object`,
          expected: 'object',
          received: Array.isArray(value) ? 'array' : typeof value,
        }
      }
      break
  }

  // Custom validation
  if (rule.custom) {
    const result = rule.custom(value)
    if (result !== true) {
      return {
        field: fieldName,
        code: 'custom_validation',
        message: typeof result === 'string' ? result : rule.message || `${fieldName} failed validation`,
        received: value,
      }
    }
  }

  return null
}

/**
 * Validate data against a custom schema
 */
export function validateCustomSchema<T>(data: unknown, schema: CustomSchema): ValidationResult<T> {
  if (typeof data !== 'object' || data === null) {
    return {
      success: false,
      errors: [{
        field: '_root',
        code: 'invalid_type',
        message: 'Expected an object',
        received: data,
      }],
    }
  }

  const errors: ValidationError[] = []
  const record = data as Record<string, unknown>

  for (const [fieldName, rule] of Object.entries(schema)) {
    const error = validateField(record[fieldName], rule, fieldName)
    if (error) {
      errors.push(error)
    }
  }

  if (errors.length > 0) {
    return { success: false, errors }
  }

  return { success: true, data: data as T }
}

/**
 * Validate data against a Zod schema
 */
export function validateZodSchema<T>(data: unknown, schema: Schema<T>): ValidationResult<T> {
  const result = schema.safeParse(data)

  if (result.success) {
    return { success: true, data: result.data }
  }

  const errors: ValidationError[] = result.error.issues.map(issue => ({
    field: issue.path.join('.') || '_root',
    code: issue.code,
    message: issue.message,
    path: issue.path.map(String),
  }))

  return { success: false, errors }
}

/**
 * Deep get value from object by path
 */
export function getByPath(obj: unknown, path: string): unknown {
  if (typeof obj !== 'object' || obj === null) return undefined

  const parts = path.split('.')
  let current: unknown = obj

  for (const part of parts) {
    if (typeof current !== 'object' || current === null) return undefined
    current = (current as Record<string, unknown>)[part]
  }

  return current
}

/**
 * Deep set value in object by path
 */
export function setByPath(obj: Record<string, unknown>, path: string, value: unknown): void {
  const parts = path.split('.')
  let current = obj

  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i]
    if (!(part in current) || typeof current[part] !== 'object') {
      current[part] = {}
    }
    current = current[part] as Record<string, unknown>
  }

  current[parts[parts.length - 1]] = value
}

/**
 * Walk through object and apply function to all string values
 */
export function walkObject(
  obj: unknown,
  fn: (value: string, path: string) => string,
  path = ''
): unknown {
  if (typeof obj === 'string') {
    return fn(obj, path)
  }

  if (Array.isArray(obj)) {
    return obj.map((item, i) => walkObject(item, fn, `${path}[${i}]`))
  }

  if (typeof obj === 'object' && obj !== null) {
    const result: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj)) {
      const newPath = path ? `${path}.${key}` : key
      result[key] = walkObject(value, fn, newPath)
    }
    return result
  }

  return obj
}

/**
 * Parse query string to object
 */
export function parseQueryString(url: string): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {}

  try {
    const urlObj = new URL(url)
    for (const [key, value] of urlObj.searchParams.entries()) {
      if (key in result) {
        const existing = result[key]
        if (Array.isArray(existing)) {
          existing.push(value)
        } else {
          result[key] = [existing, value]
        }
      } else {
        result[key] = value
      }
    }
  } catch {
    // Invalid URL, return empty
  }

  return result
}
