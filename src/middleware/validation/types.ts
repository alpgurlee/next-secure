import type { NextRequest } from 'next/server'

/**
 * Validation error details
 */
export interface ValidationError {
  field: string
  message: string
  code: string
  path?: string[]
  received?: unknown
  expected?: string
}

/**
 * Validation result
 */
export interface ValidationResult<T = unknown> {
  success: boolean
  data?: T
  errors?: ValidationError[]
}

/**
 * Generic schema interface (Zod-compatible)
 */
export interface Schema<T = unknown> {
  parse: (data: unknown) => T
  safeParse: (data: unknown) => { success: true; data: T } | { success: false; error: { issues: SchemaIssue[] } }
}

export interface SchemaIssue {
  path: (string | number)[]
  message: string
  code: string
}

/**
 * Built-in field types for schema-less validation
 */
export type FieldType =
  | 'string'
  | 'number'
  | 'boolean'
  | 'email'
  | 'url'
  | 'uuid'
  | 'date'
  | 'array'
  | 'object'

/**
 * Field validation rules (without Zod)
 */
export interface FieldRule {
  type: FieldType
  required?: boolean
  // String rules
  minLength?: number
  maxLength?: number
  pattern?: RegExp
  // Number rules
  min?: number
  max?: number
  integer?: boolean
  // Array rules
  minItems?: number
  maxItems?: number
  items?: FieldRule
  // Custom
  custom?: (value: unknown) => boolean | string
  message?: string
}

/**
 * Custom schema definition (without Zod)
 */
export type CustomSchema = Record<string, FieldRule>

/**
 * Validation config for middleware
 */
export interface ValidationConfig<
  TBody = unknown,
  TQuery = unknown,
  TParams = unknown
> {
  body?: Schema<TBody> | CustomSchema
  query?: Schema<TQuery> | CustomSchema
  params?: Schema<TParams> | CustomSchema
  strict?: boolean
  stripUnknown?: boolean
  onError?: (req: NextRequest, errors: ValidationError[]) => Response | Promise<Response>
}

/**
 * Validated request context
 */
export interface ValidatedContext<TBody = unknown, TQuery = unknown, TParams = unknown> {
  body: TBody
  query: TQuery
  params: TParams
}

/**
 * XSS sanitization modes
 */
export type SanitizeMode = 'escape' | 'strip' | 'allow-safe'

/**
 * XSS sanitization config
 */
export interface SanitizeConfig {
  mode?: SanitizeMode
  allowedTags?: string[]
  allowedAttributes?: Record<string, string[]>
  allowedProtocols?: string[]
  maxLength?: number
  stripNull?: boolean
}

/**
 * Sanitization middleware config
 */
export interface SanitizationMiddlewareConfig {
  fields?: string[]
  deep?: boolean
  mode?: SanitizeMode
  allowedTags?: string[]
  skip?: (req: NextRequest) => boolean | Promise<boolean>
  onSanitized?: (req: NextRequest, changes: SanitizationChange[]) => void
}

export interface SanitizationChange {
  field: string
  original: string
  sanitized: string
}

/**
 * SQL injection detection config
 */
export interface SQLProtectionConfig {
  fields?: string[]
  deep?: boolean
  mode?: 'detect' | 'block' | 'sanitize'
  customPatterns?: RegExp[]
  allowList?: string[]
  onDetection?: (req: NextRequest, detections: SQLDetection[]) => Response | void | Promise<Response | void>
}

export interface SQLDetection {
  field: string
  value: string
  pattern: string
  severity: 'low' | 'medium' | 'high'
}

/**
 * Path traversal prevention config
 */
export interface PathValidationConfig {
  allowAbsolute?: boolean
  allowedPrefixes?: string[]
  allowedExtensions?: string[]
  blockedExtensions?: string[]
  maxDepth?: number
  maxLength?: number
  normalize?: boolean
}

export interface PathValidationResult {
  valid: boolean
  sanitized?: string
  reason?: string
}

/**
 * Content-Type validation config
 */
export interface ContentTypeConfig {
  allowed: string[]
  strict?: boolean
  charset?: string
  onInvalid?: (req: NextRequest, contentType: string | null) => Response | Promise<Response>
}

/**
 * File validation config
 */
export interface FileValidationConfig {
  maxSize?: number
  minSize?: number
  allowedTypes?: string[]
  blockedTypes?: string[]
  allowedExtensions?: string[]
  blockedExtensions?: string[]
  maxFiles?: number
  validateMagicNumbers?: boolean
  sanitizeFilename?: boolean
  onInvalid?: (req: NextRequest, errors: FileValidationError[]) => Response | Promise<Response>
}

export interface FileValidationError {
  filename: string
  field?: string
  code: 'size_exceeded' | 'size_too_small' | 'type_not_allowed' | 'extension_not_allowed' | 'invalid_content' | 'too_many_files'
  message: string
  details?: Record<string, unknown>
}

export interface FileInfo {
  filename: string
  size: number
  type: string
  extension: string
  field?: string
}

/**
 * Magic number signatures for file type validation
 */
export interface MagicNumber {
  type: string
  extension: string
  signature: number[]
  offset?: number
}
