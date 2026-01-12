import type { NextRequest } from 'next/server'

/**
 * Log severity levels
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'critical'

/**
 * Security event types
 */
export type SecurityEventType =
  | 'auth.login'
  | 'auth.logout'
  | 'auth.failed'
  | 'auth.token_expired'
  | 'auth.token_invalid'
  | 'auth.permission_denied'
  | 'ratelimit.exceeded'
  | 'ratelimit.warning'
  | 'csrf.invalid'
  | 'csrf.missing'
  | 'xss.detected'
  | 'sqli.detected'
  | 'validation.failed'
  | 'file.rejected'
  | 'ip.blocked'
  | 'ip.suspicious'
  | 'request.malformed'
  | 'request.timeout'
  | 'error.unhandled'
  | 'error.internal'
  | 'custom'

/**
 * Log entry base
 */
export interface LogEntry {
  id: string
  timestamp: Date
  level: LogLevel
  message: string
  category?: string
  metadata?: Record<string, unknown>
}

/**
 * Request log entry
 */
export interface RequestLogEntry extends LogEntry {
  type: 'request'
  request: {
    id: string
    method: string
    url: string
    path: string
    query?: Record<string, string>
    headers?: Record<string, string>
    ip?: string
    userAgent?: string
    contentType?: string
    contentLength?: number
  }
  response?: {
    status: number
    headers?: Record<string, string>
    duration: number
    contentLength?: number
  }
  user?: {
    id?: string
    email?: string
    role?: string
  }
  error?: {
    name: string
    message: string
    stack?: string
  }
}

/**
 * Security event entry
 */
export interface SecurityEventEntry extends LogEntry {
  type: 'security'
  event: SecurityEventType
  severity: 'low' | 'medium' | 'high' | 'critical'
  source: {
    ip?: string
    userAgent?: string
    userId?: string
  }
  target?: {
    resource?: string
    action?: string
    userId?: string
  }
  details?: Record<string, unknown>
  mitigated?: boolean
}

/**
 * Audit log entry (union type)
 */
export type AuditLogEntry = RequestLogEntry | SecurityEventEntry

/**
 * Log store interface
 */
export interface LogStore {
  write(entry: AuditLogEntry): Promise<void>
  query?(options: LogQueryOptions): Promise<AuditLogEntry[]>
  flush?(): Promise<void>
  close?(): Promise<void>
}

/**
 * Log query options
 */
export interface LogQueryOptions {
  level?: LogLevel | LogLevel[]
  type?: 'request' | 'security'
  event?: SecurityEventType | SecurityEventType[]
  startTime?: Date
  endTime?: Date
  ip?: string
  userId?: string
  limit?: number
  offset?: number
}

/**
 * Log formatter interface
 */
export interface LogFormatter {
  format(entry: AuditLogEntry): string
}

/**
 * PII field configuration
 */
export interface PIIConfig {
  fields: string[]
  mode: 'mask' | 'hash' | 'remove'
  maskChar?: string
  maskLength?: number
  preserveLength?: boolean
  customRedactor?: (value: string, field: string) => string
}

/**
 * Audit middleware configuration
 */
export interface AuditConfig {
  enabled?: boolean
  store: LogStore
  formatter?: LogFormatter
  level?: LogLevel

  // What to include
  include?: {
    ip?: boolean
    userAgent?: boolean
    headers?: boolean | string[]
    query?: boolean
    body?: boolean | string[]
    response?: boolean
    responseBody?: boolean
    duration?: boolean
    user?: boolean
  }

  // What to exclude
  exclude?: {
    paths?: string[]
    methods?: string[]
    statusCodes?: number[]
  }

  // PII handling
  pii?: PIIConfig

  // User extraction
  getUser?: (req: NextRequest) => Promise<{ id?: string; email?: string; role?: string } | null>

  // Request ID
  requestIdHeader?: string
  generateRequestId?: () => string

  // Error handling
  onError?: (error: Error, entry: Partial<AuditLogEntry>) => void

  // Skip condition
  skip?: (req: NextRequest) => boolean | Promise<boolean>
}

/**
 * Security event configuration
 */
export interface SecurityEventConfig {
  store: LogStore
  formatter?: LogFormatter
  defaultSeverity?: 'low' | 'medium' | 'high' | 'critical'
  onEvent?: (event: SecurityEventEntry) => void | Promise<void>
}

/**
 * Console store options
 */
export interface ConsoleStoreOptions {
  colorize?: boolean
  timestamp?: boolean
  pretty?: boolean
  level?: LogLevel
}

/**
 * File store options
 */
export interface FileStoreOptions {
  path: string
  maxSize?: number
  maxFiles?: number
  compress?: boolean
  rotationInterval?: 'hourly' | 'daily' | 'weekly'
}

/**
 * Memory store options
 */
export interface MemoryStoreOptions {
  maxEntries?: number
  ttl?: number
}

/**
 * External service store options
 */
export interface ExternalStoreOptions {
  endpoint: string
  apiKey?: string
  headers?: Record<string, string>
  batchSize?: number
  flushInterval?: number
  retryAttempts?: number
  timeout?: number
}
