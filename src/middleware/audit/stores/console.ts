import type { LogStore, AuditLogEntry, ConsoleStoreOptions, LogLevel } from '../types'

/**
 * ANSI color codes
 */
const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',

  // Log levels
  debug: '\x1b[36m',    // Cyan
  info: '\x1b[32m',     // Green
  warn: '\x1b[33m',     // Yellow
  error: '\x1b[31m',    // Red
  critical: '\x1b[35m', // Magenta

  // Security severity
  low: '\x1b[36m',      // Cyan
  medium: '\x1b[33m',   // Yellow
  high: '\x1b[31m',     // Red

  // Other
  timestamp: '\x1b[90m', // Gray
  method: '\x1b[34m',    // Blue
  status2xx: '\x1b[32m', // Green
  status3xx: '\x1b[36m', // Cyan
  status4xx: '\x1b[33m', // Yellow
  status5xx: '\x1b[31m', // Red
}

/**
 * Log level priority
 */
const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  critical: 4,
}

/**
 * Console log store
 * Outputs formatted logs to console
 */
export class ConsoleStore implements LogStore {
  private readonly colorize: boolean
  private readonly showTimestamp: boolean
  private readonly pretty: boolean
  private readonly minLevel: LogLevel

  constructor(options: ConsoleStoreOptions = {}) {
    this.colorize = options.colorize ?? (process.env.NODE_ENV !== 'production')
    this.showTimestamp = options.timestamp ?? true
    this.pretty = options.pretty ?? false
    this.minLevel = options.level || 'info'
  }

  async write(entry: AuditLogEntry): Promise<void> {
    // Check log level
    if (LEVEL_PRIORITY[entry.level] < LEVEL_PRIORITY[this.minLevel]) {
      return
    }

    const output = this.pretty
      ? this.formatPretty(entry)
      : this.formatCompact(entry)

    // Use appropriate console method
    switch (entry.level) {
      case 'debug':
        console.debug(output)
        break
      case 'info':
        console.info(output)
        break
      case 'warn':
        console.warn(output)
        break
      case 'error':
      case 'critical':
        console.error(output)
        break
      default:
        console.log(output)
    }
  }

  async flush(): Promise<void> {
    // No-op for console
  }

  async close(): Promise<void> {
    // No-op for console
  }

  /**
   * Format entry in compact single-line format
   */
  private formatCompact(entry: AuditLogEntry): string {
    const parts: string[] = []

    // Timestamp
    if (this.showTimestamp) {
      const ts = entry.timestamp.toISOString()
      parts.push(this.color(ts, 'timestamp'))
    }

    // Level
    parts.push(this.colorLevel(entry.level))

    if (entry.type === 'request') {
      // Request log
      const req = entry.request
      const res = entry.response

      // Method and path
      parts.push(this.color(req.method, 'method'))
      parts.push(req.path)

      // Status and duration
      if (res) {
        parts.push(this.colorStatus(res.status))
        parts.push(this.color(`${res.duration}ms`, 'dim'))
      }

      // IP
      if (req.ip) {
        parts.push(this.color(`[${req.ip}]`, 'dim'))
      }

      // User
      if (entry.user?.id) {
        parts.push(this.color(`user:${entry.user.id}`, 'dim'))
      }

      // Error
      if (entry.error) {
        parts.push(this.color(`ERROR: ${entry.error.message}`, 'error'))
      }
    } else if (entry.type === 'security') {
      // Security event
      parts.push(this.colorSeverity(entry.severity))
      parts.push(entry.event)

      if (entry.source.ip) {
        parts.push(this.color(`[${entry.source.ip}]`, 'dim'))
      }

      if (entry.source.userId) {
        parts.push(this.color(`user:${entry.source.userId}`, 'dim'))
      }

      parts.push(entry.message)
    }

    return parts.join(' ')
  }

  /**
   * Format entry in pretty multi-line format
   */
  private formatPretty(entry: AuditLogEntry): string {
    const lines: string[] = []

    // Header
    const header = [
      this.color(entry.timestamp.toISOString(), 'timestamp'),
      this.colorLevel(entry.level),
      `[${entry.type.toUpperCase()}]`,
    ].join(' ')

    lines.push(header)

    if (entry.type === 'request') {
      const req = entry.request
      const res = entry.response

      // Request line
      lines.push(`  ${this.color(req.method, 'method')} ${req.url}`)

      // Request details
      if (req.ip) lines.push(`  IP: ${req.ip}`)
      if (req.userAgent) lines.push(`  UA: ${req.userAgent}`)

      // Response
      if (res) {
        lines.push(`  Status: ${this.colorStatus(res.status)} (${res.duration}ms)`)
      }

      // User
      if (entry.user) {
        lines.push(`  User: ${JSON.stringify(entry.user)}`)
      }

      // Error
      if (entry.error) {
        lines.push(`  ${this.color('Error:', 'error')} ${entry.error.message}`)
        if (entry.error.stack) {
          lines.push(`  ${this.color(entry.error.stack, 'dim')}`)
        }
      }
    } else if (entry.type === 'security') {
      lines.push(`  Event: ${entry.event}`)
      lines.push(`  Severity: ${this.colorSeverity(entry.severity)}`)
      lines.push(`  Message: ${entry.message}`)

      if (entry.source.ip) lines.push(`  Source IP: ${entry.source.ip}`)
      if (entry.source.userId) lines.push(`  Source User: ${entry.source.userId}`)

      if (entry.target) {
        lines.push(`  Target: ${JSON.stringify(entry.target)}`)
      }

      if (entry.details) {
        lines.push(`  Details: ${JSON.stringify(entry.details)}`)
      }
    }

    // Metadata
    if (entry.metadata && Object.keys(entry.metadata).length > 0) {
      lines.push(`  Metadata: ${JSON.stringify(entry.metadata)}`)
    }

    return lines.join('\n')
  }

  /**
   * Apply color if enabled
   */
  private color(text: string, colorName: keyof typeof COLORS): string {
    if (!this.colorize) return text
    return `${COLORS[colorName]}${text}${COLORS.reset}`
  }

  /**
   * Color log level
   */
  private colorLevel(level: LogLevel): string {
    const text = level.toUpperCase().padEnd(8)
    if (!this.colorize) return `[${text}]`
    return `[${COLORS[level]}${text}${COLORS.reset}]`
  }

  /**
   * Color HTTP status
   */
  private colorStatus(status: number): string {
    const text = status.toString()
    if (!this.colorize) return text

    if (status >= 500) return `${COLORS.status5xx}${text}${COLORS.reset}`
    if (status >= 400) return `${COLORS.status4xx}${text}${COLORS.reset}`
    if (status >= 300) return `${COLORS.status3xx}${text}${COLORS.reset}`
    return `${COLORS.status2xx}${text}${COLORS.reset}`
  }

  /**
   * Color severity
   */
  private colorSeverity(severity: 'low' | 'medium' | 'high' | 'critical'): string {
    const text = `[${severity.toUpperCase()}]`
    if (!this.colorize) return text

    const colorKey = severity === 'critical' ? 'critical' : severity
    return `${COLORS[colorKey]}${text}${COLORS.reset}`
  }
}

/**
 * Create a console store
 */
export function createConsoleStore(options?: ConsoleStoreOptions): ConsoleStore {
  return new ConsoleStore(options)
}
