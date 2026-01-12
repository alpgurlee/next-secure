import type { LogFormatter, AuditLogEntry } from './types'

/**
 * JSON formatter - outputs logs as JSON strings
 */
export class JSONFormatter implements LogFormatter {
  private readonly pretty: boolean
  private readonly includeTimestamp: boolean

  constructor(options: { pretty?: boolean; includeTimestamp?: boolean } = {}) {
    this.pretty = options.pretty ?? false
    this.includeTimestamp = options.includeTimestamp ?? true
  }

  format(entry: AuditLogEntry): string {
    const output = {
      ...entry,
      timestamp: this.includeTimestamp ? entry.timestamp.toISOString() : undefined,
    }

    return this.pretty
      ? JSON.stringify(output, null, 2)
      : JSON.stringify(output)
  }
}

/**
 * Text formatter - outputs logs as human-readable text
 */
export class TextFormatter implements LogFormatter {
  private readonly template: string
  private readonly dateFormat: 'iso' | 'utc' | 'local'

  constructor(options: {
    template?: string
    dateFormat?: 'iso' | 'utc' | 'local'
  } = {}) {
    this.template = options.template || '{timestamp} [{level}] {message}'
    this.dateFormat = options.dateFormat || 'iso'
  }

  format(entry: AuditLogEntry): string {
    let output = this.template

    // Replace placeholders
    output = output.replace('{timestamp}', this.formatDate(entry.timestamp))
    output = output.replace('{level}', entry.level.toUpperCase().padEnd(8))
    output = output.replace('{message}', entry.message)
    output = output.replace('{type}', entry.type)
    output = output.replace('{id}', entry.id)

    if (entry.category) {
      output = output.replace('{category}', entry.category)
    }

    // Request-specific
    if (entry.type === 'request') {
      output = output.replace('{method}', entry.request.method)
      output = output.replace('{path}', entry.request.path)
      output = output.replace('{url}', entry.request.url)
      output = output.replace('{ip}', entry.request.ip || '-')
      output = output.replace('{status}', entry.response?.status?.toString() || '-')
      output = output.replace('{duration}', entry.response?.duration?.toString() || '-')
    }

    // Security-specific
    if (entry.type === 'security') {
      output = output.replace('{event}', entry.event)
      output = output.replace('{severity}', entry.severity)
    }

    return output
  }

  private formatDate(date: Date): string {
    switch (this.dateFormat) {
      case 'utc':
        return date.toUTCString()
      case 'local':
        return date.toLocaleString()
      case 'iso':
      default:
        return date.toISOString()
    }
  }
}

/**
 * CLF (Common Log Format) formatter
 * Apache/Nginx style: host ident authuser date request status bytes
 */
export class CLFFormatter implements LogFormatter {
  format(entry: AuditLogEntry): string {
    if (entry.type !== 'request') {
      // Fall back to simple format for non-request entries
      return `[${entry.timestamp.toISOString()}] ${entry.level.toUpperCase()} ${entry.message}`
    }

    const req = entry.request
    const res = entry.response

    const host = req.ip || '-'
    const ident = '-'
    const authuser = entry.user?.id || '-'
    const date = this.formatCLFDate(entry.timestamp)
    const request = `${req.method} ${req.path} HTTP/1.1`
    const status = res?.status || 0
    const bytes = res?.contentLength || 0

    return `${host} ${ident} ${authuser} [${date}] "${request}" ${status} ${bytes}`
  }

  private formatCLFDate(date: Date): string {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    const day = date.getDate().toString().padStart(2, '0')
    const month = months[date.getMonth()]
    const year = date.getFullYear()
    const hours = date.getHours().toString().padStart(2, '0')
    const minutes = date.getMinutes().toString().padStart(2, '0')
    const seconds = date.getSeconds().toString().padStart(2, '0')

    const offset = -date.getTimezoneOffset()
    const offsetSign = offset >= 0 ? '+' : '-'
    const offsetHours = Math.floor(Math.abs(offset) / 60).toString().padStart(2, '0')
    const offsetMins = (Math.abs(offset) % 60).toString().padStart(2, '0')

    return `${day}/${month}/${year}:${hours}:${minutes}:${seconds} ${offsetSign}${offsetHours}${offsetMins}`
  }
}

/**
 * Structured formatter for ELK/Splunk
 * Outputs key=value pairs
 */
export class StructuredFormatter implements LogFormatter {
  private readonly delimiter: string
  private readonly kvSeparator: string

  constructor(options: { delimiter?: string; kvSeparator?: string } = {}) {
    this.delimiter = options.delimiter || ' '
    this.kvSeparator = options.kvSeparator || '='
  }

  format(entry: AuditLogEntry): string {
    const pairs: string[] = []

    pairs.push(this.pair('timestamp', entry.timestamp.toISOString()))
    pairs.push(this.pair('level', entry.level))
    pairs.push(this.pair('type', entry.type))
    pairs.push(this.pair('id', entry.id))
    pairs.push(this.pair('message', this.escape(entry.message)))

    if (entry.category) {
      pairs.push(this.pair('category', entry.category))
    }

    if (entry.type === 'request') {
      pairs.push(this.pair('method', entry.request.method))
      pairs.push(this.pair('path', entry.request.path))
      if (entry.request.ip) pairs.push(this.pair('ip', entry.request.ip))
      if (entry.response) {
        pairs.push(this.pair('status', entry.response.status.toString()))
        pairs.push(this.pair('duration_ms', entry.response.duration.toString()))
      }
      if (entry.user?.id) pairs.push(this.pair('user_id', entry.user.id))
      if (entry.error) {
        pairs.push(this.pair('error', this.escape(entry.error.message)))
      }
    }

    if (entry.type === 'security') {
      pairs.push(this.pair('event', entry.event))
      pairs.push(this.pair('severity', entry.severity))
      if (entry.source.ip) pairs.push(this.pair('source_ip', entry.source.ip))
      if (entry.source.userId) pairs.push(this.pair('source_user', entry.source.userId))
    }

    return pairs.join(this.delimiter)
  }

  private pair(key: string, value: string): string {
    return `${key}${this.kvSeparator}${value}`
  }

  private escape(value: string): string {
    // Escape quotes and wrap in quotes if contains spaces
    if (value.includes(' ') || value.includes('"')) {
      return `"${value.replace(/"/g, '\\"')}"`
    }
    return value
  }
}

/**
 * Create a JSON formatter
 */
export function createJSONFormatter(options?: { pretty?: boolean }): JSONFormatter {
  return new JSONFormatter(options)
}

/**
 * Create a text formatter
 */
export function createTextFormatter(options?: {
  template?: string
  dateFormat?: 'iso' | 'utc' | 'local'
}): TextFormatter {
  return new TextFormatter(options)
}

/**
 * Create a CLF formatter
 */
export function createCLFFormatter(): CLFFormatter {
  return new CLFFormatter()
}

/**
 * Create a structured formatter
 */
export function createStructuredFormatter(options?: {
  delimiter?: string
  kvSeparator?: string
}): StructuredFormatter {
  return new StructuredFormatter(options)
}
