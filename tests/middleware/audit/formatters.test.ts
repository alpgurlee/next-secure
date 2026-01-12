import { describe, it, expect } from 'vitest'
import {
  JSONFormatter,
  TextFormatter,
  CLFFormatter,
  StructuredFormatter,
  createJSONFormatter,
  createTextFormatter,
  createCLFFormatter,
  createStructuredFormatter,
} from '../../../src/middleware/audit/formatters'
import type { RequestLogEntry, AuditLogEntry } from '../../../src/middleware/audit/types'

function createRequestEntry(overrides: Partial<RequestLogEntry> = {}): RequestLogEntry {
  return {
    id: 'req_test123',
    timestamp: new Date('2024-01-15T10:30:00Z'),
    type: 'request',
    level: 'info',
    message: 'GET /api/test 200 50ms',
    request: {
      id: 'req_test123',
      method: 'GET',
      url: 'https://example.com/api/test',
      path: '/api/test',
      ip: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
    },
    response: {
      status: 200,
      duration: 50,
    },
    ...overrides,
  }
}

function createAuditEntry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    id: 'audit_test123',
    timestamp: new Date('2024-01-15T10:30:00Z'),
    type: 'audit',
    level: 'info',
    message: 'User performed action',
    ...overrides,
  }
}

describe('JSONFormatter', () => {
  it('should format entry as JSON', () => {
    const formatter = new JSONFormatter()
    const entry = createAuditEntry()

    const result = formatter.format(entry)

    expect(() => JSON.parse(result)).not.toThrow()
    const parsed = JSON.parse(result)
    expect(parsed.id).toBe('audit_test123')
    expect(parsed.level).toBe('info')
  })

  it('should use pretty print when configured', () => {
    const formatter = new JSONFormatter({ pretty: true })
    const entry = createAuditEntry()

    const result = formatter.format(entry)

    expect(result).toContain('\n')
  })

  it('should preserve all entry fields', () => {
    const formatter = new JSONFormatter()
    const entry = createAuditEntry({
      metadata: { service: 'api', version: '1.0' },
    })

    const result = formatter.format(entry)
    const parsed = JSON.parse(result)

    expect(parsed.metadata?.service).toBe('api')
    expect(parsed.metadata?.version).toBe('1.0')
  })

  it('should handle timestamp as ISO string', () => {
    const formatter = new JSONFormatter()
    const entry = createAuditEntry()

    const result = formatter.format(entry)
    const parsed = JSON.parse(result)

    expect(parsed.timestamp).toBe('2024-01-15T10:30:00.000Z')
  })
})

describe('TextFormatter', () => {
  it('should format entry as text', () => {
    const formatter = new TextFormatter()
    const entry = createAuditEntry()

    const result = formatter.format(entry)

    expect(result).toContain('INFO')
    expect(result).toContain('User performed action')
  })

  it('should include timestamp', () => {
    const formatter = new TextFormatter({ includeTimestamp: true })
    const entry = createAuditEntry()

    const result = formatter.format(entry)

    expect(result).toContain('2024')
  })

  it('should format request entries with details', () => {
    const formatter = new TextFormatter()
    const entry = createRequestEntry()

    const result = formatter.format(entry)

    expect(result).toContain('GET')
    expect(result).toContain('/api/test')
  })
})

describe('CLFFormatter', () => {
  it('should format entry in Common Log Format', () => {
    const formatter = new CLFFormatter()
    const entry = createRequestEntry()

    const result = formatter.format(entry)

    // CLF format: ip ident authuser [timestamp] "method path protocol" status size
    expect(result).toContain('192.168.1.1')
    expect(result).toContain('"GET /api/test')
    expect(result).toContain('200')
  })

  it('should handle missing user', () => {
    const formatter = new CLFFormatter()
    const entry = createRequestEntry()

    const result = formatter.format(entry)

    expect(result).toContain(' - ')
  })

  it('should format date in CLF format', () => {
    const formatter = new CLFFormatter()
    const entry = createRequestEntry()

    const result = formatter.format(entry)

    // CLF date format: [dd/Mon/yyyy:HH:mm:ss +0000]
    expect(result).toMatch(/\[\d{2}\/[A-Za-z]{3}\/\d{4}/)
  })
})

describe('StructuredFormatter', () => {
  it('should format entry as key=value pairs', () => {
    const formatter = new StructuredFormatter()
    const entry = createRequestEntry()

    const result = formatter.format(entry)

    // Key=value format
    expect(result).toContain('timestamp=')
    expect(result).toContain('level=info')
    expect(result).toContain('type=request')
  })

  it('should include method and path for request entries', () => {
    const formatter = new StructuredFormatter()
    const entry = createRequestEntry()

    const result = formatter.format(entry)

    expect(result).toContain('method=GET')
    expect(result).toContain('path=/api/test')
  })

  it('should include status and duration', () => {
    const formatter = new StructuredFormatter()
    const entry = createRequestEntry()

    const result = formatter.format(entry)

    expect(result).toContain('status=200')
    expect(result).toContain('duration_ms=50')
  })

  it('should use custom delimiter', () => {
    const formatter = new StructuredFormatter({ delimiter: '|' })
    const entry = createAuditEntry()

    const result = formatter.format(entry)

    expect(result).toContain('|')
  })

  it('should use custom key-value separator', () => {
    const formatter = new StructuredFormatter({ kvSeparator: ':' })
    const entry = createAuditEntry()

    const result = formatter.format(entry)

    expect(result).toContain('level:info')
  })
})

describe('Factory functions', () => {
  it('createJSONFormatter should create JSONFormatter', () => {
    const formatter = createJSONFormatter({ pretty: true })
    expect(formatter).toBeInstanceOf(JSONFormatter)
  })

  it('createTextFormatter should create TextFormatter', () => {
    const formatter = createTextFormatter()
    expect(formatter).toBeInstanceOf(TextFormatter)
  })

  it('createCLFFormatter should create CLFFormatter', () => {
    const formatter = createCLFFormatter()
    expect(formatter).toBeInstanceOf(CLFFormatter)
  })

  it('createStructuredFormatter should create StructuredFormatter', () => {
    const formatter = createStructuredFormatter({ format: 'elk' })
    expect(formatter).toBeInstanceOf(StructuredFormatter)
  })
})
