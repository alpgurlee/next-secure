import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import {
  withAuditLog,
  withRequestId,
  withTiming,
  createAuditMiddleware,
} from '../../../src/middleware/audit/middleware'
import { MemoryStore } from '../../../src/middleware/audit/stores'
import type { AuditConfig } from '../../../src/middleware/audit/types'

function createMockRequest(
  url = 'https://example.com/api/test',
  options: RequestInit & { headers?: Record<string, string> } = {}
): NextRequest {
  const request = new Request(url, {
    method: options.method || 'GET',
    headers: new Headers(options.headers || {}),
  })
  return request as unknown as NextRequest
}

describe('withAuditLog', () => {
  let store: MemoryStore
  let config: AuditConfig

  beforeEach(() => {
    store = new MemoryStore()
    config = {
      enabled: true,
      store,
    }
  })

  it('should log successful requests', async () => {
    const handler = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200 })
    )

    const wrapped = withAuditLog(handler, config)
    const request = createMockRequest()

    await wrapped(request)

    const logs = await store.query({})
    expect(logs).toHaveLength(1)
    expect(logs[0].type).toBe('request')
    expect(logs[0].level).toBe('info')
  })

  it('should log error responses', async () => {
    const handler = vi.fn().mockResolvedValue(
      new Response('Not found', { status: 404 })
    )

    const wrapped = withAuditLog(handler, config)
    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs[0].level).toBe('warn')
  })

  it('should log server errors', async () => {
    const handler = vi.fn().mockResolvedValue(
      new Response('Internal error', { status: 500 })
    )

    const wrapped = withAuditLog(handler, config)
    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs[0].level).toBe('error')
  })

  it('should include request info', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      ...config,
      include: { ip: true, userAgent: true, query: true },
    })

    const request = createMockRequest('https://example.com/api/test?foo=bar', {
      headers: {
        'user-agent': 'TestAgent/1.0',
        'x-forwarded-for': '192.168.1.1',
      },
    })

    await wrapped(request)

    const logs = await store.query({})
    expect(logs[0].request?.path).toBe('/api/test')
    expect(logs[0].request?.query?.foo).toBe('bar')
  })

  it('should skip disabled logging', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, { ...config, enabled: false })
    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs).toHaveLength(0)
  })

  it('should exclude paths', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      ...config,
      exclude: { paths: ['/health', '/api/health*'] },
    })

    await wrapped(createMockRequest('https://example.com/health'))
    await wrapped(createMockRequest('https://example.com/api/healthcheck'))

    const logs = await store.query({})
    expect(logs).toHaveLength(0)
  })

  it('should exclude methods', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      ...config,
      exclude: { methods: ['OPTIONS', 'HEAD'] },
    })

    await wrapped(createMockRequest('https://example.com/api/test', { method: 'OPTIONS' }))

    const logs = await store.query({})
    expect(logs).toHaveLength(0)
  })

  it('should exclude status codes', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('Not Found', { status: 404 }))

    const wrapped = withAuditLog(handler, {
      ...config,
      exclude: { statusCodes: [404] },
    })

    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs).toHaveLength(0)
  })

  it('should use custom skip function', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      ...config,
      skip: async (req) => req.url.includes('internal'),
    })

    await wrapped(createMockRequest('https://example.com/internal/status'))

    const logs = await store.query({})
    expect(logs).toHaveLength(0)
  })

  it('should use existing request ID header', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      ...config,
      requestIdHeader: 'x-request-id',
    })

    const request = createMockRequest('https://example.com/api/test', {
      headers: { 'x-request-id': 'custom-id-123' },
    })

    await wrapped(request)

    const logs = await store.query({})
    expect(logs[0].request?.id).toBe('custom-id-123')
  })

  it('should generate request ID if not present', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, config)
    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs[0].request?.id).toMatch(/^req_/)
  })

  it('should use custom request ID generator', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      ...config,
      generateRequestId: () => 'my-custom-id',
    })

    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs[0].request?.id).toBe('my-custom-id')
  })

  it('should include user info when getUser is provided', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      ...config,
      include: { user: true },
      getUser: async () => ({ id: 'user123', email: 'user@example.com' }),
    })

    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs[0].user?.id).toBe('user123')
  })

  it('should call onError when write fails', async () => {
    const failingStore = {
      write: vi.fn().mockRejectedValue(new Error('Write failed')),
      query: vi.fn(),
    }

    const onError = vi.fn()
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      enabled: true,
      store: failingStore,
      onError,
    })

    await wrapped(createMockRequest())

    expect(onError).toHaveBeenCalled()
  })

  it('should redact PII fields', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withAuditLog(handler, {
      ...config,
      include: { query: true },
      pii: {
        fields: ['token'],
        mode: 'remove',
      },
    })

    await wrapped(createMockRequest('https://example.com/api?token=secret123'))

    const logs = await store.query({})
    expect(logs[0].request?.query?.token).toBe('[REDACTED]')
  })

  it('should include response info', async () => {
    const handler = vi.fn().mockResolvedValue(
      new Response('OK', { status: 201 })
    )

    const wrapped = withAuditLog(handler, {
      ...config,
      include: { response: true, duration: true },
    })

    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs[0].response?.status).toBe(201)
    expect(logs[0].response?.duration).toBeGreaterThanOrEqual(0)
  })
})

describe('withRequestId', () => {
  it('should add request ID to response', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withRequestId(handler)
    const response = await wrapped(createMockRequest())

    expect(response.headers.get('x-request-id')).toMatch(/^req_/)
  })

  it('should use existing request ID', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withRequestId(handler)
    const request = createMockRequest('https://example.com/api', {
      headers: { 'x-request-id': 'existing-id' },
    })

    const response = await wrapped(request)

    expect(response.headers.get('x-request-id')).toBe('existing-id')
  })

  it('should use custom header name', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withRequestId(handler, { headerName: 'x-correlation-id' })
    const response = await wrapped(createMockRequest())

    expect(response.headers.get('x-correlation-id')).toBeDefined()
  })

  it('should use custom ID generator', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withRequestId(handler, {
      generateId: () => 'custom-generated-id',
    })

    const response = await wrapped(createMockRequest())

    expect(response.headers.get('x-request-id')).toBe('custom-generated-id')
  })
})

describe('withTiming', () => {
  it('should add response time header', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withTiming(handler)
    const response = await wrapped(createMockRequest())

    const timing = response.headers.get('x-response-time')
    expect(timing).toMatch(/^\d+ms$/)
  })

  it('should use custom header name', async () => {
    const handler = vi.fn().mockResolvedValue(new Response('OK'))

    const wrapped = withTiming(handler, { headerName: 'x-duration' })
    const response = await wrapped(createMockRequest())

    expect(response.headers.get('x-duration')).toBeDefined()
  })

  it('should log to console when enabled', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const handler = vi.fn().mockResolvedValue(new Response('OK', { status: 200 }))

    const wrapped = withTiming(handler, { log: true })
    await wrapped(createMockRequest())

    expect(consoleSpy).toHaveBeenCalled()
    consoleSpy.mockRestore()
  })
})

describe('createAuditMiddleware', () => {
  it('should create reusable middleware factory', async () => {
    const store = new MemoryStore()
    const auditMiddleware = createAuditMiddleware({ store })

    const handler = vi.fn().mockResolvedValue(new Response('OK'))
    const wrapped = auditMiddleware(handler)

    await wrapped(createMockRequest())

    const logs = await store.query({})
    expect(logs).toHaveLength(1)
  })
})
