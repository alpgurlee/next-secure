import { describe, it, expect, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import {
  withValidation,
  withSanitization,
  withXSSProtection,
  withSQLProtection,
  withContentType,
} from '../../../src/middleware/validation'

// Helper to create mock NextRequest
function createMockRequest(
  url: string,
  options: {
    method?: string
    body?: unknown
    headers?: Record<string, string>
  } = {}
): NextRequest {
  const { method = 'GET', body, headers = {} } = options

  const init: RequestInit = {
    method,
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
  }

  if (body && method !== 'GET') {
    init.body = JSON.stringify(body)
  }

  return new NextRequest(new URL(url, 'http://localhost'), init)
}

describe('withValidation', () => {
  it('passes valid request to handler', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))
    const schema = { name: { type: 'string' as const, required: true } }

    const wrappedHandler = withValidation(handler, { body: schema })
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { name: 'John' },
    })

    const response = await wrappedHandler(request)
    expect(handler).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })

  it('returns 400 for invalid body', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))
    const schema = { name: { type: 'string' as const, required: true } }

    const wrappedHandler = withValidation(handler, { body: schema })
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: {},
    })

    const response = await wrappedHandler(request)
    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(400)
  })

  it('validates query parameters', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))
    const schema = { page: { type: 'number' as const } }

    const wrappedHandler = withValidation(handler, { query: schema })
    const request = createMockRequest('http://localhost/api/test?page=abc')

    const response = await wrappedHandler(request)
    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(400)
  })

  it('accepts valid query parameters', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))
    const schema = { page: { type: 'number' as const } }

    const wrappedHandler = withValidation(handler, { query: schema })
    const request = createMockRequest('http://localhost/api/test?page=1')

    const response = await wrappedHandler(request)
    expect(handler).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })
})

describe('withSanitization', () => {
  it('sanitizes request body', async () => {
    const handler = vi.fn().mockImplementation((req) => {
      return NextResponse.json({ received: true })
    })

    const wrappedHandler = withSanitization(handler)
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { name: '<script>alert(1)</script>' },
    })

    await wrappedHandler(request)
    expect(handler).toHaveBeenCalled()
  })

  it('passes through GET requests', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withSanitization(handler)
    const request = createMockRequest('http://localhost/api/test')

    const response = await wrappedHandler(request)
    expect(handler).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })
})

describe('withXSSProtection', () => {
  it('blocks XSS in request body', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withXSSProtection(handler)
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { content: '<script>alert("xss")</script>' },
    })

    const response = await wrappedHandler(request)
    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(400)
  })

  it('allows safe content', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withXSSProtection(handler)
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { content: 'Hello World' },
    })

    const response = await wrappedHandler(request)
    expect(handler).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })

  it('blocks XSS in query parameters', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withXSSProtection(handler)
    const request = createMockRequest('http://localhost/api/test?q=<script>alert(1)</script>')

    const response = await wrappedHandler(request)
    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(400)
  })
})

describe('withSQLProtection', () => {
  it('blocks SQL injection in body', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withSQLProtection(handler)
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { query: "' OR '1'='1" },
    })

    const response = await wrappedHandler(request)
    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(400)
  })

  it('blocks DROP TABLE attacks', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withSQLProtection(handler)
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { input: '; DROP TABLE users;' },
    })

    const response = await wrappedHandler(request)
    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(400)
  })

  it('allows safe queries', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withSQLProtection(handler)
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { search: 'normal search term' },
    })

    const response = await wrappedHandler(request)
    expect(handler).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })
})

describe('withContentType', () => {
  it('allows configured content types', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withContentType(handler, {
      allowed: ['application/json'],
    })
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { data: 'test' },
      headers: { 'content-type': 'application/json' },
    })

    const response = await wrappedHandler(request)
    expect(handler).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })

  it('rejects non-allowed content types', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withContentType(handler, {
      allowed: ['application/json'],
    })
    const request = createMockRequest('http://localhost/api/test', {
      method: 'POST',
      body: { data: 'test' },
      headers: { 'content-type': 'text/xml' },
    })

    const response = await wrappedHandler(request)
    expect(handler).not.toHaveBeenCalled()
    expect(response.status).toBe(415)
  })

  it('skips validation for GET requests by default', async () => {
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ success: true }))

    const wrappedHandler = withContentType(handler, {
      allowed: ['application/json'],
    })
    const request = createMockRequest('http://localhost/api/test')

    const response = await wrappedHandler(request)
    expect(handler).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })
})
