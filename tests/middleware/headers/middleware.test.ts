import { describe, it, expect } from 'vitest'
import { NextRequest } from 'next/server'
import {
  withSecurityHeaders,
  createSecurityHeaders,
  createSecurityHeadersObject,
} from '../../../src/middleware/headers'

function createRequest(): NextRequest {
  return new NextRequest('http://localhost:3000/api/test')
}

describe('withSecurityHeaders', () => {
  const handler = async () => Response.json({ ok: true })

  it('adds security headers to response', async () => {
    const wrapped = withSecurityHeaders(handler)
    const res = await wrapped(createRequest())

    expect(res.headers.get('X-Frame-Options')).toBe('DENY')
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(res.headers.get('Content-Security-Policy')).toBeTruthy()
  })

  it('uses strict preset by default', async () => {
    const wrapped = withSecurityHeaders(handler)
    const res = await wrapped(createRequest())

    expect(res.headers.get('X-Frame-Options')).toBe('DENY')
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin')
  })

  it('uses specified preset', async () => {
    const wrapped = withSecurityHeaders(handler, { preset: 'api' })
    const res = await wrapped(createRequest())

    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer')
  })

  it('uses relaxed preset', async () => {
    const wrapped = withSecurityHeaders(handler, { preset: 'relaxed' })
    const res = await wrapped(createRequest())

    expect(res.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
  })

  it('merges custom config with preset', async () => {
    const wrapped = withSecurityHeaders(handler, {
      preset: 'strict',
      config: {
        xFrameOptions: 'SAMEORIGIN',
      },
    })
    const res = await wrapped(createRequest())

    expect(res.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
    // Other strict headers should still be present
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
  })

  it('can disable specific headers', async () => {
    const wrapped = withSecurityHeaders(handler, {
      config: {
        xFrameOptions: false,
        contentSecurityPolicy: false,
      },
    })
    const res = await wrapped(createRequest())

    expect(res.headers.has('X-Frame-Options')).toBe(false)
    expect(res.headers.has('Content-Security-Policy')).toBe(false)
  })

  it('preserves existing response headers', async () => {
    const customHandler = async () =>
      new Response('ok', {
        headers: { 'X-Custom': 'value' },
      })

    const wrapped = withSecurityHeaders(customHandler)
    const res = await wrapped(createRequest())

    expect(res.headers.get('X-Custom')).toBe('value')
    expect(res.headers.get('X-Frame-Options')).toBe('DENY')
  })

  it('does not override existing headers by default', async () => {
    const customHandler = async () =>
      new Response('ok', {
        headers: { 'X-Frame-Options': 'SAMEORIGIN' },
      })

    const wrapped = withSecurityHeaders(customHandler)
    const res = await wrapped(createRequest())

    expect(res.headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
  })

  it('overrides existing headers when override=true', async () => {
    const customHandler = async () =>
      new Response('ok', {
        headers: { 'X-Frame-Options': 'SAMEORIGIN' },
      })

    const wrapped = withSecurityHeaders(customHandler, { override: true })
    const res = await wrapped(createRequest())

    expect(res.headers.get('X-Frame-Options')).toBe('DENY')
  })

  it('preserves response body and status', async () => {
    const customHandler = async () =>
      new Response(JSON.stringify({ data: 'test' }), {
        status: 201,
        statusText: 'Created',
        headers: { 'Content-Type': 'application/json' },
      })

    const wrapped = withSecurityHeaders(customHandler)
    const res = await wrapped(createRequest())

    expect(res.status).toBe(201)
    expect(res.statusText).toBe('Created')
    const body = await res.json()
    expect(body.data).toBe('test')
  })
})

describe('createSecurityHeaders', () => {
  it('creates headers with strict preset', () => {
    const headers = createSecurityHeaders({ preset: 'strict' })

    expect(headers.get('X-Frame-Options')).toBe('DENY')
    expect(headers.get('X-Content-Type-Options')).toBe('nosniff')
  })

  it('creates headers with custom config', () => {
    const headers = createSecurityHeaders({
      config: {
        xFrameOptions: 'SAMEORIGIN',
        referrerPolicy: 'no-referrer',
      },
    })

    expect(headers.get('X-Frame-Options')).toBe('SAMEORIGIN')
    expect(headers.get('Referrer-Policy')).toBe('no-referrer')
  })
})

describe('createSecurityHeadersObject', () => {
  it('returns plain object', () => {
    const headers = createSecurityHeadersObject({ preset: 'api' })

    expect(typeof headers).toBe('object')
    // Headers API normalizes to lowercase
    expect(headers['x-frame-options']).toBe('DENY')
    expect(headers['referrer-policy']).toBe('no-referrer')
  })
})
