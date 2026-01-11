import { describe, it, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { withCSRF, generateCSRF, validateCSRF } from '../../../src/middleware/csrf'

// mock env
vi.stubEnv('CSRF_SECRET', 'test-secret-for-csrf-testing')

function createRequest(
  method: string,
  options: {
    headers?: Record<string, string>
    cookies?: Record<string, string>
    body?: any
  } = {}
): NextRequest {
  const url = 'http://localhost:3000/api/test'
  const headers = new Headers(options.headers)

  let bodyInit: BodyInit | undefined
  if (options.body) {
    if (typeof options.body === 'object') {
      bodyInit = JSON.stringify(options.body)
      headers.set('content-type', 'application/json')
    } else {
      bodyInit = options.body
    }
  }

  const req = new NextRequest(url, {
    method,
    headers,
    body: method !== 'GET' ? bodyInit : undefined,
  })

  // add cookies
  if (options.cookies) {
    for (const [name, value] of Object.entries(options.cookies)) {
      req.cookies.set(name, value)
    }
  }

  return req
}

describe('generateCSRF', () => {
  it('generates token and cookie', async () => {
    const { token, cookieHeader } = await generateCSRF()

    expect(token).toContain('.')
    expect(cookieHeader).toContain('__csrf=')
    expect(cookieHeader).toContain('HttpOnly')
    expect(cookieHeader).toContain('SameSite=strict')
  })

  it('uses custom cookie name', async () => {
    const { cookieHeader } = await generateCSRF({
      cookie: { name: 'my-csrf' },
    })

    expect(cookieHeader).toContain('my-csrf=')
  })
})

describe('withCSRF', () => {
  const handler = async () => new Response('ok')

  it('allows GET requests without token', async () => {
    const wrapped = withCSRF(handler)
    const req = createRequest('GET')

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })

  it('allows HEAD requests without token', async () => {
    const wrapped = withCSRF(handler)
    const req = createRequest('HEAD')

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })

  it('blocks POST without cookie', async () => {
    const wrapped = withCSRF(handler)
    const req = createRequest('POST')

    const res = await wrapped(req)
    expect(res.status).toBe(403)

    const body = await res.json()
    expect(body.reason).toBe('missing_cookie')
  })

  it('blocks POST with invalid cookie', async () => {
    const wrapped = withCSRF(handler)
    const req = createRequest('POST', {
      cookies: { __csrf: 'invalid.token' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(403)

    const body = await res.json()
    expect(body.reason).toBe('invalid_cookie')
  })

  it('blocks POST with missing header token', async () => {
    const { token } = await generateCSRF()
    const wrapped = withCSRF(handler)
    const req = createRequest('POST', {
      cookies: { __csrf: token },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(403)

    const body = await res.json()
    expect(body.reason).toBe('missing_token')
  })

  it('blocks POST with mismatched tokens', async () => {
    const { token } = await generateCSRF()
    const { token: otherToken } = await generateCSRF()

    const wrapped = withCSRF(handler)
    const req = createRequest('POST', {
      cookies: { __csrf: token },
      headers: { 'x-csrf-token': otherToken },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(403)

    const body = await res.json()
    expect(body.reason).toBe('token_mismatch')
  })

  it('allows POST with valid token in header', async () => {
    const { token } = await generateCSRF()
    const wrapped = withCSRF(handler)
    const req = createRequest('POST', {
      cookies: { __csrf: token },
      headers: { 'x-csrf-token': token },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })

  it('allows POST with valid token in body', async () => {
    const { token } = await generateCSRF()
    const wrapped = withCSRF(handler)
    const req = createRequest('POST', {
      cookies: { __csrf: token },
      body: { _csrf: token, data: 'test' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })

  it('respects custom header name', async () => {
    const { token } = await generateCSRF()
    const wrapped = withCSRF(handler, { headerName: 'x-xsrf-token' })
    const req = createRequest('POST', {
      cookies: { __csrf: token },
      headers: { 'x-xsrf-token': token },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })

  it('supports skip function', async () => {
    const wrapped = withCSRF(handler, {
      skip: (req) => req.headers.get('x-api-key') === 'trusted',
    })
    const req = createRequest('POST', {
      headers: { 'x-api-key': 'trusted' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })

  it('supports custom error handler', async () => {
    const wrapped = withCSRF(handler, {
      onError: (req, reason) => new Response(`nope: ${reason}`, { status: 400 }),
    })
    const req = createRequest('POST')

    const res = await wrapped(req)
    expect(res.status).toBe(400)
    expect(await res.text()).toBe('nope: missing_cookie')
  })

  it('protects PUT, PATCH, DELETE', async () => {
    const wrapped = withCSRF(handler)

    for (const method of ['PUT', 'PATCH', 'DELETE']) {
      const req = createRequest(method)
      const res = await wrapped(req)
      expect(res.status).toBe(403)
    }
  })
})

describe('validateCSRF', () => {
  it('returns valid for correct token', async () => {
    const { token } = await generateCSRF()
    const req = createRequest('POST', {
      cookies: { __csrf: token },
      headers: { 'x-csrf-token': token },
    })

    const result = await validateCSRF(req)
    expect(result.valid).toBe(true)
    expect(result.reason).toBeUndefined()
  })

  it('returns reason for invalid', async () => {
    const req = createRequest('POST')
    const result = await validateCSRF(req)

    expect(result.valid).toBe(false)
    expect(result.reason).toBe('missing_cookie')
  })
})
