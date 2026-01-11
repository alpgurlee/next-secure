import { describe, it, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { webcrypto } from 'node:crypto'
import {
  withJWT,
  withAPIKey,
  withSession,
  withAuth,
  withRoles,
} from '../../../src/middleware/auth'

const encoder = new TextEncoder()

// Helper to create test JWTs
async function createTestJWT(
  payload: Record<string, unknown>,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' }
  const now = Math.floor(Date.now() / 1000)
  const fullPayload = { iat: now, exp: now + 3600, ...payload }

  const base64urlStr = (str: string): string =>
    Buffer.from(str).toString('base64url')

  const base64urlBytes = (bytes: Uint8Array): string =>
    Buffer.from(bytes).toString('base64url')

  const headerB64 = base64urlStr(JSON.stringify(header))
  const payloadB64 = base64urlStr(JSON.stringify(fullPayload))
  const signedData = `${headerB64}.${payloadB64}`

  const key = await webcrypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )

  const signature = await webcrypto.subtle.sign('HMAC', key, encoder.encode(signedData))
  const signatureB64 = base64urlBytes(new Uint8Array(signature))

  return `${signedData}.${signatureB64}`
}

function createRequest(options: {
  headers?: Record<string, string>
  cookies?: Record<string, string>
  url?: string
} = {}): NextRequest {
  const url = options.url || 'http://localhost:3000/api/test'
  const headers = new Headers(options.headers)

  const req = new NextRequest(url, { headers })

  if (options.cookies) {
    for (const [name, value] of Object.entries(options.cookies)) {
      req.cookies.set(name, value)
    }
  }

  return req
}

describe('withJWT', () => {
  const secret = 'test-jwt-secret'
  const handler = async (_req: NextRequest, ctx: { user: any }) =>
    Response.json({ user: ctx.user })

  it('authenticates with valid JWT', async () => {
    const token = await createTestJWT({ sub: 'user123', email: 'test@example.com' }, secret)
    const wrapped = withJWT(handler, { secret })
    const req = createRequest({
      headers: { Authorization: `Bearer ${token}` },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.user.id).toBe('user123')
    expect(body.user.email).toBe('test@example.com')
  })

  it('rejects missing token', async () => {
    const wrapped = withJWT(handler, { secret })
    const req = createRequest()

    const res = await wrapped(req)
    expect(res.status).toBe(401)

    const body = await res.json()
    expect(body.error).toBe('missing_token')
  })

  it('rejects invalid token', async () => {
    const wrapped = withJWT(handler, { secret })
    const req = createRequest({
      headers: { Authorization: 'Bearer invalid.token.here' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(401)
  })

  it('uses custom token extractor', async () => {
    const token = await createTestJWT({ sub: 'user123' }, secret)
    const wrapped = withJWT(handler, {
      secret,
      getToken: (req) => req.headers.get('x-custom-token'),
    })
    const req = createRequest({
      headers: { 'x-custom-token': token },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })

  it('uses custom user mapper', async () => {
    const token = await createTestJWT({ sub: 'user123', role: 'admin' }, secret)
    const wrapped = withJWT(handler, {
      secret,
      mapUser: (payload) => ({
        id: payload.sub!,
        isAdmin: payload.role === 'admin',
      }),
    })
    const req = createRequest({
      headers: { Authorization: `Bearer ${token}` },
    })

    const res = await wrapped(req)
    const body = await res.json()
    expect(body.user.isAdmin).toBe(true)
  })
})

describe('withAPIKey', () => {
  const handler = async (_req: NextRequest, ctx: { user: any }) =>
    Response.json({ user: ctx.user })

  const validate = async (key: string) => {
    if (key === 'valid-api-key') {
      return { id: 'api-user', name: 'API User' }
    }
    return null
  }

  it('authenticates with valid API key in header', async () => {
    const wrapped = withAPIKey(handler, { validate })
    const req = createRequest({
      headers: { 'x-api-key': 'valid-api-key' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.user.id).toBe('api-user')
  })

  it('authenticates with API key in query param', async () => {
    const wrapped = withAPIKey(handler, { validate })
    const req = createRequest({
      url: 'http://localhost:3000/api/test?api_key=valid-api-key',
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })

  it('rejects missing API key', async () => {
    const wrapped = withAPIKey(handler, { validate })
    const req = createRequest()

    const res = await wrapped(req)
    expect(res.status).toBe(401)

    const body = await res.json()
    expect(body.error).toBe('missing_api_key')
  })

  it('rejects invalid API key', async () => {
    const wrapped = withAPIKey(handler, { validate })
    const req = createRequest({
      headers: { 'x-api-key': 'invalid-key' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(401)

    const body = await res.json()
    expect(body.error).toBe('invalid_api_key')
  })

  it('uses custom header name', async () => {
    const wrapped = withAPIKey(handler, {
      validate,
      headerName: 'x-custom-key',
    })
    const req = createRequest({
      headers: { 'x-custom-key': 'valid-api-key' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)
  })
})

describe('withSession', () => {
  const handler = async (_req: NextRequest, ctx: { user: any }) =>
    Response.json({ user: ctx.user })

  const validate = async (sessionId: string) => {
    if (sessionId === 'valid-session') {
      return { id: 'session-user', name: 'Session User' }
    }
    return null
  }

  it('authenticates with valid session', async () => {
    const wrapped = withSession(handler, { validate })
    const req = createRequest({
      cookies: { session: 'valid-session' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.user.id).toBe('session-user')
  })

  it('rejects missing session', async () => {
    const wrapped = withSession(handler, { validate })
    const req = createRequest()

    const res = await wrapped(req)
    expect(res.status).toBe(401)

    const body = await res.json()
    expect(body.error).toBe('missing_session')
  })

  it('rejects invalid session', async () => {
    const wrapped = withSession(handler, { validate })
    const req = createRequest({
      cookies: { session: 'invalid-session' },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(401)

    const body = await res.json()
    expect(body.error).toBe('invalid_session')
  })
})

describe('withRoles', () => {
  const handler = async (_req: NextRequest, ctx: { user: any }) =>
    Response.json({ ok: true })

  it('allows user with required role', async () => {
    const wrapped = withRoles(handler, { roles: ['admin'] })
    const req = createRequest()

    const res = await wrapped(req, {
      user: { id: 'user1', roles: ['admin', 'user'] },
    })
    expect(res.status).toBe(200)
  })

  it('rejects user without required role', async () => {
    const wrapped = withRoles(handler, { roles: ['admin'] })
    const req = createRequest()

    const res = await wrapped(req, {
      user: { id: 'user1', roles: ['user'] },
    })
    expect(res.status).toBe(403)

    const body = await res.json()
    expect(body.error).toBe('insufficient_roles')
  })

  it('checks permissions', async () => {
    const wrapped = withRoles(handler, { permissions: ['read', 'write'] })
    const req = createRequest()

    // Has all permissions
    let res = await wrapped(req, {
      user: { id: 'user1', permissions: ['read', 'write', 'delete'] },
    })
    expect(res.status).toBe(200)

    // Missing permission
    res = await wrapped(req, {
      user: { id: 'user1', permissions: ['read'] },
    })
    expect(res.status).toBe(403)
  })

  it('supports custom authorization', async () => {
    const wrapped = withRoles(handler, {
      authorize: (user, req) => user.id === 'allowed-user',
    })
    const req = createRequest()

    let res = await wrapped(req, { user: { id: 'allowed-user' } })
    expect(res.status).toBe(200)

    res = await wrapped(req, { user: { id: 'other-user' } })
    expect(res.status).toBe(403)
  })
})

describe('withAuth', () => {
  const secret = 'combined-secret'
  const handler = async (_req: NextRequest, ctx: { user: any }) =>
    Response.json({ user: ctx.user })

  it('tries multiple auth methods', async () => {
    const token = await createTestJWT({ sub: 'jwt-user' }, secret)

    const wrapped = withAuth(handler, {
      jwt: { secret },
      apiKey: {
        validate: (key) => (key === 'api-key' ? { id: 'api-user' } : null),
      },
    })

    // JWT auth
    let req = createRequest({
      headers: { Authorization: `Bearer ${token}` },
    })
    let res = await wrapped(req)
    let body = await res.json()
    expect(body.user.id).toBe('jwt-user')

    // API key auth
    req = createRequest({
      headers: { 'x-api-key': 'api-key' },
    })
    res = await wrapped(req)
    body = await res.json()
    expect(body.user.id).toBe('api-user')
  })

  it('applies RBAC after auth', async () => {
    const token = await createTestJWT({ sub: 'user1', roles: ['user'] }, secret)

    const wrapped = withAuth(handler, {
      jwt: { secret },
      rbac: { roles: ['admin'] },
    })

    const req = createRequest({
      headers: { Authorization: `Bearer ${token}` },
    })

    const res = await wrapped(req)
    expect(res.status).toBe(403)
  })
})
