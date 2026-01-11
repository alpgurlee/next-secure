import { describe, it, expect, vi } from 'vitest'
import { webcrypto } from 'node:crypto'
import { verifyJWT, decodeJWT, extractBearerToken } from '../../../src/middleware/auth'

const encoder = new TextEncoder()

// Helper to create test JWTs
async function createTestJWT(
  payload: Record<string, unknown>,
  secret: string,
  options: { alg?: string; exp?: number } = {}
): Promise<string> {
  const header = { alg: options.alg || 'HS256', typ: 'JWT' }

  const now = Math.floor(Date.now() / 1000)
  const fullPayload = {
    iat: now,
    exp: options.exp ?? now + 3600,
    ...payload,
  }

  const base64urlStr = (str: string): string => {
    return Buffer.from(str).toString('base64url')
  }

  const base64urlBytes = (bytes: Uint8Array): string => {
    return Buffer.from(bytes).toString('base64url')
  }

  const headerB64 = base64urlStr(JSON.stringify(header))
  const payloadB64 = base64urlStr(JSON.stringify(fullPayload))
  const signedData = `${headerB64}.${payloadB64}`

  // Create HMAC signature
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

describe('decodeJWT', () => {
  it('decodes valid JWT', async () => {
    const token = await createTestJWT({ sub: 'user123' }, 'secret')
    const decoded = decodeJWT(token)

    expect(decoded).not.toBeNull()
    expect(decoded?.header.alg).toBe('HS256')
    expect(decoded?.payload.sub).toBe('user123')
  })

  it('returns null for malformed token', () => {
    expect(decodeJWT('')).toBeNull()
    expect(decodeJWT('not.valid')).toBeNull()
    expect(decodeJWT('a.b.c.d')).toBeNull()
    expect(decodeJWT('invalid')).toBeNull()
  })
})

describe('verifyJWT', () => {
  const secret = 'test-secret-key-123'

  it('verifies valid token', async () => {
    const token = await createTestJWT({ sub: 'user123' }, secret)
    const result = await verifyJWT(token, { secret })

    expect(result.error).toBeNull()
    expect(result.payload?.sub).toBe('user123')
  })

  it('rejects expired token', async () => {
    const expired = Math.floor(Date.now() / 1000) - 100
    const token = await createTestJWT({ sub: 'user123' }, secret, { exp: expired })
    const result = await verifyJWT(token, { secret })

    expect(result.error?.code).toBe('expired_token')
    expect(result.payload).toBeNull()
  })

  it('rejects wrong signature', async () => {
    const token = await createTestJWT({ sub: 'user123' }, 'wrong-secret')
    const result = await verifyJWT(token, { secret })

    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects disallowed algorithm', async () => {
    const token = await createTestJWT({ sub: 'user123' }, secret)
    const result = await verifyJWT(token, {
      secret,
      algorithms: ['RS256'],
    })

    expect(result.error?.code).toBe('invalid_token')
    expect(result.error?.message).toContain('not allowed')
  })

  it('validates issuer', async () => {
    const token = await createTestJWT({ sub: 'user123', iss: 'myapp' }, secret)

    // Correct issuer
    let result = await verifyJWT(token, { secret, issuer: 'myapp' })
    expect(result.error).toBeNull()

    // Wrong issuer
    result = await verifyJWT(token, { secret, issuer: 'other' })
    expect(result.error?.code).toBe('invalid_token')
  })

  it('validates audience', async () => {
    const token = await createTestJWT({ sub: 'user123', aud: 'api' }, secret)

    // Correct audience
    let result = await verifyJWT(token, { secret, audience: 'api' })
    expect(result.error).toBeNull()

    // Wrong audience
    result = await verifyJWT(token, { secret, audience: 'other' })
    expect(result.error?.code).toBe('invalid_token')
  })

  it('supports clock tolerance', async () => {
    // Token expired 5 seconds ago
    const expired = Math.floor(Date.now() / 1000) - 5
    const token = await createTestJWT({ sub: 'user123' }, secret, { exp: expired })

    // Without tolerance - fails
    let result = await verifyJWT(token, { secret })
    expect(result.error?.code).toBe('expired_token')

    // With 10 second tolerance - passes
    result = await verifyJWT(token, { secret, clockTolerance: 10 })
    expect(result.error).toBeNull()
  })
})

describe('extractBearerToken', () => {
  it('extracts token from Bearer header', () => {
    expect(extractBearerToken('Bearer abc123')).toBe('abc123')
    expect(extractBearerToken('Bearer eyJhbGc...')).toBe('eyJhbGc...')
  })

  it('returns null for invalid headers', () => {
    expect(extractBearerToken(null)).toBeNull()
    expect(extractBearerToken('')).toBeNull()
    expect(extractBearerToken('Basic abc123')).toBeNull()
    expect(extractBearerToken('bearer abc')).toBeNull() // Case sensitive
  })
})
