import { describe, it, expect } from 'vitest'
import {
  createToken,
  verifyToken,
  tokensMatch,
  randomBytes,
} from '../../../src/middleware/csrf/token'

describe('randomBytes', () => {
  it('generates hex string of correct length', () => {
    const bytes = randomBytes(16)
    expect(bytes).toHaveLength(32) // 16 bytes = 32 hex chars
  })

  it('generates different values', () => {
    const a = randomBytes(16)
    const b = randomBytes(16)
    expect(a).not.toBe(b)
  })
})

describe('createToken', () => {
  const secret = 'test-secret-key-123'

  it('creates signed token', async () => {
    const token = await createToken(secret)
    expect(token).toContain('.')
    const [data, sig] = token.split('.')
    expect(data.length).toBeGreaterThan(0)
    expect(sig.length).toBe(64) // SHA-256 = 32 bytes = 64 hex
  })

  it('respects custom length', async () => {
    const token = await createToken(secret, 16)
    const [data] = token.split('.')
    expect(data).toHaveLength(32) // 16 bytes = 32 hex
  })

  it('creates unique tokens', async () => {
    const t1 = await createToken(secret)
    const t2 = await createToken(secret)
    expect(t1).not.toBe(t2)
  })
})

describe('verifyToken', () => {
  const secret = 'my-secret'

  it('verifies valid token', async () => {
    const token = await createToken(secret)
    const valid = await verifyToken(token, secret)
    expect(valid).toBe(true)
  })

  it('rejects tampered token', async () => {
    const token = await createToken(secret)
    const tampered = 'x' + token.slice(1)
    const valid = await verifyToken(tampered, secret)
    expect(valid).toBe(false)
  })

  it('rejects wrong secret', async () => {
    const token = await createToken(secret)
    const valid = await verifyToken(token, 'wrong-secret')
    expect(valid).toBe(false)
  })

  it('rejects malformed tokens', async () => {
    expect(await verifyToken('', secret)).toBe(false)
    expect(await verifyToken('no-dot', secret)).toBe(false)
    expect(await verifyToken('a.b.c', secret)).toBe(false)
    expect(await verifyToken(null as any, secret)).toBe(false)
    expect(await verifyToken(undefined as any, secret)).toBe(false)
  })
})

describe('tokensMatch', () => {
  it('matches identical tokens', () => {
    const token = 'abc123.def456'
    expect(tokensMatch(token, token)).toBe(true)
  })

  it('rejects different tokens', () => {
    expect(tokensMatch('abc.123', 'xyz.789')).toBe(false)
  })

  it('handles empty/null', () => {
    expect(tokensMatch('', 'abc')).toBe(false)
    expect(tokensMatch('abc', '')).toBe(false)
    expect(tokensMatch(null as any, 'abc')).toBe(false)
    expect(tokensMatch('abc', undefined as any)).toBe(false)
  })

  it('timing safe comparison', () => {
    // same length but different
    const a = 'aaaaaaaaaaaaaaaa'
    const b = 'aaaaaaaaaaaaaaab'
    expect(tokensMatch(a, b)).toBe(false)
  })
})
