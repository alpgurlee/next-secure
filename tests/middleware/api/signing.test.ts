import { describe, it, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'
import {
  createHMAC,
  timingSafeEqual,
  buildCanonicalString,
  verifySignature,
  generateSignature,
  withRequestSigning,
} from '../../../src/middleware/api/signing'

function createRequest(options: {
  method?: string
  path?: string
  body?: string
  headers?: Record<string, string>
  query?: Record<string, string>
} = {}): NextRequest {
  const {
    method = 'POST',
    path = '/api/test',
    body,
    headers = {},
    query = {},
  } = options

  const url = new URL(`http://localhost${path}`)
  Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v))

  const init: RequestInit = {
    method,
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
  }

  if (body) {
    init.body = body
  }

  return new NextRequest(url, init)
}

describe('Request Signing', () => {
  const testSecret = 'test-secret-key-12345'

  describe('createHMAC', () => {
    it('should create SHA-256 HMAC by default', async () => {
      const signature = await createHMAC('test data', testSecret)
      expect(signature).toMatch(/^[a-f0-9]{64}$/) // SHA-256 = 64 hex chars
    })

    it('should create SHA-512 HMAC', async () => {
      const signature = await createHMAC('test data', testSecret, 'sha512')
      expect(signature).toMatch(/^[a-f0-9]{128}$/) // SHA-512 = 128 hex chars
    })

    it('should support base64 encoding', async () => {
      const signature = await createHMAC('test data', testSecret, 'sha256', 'base64')
      expect(signature).toMatch(/^[A-Za-z0-9+/]+=*$/) // base64 pattern
    })

    it('should support base64url encoding', async () => {
      const signature = await createHMAC('test data', testSecret, 'sha256', 'base64url')
      expect(signature).toMatch(/^[A-Za-z0-9_-]+$/) // base64url pattern (no + / =)
    })

    it('should produce consistent results', async () => {
      const sig1 = await createHMAC('test', testSecret)
      const sig2 = await createHMAC('test', testSecret)
      expect(sig1).toBe(sig2)
    })

    it('should produce different results for different data', async () => {
      const sig1 = await createHMAC('test1', testSecret)
      const sig2 = await createHMAC('test2', testSecret)
      expect(sig1).not.toBe(sig2)
    })

    it('should produce different results for different secrets', async () => {
      const sig1 = await createHMAC('test', 'secret1')
      const sig2 = await createHMAC('test', 'secret2')
      expect(sig1).not.toBe(sig2)
    })
  })

  describe('timingSafeEqual', () => {
    it('should return true for equal strings', () => {
      expect(timingSafeEqual('abc123', 'abc123')).toBe(true)
    })

    it('should return false for different strings', () => {
      expect(timingSafeEqual('abc123', 'abc456')).toBe(false)
    })

    it('should return false for different length strings', () => {
      expect(timingSafeEqual('abc', 'abcd')).toBe(false)
    })

    it('should return true for empty strings', () => {
      expect(timingSafeEqual('', '')).toBe(true)
    })
  })

  describe('buildCanonicalString', () => {
    it('should include method', async () => {
      const req = createRequest({ method: 'POST' })
      const canonical = await buildCanonicalString(req, { method: true })
      expect(canonical).toBe('POST')
    })

    it('should include path', async () => {
      const req = createRequest({ path: '/api/users' })
      const canonical = await buildCanonicalString(req, { path: true })
      expect(canonical).toBe('/api/users')
    })

    it('should include sorted query string', async () => {
      const req = createRequest({ query: { b: '2', a: '1' } })
      const canonical = await buildCanonicalString(req, { query: true })
      expect(canonical).toBe('a=1&b=2')
    })

    it('should include body', async () => {
      const req = createRequest({ body: '{"name":"test"}' })
      const canonical = await buildCanonicalString(req, { body: true })
      expect(canonical).toBe('{"name":"test"}')
    })

    it('should include timestamp from header', async () => {
      const req = createRequest({ headers: { 'x-timestamp': '1234567890' } })
      const canonical = await buildCanonicalString(req, { timestamp: true })
      expect(canonical).toBe('1234567890')
    })

    it('should combine multiple components', async () => {
      const req = createRequest({
        method: 'POST',
        path: '/api/test',
        headers: { 'x-timestamp': '1234567890' },
      })
      const canonical = await buildCanonicalString(req, {
        method: true,
        path: true,
        timestamp: true,
      })
      expect(canonical).toBe('POST\n/api/test\n1234567890')
    })
  })

  describe('verifySignature', () => {
    it('should verify valid signature', async () => {
      const timestamp = Math.floor(Date.now() / 1000).toString()
      const req = createRequest({
        method: 'POST',
        path: '/api/test',
        headers: { 'x-timestamp': timestamp },
      })

      // Generate signature
      const signature = await generateSignature(req, { secret: testSecret })

      // Create new request with signature
      const signedReq = createRequest({
        method: 'POST',
        path: '/api/test',
        headers: {
          'x-timestamp': timestamp,
          'x-signature': signature,
        },
      })

      const result = await verifySignature(signedReq, { secret: testSecret })
      expect(result.valid).toBe(true)
    })

    it('should reject missing signature', async () => {
      const req = createRequest()
      const result = await verifySignature(req, { secret: testSecret })
      expect(result.valid).toBe(false)
      expect(result.reason).toContain('Missing signature')
    })

    it('should reject invalid signature', async () => {
      const req = createRequest({
        headers: {
          'x-signature': 'invalid-signature',
          'x-timestamp': Math.floor(Date.now() / 1000).toString(),
        },
      })
      const result = await verifySignature(req, { secret: testSecret })
      expect(result.valid).toBe(false)
      expect(result.reason).toContain('mismatch')
    })

    it('should reject expired timestamp', async () => {
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString() // 10 minutes ago
      const req = createRequest({
        headers: {
          'x-timestamp': oldTimestamp,
        },
      })

      // Generate valid signature but with old timestamp
      const signature = await generateSignature(req, { secret: testSecret })

      const signedReq = createRequest({
        headers: {
          'x-timestamp': oldTimestamp,
          'x-signature': signature,
        },
      })

      const result = await verifySignature(signedReq, {
        secret: testSecret,
        timestampTolerance: 300, // 5 minutes
      })
      expect(result.valid).toBe(false)
      expect(result.reason).toContain('too old')
    })

    it('should use custom header names', async () => {
      const timestamp = Math.floor(Date.now() / 1000).toString()
      const req = createRequest({
        headers: { 'custom-timestamp': timestamp },
      })

      const signature = await generateSignature(req, {
        secret: testSecret,
        timestampHeader: 'custom-timestamp',
        signatureHeader: 'custom-signature',
      })

      const signedReq = createRequest({
        headers: {
          'custom-timestamp': timestamp,
          'custom-signature': signature,
        },
      })

      const result = await verifySignature(signedReq, {
        secret: testSecret,
        timestampHeader: 'custom-timestamp',
        signatureHeader: 'custom-signature',
      })
      expect(result.valid).toBe(true)
    })
  })

  describe('withRequestSigning', () => {
    it('should allow valid signed requests', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withRequestSigning(handler, { secret: testSecret })

      const timestamp = Math.floor(Date.now() / 1000).toString()
      const reqForSigning = createRequest({
        method: 'POST',
        path: '/api/test',
        headers: { 'x-timestamp': timestamp },
      })

      const signature = await generateSignature(reqForSigning, { secret: testSecret })

      const req = createRequest({
        method: 'POST',
        path: '/api/test',
        headers: {
          'x-timestamp': timestamp,
          'x-signature': signature,
        },
      })

      const response = await wrapped(req, {})
      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(401)
    })

    it('should reject invalid signed requests', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withRequestSigning(handler, { secret: testSecret })

      const req = createRequest({
        headers: {
          'x-timestamp': Math.floor(Date.now() / 1000).toString(),
          'x-signature': 'invalid',
        },
      })

      const response = await wrapped(req, {})
      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(401)
    })

    it('should skip when configured', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withRequestSigning(handler, {
        secret: testSecret,
        skip: () => true,
      })

      const req = createRequest()
      const response = await wrapped(req, {})
      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(401)
    })
  })
})
