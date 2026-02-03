import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import {
  MemoryIdempotencyStore,
  generateIdempotencyKey,
  isValidIdempotencyKey,
  checkIdempotency,
  withIdempotency,
  hashRequestBody,
} from '../../../src/middleware/api/idempotency'

function createRequest(options: {
  method?: string
  path?: string
  body?: string
  headers?: Record<string, string>
} = {}): NextRequest {
  const {
    method = 'POST',
    path = '/api/test',
    body,
    headers = {},
  } = options

  const url = new URL(`http://localhost${path}`)
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

describe('Idempotency', () => {
  describe('MemoryIdempotencyStore', () => {
    let store: MemoryIdempotencyStore

    beforeEach(() => {
      store = new MemoryIdempotencyStore({ autoCleanup: false })
    })

    it('should store and retrieve cached response', async () => {
      const key = 'test-key'
      const cachedResponse = {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"success":true}',
        cachedAt: Date.now(),
      }

      await store.set(key, cachedResponse, 60000)

      const retrieved = await store.get(key)
      expect(retrieved).toEqual(cachedResponse)
    })

    it('should return null for non-existent key', async () => {
      const result = await store.get('non-existent')
      expect(result).toBeNull()
    })

    it('should expire cached response after TTL', async () => {
      const key = 'expiring-key'
      const cachedResponse = {
        status: 200,
        headers: {},
        body: '',
        cachedAt: Date.now(),
      }

      await store.set(key, cachedResponse, 1) // 1ms TTL

      await new Promise(resolve => setTimeout(resolve, 10))

      const result = await store.get(key)
      expect(result).toBeNull()
    })

    it('should track processing status', async () => {
      const key = 'processing-key'

      expect(await store.isProcessing(key)).toBe(false)

      await store.startProcessing(key, 5000)

      expect(await store.isProcessing(key)).toBe(true)

      await store.endProcessing(key)

      expect(await store.isProcessing(key)).toBe(false)
    })

    it('should prevent duplicate processing', async () => {
      const key = 'dup-key'

      const first = await store.startProcessing(key, 5000)
      const second = await store.startProcessing(key, 5000)

      expect(first).toBe(true)
      expect(second).toBe(false)
    })

    it('should expire processing lock', async () => {
      const key = 'expiring-lock'

      await store.startProcessing(key, 1) // 1ms timeout

      await new Promise(resolve => setTimeout(resolve, 10))

      expect(await store.isProcessing(key)).toBe(false)
    })

    it('should delete entries', async () => {
      const key = 'delete-key'
      const cachedResponse = {
        status: 200,
        headers: {},
        body: '',
        cachedAt: Date.now(),
      }

      await store.set(key, cachedResponse, 60000)
      await store.delete(key)

      expect(await store.get(key)).toBeNull()
    })

    it('should clear all entries', () => {
      store.set('key1', { status: 200, headers: {}, body: '', cachedAt: Date.now() }, 60000)
      store.set('key2', { status: 200, headers: {}, body: '', cachedAt: Date.now() }, 60000)

      store.clear()

      expect(store.getStats().cacheSize).toBe(0)
    })
  })

  describe('generateIdempotencyKey', () => {
    it('should generate random key', () => {
      const key1 = generateIdempotencyKey()
      const key2 = generateIdempotencyKey()

      expect(key1).not.toBe(key2)
    })

    it('should generate key of specified length', () => {
      const key = generateIdempotencyKey(16)
      expect(key.length).toBe(32) // 16 bytes = 32 hex chars
    })

    it('should generate hex string', () => {
      const key = generateIdempotencyKey()
      expect(key).toMatch(/^[a-f0-9]+$/)
    })
  })

  describe('isValidIdempotencyKey', () => {
    it('should accept valid keys', () => {
      expect(isValidIdempotencyKey('abc123def456789012345678')).toBe(true)
      expect(isValidIdempotencyKey('ABC-123_def-456789012345')).toBe(true)
    })

    it('should reject short keys', () => {
      expect(isValidIdempotencyKey('short', 16)).toBe(false)
    })

    it('should reject long keys', () => {
      expect(isValidIdempotencyKey('a'.repeat(300), 16, 256)).toBe(false)
    })

    it('should reject invalid characters', () => {
      expect(isValidIdempotencyKey('key!@#$%^&*()12345678')).toBe(false)
    })
  })

  describe('hashRequestBody', () => {
    it('should hash body consistently', async () => {
      const body = '{"name":"test"}'

      const hash1 = await hashRequestBody(body)
      const hash2 = await hashRequestBody(body)

      expect(hash1).toBe(hash2)
    })

    it('should produce different hashes for different bodies', async () => {
      const hash1 = await hashRequestBody('{"name":"test1"}')
      const hash2 = await hashRequestBody('{"name":"test2"}')

      expect(hash1).not.toBe(hash2)
    })

    it('should produce 64-char hex hash', async () => {
      const hash = await hashRequestBody('test')
      expect(hash).toMatch(/^[a-f0-9]{64}$/)
    })
  })

  describe('checkIdempotency', () => {
    let store: MemoryIdempotencyStore

    beforeEach(() => {
      store = new MemoryIdempotencyStore({ autoCleanup: false })
    })

    it('should pass for new key', async () => {
      const key = generateIdempotencyKey()
      const req = createRequest({ headers: { 'idempotency-key': key } })

      const result = await checkIdempotency(req, { store })

      expect(result.fromCache).toBe(false)
      expect(result.isProcessing).toBe(false)
      expect(result.key).toBe(key)
    })

    it('should return cached response for existing key', async () => {
      const key = generateIdempotencyKey()
      const cachedResponse = {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"cached":true}',
        cachedAt: Date.now(),
      }

      // Store cached response
      await store.set(`${key}:POST:/api/test`, cachedResponse, 60000)

      const req = createRequest({ headers: { 'idempotency-key': key } })
      const result = await checkIdempotency(req, { store, hashRequestBody: false })

      expect(result.fromCache).toBe(true)
      expect(result.cachedResponse).toEqual(cachedResponse)
    })

    it('should report missing key when required', async () => {
      const req = createRequest()

      const result = await checkIdempotency(req, { store, required: true })

      expect(result.reason).toContain('Missing idempotency key')
    })

    it('should pass when key not required and missing', async () => {
      const req = createRequest()

      const result = await checkIdempotency(req, { store, required: false })

      expect(result.key).toBeNull()
      expect(result.reason).toBeUndefined()
    })

    it('should skip non-mutating methods', async () => {
      const req = createRequest({ method: 'GET' })

      const result = await checkIdempotency(req, { store })

      expect(result.key).toBeNull()
    })

    it('should use custom header name', async () => {
      const key = generateIdempotencyKey()
      const req = createRequest({ headers: { 'x-idem-key': key } })

      const result = await checkIdempotency(req, {
        store,
        keyHeader: 'x-idem-key',
      })

      expect(result.key).toBe(key)
    })
  })

  describe('withIdempotency', () => {
    let store: MemoryIdempotencyStore

    beforeEach(() => {
      store = new MemoryIdempotencyStore({ autoCleanup: false })
    })

    it('should execute handler for new key', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withIdempotency(handler, { store })

      const key = generateIdempotencyKey()
      const req = createRequest({ headers: { 'idempotency-key': key } })

      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).toBe(200)
    })

    it('should return cached response for duplicate request', async () => {
      let callCount = 0
      const handler = vi.fn().mockImplementation(async () => {
        callCount++
        return new Response(JSON.stringify({ call: callCount }), {
          headers: { 'content-type': 'application/json' },
        })
      })
      const wrapped = withIdempotency(handler, { store, hashRequestBody: false })

      const key = generateIdempotencyKey()

      // First request
      const req1 = createRequest({ headers: { 'idempotency-key': key } })
      const response1 = await wrapped(req1, {})
      const body1 = await response1.json()

      // Duplicate request
      const req2 = createRequest({ headers: { 'idempotency-key': key } })
      const response2 = await wrapped(req2, {})
      const body2 = await response2.json()

      expect(handler).toHaveBeenCalledTimes(1)
      expect(body1.call).toBe(1)
      expect(body2.call).toBe(1)
      expect(response2.headers.get('x-idempotency-replayed')).toBe('true')
    })

    it('should handle missing key when not required', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withIdempotency(handler, { store, required: false })

      const req = createRequest()
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).toBe(200)
    })

    it('should reject missing key when required', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withIdempotency(handler, { store, required: true })

      const req = createRequest()
      const response = await wrapped(req, {})

      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(400)
    })

    it('should skip GET requests', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withIdempotency(handler, { store })

      const req = createRequest({ method: 'GET' })
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
    })

    it('should skip when configured', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withIdempotency(handler, { store, skip: () => true })

      const req = createRequest()
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
    })

    it('should not cache error responses', async () => {
      let callCount = 0
      const handler = vi.fn().mockImplementation(async () => {
        callCount++
        return new Response(JSON.stringify({ error: true }), { status: 500 })
      })
      const wrapped = withIdempotency(handler, { store, hashRequestBody: false })

      const key = generateIdempotencyKey()

      // First request (error)
      const req1 = createRequest({ headers: { 'idempotency-key': key } })
      await wrapped(req1, {})

      // Second request should retry
      const req2 = createRequest({ headers: { 'idempotency-key': key } })
      await wrapped(req2, {})

      expect(handler).toHaveBeenCalledTimes(2)
    })
  })
})
