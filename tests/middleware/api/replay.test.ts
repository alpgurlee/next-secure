import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import {
  MemoryNonceStore,
  generateNonce,
  isValidNonceFormat,
  checkReplay,
  withReplayPrevention,
} from '../../../src/middleware/api/replay'

function createRequest(options: {
  headers?: Record<string, string>
  query?: Record<string, string>
} = {}): NextRequest {
  const { headers = {}, query = {} } = options

  const url = new URL('http://localhost/api/test')
  Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v))

  return new NextRequest(url, {
    method: 'POST',
    headers,
  })
}

describe('Replay Prevention', () => {
  describe('MemoryNonceStore', () => {
    let store: MemoryNonceStore

    beforeEach(() => {
      store = new MemoryNonceStore({ autoCleanup: false })
    })

    it('should store and check nonces', async () => {
      const nonce = 'test-nonce-12345678'

      expect(await store.exists(nonce)).toBe(false)

      await store.set(nonce, 60000)

      expect(await store.exists(nonce)).toBe(true)
    })

    it('should expire nonces after TTL', async () => {
      const nonce = 'expiring-nonce-123'

      await store.set(nonce, 1) // 1ms TTL

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10))

      expect(await store.exists(nonce)).toBe(false)
    })

    it('should cleanup expired nonces', async () => {
      await store.set('nonce1', 1)
      await store.set('nonce2', 60000)

      await new Promise(resolve => setTimeout(resolve, 10))

      await store.cleanup()

      expect(await store.exists('nonce1')).toBe(false)
      expect(await store.exists('nonce2')).toBe(true)
    })

    it('should evict old entries when at capacity', async () => {
      const smallStore = new MemoryNonceStore({ maxSize: 2, autoCleanup: false })

      await smallStore.set('nonce1', 60000)
      await smallStore.set('nonce2', 60000)
      await smallStore.set('nonce3', 60000)

      const stats = smallStore.getStats()
      expect(stats.size).toBeLessThanOrEqual(2)
    })

    it('should clear all nonces', () => {
      store.set('nonce1', 60000)
      store.set('nonce2', 60000)

      store.clear()

      expect(store.getStats().size).toBe(0)
    })
  })

  describe('generateNonce', () => {
    it('should generate random nonce', () => {
      const nonce1 = generateNonce()
      const nonce2 = generateNonce()

      expect(nonce1).not.toBe(nonce2)
    })

    it('should generate nonce of specified length', () => {
      const nonce = generateNonce(16)
      expect(nonce.length).toBe(32) // 16 bytes = 32 hex chars
    })

    it('should generate hex string', () => {
      const nonce = generateNonce()
      expect(nonce).toMatch(/^[a-f0-9]+$/)
    })
  })

  describe('isValidNonceFormat', () => {
    it('should accept valid nonces', () => {
      expect(isValidNonceFormat('abc123def456789012345678')).toBe(true)
      expect(isValidNonceFormat('ABC-123_def', 8)).toBe(true)
    })

    it('should reject short nonces', () => {
      expect(isValidNonceFormat('short', 16)).toBe(false)
    })

    it('should reject long nonces', () => {
      expect(isValidNonceFormat('a'.repeat(200), 16, 128)).toBe(false)
    })

    it('should reject invalid characters', () => {
      expect(isValidNonceFormat('nonce!@#$%')).toBe(false)
      expect(isValidNonceFormat('nonce with spaces')).toBe(false)
    })

    it('should reject empty values', () => {
      expect(isValidNonceFormat('')).toBe(false)
      expect(isValidNonceFormat(null as unknown as string)).toBe(false)
    })
  })

  describe('checkReplay', () => {
    let store: MemoryNonceStore

    beforeEach(() => {
      store = new MemoryNonceStore({ autoCleanup: false })
    })

    it('should pass new nonce', async () => {
      const nonce = generateNonce()
      const req = createRequest({ headers: { 'x-nonce': nonce } })

      const result = await checkReplay(req, { store })

      expect(result.isReplay).toBe(false)
      expect(result.nonce).toBe(nonce)
    })

    it('should detect replay', async () => {
      const nonce = generateNonce()

      // First request
      const req1 = createRequest({ headers: { 'x-nonce': nonce } })
      await checkReplay(req1, { store })

      // Replay
      const req2 = createRequest({ headers: { 'x-nonce': nonce } })
      const result = await checkReplay(req2, { store })

      expect(result.isReplay).toBe(true)
      expect(result.reason).toContain('already been used')
    })

    it('should report missing nonce when required', async () => {
      const req = createRequest()

      const result = await checkReplay(req, { store, required: true })

      expect(result.isReplay).toBe(false)
      expect(result.reason).toContain('Missing nonce')
    })

    it('should pass when nonce not required and missing', async () => {
      const req = createRequest()

      const result = await checkReplay(req, { store, required: false })

      expect(result.isReplay).toBe(false)
      expect(result.reason).toBeUndefined()
    })

    it('should use custom header name', async () => {
      const nonce = generateNonce()
      const req = createRequest({ headers: { 'custom-nonce': nonce } })

      const result = await checkReplay(req, {
        store,
        nonceHeader: 'custom-nonce',
      })

      expect(result.isReplay).toBe(false)
      expect(result.nonce).toBe(nonce)
    })

    it('should use query param', async () => {
      const nonce = generateNonce()
      const req = createRequest({ query: { nonce } })

      const result = await checkReplay(req, {
        store,
        nonceQuery: 'nonce',
      })

      expect(result.isReplay).toBe(false)
      expect(result.nonce).toBe(nonce)
    })
  })

  describe('withReplayPrevention', () => {
    let store: MemoryNonceStore

    beforeEach(() => {
      store = new MemoryNonceStore({ autoCleanup: false })
    })

    it('should allow first request with nonce', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withReplayPrevention(handler, { store })

      const nonce = generateNonce()
      const req = createRequest({ headers: { 'x-nonce': nonce } })

      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(403)
    })

    it('should block replay request', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withReplayPrevention(handler, { store })

      const nonce = generateNonce()

      // First request
      const req1 = createRequest({ headers: { 'x-nonce': nonce } })
      await wrapped(req1, {})

      // Replay
      const req2 = createRequest({ headers: { 'x-nonce': nonce } })
      const response = await wrapped(req2, {})

      expect(response.status).toBe(403)
      const body = await response.json()
      expect(body.code).toBe('REPLAY_DETECTED')
    })

    it('should block missing nonce when required', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withReplayPrevention(handler, { store, required: true })

      const req = createRequest()
      const response = await wrapped(req, {})

      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(400)
    })

    it('should skip when configured', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withReplayPrevention(handler, {
        store,
        skip: () => true,
      })

      const req = createRequest()
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(403)
    })
  })
})
