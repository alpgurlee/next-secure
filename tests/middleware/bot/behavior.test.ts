import { describe, it, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import {
  MemoryBehaviorStore,
  analyzeBehavior,
  checkBehavior,
  withBehaviorAnalysis,
  getGlobalBehaviorStore,
} from '../../../src/middleware/bot/behavior'
import type { RequestRecord } from '../../../src/middleware/bot/types'

function createRequest(options: {
  path?: string
  ip?: string
  headers?: Record<string, string>
} = {}): NextRequest {
  const { path = '/api/test', ip = '192.168.1.1', headers = {} } = options

  return new NextRequest(`http://localhost${path}`, {
    headers: {
      'x-forwarded-for': ip,
      'accept': 'text/html',
      'accept-language': 'en-US',
      'accept-encoding': 'gzip',
      ...headers,
    },
  })
}

describe('Behavior Analysis', () => {
  describe('MemoryBehaviorStore', () => {
    let store: MemoryBehaviorStore

    beforeEach(() => {
      store = new MemoryBehaviorStore()
    })

    it('should record requests', async () => {
      await store.record('user1', Date.now(), '/api/test')
      const history = await store.getHistory('user1', 60000)
      expect(history.length).toBe(1)
    })

    it('should return requests within window', async () => {
      const now = Date.now()
      await store.record('user1', now - 30000, '/api/test1')
      await store.record('user1', now - 10000, '/api/test2')
      await store.record('user1', now, '/api/test3')

      const history = await store.getHistory('user1', 20000)
      expect(history.length).toBe(2)
    })

    it('should filter out old requests', async () => {
      const now = Date.now()
      await store.record('user1', now - 120000, '/old')
      await store.record('user1', now, '/new')

      const history = await store.getHistory('user1', 60000)
      expect(history.length).toBe(1)
      expect(history[0].path).toBe('/new')
    })

    it('should handle multiple identifiers', async () => {
      await store.record('user1', Date.now(), '/api/test')
      await store.record('user2', Date.now(), '/api/test')

      const history1 = await store.getHistory('user1', 60000)
      const history2 = await store.getHistory('user2', 60000)

      expect(history1.length).toBe(1)
      expect(history2.length).toBe(1)
    })

    it('should evict old entries with LRU', async () => {
      const smallStore = new MemoryBehaviorStore({ maxIdentifiers: 2 })

      await smallStore.record('user1', Date.now(), '/test')
      await smallStore.record('user2', Date.now(), '/test')
      await smallStore.record('user3', Date.now(), '/test')

      const stats = smallStore.getStats()
      expect(stats.identifiers).toBe(2)
    })

    it('should cleanup old records', async () => {
      const now = Date.now()
      await store.record('user1', now - 120000, '/old')
      await store.record('user2', now, '/new')

      await store.cleanup(60000)

      const history1 = await store.getHistory('user1', 120000)
      const history2 = await store.getHistory('user2', 120000)

      expect(history1.length).toBe(0)
      expect(history2.length).toBe(1)
    })

    it('should clear all records', () => {
      store.record('user1', Date.now(), '/test')
      store.clear()

      const stats = store.getStats()
      expect(stats.identifiers).toBe(0)
      expect(stats.totalRecords).toBe(0)
    })
  })

  describe('analyzeBehavior', () => {
    it('should pass with normal behavior', async () => {
      const req = createRequest()
      const history: RequestRecord[] = [
        { timestamp: Date.now() - 2000, path: '/page1' },
        { timestamp: Date.now() - 1000, path: '/page2' },
      ]

      const result = await analyzeBehavior(req, history)
      expect(result.suspicious).toBe(false)
      expect(result.score).toBeLessThan(0.5)
    })

    it('should flag high request rate', async () => {
      const req = createRequest()
      const now = Date.now()

      // 15 requests all within the last 100ms - definitely in the last second
      // Using same timestamp to ensure they're all counted
      const history: RequestRecord[] = Array.from({ length: 15 }, () => ({
        timestamp: now - 50, // All at the same time, 50ms ago
        path: '/api/test',
      }))

      const result = await analyzeBehavior(req, history, { maxRequestsPerSecond: 10 })
      expect(result.suspicious).toBe(true)
      expect(result.reasons.some(r => r.includes('High request rate'))).toBe(true)
    })

    it('should flag rapid requests', async () => {
      const req = createRequest()
      const now = Date.now()

      // Create history with 10ms intervals - clearly too fast
      // All in ascending order for proper interval calculation
      const history: RequestRecord[] = [
        { timestamp: now - 40, path: '/api/test' },
        { timestamp: now - 30, path: '/api/test' },  // 10ms interval - too fast
        { timestamp: now - 20, path: '/api/test' },  // 10ms interval - too fast
        { timestamp: now - 10, path: '/api/test' },  // 10ms interval - too fast
      ]

      const result = await analyzeBehavior(req, history, { minRequestInterval: 100 })
      expect(result.reasons.some(r => r.includes('Rapid requests'))).toBe(true)
    })

    it('should flag regular timing patterns', async () => {
      const req = createRequest()
      const now = Date.now()

      // Exactly 100ms intervals - very suspicious
      const history: RequestRecord[] = Array.from({ length: 10 }, (_, i) => ({
        timestamp: now - (i * 100),
        path: '/api/test',
      }))

      const result = await analyzeBehavior(req, history)
      expect(result.reasons.some(r => r.includes('regular'))).toBe(true)
    })

    it('should flag sequential URL patterns', async () => {
      const req = createRequest()
      const now = Date.now()

      const history: RequestRecord[] = [
        { timestamp: now - 5000, path: '/products/1' },
        { timestamp: now - 4000, path: '/products/2' },
        { timestamp: now - 3000, path: '/products/3' },
        { timestamp: now - 2000, path: '/products/4' },
        { timestamp: now - 1000, path: '/products/5' },
      ]

      const result = await analyzeBehavior(req, history)
      expect(result.reasons.some(r => r.includes('Sequential'))).toBe(true)
    })

    it('should flag missing browser headers', async () => {
      const req = new NextRequest('http://localhost/api/test', {
        headers: {
          'x-forwarded-for': '192.168.1.1',
          // Missing accept, accept-language, accept-encoding
        },
      })

      const result = await analyzeBehavior(req, [])
      expect(result.reasons.some(r => r.includes('headers'))).toBe(true)
    })
  })

  describe('checkBehavior', () => {
    it('should track and analyze requests', async () => {
      const store = new MemoryBehaviorStore()
      const req = createRequest({ ip: '10.0.0.1' })

      const result = await checkBehavior(req, { store })
      expect(result.isBot).toBe(false)

      // Verify request was recorded
      const history = await store.getHistory('10.0.0.1', 60000)
      expect(history.length).toBe(1)
    })

    it('should use custom identifier', async () => {
      const store = new MemoryBehaviorStore()
      const req = createRequest()

      await checkBehavior(req, {
        store,
        identifier: () => 'custom-id',
      })

      const history = await store.getHistory('custom-id', 60000)
      expect(history.length).toBe(1)
    })
  })

  describe('withBehaviorAnalysis', () => {
    it('should pass normal requests', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withBehaviorAnalysis(handler, {
        store: new MemoryBehaviorStore(),
      })

      const req = createRequest()
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(429)
    })

    it('should block suspicious behavior', async () => {
      const store = new MemoryBehaviorStore()
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withBehaviorAnalysis(handler, {
        store,
        maxRequestsPerSecond: 5,
      })

      const req = createRequest({ ip: '10.0.0.1' })

      // Make many rapid requests
      const now = Date.now()
      for (let i = 0; i < 10; i++) {
        await store.record('10.0.0.1', now - (i * 50), '/api/test')
      }

      const response = await wrapped(req, {})
      expect(response.status).toBe(429)
    })
  })

  describe('getGlobalBehaviorStore', () => {
    it('should return singleton store', () => {
      const store1 = getGlobalBehaviorStore()
      const store2 = getGlobalBehaviorStore()
      expect(store1).toBe(store2)
    })
  })
})
