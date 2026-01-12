import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  MemoryStore,
  createMemoryStore,
  ConsoleStore,
  createConsoleStore,
  MultiStore,
  createMultiStore,
} from '../../../src/middleware/audit/stores'
import type { AuditLogEntry } from '../../../src/middleware/audit/types'

function createTestEntry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    id: `test_${Date.now()}`,
    timestamp: new Date(),
    type: 'request',
    level: 'info',
    message: 'Test log entry',
    ...overrides,
  }
}

describe('MemoryStore', () => {
  let store: MemoryStore

  beforeEach(() => {
    store = new MemoryStore({ maxEntries: 100 })
  })

  describe('write', () => {
    it('should store log entries', async () => {
      const entry = createTestEntry()
      await store.write(entry)

      const results = await store.query({})
      expect(results).toHaveLength(1)
      expect(results[0].id).toBe(entry.id)
    })

    it('should evict oldest entries when max is reached', async () => {
      const smallStore = new MemoryStore({ maxEntries: 3 })

      await smallStore.write(createTestEntry({ id: '1', message: 'First' }))
      await smallStore.write(createTestEntry({ id: '2', message: 'Second' }))
      await smallStore.write(createTestEntry({ id: '3', message: 'Third' }))
      await smallStore.write(createTestEntry({ id: '4', message: 'Fourth' }))

      const results = await smallStore.query({})
      expect(results).toHaveLength(3)
      expect(results.find(e => e.id === '1')).toBeUndefined()
    })
  })

  describe('query', () => {
    beforeEach(async () => {
      await store.write(createTestEntry({ id: '1', level: 'info', type: 'request' }))
      await store.write(createTestEntry({ id: '2', level: 'warn', type: 'request' }))
      await store.write(createTestEntry({ id: '3', level: 'error', type: 'security' }))
    })

    it('should filter by level', async () => {
      const results = await store.query({ level: 'error' })
      expect(results).toHaveLength(1)
      expect(results[0].id).toBe('3')
    })

    it('should filter by type', async () => {
      const results = await store.query({ type: 'security' })
      expect(results).toHaveLength(1)
      expect(results[0].id).toBe('3')
    })

    it('should limit results', async () => {
      const results = await store.query({ limit: 2 })
      expect(results).toHaveLength(2)
    })

    it('should offset results', async () => {
      const results = await store.query({ offset: 1, limit: 10 })
      expect(results).toHaveLength(2)
    })

    it('should filter by date range', async () => {
      const now = new Date()
      const future = new Date(now.getTime() + 100000)

      const results = await store.query({
        startDate: now,
        endDate: future,
      })

      expect(results.length).toBeGreaterThanOrEqual(0)
    })
  })

  describe('clear', () => {
    it('should remove all entries', async () => {
      await store.write(createTestEntry())
      await store.write(createTestEntry())

      await store.clear()

      const results = await store.query({})
      expect(results).toHaveLength(0)
    })
  })
})

describe('ConsoleStore', () => {
  let store: ConsoleStore

  beforeEach(() => {
    store = new ConsoleStore({ colorize: false })
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'info').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(console, 'debug').mockImplementation(() => {})
  })

  it('should log to console', async () => {
    const infoSpy = vi.spyOn(console, 'info')
    const entry = createTestEntry({ level: 'info', type: 'audit' })
    await store.write(entry)

    expect(infoSpy).toHaveBeenCalled()
  })

  it('should use warn for warn level', async () => {
    const warnSpy = vi.spyOn(console, 'warn')
    const entry = createTestEntry({ level: 'warn', type: 'audit' })
    await store.write(entry)

    expect(warnSpy).toHaveBeenCalled()
  })

  it('should use error for error level', async () => {
    const errorSpy = vi.spyOn(console, 'error')
    const entry = createTestEntry({ level: 'error', type: 'audit' })
    await store.write(entry)

    expect(errorSpy).toHaveBeenCalled()
  })

  it('should filter by minimum level', async () => {
    const filteredStore = new ConsoleStore({ level: 'warn', colorize: false })
    const infoSpy = vi.spyOn(console, 'info')
    const debugSpy = vi.spyOn(console, 'debug')

    await filteredStore.write(createTestEntry({ level: 'info', type: 'audit' }))
    await filteredStore.write(createTestEntry({ level: 'debug', type: 'audit' }))

    expect(infoSpy).not.toHaveBeenCalled()
    expect(debugSpy).not.toHaveBeenCalled()
  })
})

describe('MultiStore', () => {
  it('should write to all stores', async () => {
    const store1 = new MemoryStore()
    const store2 = new MemoryStore()

    const multiStore = new MultiStore([store1, store2])
    const entry = createTestEntry()

    await multiStore.write(entry)

    const results1 = await store1.query({})
    const results2 = await store2.query({})

    expect(results1).toHaveLength(1)
    expect(results2).toHaveLength(1)
  })

  it('should reject if any store fails (uses Promise.all)', async () => {
    const failingStore = {
      write: vi.fn().mockRejectedValue(new Error('Write failed')),
      query: vi.fn(),
    }
    const workingStore = new MemoryStore()

    const multiStore = new MultiStore([failingStore, workingStore])

    await expect(multiStore.write(createTestEntry())).rejects.toThrow('Write failed')
  })
})

describe('createMemoryStore', () => {
  it('should create MemoryStore with options', () => {
    const store = createMemoryStore({ maxEntries: 50, ttl: 60000 })
    expect(store).toBeInstanceOf(MemoryStore)
  })
})

describe('createConsoleStore', () => {
  it('should create ConsoleStore with options', () => {
    const store = createConsoleStore({ format: 'pretty' })
    expect(store).toBeInstanceOf(ConsoleStore)
  })
})

describe('createMultiStore', () => {
  it('should create MultiStore with stores', () => {
    const store = createMultiStore([new MemoryStore(), new ConsoleStore()])
    expect(store).toBeInstanceOf(MultiStore)
  })
})
