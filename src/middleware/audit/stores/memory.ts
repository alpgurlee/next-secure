import type { LogStore, AuditLogEntry, LogQueryOptions, MemoryStoreOptions, SecurityEventType } from '../types'

/**
 * In-memory log store with LRU eviction
 * Useful for development and testing
 */
export class MemoryStore implements LogStore {
  private entries: AuditLogEntry[] = []
  private readonly maxEntries: number
  private readonly ttl: number

  constructor(options: MemoryStoreOptions = {}) {
    this.maxEntries = options.maxEntries || 1000
    this.ttl = options.ttl || 0 // 0 = no TTL
  }

  async write(entry: AuditLogEntry): Promise<void> {
    // Add entry
    this.entries.push(entry)

    // Evict old entries if over limit
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(-this.maxEntries)
    }

    // Clean expired entries if TTL is set
    if (this.ttl > 0) {
      this.cleanExpired()
    }
  }

  async query(options: LogQueryOptions = {}): Promise<AuditLogEntry[]> {
    let result = [...this.entries]

    // Filter by level
    if (options.level) {
      const levels = Array.isArray(options.level) ? options.level : [options.level]
      result = result.filter(e => levels.includes(e.level))
    }

    // Filter by type
    if (options.type) {
      result = result.filter(e => e.type === options.type)
    }

    // Filter by event type (for security events)
    if (options.event) {
      const events = Array.isArray(options.event) ? options.event : [options.event]
      result = result.filter(e =>
        e.type === 'security' && events.includes((e as { event: SecurityEventType }).event)
      )
    }

    // Filter by time range
    if (options.startTime) {
      result = result.filter(e => e.timestamp >= options.startTime!)
    }
    if (options.endTime) {
      result = result.filter(e => e.timestamp <= options.endTime!)
    }

    // Filter by IP
    if (options.ip) {
      result = result.filter(e => {
        if (e.type === 'request') return e.request.ip === options.ip
        if (e.type === 'security') return e.source.ip === options.ip
        return false
      })
    }

    // Filter by user ID
    if (options.userId) {
      result = result.filter(e => {
        if (e.type === 'request') return e.user?.id === options.userId
        if (e.type === 'security') return e.source.userId === options.userId
        return false
      })
    }

    // Apply offset
    if (options.offset) {
      result = result.slice(options.offset)
    }

    // Apply limit
    if (options.limit) {
      result = result.slice(0, options.limit)
    }

    return result
  }

  async flush(): Promise<void> {
    // No-op for memory store
  }

  async close(): Promise<void> {
    this.entries = []
  }

  /**
   * Get all entries (for testing)
   */
  getEntries(): AuditLogEntry[] {
    return [...this.entries]
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.entries = []
  }

  /**
   * Get entry count
   */
  size(): number {
    return this.entries.length
  }

  /**
   * Clean expired entries
   */
  private cleanExpired(): void {
    if (this.ttl <= 0) return

    const now = Date.now()
    this.entries = this.entries.filter(e => {
      const age = now - e.timestamp.getTime()
      return age < this.ttl
    })
  }
}

/**
 * Create a memory store
 */
export function createMemoryStore(options?: MemoryStoreOptions): MemoryStore {
  return new MemoryStore(options)
}
