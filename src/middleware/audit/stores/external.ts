import type { LogStore, AuditLogEntry, ExternalStoreOptions } from '../types'

/**
 * External HTTP log store
 * Sends logs to external services (Datadog, Sentry, custom endpoints)
 */
export class ExternalStore implements LogStore {
  private readonly endpoint: string
  private readonly headers: Record<string, string>
  private readonly batchSize: number
  private readonly flushInterval: number
  private readonly retryAttempts: number
  private readonly timeout: number

  private buffer: AuditLogEntry[] = []
  private flushTimer: ReturnType<typeof setInterval> | null = null
  private isFlushing = false

  constructor(options: ExternalStoreOptions) {
    this.endpoint = options.endpoint
    this.headers = {
      'Content-Type': 'application/json',
      ...(options.apiKey ? { 'Authorization': `Bearer ${options.apiKey}` } : {}),
      ...options.headers,
    }
    this.batchSize = options.batchSize || 100
    this.flushInterval = options.flushInterval || 5000 // 5 seconds
    this.retryAttempts = options.retryAttempts || 3
    this.timeout = options.timeout || 10000 // 10 seconds

    // Start auto-flush timer
    if (this.flushInterval > 0) {
      this.flushTimer = setInterval(() => this.flush(), this.flushInterval)
    }
  }

  async write(entry: AuditLogEntry): Promise<void> {
    this.buffer.push(entry)

    // Flush if batch size reached
    if (this.buffer.length >= this.batchSize) {
      await this.flush()
    }
  }

  async flush(): Promise<void> {
    if (this.isFlushing || this.buffer.length === 0) return

    this.isFlushing = true
    const entries = [...this.buffer]
    this.buffer = []

    try {
      await this.send(entries)
    } catch (error) {
      // Put entries back in buffer on failure
      this.buffer = [...entries, ...this.buffer]
      console.error('[ExternalStore] Failed to flush logs:', error)
    } finally {
      this.isFlushing = false
    }
  }

  async close(): Promise<void> {
    // Clear timer
    if (this.flushTimer) {
      clearInterval(this.flushTimer)
      this.flushTimer = null
    }

    // Final flush
    await this.flush()
  }

  /**
   * Send entries to external endpoint
   */
  private async send(entries: AuditLogEntry[]): Promise<void> {
    let lastError: Error | null = null

    for (let attempt = 0; attempt < this.retryAttempts; attempt++) {
      try {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), this.timeout)

        const response = await fetch(this.endpoint, {
          method: 'POST',
          headers: this.headers,
          body: JSON.stringify({
            logs: entries.map(e => this.serialize(e)),
            timestamp: new Date().toISOString(),
            count: entries.length,
          }),
          signal: controller.signal,
        })

        clearTimeout(timeoutId)

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }

        return // Success
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error))

        // Wait before retry (exponential backoff)
        if (attempt < this.retryAttempts - 1) {
          await this.sleep(Math.pow(2, attempt) * 1000)
        }
      }
    }

    throw lastError || new Error('Failed to send logs')
  }

  /**
   * Serialize entry for transmission
   */
  private serialize(entry: AuditLogEntry): Record<string, unknown> {
    return {
      ...entry,
      timestamp: entry.timestamp.toISOString(),
    }
  }

  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  /**
   * Get buffer size (for monitoring)
   */
  getBufferSize(): number {
    return this.buffer.length
  }
}

/**
 * Create an external store
 */
export function createExternalStore(options: ExternalStoreOptions): ExternalStore {
  return new ExternalStore(options)
}

/**
 * Create a Datadog store
 */
export function createDatadogStore(options: {
  apiKey: string
  site?: 'datadoghq.com' | 'datadoghq.eu' | 'us3.datadoghq.com' | 'us5.datadoghq.com'
  service?: string
  source?: string
  tags?: string[]
  batchSize?: number
  flushInterval?: number
}): ExternalStore {
  const site = options.site || 'datadoghq.com'
  const endpoint = `https://http-intake.logs.${site}/api/v2/logs`

  return new ExternalStore({
    endpoint,
    headers: {
      'DD-API-KEY': options.apiKey,
      'Content-Type': 'application/json',
    },
    batchSize: options.batchSize || 100,
    flushInterval: options.flushInterval || 5000,
  })
}

/**
 * Create a multi-store that writes to multiple stores
 */
export class MultiStore implements LogStore {
  private stores: LogStore[]

  constructor(stores: LogStore[]) {
    this.stores = stores
  }

  async write(entry: AuditLogEntry): Promise<void> {
    await Promise.all(this.stores.map(store => store.write(entry)))
  }

  async query(options: Parameters<NonNullable<LogStore['query']>>[0]): Promise<AuditLogEntry[]> {
    // Query from first store that supports it
    for (const store of this.stores) {
      if (store.query) {
        return store.query(options)
      }
    }
    return []
  }

  async flush(): Promise<void> {
    await Promise.all(this.stores.map(store => store.flush?.()))
  }

  async close(): Promise<void> {
    await Promise.all(this.stores.map(store => store.close?.()))
  }
}

/**
 * Create a multi-store
 */
export function createMultiStore(stores: LogStore[]): MultiStore {
  return new MultiStore(stores)
}
