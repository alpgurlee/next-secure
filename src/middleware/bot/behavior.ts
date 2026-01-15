/**
 * Behavior Analysis for Bot Detection
 * @module nextjs-secure/bot
 */

import type { NextRequest } from 'next/server'
import type {
  BehaviorOptions,
  BehaviorStore,
  BehaviorAnalysisResult,
  RequestRecord,
  BotDetectionResult,
} from './types'

// ============================================================================
// Default Configuration
// ============================================================================

/**
 * Default behavior analysis options
 */
export const DEFAULT_BEHAVIOR_OPTIONS: Required<Omit<BehaviorOptions, 'store' | 'identifier'>> & Pick<BehaviorOptions, 'store' | 'identifier'> = {
  minRequestInterval: 100,
  maxRequestsPerSecond: 10,
  windowMs: 60000,
  store: undefined,
  identifier: undefined,
  patterns: {
    sequentialAccess: true,
    regularTiming: true,
    missingHeaders: true,
  },
}

// ============================================================================
// In-Memory Behavior Store
// ============================================================================

/**
 * In-memory behavior tracking store with LRU eviction
 */
export class MemoryBehaviorStore implements BehaviorStore {
  private records: Map<string, RequestRecord[]> = new Map()
  private maxIdentifiers: number
  private accessOrder: string[] = []

  constructor(options: { maxIdentifiers?: number } = {}) {
    this.maxIdentifiers = options.maxIdentifiers || 10000
  }

  async record(identifier: string, timestamp: number, path: string): Promise<void> {
    // LRU eviction
    if (!this.records.has(identifier) && this.records.size >= this.maxIdentifiers) {
      const oldest = this.accessOrder.shift()
      if (oldest) {
        this.records.delete(oldest)
      }
    }

    // Update access order
    const idx = this.accessOrder.indexOf(identifier)
    if (idx > -1) {
      this.accessOrder.splice(idx, 1)
    }
    this.accessOrder.push(identifier)

    // Add record
    const records = this.records.get(identifier) || []
    records.push({ timestamp, path })
    this.records.set(identifier, records)
  }

  async getHistory(identifier: string, windowMs: number): Promise<RequestRecord[]> {
    const records = this.records.get(identifier) || []
    const cutoff = Date.now() - windowMs

    // Filter and cleanup old records
    const filtered = records.filter(r => r.timestamp > cutoff)
    if (filtered.length !== records.length) {
      this.records.set(identifier, filtered)
    }

    return filtered
  }

  async cleanup(maxAge: number): Promise<void> {
    const cutoff = Date.now() - maxAge

    for (const [identifier, records] of this.records.entries()) {
      const filtered = records.filter(r => r.timestamp > cutoff)
      if (filtered.length === 0) {
        this.records.delete(identifier)
        const idx = this.accessOrder.indexOf(identifier)
        if (idx > -1) {
          this.accessOrder.splice(idx, 1)
        }
      } else {
        this.records.set(identifier, filtered)
      }
    }
  }

  /**
   * Get store statistics
   */
  getStats(): { identifiers: number; totalRecords: number } {
    let totalRecords = 0
    for (const records of this.records.values()) {
      totalRecords += records.length
    }
    return {
      identifiers: this.records.size,
      totalRecords,
    }
  }

  /**
   * Clear all records
   */
  clear(): void {
    this.records.clear()
    this.accessOrder = []
  }
}

// ============================================================================
// Behavior Analysis
// ============================================================================

/**
 * Analyze request behavior for bot patterns
 */
export async function analyzeBehavior(
  req: NextRequest,
  history: RequestRecord[],
  options: BehaviorOptions = {}
): Promise<BehaviorAnalysisResult> {
  const {
    minRequestInterval = DEFAULT_BEHAVIOR_OPTIONS.minRequestInterval,
    maxRequestsPerSecond = DEFAULT_BEHAVIOR_OPTIONS.maxRequestsPerSecond,
    patterns = DEFAULT_BEHAVIOR_OPTIONS.patterns,
  } = options

  const reasons: string[] = []
  let score = 0

  const now = Date.now()
  const requestCount = history.length

  // Calculate intervals between requests
  const intervals: number[] = []
  for (let i = 1; i < history.length; i++) {
    intervals.push(history[i].timestamp - history[i - 1].timestamp)
  }

  // Average interval
  const avgInterval = intervals.length > 0
    ? intervals.reduce((a, b) => a + b, 0) / intervals.length
    : Infinity

  // 1. Check request rate
  const oneSecondAgo = now - 1000
  const requestsLastSecond = history.filter(r => r.timestamp > oneSecondAgo).length

  if (requestsLastSecond > maxRequestsPerSecond) {
    score += 0.3
    reasons.push(`High request rate: ${requestsLastSecond}/s (max: ${maxRequestsPerSecond})`)
  }

  // 2. Check minimum interval
  const hasRapidRequests = intervals.some(i => i < minRequestInterval)
  if (hasRapidRequests) {
    score += 0.25
    reasons.push(`Rapid requests detected: interval < ${minRequestInterval}ms`)
  }

  // 3. Check for regular timing (bots often have very consistent intervals)
  if (patterns?.regularTiming && intervals.length >= 5) {
    const variance = calculateVariance(intervals)
    const coefficientOfVariation = Math.sqrt(variance) / avgInterval

    // Very low variance indicates automated requests
    if (coefficientOfVariation < 0.1) {
      score += 0.2
      reasons.push('Suspiciously regular request timing')
    }
  }

  // 4. Check for sequential URL patterns
  if (patterns?.sequentialAccess && history.length >= 5) {
    const paths = history.map(r => r.path)
    if (isSequentialPattern(paths)) {
      score += 0.15
      reasons.push('Sequential URL access pattern detected')
    }
  }

  // 5. Check missing typical browser headers
  if (patterns?.missingHeaders) {
    const missingScore = checkMissingHeaders(req)
    if (missingScore > 0) {
      score += missingScore
      reasons.push('Missing typical browser headers')
    }
  }

  // Normalize score to 0-1 range
  score = Math.min(1, score)

  return {
    suspicious: score >= 0.5,
    score,
    reasons,
    requestCount,
    avgInterval,
  }
}

/**
 * Check behavior and return bot detection result
 */
export async function checkBehavior(
  req: NextRequest,
  options: BehaviorOptions = {}
): Promise<BotDetectionResult> {
  const {
    store = new MemoryBehaviorStore(),
    windowMs = DEFAULT_BEHAVIOR_OPTIONS.windowMs,
    identifier: getIdentifier,
  } = options

  // Get identifier
  const identifier = getIdentifier
    ? await getIdentifier(req)
    : getClientIP(req)

  // Get history
  const history = await store.getHistory(identifier, windowMs)

  // Record current request
  const now = Date.now()
  const path = new URL(req.url).pathname
  await store.record(identifier, now, path)

  // Analyze behavior (with the new record included)
  const updatedHistory = [...history, { timestamp: now, path }]
  const analysis = await analyzeBehavior(req, updatedHistory, options)

  return {
    isBot: analysis.suspicious,
    confidence: analysis.score,
    reason: analysis.reasons.join('; ') || 'Behavior analysis passed',
    ip: identifier,
  }
}

// ============================================================================
// Behavior Middleware
// ============================================================================

/**
 * Global behavior store instance
 */
let globalBehaviorStore: MemoryBehaviorStore | undefined

/**
 * Get or create global behavior store
 */
export function getGlobalBehaviorStore(): MemoryBehaviorStore {
  if (!globalBehaviorStore) {
    globalBehaviorStore = new MemoryBehaviorStore()
  }
  return globalBehaviorStore
}

/**
 * Create behavior analysis middleware
 */
export function withBehaviorAnalysis<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: BehaviorOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  // Use provided store or global store
  const store = options.store || getGlobalBehaviorStore()
  const mergedOptions = { ...options, store }

  return async (req: NextRequest, ctx: T): Promise<Response> => {
    const result = await checkBehavior(req, mergedOptions)

    if (result.isBot && result.confidence >= 0.5) {
      return new Response(
        JSON.stringify({
          error: 'Too Many Requests',
          message: 'Unusual request pattern detected',
          retryAfter: 60,
        }),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '60',
          },
        }
      )
    }

    return handler(req, ctx)
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get client IP from request
 */
function getClientIP(req: NextRequest): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    req.headers.get('cf-connecting-ip') ||
    'unknown'
  )
}

/**
 * Calculate variance of numbers
 */
function calculateVariance(numbers: number[]): number {
  if (numbers.length === 0) return 0
  const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length
  const squaredDiffs = numbers.map(n => Math.pow(n - mean, 2))
  return squaredDiffs.reduce((a, b) => a + b, 0) / numbers.length
}

/**
 * Detect sequential URL patterns
 */
function isSequentialPattern(paths: string[]): boolean {
  // Check for numeric sequences in paths
  const numbers = paths.map(p => {
    const match = p.match(/(\d+)/)
    return match ? parseInt(match[1], 10) : null
  }).filter((n): n is number => n !== null)

  if (numbers.length < 3) return false

  // Check if numbers are sequential
  let sequential = 0
  for (let i = 1; i < numbers.length; i++) {
    if (numbers[i] === numbers[i - 1] + 1) {
      sequential++
    }
  }

  return sequential >= numbers.length * 0.6
}

/**
 * Check for missing typical browser headers
 */
function checkMissingHeaders(req: NextRequest): number {
  let score = 0

  // Typical browser headers
  const typicalHeaders = [
    'accept',
    'accept-language',
    'accept-encoding',
  ]

  for (const header of typicalHeaders) {
    if (!req.headers.get(header)) {
      score += 0.05
    }
  }

  // Check for suspicious accept header
  const accept = req.headers.get('accept')
  if (accept && !accept.includes('text/html') && !accept.includes('application/json') && !accept.includes('*/*')) {
    score += 0.05
  }

  // Check for missing referer on non-entry pages
  const referer = req.headers.get('referer')
  const path = new URL(req.url).pathname
  if (!referer && path !== '/' && !path.includes('/api/')) {
    score += 0.03
  }

  return score
}
