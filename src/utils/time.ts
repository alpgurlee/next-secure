/**
 * Time parsing and manipulation utilities
 */

import type { Duration } from '../core/types'

/**
 * Time unit multipliers in milliseconds
 */
const TIME_UNITS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
}

/**
 * Extended time unit names
 */
const TIME_UNIT_ALIASES: Record<string, string> = {
  millisecond: 'ms',
  milliseconds: 'ms',
  second: 's',
  seconds: 's',
  sec: 's',
  secs: 's',
  minute: 'm',
  minutes: 'm',
  min: 'm',
  mins: 'm',
  hour: 'h',
  hours: 'h',
  hr: 'h',
  hrs: 'h',
  day: 'd',
  days: 'd',
}

/**
 * Parse a duration string or number to milliseconds
 *
 * @example
 * ```typescript
 * parseDuration('15m')      // 900000 (15 minutes)
 * parseDuration('1h')       // 3600000 (1 hour)
 * parseDuration('30s')      // 30000 (30 seconds)
 * parseDuration('1d')       // 86400000 (1 day)
 * parseDuration(60000)      // 60000 (already in ms)
 * parseDuration('2 hours')  // 7200000 (2 hours)
 * parseDuration('1h 30m')   // 5400000 (1.5 hours)
 * ```
 *
 * @param duration - Duration string (e.g., '15m', '1h', '30s') or number in milliseconds
 * @returns Duration in milliseconds
 * @throws Error if the duration format is invalid
 */
export function parseDuration(duration: Duration | string): number {
  // If it's already a number, return as-is
  if (typeof duration === 'number') {
    if (duration < 0) {
      throw new Error(`Invalid duration: ${duration}. Duration must be non-negative.`)
    }
    return duration
  }

  // Trim and lowercase the string
  const input = duration.trim().toLowerCase()

  if (!input) {
    throw new Error('Invalid duration: empty string')
  }

  // Try to parse as a simple number (assume milliseconds)
  const numericValue = Number(input)
  if (!isNaN(numericValue)) {
    if (numericValue < 0) {
      throw new Error(`Invalid duration: ${duration}. Duration must be non-negative.`)
    }
    return numericValue
  }

  // Handle compound durations like "1h 30m" or "1h30m"
  let totalMs = 0
  const regex = /(\d+(?:\.\d+)?)\s*([a-z]+)/g
  let match: RegExpExecArray | null
  let hasMatch = false

  while ((match = regex.exec(input)) !== null) {
    hasMatch = true
    const value = parseFloat(match[1])
    let unit = match[2]

    // Resolve unit aliases
    if (unit in TIME_UNIT_ALIASES) {
      unit = TIME_UNIT_ALIASES[unit]
    }

    // Get multiplier
    const multiplier = TIME_UNITS[unit]
    if (multiplier === undefined) {
      throw new Error(
        `Invalid duration unit: "${unit}" in "${duration}". ` +
        `Valid units: s, m, h, d (or seconds, minutes, hours, days)`
      )
    }

    totalMs += value * multiplier
  }

  if (!hasMatch) {
    throw new Error(
      `Invalid duration format: "${duration}". ` +
      `Expected format like "15m", "1h", "30s", "1d", or "1h 30m"`
    )
  }

  return Math.floor(totalMs)
}

/**
 * Format milliseconds to a human-readable duration string
 *
 * @example
 * ```typescript
 * formatDuration(900000)   // "15m"
 * formatDuration(3600000)  // "1h"
 * formatDuration(5400000)  // "1h 30m"
 * formatDuration(86400000) // "1d"
 * formatDuration(90061000) // "1d 1h 1m 1s"
 * ```
 *
 * @param ms - Duration in milliseconds
 * @param options - Formatting options
 * @returns Human-readable duration string
 */
export function formatDuration(
  ms: number,
  options: {
    /**
     * Use long unit names (e.g., "minutes" instead of "m")
     */
    long?: boolean
    /**
     * Maximum number of units to include
     */
    maxUnits?: number
    /**
     * Separator between units
     */
    separator?: string
  } = {}
): string {
  const { long = false, maxUnits = 4, separator = ' ' } = options

  if (ms < 0) {
    return `-${formatDuration(-ms, options)}`
  }

  if (ms === 0) {
    return long ? '0 seconds' : '0s'
  }

  const units: Array<{ value: number; short: string; long: string; longPlural: string }> = [
    { value: 86400000, short: 'd', long: 'day', longPlural: 'days' },
    { value: 3600000, short: 'h', long: 'hour', longPlural: 'hours' },
    { value: 60000, short: 'm', long: 'minute', longPlural: 'minutes' },
    { value: 1000, short: 's', long: 'second', longPlural: 'seconds' },
    { value: 1, short: 'ms', long: 'millisecond', longPlural: 'milliseconds' },
  ]

  const parts: string[] = []
  let remaining = ms

  for (const unit of units) {
    if (parts.length >= maxUnits) break
    if (remaining >= unit.value) {
      const count = Math.floor(remaining / unit.value)
      remaining = remaining % unit.value

      if (long) {
        parts.push(`${count} ${count === 1 ? unit.long : unit.longPlural}`)
      } else {
        parts.push(`${count}${unit.short}`)
      }
    }
  }

  return parts.join(separator)
}

/**
 * Get the current timestamp in seconds (Unix timestamp)
 */
export function nowInSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * Get the current timestamp in milliseconds
 */
export function nowInMs(): number {
  return Date.now()
}

/**
 * Calculate reset time for a fixed window
 *
 * @param windowMs - Window size in milliseconds
 * @returns Unix timestamp (seconds) when the window resets
 */
export function getWindowReset(windowMs: number): number {
  const now = Date.now()
  const windowStart = Math.floor(now / windowMs) * windowMs
  const windowEnd = windowStart + windowMs
  return Math.floor(windowEnd / 1000)
}

/**
 * Get the start of the current window
 *
 * @param windowMs - Window size in milliseconds
 * @returns Timestamp (ms) of window start
 */
export function getWindowStart(windowMs: number): number {
  return Math.floor(Date.now() / windowMs) * windowMs
}

/**
 * Sleep for a specified duration
 *
 * @param duration - Duration to sleep
 * @returns Promise that resolves after the duration
 */
export function sleep(duration: Duration | string): Promise<void> {
  const ms = parseDuration(duration)
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Check if a timestamp has expired
 *
 * @param timestampMs - Timestamp in milliseconds
 * @param ttlMs - Time-to-live in milliseconds
 * @returns true if expired
 */
export function isExpired(timestampMs: number, ttlMs: number): boolean {
  return Date.now() > timestampMs + ttlMs
}

/**
 * Calculate time until expiration
 *
 * @param expiresAt - Expiration timestamp in milliseconds
 * @returns Milliseconds until expiration (0 if already expired)
 */
export function timeUntilExpiry(expiresAt: number): number {
  return Math.max(0, expiresAt - Date.now())
}

/**
 * Convert seconds to milliseconds
 */
export function secondsToMs(seconds: number): number {
  return seconds * 1000
}

/**
 * Convert milliseconds to seconds
 */
export function msToSeconds(ms: number): number {
  return Math.floor(ms / 1000)
}
