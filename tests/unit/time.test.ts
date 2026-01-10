/**
 * Time utility tests
 */

import { describe, it, expect } from 'vitest'
import {
  parseDuration,
  formatDuration,
  nowInSeconds,
  nowInMs,
  isExpired,
  timeUntilExpiry,
  secondsToMs,
  msToSeconds,
} from '../../src/utils/time'

describe('parseDuration', () => {
  it('should parse seconds', () => {
    expect(parseDuration('30s')).toBe(30000)
    expect(parseDuration('1s')).toBe(1000)
    expect(parseDuration('0s')).toBe(0)
  })

  it('should parse minutes', () => {
    expect(parseDuration('15m')).toBe(900000)
    expect(parseDuration('1m')).toBe(60000)
    expect(parseDuration('60m')).toBe(3600000)
  })

  it('should parse hours', () => {
    expect(parseDuration('1h')).toBe(3600000)
    expect(parseDuration('24h')).toBe(86400000)
  })

  it('should parse days', () => {
    expect(parseDuration('1d')).toBe(86400000)
    expect(parseDuration('7d')).toBe(604800000)
  })

  it('should parse compound durations', () => {
    expect(parseDuration('1h 30m')).toBe(5400000)
    expect(parseDuration('1h30m')).toBe(5400000)
    expect(parseDuration('2d 12h')).toBe(216000000)
  })

  it('should parse long unit names', () => {
    expect(parseDuration('30 seconds')).toBe(30000)
    expect(parseDuration('15 minutes')).toBe(900000)
    expect(parseDuration('1 hour')).toBe(3600000)
    expect(parseDuration('2 days')).toBe(172800000)
  })

  it('should handle numbers (milliseconds)', () => {
    expect(parseDuration(60000)).toBe(60000)
    expect(parseDuration(0)).toBe(0)
  })

  it('should handle numeric strings', () => {
    expect(parseDuration('60000')).toBe(60000)
  })

  it('should throw on invalid format', () => {
    expect(() => parseDuration('invalid')).toThrow()
    expect(() => parseDuration('')).toThrow()
    expect(() => parseDuration('15x')).toThrow()
  })

  it('should throw on negative duration', () => {
    expect(() => parseDuration(-1000)).toThrow()
  })

  it('should handle decimal values', () => {
    expect(parseDuration('1.5h')).toBe(5400000)
    expect(parseDuration('0.5m')).toBe(30000)
  })
})

describe('formatDuration', () => {
  it('should format milliseconds to short format', () => {
    expect(formatDuration(30000)).toBe('30s')
    expect(formatDuration(900000)).toBe('15m')
    expect(formatDuration(3600000)).toBe('1h')
    expect(formatDuration(86400000)).toBe('1d')
  })

  it('should format compound durations', () => {
    expect(formatDuration(5400000)).toBe('1h 30m')
    expect(formatDuration(90061000)).toBe('1d 1h 1m 1s')
  })

  it('should handle zero', () => {
    expect(formatDuration(0)).toBe('0s')
  })

  it('should handle negative values', () => {
    expect(formatDuration(-30000)).toBe('-30s')
  })

  it('should support long format', () => {
    expect(formatDuration(30000, { long: true })).toBe('30 seconds')
    expect(formatDuration(60000, { long: true })).toBe('1 minute')
    expect(formatDuration(3600000, { long: true })).toBe('1 hour')
  })

  it('should limit units', () => {
    expect(formatDuration(90061000, { maxUnits: 2 })).toBe('1d 1h')
  })

  it('should support custom separator', () => {
    expect(formatDuration(5400000, { separator: ', ' })).toBe('1h, 30m')
  })
})

describe('nowInSeconds', () => {
  it('should return current time in seconds', () => {
    const now = nowInSeconds()
    const expected = Math.floor(Date.now() / 1000)
    expect(now).toBeCloseTo(expected, 0)
  })
})

describe('nowInMs', () => {
  it('should return current time in milliseconds', () => {
    const now = nowInMs()
    const expected = Date.now()
    expect(now).toBeCloseTo(expected, -2) // Within 100ms
  })
})

describe('isExpired', () => {
  it('should return true for expired timestamps', () => {
    const past = Date.now() - 10000 // 10 seconds ago
    expect(isExpired(past, 5000)).toBe(true) // 5 second TTL
  })

  it('should return false for non-expired timestamps', () => {
    const past = Date.now() - 1000 // 1 second ago
    expect(isExpired(past, 5000)).toBe(false) // 5 second TTL
  })
})

describe('timeUntilExpiry', () => {
  it('should return time until expiry', () => {
    const future = Date.now() + 5000
    const time = timeUntilExpiry(future)
    expect(time).toBeGreaterThan(4000)
    expect(time).toBeLessThanOrEqual(5000)
  })

  it('should return 0 for past timestamps', () => {
    const past = Date.now() - 5000
    expect(timeUntilExpiry(past)).toBe(0)
  })
})

describe('secondsToMs', () => {
  it('should convert seconds to milliseconds', () => {
    expect(secondsToMs(1)).toBe(1000)
    expect(secondsToMs(60)).toBe(60000)
    expect(secondsToMs(0)).toBe(0)
  })
})

describe('msToSeconds', () => {
  it('should convert milliseconds to seconds', () => {
    expect(msToSeconds(1000)).toBe(1)
    expect(msToSeconds(60000)).toBe(60)
    expect(msToSeconds(0)).toBe(0)
  })

  it('should floor the result', () => {
    expect(msToSeconds(1500)).toBe(1)
    expect(msToSeconds(999)).toBe(0)
  })
})
