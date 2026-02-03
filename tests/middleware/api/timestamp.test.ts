import { describe, it, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'
import {
  parseTimestamp,
  formatTimestamp,
  validateTimestamp,
  isTimestampValid,
  withTimestamp,
  getRequestAge,
} from '../../../src/middleware/api/timestamp'

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

describe('Timestamp Validation', () => {
  describe('parseTimestamp', () => {
    it('should parse unix timestamp', () => {
      const result = parseTimestamp('1609459200', 'unix')
      expect(result).toBe(1609459200)
    })

    it('should parse unix milliseconds', () => {
      const result = parseTimestamp('1609459200000', 'unix-ms')
      expect(result).toBe(1609459200)
    })

    it('should parse ISO 8601', () => {
      const result = parseTimestamp('2021-01-01T00:00:00.000Z', 'iso8601')
      expect(result).toBe(1609459200)
    })

    it('should return null for invalid timestamp', () => {
      expect(parseTimestamp('invalid', 'unix')).toBeNull()
      expect(parseTimestamp('', 'unix')).toBeNull()
      expect(parseTimestamp('-1', 'unix')).toBeNull()
    })

    it('should return null for invalid ISO date', () => {
      expect(parseTimestamp('not-a-date', 'iso8601')).toBeNull()
    })
  })

  describe('formatTimestamp', () => {
    it('should format as unix timestamp', () => {
      const result = formatTimestamp('unix')
      expect(result).toMatch(/^\d{10}$/)
    })

    it('should format as unix milliseconds', () => {
      const result = formatTimestamp('unix-ms')
      expect(result).toMatch(/^\d{13}$/)
    })

    it('should format as ISO 8601', () => {
      const result = formatTimestamp('iso8601')
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
    })
  })

  describe('validateTimestamp', () => {
    it('should accept valid current timestamp', () => {
      const timestamp = Math.floor(Date.now() / 1000).toString()
      const req = createRequest({ headers: { 'x-timestamp': timestamp } })

      const result = validateTimestamp(req)

      expect(result.valid).toBe(true)
      expect(result.timestamp).toBeDefined()
    })

    it('should reject old timestamp', () => {
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString() // 10 minutes ago
      const req = createRequest({ headers: { 'x-timestamp': oldTimestamp } })

      const result = validateTimestamp(req, { maxAge: 300 })

      expect(result.valid).toBe(false)
      expect(result.reason).toContain('too old')
    })

    it('should reject future timestamp by default', () => {
      const futureTimestamp = (Math.floor(Date.now() / 1000) + 120).toString() // 2 minutes in future
      const req = createRequest({ headers: { 'x-timestamp': futureTimestamp } })

      const result = validateTimestamp(req)

      expect(result.valid).toBe(false)
      expect(result.reason).toContain('future')
    })

    it('should accept future timestamp when allowed', () => {
      const futureTimestamp = (Math.floor(Date.now() / 1000) + 30).toString() // 30 seconds in future
      const req = createRequest({ headers: { 'x-timestamp': futureTimestamp } })

      const result = validateTimestamp(req, { allowFuture: true, maxFuture: 60 })

      expect(result.valid).toBe(true)
    })

    it('should reject too far future timestamp', () => {
      const futureTimestamp = (Math.floor(Date.now() / 1000) + 120).toString() // 2 minutes in future
      const req = createRequest({ headers: { 'x-timestamp': futureTimestamp } })

      const result = validateTimestamp(req, { allowFuture: true, maxFuture: 60 })

      expect(result.valid).toBe(false)
      expect(result.reason).toContain('too far in future')
    })

    it('should report missing timestamp when required', () => {
      const req = createRequest()

      const result = validateTimestamp(req, { required: true })

      expect(result.valid).toBe(false)
      expect(result.reason).toContain('Missing timestamp')
    })

    it('should pass when timestamp not required and missing', () => {
      const req = createRequest()

      const result = validateTimestamp(req, { required: false })

      expect(result.valid).toBe(true)
    })

    it('should reject invalid format', () => {
      const req = createRequest({ headers: { 'x-timestamp': 'not-a-number' } })

      const result = validateTimestamp(req)

      expect(result.valid).toBe(false)
      expect(result.reason).toContain('Invalid timestamp format')
    })

    it('should use custom header name', () => {
      const timestamp = Math.floor(Date.now() / 1000).toString()
      const req = createRequest({ headers: { 'custom-ts': timestamp } })

      const result = validateTimestamp(req, { timestampHeader: 'custom-ts' })

      expect(result.valid).toBe(true)
    })

    it('should use query param', () => {
      const timestamp = Math.floor(Date.now() / 1000).toString()
      const req = createRequest({ query: { ts: timestamp } })

      const result = validateTimestamp(req, { timestampQuery: 'ts' })

      expect(result.valid).toBe(true)
    })
  })

  describe('isTimestampValid', () => {
    it('should return true for valid timestamp', () => {
      const timestamp = Math.floor(Date.now() / 1000).toString()
      expect(isTimestampValid(timestamp)).toBe(true)
    })

    it('should return false for invalid timestamp', () => {
      expect(isTimestampValid('invalid')).toBe(false)
    })

    it('should return false for old timestamp', () => {
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString()
      expect(isTimestampValid(oldTimestamp, { maxAge: 300 })).toBe(false)
    })
  })

  describe('withTimestamp', () => {
    it('should allow valid timestamp', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withTimestamp(handler)

      const timestamp = Math.floor(Date.now() / 1000).toString()
      const req = createRequest({ headers: { 'x-timestamp': timestamp } })

      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(400)
    })

    it('should reject invalid timestamp', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withTimestamp(handler)

      const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString()
      const req = createRequest({ headers: { 'x-timestamp': oldTimestamp } })

      const response = await wrapped(req, {})

      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(400)
    })

    it('should skip when configured', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withTimestamp(handler, { skip: () => true })

      const req = createRequest()
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
    })
  })

  describe('getRequestAge', () => {
    it('should return age for valid timestamp', () => {
      const timestamp = (Math.floor(Date.now() / 1000) - 30).toString() // 30 seconds ago
      const req = createRequest({ headers: { 'x-timestamp': timestamp } })

      const age = getRequestAge(req)

      expect(age).toBeGreaterThanOrEqual(29)
      expect(age).toBeLessThanOrEqual(32)
    })

    it('should return null for missing timestamp', () => {
      const req = createRequest()
      expect(getRequestAge(req)).toBeNull()
    })

    it('should return null for invalid timestamp', () => {
      const req = createRequest({ headers: { 'x-timestamp': 'invalid' } })
      expect(getRequestAge(req)).toBeNull()
    })
  })
})
