import { describe, it, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'
import {
  checkHoneypot,
  withHoneypot,
  generateHoneypotHTML,
  generateHoneypotCSS,
  DEFAULT_HONEYPOT_FIELDS,
} from '../../../src/middleware/bot/honeypot'

function createRequest(options: {
  method?: string
  body?: unknown
  query?: Record<string, string>
  headers?: Record<string, string>
  contentType?: string
} = {}): NextRequest {
  const {
    method = 'POST',
    body,
    query = {},
    headers = {},
    contentType = 'application/json',
  } = options

  const url = new URL('http://localhost/api/test')
  Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v))

  const init: RequestInit = {
    method,
    headers: {
      'content-type': contentType,
      ...headers,
    },
  }

  if (body && method !== 'GET') {
    init.body = JSON.stringify(body)
  }

  return new NextRequest(url, init)
}

describe('Honeypot Detection', () => {
  describe('checkHoneypot', () => {
    it('should pass when honeypot field is empty', async () => {
      const req = createRequest({
        body: { email: 'test@example.com', _hp_email: '' },
      })

      const result = await checkHoneypot(req)
      expect(result.isBot).toBe(false)
    })

    it('should pass when honeypot field is missing', async () => {
      const req = createRequest({
        body: { email: 'test@example.com' },
      })

      const result = await checkHoneypot(req)
      expect(result.isBot).toBe(false)
    })

    it('should detect bot when honeypot field is filled', async () => {
      const req = createRequest({
        body: { email: 'test@example.com', _hp_email: 'spam@bot.com' },
      })

      const result = await checkHoneypot(req)
      expect(result.isBot).toBe(true)
      expect(result.category).toBe('spam')
      expect(result.confidence).toBeGreaterThan(0.9)
    })

    it('should detect bot with custom field name', async () => {
      const req = createRequest({
        body: { website_url: 'http://spam.com' },
      })

      const result = await checkHoneypot(req, { fieldName: 'website_url' })
      expect(result.isBot).toBe(true)
    })

    it('should check multiple honeypot fields', async () => {
      const req = createRequest({
        body: { _hp_name: 'Bot Name' },
      })

      const result = await checkHoneypot(req, {
        fieldName: '_hp_email',
        additionalFields: ['_hp_name', '_hp_phone'],
      })
      expect(result.isBot).toBe(true)
      expect(result.reason).toContain('_hp_name')
    })

    it('should check query parameters', async () => {
      const req = createRequest({
        method: 'GET',
        query: { _hp_email: 'spam@bot.com' },
      })

      const result = await checkHoneypot(req)
      expect(result.isBot).toBe(true)
      expect(result.reason).toContain('query:_hp_email')
    })

    it('should use custom validation', async () => {
      const req = createRequest({
        body: { _hp_email: '0' }, // Should fail custom validation
      })

      const result = await checkHoneypot(req, {
        validate: (value) => value !== '0', // Only '0' passes
      })
      expect(result.isBot).toBe(false) // Custom validator says '0' is ok
    })

    it('should handle form-urlencoded bodies', async () => {
      const req = new NextRequest('http://localhost/api/test', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: '_hp_email=spam@bot.com&email=real@user.com',
      })

      const result = await checkHoneypot(req)
      expect(result.isBot).toBe(true)
    })
  })

  describe('withHoneypot', () => {
    it('should pass request when honeypot is empty', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withHoneypot(handler)

      const req = createRequest({
        body: { email: 'test@example.com' },
      })

      const response = await wrapped(req, {})
      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(403)
    })

    it('should block request when honeypot is filled', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withHoneypot(handler)

      const req = createRequest({
        body: { _hp_email: 'bot@spam.com' },
      })

      const response = await wrapped(req, {})
      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(403)
    })
  })

  describe('generateHoneypotHTML', () => {
    it('should generate HTML for default field', () => {
      const html = generateHoneypotHTML()
      expect(html).toContain('_hp_email')
      expect(html).toContain('aria-hidden="true"')
      expect(html).toContain('autocomplete="off"')
      expect(html).toContain('tabindex="-1"')
    })

    it('should generate HTML for custom fields', () => {
      const html = generateHoneypotHTML({
        fieldName: 'trap_field',
        additionalFields: ['extra_trap'],
      })
      expect(html).toContain('trap_field')
      expect(html).toContain('extra_trap')
    })

    it('should include hiding styles', () => {
      const html = generateHoneypotHTML()
      // The function uses random hiding techniques, accept any of them
      const hasHidingStyle =
        /position:\s*(absolute|fixed)/i.test(html) ||
        /clip:\s*rect/i.test(html) ||
        /opacity:\s*0/i.test(html) ||
        /transform:\s*scale\(0\)/i.test(html) ||
        /visibility:\s*hidden/i.test(html)
      expect(hasHidingStyle).toBe(true)
    })
  })

  describe('generateHoneypotCSS', () => {
    it('should generate CSS for hiding honeypot fields', () => {
      const css = generateHoneypotCSS()
      expect(css).toContain('#_hp_email')
      expect(css).toContain('position: absolute')
      expect(css).toContain('opacity: 0')
    })

    it('should include custom field selectors', () => {
      const css = generateHoneypotCSS({
        fieldName: 'trap',
        additionalFields: ['trap2'],
      })
      expect(css).toContain('#trap')
      expect(css).toContain('#trap2')
    })
  })

  describe('DEFAULT_HONEYPOT_FIELDS', () => {
    it('should have common trap field names', () => {
      expect(DEFAULT_HONEYPOT_FIELDS).toContain('_hp_email')
      expect(DEFAULT_HONEYPOT_FIELDS).toContain('_hp_name')
      expect(DEFAULT_HONEYPOT_FIELDS.length).toBeGreaterThan(5)
    })
  })
})
