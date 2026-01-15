import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import {
  detectBot,
  withBotProtection,
  withUserAgentProtection,
  withHoneypotProtection,
  withBehaviorProtection,
  BOT_PROTECTION_PRESETS,
  withBotProtectionPreset,
} from '../../../src/middleware/bot/middleware'
import { MemoryBehaviorStore } from '../../../src/middleware/bot/behavior'

function createRequest(options: {
  method?: string
  path?: string
  userAgent?: string
  body?: unknown
  headers?: Record<string, string>
  ip?: string
} = {}): NextRequest {
  const {
    method = 'GET',
    path = '/api/test',
    userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
    body,
    headers = {},
    ip = '192.168.1.1',
  } = options

  const url = new URL(`http://localhost${path}`)

  const init: RequestInit = {
    method,
    headers: {
      'user-agent': userAgent,
      'x-forwarded-for': ip,
      'accept': 'text/html',
      'accept-language': 'en-US',
      'accept-encoding': 'gzip',
      'content-type': 'application/json',
      ...headers,
    },
  }

  if (body && method !== 'GET') {
    init.body = JSON.stringify(body)
  }

  return new NextRequest(url, init)
}

describe('Bot Protection Middleware', () => {
  describe('detectBot', () => {
    it('should pass normal browser requests', async () => {
      const req = createRequest()
      const result = await detectBot(req, {
        behavior: false, // Disable to avoid test interference
      })
      expect(result.isBot).toBe(false)
    })

    it('should detect known bots by user-agent', async () => {
      const req = createRequest({ userAgent: 'Googlebot/2.1' })
      const result = await detectBot(req, {
        userAgent: { blockAllBots: true },
        behavior: false,
      })
      expect(result.isBot).toBe(true)
    })

    it('should allow search engine bots by default', async () => {
      const req = createRequest({ userAgent: 'Googlebot/2.1' })
      const result = await detectBot(req, {
        behavior: false,
      })
      // Googlebot is allowed by default, so isBot should indicate detected but allowed
      expect(result.isBot).toBe(false)
    })

    it('should detect honeypot triggers', async () => {
      const req = createRequest({
        method: 'POST',
        body: { _hp_email: 'bot@spam.com' },
      })
      const result = await detectBot(req, {
        userAgent: false,
        behavior: false,
      })
      expect(result.isBot).toBe(true)
      expect(result.reason).toContain('Honeypot')
    })

    it('should combine multiple detection methods', async () => {
      const req = createRequest({
        method: 'POST',
        userAgent: 'python-requests/2.28',
        body: { _hp_email: 'bot@spam.com' },
      })
      const result = await detectBot(req, {
        behavior: false,
      })
      expect(result.isBot).toBe(true)
      // Should have multiple reasons
      expect(result.reason).toContain(';')
    })
  })

  describe('withBotProtection', () => {
    it('should pass legitimate requests', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withBotProtection(handler, {
        behavior: false,
      })

      const req = createRequest()
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(403)
    })

    it('should block detected bots', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withBotProtection(handler, {
        userAgent: { blockAllBots: true },
        behavior: false,
      })

      const req = createRequest({ userAgent: 'curl/7.84' })
      const response = await wrapped(req, {})

      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(403)
    })

    it('should use custom onBot handler', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const onBot = vi.fn().mockResolvedValue(new Response('Custom', { status: 418 }))

      const wrapped = withBotProtection(handler, {
        userAgent: { blockAllBots: true },
        behavior: false,
        onBot,
      })

      const req = createRequest({ userAgent: 'curl/7.84' })
      const response = await wrapped(req, {})

      expect(onBot).toHaveBeenCalled()
      expect(response.status).toBe(418)
    })

    it('should skip protection when skip returns true', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withBotProtection(handler, {
        userAgent: { blockAllBots: true },
        behavior: false,
        skip: () => true,
      })

      const req = createRequest({ userAgent: 'curl/7.84' })
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
    })

    it('should add bot context in detect mode', async () => {
      const handler = vi.fn().mockImplementation((req, ctx) => {
        expect(ctx.bot).toBeDefined()
        return new Response('OK')
      })

      const wrapped = withBotProtection(handler, {
        userAgent: { blockAllBots: true },
        behavior: false,
        mode: 'detect',
      })

      const req = createRequest({ userAgent: 'curl/7.84' })
      await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
    })

    it('should log bot detections when log is true', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const handler = vi.fn().mockResolvedValue(new Response('OK'))

      const wrapped = withBotProtection(handler, {
        userAgent: { blockAllBots: true },
        behavior: false,
        log: true,
      })

      const req = createRequest({ userAgent: 'curl/7.84' })
      await wrapped(req, {})

      expect(consoleSpy).toHaveBeenCalled()
      consoleSpy.mockRestore()
    })

    it('should use custom log function', async () => {
      const logFn = vi.fn()
      const handler = vi.fn().mockResolvedValue(new Response('OK'))

      const wrapped = withBotProtection(handler, {
        userAgent: { blockAllBots: true },
        behavior: false,
        log: logFn,
      })

      const req = createRequest({ userAgent: 'curl/7.84' })
      await wrapped(req, {})

      expect(logFn).toHaveBeenCalledWith(expect.objectContaining({
        isBot: true,
      }))
    })
  })

  describe('withUserAgentProtection', () => {
    it('should only check user-agent', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withUserAgentProtection(handler, {
        blockAllBots: true,
      })

      const req = createRequest({
        method: 'POST',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        body: { _hp_email: 'bot@spam.com' }, // Honeypot would trigger but UA protection ignores it
      })

      const response = await wrapped(req, {})
      expect(handler).toHaveBeenCalled()
    })
  })

  describe('withHoneypotProtection', () => {
    it('should only check honeypot', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withHoneypotProtection(handler)

      const req = createRequest({
        method: 'POST',
        userAgent: 'curl/7.84', // Would be detected by UA but honeypot ignores it
        body: { email: 'legit@user.com' },
      })

      const response = await wrapped(req, {})
      expect(handler).toHaveBeenCalled()
    })
  })

  describe('withBehaviorProtection', () => {
    it('should only check behavior', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withBehaviorProtection(handler, {
        store: new MemoryBehaviorStore(),
      })

      const req = createRequest({
        userAgent: 'curl/7.84', // Would be detected by UA but behavior ignores it
      })

      const response = await wrapped(req, {})
      expect(handler).toHaveBeenCalled()
    })
  })

  describe('BOT_PROTECTION_PRESETS', () => {
    it('should have relaxed preset', () => {
      expect(BOT_PROTECTION_PRESETS.relaxed).toBeDefined()
      expect(BOT_PROTECTION_PRESETS.relaxed.honeypot).toBe(false)
    })

    it('should have standard preset', () => {
      expect(BOT_PROTECTION_PRESETS.standard).toBeDefined()
      expect(BOT_PROTECTION_PRESETS.standard.honeypot).toBe(true)
    })

    it('should have strict preset', () => {
      expect(BOT_PROTECTION_PRESETS.strict).toBeDefined()
      expect(BOT_PROTECTION_PRESETS.strict.behavior).toBeDefined()
    })

    it('should have api preset', () => {
      expect(BOT_PROTECTION_PRESETS.api).toBeDefined()
      expect(BOT_PROTECTION_PRESETS.api.userAgent).toHaveProperty('blockAllBots', true)
    })
  })

  describe('withBotProtectionPreset', () => {
    it('should apply preset configuration', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withBotProtectionPreset(handler, 'api')

      const req = createRequest({ userAgent: 'curl/7.84' })
      const response = await wrapped(req, {})

      expect(response.status).toBe(403)
    })

    it('should allow overrides', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withBotProtectionPreset(handler, 'api', {
        mode: 'detect', // Override to detect mode
      })

      const req = createRequest({ userAgent: 'curl/7.84' })
      await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
    })
  })
})
