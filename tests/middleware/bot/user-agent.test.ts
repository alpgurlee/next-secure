import { describe, it, expect } from 'vitest'
import {
  analyzeUserAgent,
  isSuspiciousUA,
  isBotAllowed,
  getBotsByCategory,
  createBotPattern,
  KNOWN_BOT_PATTERNS,
  DEFAULT_ALLOWED_CATEGORIES,
  DEFAULT_ALLOWED_BOTS,
} from '../../../src/middleware/bot/user-agent'

describe('User-Agent Analysis', () => {
  describe('analyzeUserAgent', () => {
    describe('search engine bots', () => {
      it('should detect Googlebot', () => {
        const result = analyzeUserAgent(
          'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        )
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Googlebot')
        expect(result.category).toBe('search_engine')
      })

      it('should detect Bingbot', () => {
        const result = analyzeUserAgent(
          'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
        )
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Bingbot')
        expect(result.category).toBe('search_engine')
      })

      it('should detect DuckDuckBot', () => {
        const result = analyzeUserAgent('DuckDuckBot/1.0')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('DuckDuckBot')
        expect(result.category).toBe('search_engine')
      })

      it('should detect Yandex', () => {
        const result = analyzeUserAgent('Mozilla/5.0 (compatible; YandexBot/3.0)')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Yandex')
        expect(result.category).toBe('search_engine')
      })
    })

    describe('social media bots', () => {
      it('should detect Facebook crawler', () => {
        const result = analyzeUserAgent('facebookexternalhit/1.1')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Facebook')
        expect(result.category).toBe('social_media')
      })

      it('should detect Twitter bot', () => {
        const result = analyzeUserAgent('Twitterbot/1.0')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Twitter')
        expect(result.category).toBe('social_media')
      })

      it('should detect LinkedIn bot', () => {
        const result = analyzeUserAgent('LinkedInBot/1.0')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('LinkedIn')
        expect(result.category).toBe('social_media')
      })

      it('should detect Slack bot', () => {
        const result = analyzeUserAgent('Slackbot-LinkExpanding 1.0')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Slack')
        expect(result.category).toBe('social_media')
      })

      it('should detect Discord bot', () => {
        const result = analyzeUserAgent('Mozilla/5.0 (compatible; Discordbot/2.0)')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Discord')
        expect(result.category).toBe('social_media')
      })
    })

    describe('AI crawlers', () => {
      it('should detect GPTBot', () => {
        const result = analyzeUserAgent('GPTBot/1.0')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('GPTBot')
        expect(result.category).toBe('ai_crawler')
      })

      it('should detect ClaudeBot', () => {
        const result = analyzeUserAgent('ClaudeBot/1.0')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Claude-Web')
        expect(result.category).toBe('ai_crawler')
      })

      it('should detect Bytespider', () => {
        const result = analyzeUserAgent('Bytespider')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Bytespider')
        expect(result.category).toBe('ai_crawler')
      })
    })

    describe('security scanners', () => {
      it('should detect Nikto', () => {
        const result = analyzeUserAgent('Nikto/2.1.6')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('Nikto')
        expect(result.category).toBe('security')
      })

      it('should detect sqlmap', () => {
        const result = analyzeUserAgent('sqlmap/1.5')
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('sqlmap')
        expect(result.category).toBe('security')
      })
    })

    describe('HTTP libraries', () => {
      it('should detect python-requests', () => {
        const result = analyzeUserAgent('python-requests/2.28.0')
        expect(result.isBot).toBe(true)
        expect(result.category).toBe('unknown')
      })

      it('should detect curl', () => {
        const result = analyzeUserAgent('curl/7.84.0')
        expect(result.isBot).toBe(true)
        expect(result.category).toBe('unknown')
      })

      it('should detect axios', () => {
        const result = analyzeUserAgent('axios/0.27.2')
        expect(result.isBot).toBe(true)
        expect(result.category).toBe('unknown')
      })
    })

    describe('real browsers', () => {
      it('should not detect Chrome as bot', () => {
        const result = analyzeUserAgent(
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        expect(result.isBot).toBe(false)
      })

      it('should not detect Firefox as bot', () => {
        const result = analyzeUserAgent(
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
        )
        expect(result.isBot).toBe(false)
      })

      it('should not detect Safari as bot', () => {
        const result = analyzeUserAgent(
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
        )
        expect(result.isBot).toBe(false)
      })

      it('should not detect Edge as bot', () => {
        const result = analyzeUserAgent(
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
        )
        expect(result.isBot).toBe(false)
      })
    })

    describe('empty and suspicious user agents', () => {
      it('should flag empty user agent', () => {
        const result = analyzeUserAgent('')
        expect(result.isBot).toBe(true)
        expect(result.reason).toContain('Empty')
      })

      it('should flag null user agent', () => {
        const result = analyzeUserAgent(null)
        expect(result.isBot).toBe(true)
      })

      it('should not flag empty UA when blockEmptyUA is false', () => {
        const result = analyzeUserAgent('', { blockEmptyUA: false })
        expect(result.isBot).toBe(false)
      })

      it('should flag very short user agent', () => {
        const result = analyzeUserAgent('test')
        expect(result.isBot).toBe(true)
        expect(result.reason).toContain('Suspicious')
      })

      it('should flag hex-like user agent', () => {
        const result = analyzeUserAgent('a1b2c3d4e5f6')
        expect(result.isBot).toBe(true)
      })
    })

    describe('options', () => {
      it('should block all bots when blockAllBots is true', () => {
        const result = analyzeUserAgent('Googlebot/2.1', { blockAllBots: true })
        expect(result.isBot).toBe(true)
        expect(result.reason).toContain('blockAllBots')
      })

      it('should allow specific bots in allowList', () => {
        const result = analyzeUserAgent('GPTBot/1.0', { allowList: ['GPTBot'] })
        expect(result.isBot).toBe(true)
        expect(result.reason).toContain('Allowed bot')
      })

      it('should block specific bots in blockList', () => {
        const result = analyzeUserAgent('Googlebot/2.1', { blockList: ['Googlebot'] })
        expect(result.isBot).toBe(true)
        expect(result.reason).toContain('Blocked')
      })

      it('should use custom patterns', () => {
        const customPattern = createBotPattern('MyBot', /MyCustomBot/i, 'monitoring', true)
        const result = analyzeUserAgent('MyCustomBot/1.0', { customPatterns: [customPattern] })
        expect(result.isBot).toBe(true)
        expect(result.name).toBe('MyBot')
      })
    })
  })

  describe('isSuspiciousUA', () => {
    it('should return true for short UAs', () => {
      expect(isSuspiciousUA('test')).toBe(true)
      expect(isSuspiciousUA('abc')).toBe(true)
    })

    it('should return true for hex strings', () => {
      expect(isSuspiciousUA('a1b2c3d4e5f6a1b2')).toBe(true)
    })

    it('should return false for normal browser UA', () => {
      expect(isSuspiciousUA(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
      )).toBe(false)
    })

    it('should return true for very old Chrome versions', () => {
      expect(isSuspiciousUA('Mozilla/5.0 Chrome/2.0')).toBe(true)
    })
  })

  describe('isBotAllowed', () => {
    it('should return true for Googlebot by default', () => {
      expect(isBotAllowed('Googlebot')).toBe(true)
    })

    it('should return false for blocked bot', () => {
      expect(isBotAllowed('Googlebot', { blockList: ['Googlebot'] })).toBe(false)
    })

    it('should return true for explicitly allowed bot', () => {
      expect(isBotAllowed('GPTBot', { allowList: ['GPTBot'] })).toBe(true)
    })

    it('should return false in blockAllBots mode', () => {
      expect(isBotAllowed('Googlebot', { blockAllBots: true })).toBe(false)
    })
  })

  describe('getBotsByCategory', () => {
    it('should return search engine bots', () => {
      const bots = getBotsByCategory('search_engine')
      expect(bots.length).toBeGreaterThan(5)
      expect(bots.every(b => b.category === 'search_engine')).toBe(true)
    })

    it('should return social media bots', () => {
      const bots = getBotsByCategory('social_media')
      expect(bots.length).toBeGreaterThan(5)
    })

    it('should return AI crawlers', () => {
      const bots = getBotsByCategory('ai_crawler')
      expect(bots.length).toBeGreaterThan(3)
    })
  })

  describe('createBotPattern', () => {
    it('should create pattern from string', () => {
      const pattern = createBotPattern('Test', 'testbot', 'unknown', false)
      expect(pattern.name).toBe('Test')
      expect(pattern.pattern.test('TestBot')).toBe(true)
    })

    it('should create pattern from RegExp', () => {
      const pattern = createBotPattern('Test', /custom-regex/i, 'monitoring', true)
      expect(pattern.pattern.test('CUSTOM-REGEX')).toBe(true)
      expect(pattern.allowed).toBe(true)
    })
  })

  describe('constants', () => {
    it('should have known bot patterns', () => {
      expect(KNOWN_BOT_PATTERNS.length).toBeGreaterThan(30)
    })

    it('should have default allowed categories', () => {
      expect(DEFAULT_ALLOWED_CATEGORIES).toContain('search_engine')
      expect(DEFAULT_ALLOWED_CATEGORIES).toContain('social_media')
    })

    it('should have default allowed bots', () => {
      expect(DEFAULT_ALLOWED_BOTS).toContain('Googlebot')
      expect(DEFAULT_ALLOWED_BOTS).toContain('Bingbot')
    })
  })
})
