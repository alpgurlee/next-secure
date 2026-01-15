/**
 * User-Agent Analysis for Bot Detection
 * @module nextjs-secure/bot
 */

import type {
  BotPattern,
  BotCategory,
  BotDetectionResult,
  UserAgentOptions,
} from './types'

// ============================================================================
// Known Bot Patterns
// ============================================================================

/**
 * Comprehensive list of known bot patterns
 */
export const KNOWN_BOT_PATTERNS: BotPattern[] = [
  // Search Engines - Generally allowed
  {
    name: 'Googlebot',
    pattern: /Googlebot|Google-InspectionTool|Storebot-Google|GoogleOther/i,
    category: 'search_engine',
    allowed: true,
    description: 'Google search crawler',
  },
  {
    name: 'Bingbot',
    pattern: /bingbot|msnbot|BingPreview/i,
    category: 'search_engine',
    allowed: true,
    description: 'Microsoft Bing crawler',
  },
  {
    name: 'Yahoo Slurp',
    pattern: /Slurp/i,
    category: 'search_engine',
    allowed: true,
    description: 'Yahoo search crawler',
  },
  {
    name: 'DuckDuckBot',
    pattern: /DuckDuckBot|DuckDuckGo-Favicons-Bot/i,
    category: 'search_engine',
    allowed: true,
    description: 'DuckDuckGo crawler',
  },
  {
    name: 'Baiduspider',
    pattern: /Baiduspider/i,
    category: 'search_engine',
    allowed: true,
    description: 'Baidu search crawler',
  },
  {
    name: 'Yandex',
    pattern: /YandexBot|YandexImages|YandexMobileBot/i,
    category: 'search_engine',
    allowed: true,
    description: 'Yandex search crawler',
  },
  {
    name: 'Applebot',
    pattern: /Applebot/i,
    category: 'search_engine',
    allowed: true,
    description: 'Apple search crawler',
  },
  {
    name: 'Sogou',
    pattern: /Sogou/i,
    category: 'search_engine',
    allowed: true,
    description: 'Sogou search crawler',
  },
  {
    name: 'Exabot',
    pattern: /Exabot/i,
    category: 'search_engine',
    allowed: true,
    description: 'Exalead search crawler',
  },

  // Social Media - Generally allowed
  {
    name: 'Facebook',
    pattern: /facebookexternalhit|Facebot|facebookcatalog/i,
    category: 'social_media',
    allowed: true,
    description: 'Facebook crawler for link previews',
  },
  {
    name: 'Twitter',
    pattern: /Twitterbot/i,
    category: 'social_media',
    allowed: true,
    description: 'Twitter/X crawler for cards',
  },
  {
    name: 'LinkedIn',
    pattern: /LinkedInBot/i,
    category: 'social_media',
    allowed: true,
    description: 'LinkedIn crawler for previews',
  },
  {
    name: 'Pinterest',
    pattern: /Pinterest|Pinterestbot/i,
    category: 'social_media',
    allowed: true,
    description: 'Pinterest crawler',
  },
  {
    name: 'Slack',
    pattern: /Slackbot/i,
    category: 'social_media',
    allowed: true,
    description: 'Slack link preview bot',
  },
  {
    name: 'Discord',
    pattern: /Discordbot/i,
    category: 'social_media',
    allowed: true,
    description: 'Discord link preview bot',
  },
  {
    name: 'Telegram',
    pattern: /TelegramBot/i,
    category: 'social_media',
    allowed: true,
    description: 'Telegram link preview bot',
  },
  {
    name: 'WhatsApp',
    pattern: /WhatsApp/i,
    category: 'social_media',
    allowed: true,
    description: 'WhatsApp link preview',
  },
  {
    name: 'Snapchat',
    pattern: /Snapchat/i,
    category: 'social_media',
    allowed: true,
    description: 'Snapchat crawler',
  },

  // Monitoring - Generally allowed
  {
    name: 'UptimeRobot',
    pattern: /UptimeRobot/i,
    category: 'monitoring',
    allowed: true,
    description: 'UptimeRobot monitoring',
  },
  {
    name: 'Pingdom',
    pattern: /Pingdom/i,
    category: 'monitoring',
    allowed: true,
    description: 'Pingdom monitoring',
  },
  {
    name: 'StatusCake',
    pattern: /StatusCake/i,
    category: 'monitoring',
    allowed: true,
    description: 'StatusCake monitoring',
  },
  {
    name: 'Site24x7',
    pattern: /Site24x7/i,
    category: 'monitoring',
    allowed: true,
    description: 'Site24x7 monitoring',
  },
  {
    name: 'Datadog',
    pattern: /Datadog/i,
    category: 'monitoring',
    allowed: true,
    description: 'Datadog synthetic monitoring',
  },
  {
    name: 'New Relic',
    pattern: /NewRelicPinger/i,
    category: 'monitoring',
    allowed: true,
    description: 'New Relic synthetic monitoring',
  },
  {
    name: 'Checkly',
    pattern: /Checkly/i,
    category: 'monitoring',
    allowed: true,
    description: 'Checkly monitoring',
  },

  // SEO Tools - Usually allowed but can be blocked
  {
    name: 'Ahrefs',
    pattern: /AhrefsBot|AhrefsSiteAudit/i,
    category: 'seo',
    allowed: false,
    description: 'Ahrefs SEO crawler',
  },
  {
    name: 'Semrush',
    pattern: /SemrushBot/i,
    category: 'seo',
    allowed: false,
    description: 'Semrush SEO crawler',
  },
  {
    name: 'Moz',
    pattern: /rogerbot|DotBot/i,
    category: 'seo',
    allowed: false,
    description: 'Moz SEO crawler',
  },
  {
    name: 'Majestic',
    pattern: /MJ12bot/i,
    category: 'seo',
    allowed: false,
    description: 'Majestic SEO crawler',
  },
  {
    name: 'Screaming Frog',
    pattern: /Screaming Frog/i,
    category: 'seo',
    allowed: false,
    description: 'Screaming Frog SEO Spider',
  },

  // AI Crawlers - Configurable
  {
    name: 'GPTBot',
    pattern: /GPTBot/i,
    category: 'ai_crawler',
    allowed: false,
    description: 'OpenAI GPT training crawler',
  },
  {
    name: 'ChatGPT-User',
    pattern: /ChatGPT-User/i,
    category: 'ai_crawler',
    allowed: false,
    description: 'ChatGPT user browsing',
  },
  {
    name: 'Claude-Web',
    pattern: /Claude-Web|ClaudeBot|anthropic-ai/i,
    category: 'ai_crawler',
    allowed: false,
    description: 'Anthropic Claude crawler',
  },
  {
    name: 'Bytespider',
    pattern: /Bytespider/i,
    category: 'ai_crawler',
    allowed: false,
    description: 'ByteDance AI crawler',
  },
  {
    name: 'CCBot',
    pattern: /CCBot/i,
    category: 'ai_crawler',
    allowed: false,
    description: 'Common Crawl bot',
  },
  {
    name: 'Google-Extended',
    pattern: /Google-Extended/i,
    category: 'ai_crawler',
    allowed: false,
    description: 'Google AI training crawler',
  },
  {
    name: 'Cohere-ai',
    pattern: /cohere-ai/i,
    category: 'ai_crawler',
    allowed: false,
    description: 'Cohere AI crawler',
  },
  {
    name: 'PerplexityBot',
    pattern: /PerplexityBot/i,
    category: 'ai_crawler',
    allowed: false,
    description: 'Perplexity AI crawler',
  },

  // Feed Readers - Generally allowed
  {
    name: 'Feedly',
    pattern: /Feedly/i,
    category: 'feed_reader',
    allowed: true,
    description: 'Feedly RSS reader',
  },
  {
    name: 'Feedbin',
    pattern: /Feedbin/i,
    category: 'feed_reader',
    allowed: true,
    description: 'Feedbin RSS reader',
  },
  {
    name: 'NewsBlur',
    pattern: /NewsBlur/i,
    category: 'feed_reader',
    allowed: true,
    description: 'NewsBlur RSS reader',
  },

  // Link Previews - Generally allowed
  {
    name: 'Embedly',
    pattern: /Embedly/i,
    category: 'preview',
    allowed: true,
    description: 'Embedly link preview',
  },
  {
    name: 'Iframely',
    pattern: /Iframely/i,
    category: 'preview',
    allowed: true,
    description: 'Iframely link preview',
  },

  // Security Scanners - Block by default
  {
    name: 'Nessus',
    pattern: /Nessus/i,
    category: 'security',
    allowed: false,
    description: 'Nessus vulnerability scanner',
  },
  {
    name: 'Nikto',
    pattern: /Nikto/i,
    category: 'security',
    allowed: false,
    description: 'Nikto web scanner',
  },
  {
    name: 'sqlmap',
    pattern: /sqlmap/i,
    category: 'security',
    allowed: false,
    description: 'sqlmap SQL injection tool',
  },
  {
    name: 'WPScan',
    pattern: /WPScan/i,
    category: 'security',
    allowed: false,
    description: 'WordPress vulnerability scanner',
  },
  {
    name: 'Acunetix',
    pattern: /Acunetix/i,
    category: 'security',
    allowed: false,
    description: 'Acunetix vulnerability scanner',
  },

  // Known Scrapers - Block
  {
    name: 'Scrapy',
    pattern: /Scrapy/i,
    category: 'scraper',
    allowed: false,
    description: 'Scrapy web scraper',
  },
  {
    name: 'HTTrack',
    pattern: /HTTrack/i,
    category: 'scraper',
    allowed: false,
    description: 'HTTrack website copier',
  },
  {
    name: 'WebCopier',
    pattern: /WebCopier/i,
    category: 'scraper',
    allowed: false,
    description: 'WebCopier tool',
  },
  {
    name: 'SiteSnagger',
    pattern: /SiteSnagger/i,
    category: 'scraper',
    allowed: false,
    description: 'SiteSnagger downloader',
  },

  // Spam Bots - Always block
  {
    name: 'Spam Bot',
    pattern: /spam|harvester|extractor|collect/i,
    category: 'spam',
    allowed: false,
    description: 'Generic spam bot pattern',
  },
  {
    name: 'Email Harvester',
    pattern: /email.*harvest|harvest.*email/i,
    category: 'spam',
    allowed: false,
    description: 'Email harvesting bot',
  },

  // Malicious - Always block
  {
    name: 'Malicious Generic',
    pattern: /masscan|ZmEu|morfeus|nmap/i,
    category: 'malicious',
    allowed: false,
    description: 'Known malicious tools',
  },
  {
    name: 'Vulnerability Scanner',
    pattern: /havij|w3af|webscarab/i,
    category: 'malicious',
    allowed: false,
    description: 'Vulnerability scanning tools',
  },

  // Generic Bot Pattern
  {
    name: 'Generic Bot',
    pattern: /bot|crawl|spider|scrape|fetch/i,
    category: 'unknown',
    allowed: false,
    description: 'Generic bot pattern',
  },
  {
    name: 'HTTP Library',
    pattern: /python-requests|python-urllib|curl|wget|axios|node-fetch|got\//i,
    category: 'unknown',
    allowed: false,
    description: 'HTTP library user agent',
  },
]

/**
 * Default allowed bot categories
 */
export const DEFAULT_ALLOWED_CATEGORIES: BotCategory[] = [
  'search_engine',
  'social_media',
  'monitoring',
  'feed_reader',
  'preview',
]

/**
 * Default allowed bot names
 */
export const DEFAULT_ALLOWED_BOTS: string[] = [
  'Googlebot',
  'Bingbot',
  'Yahoo Slurp',
  'DuckDuckBot',
  'Applebot',
  'Facebook',
  'Twitter',
  'LinkedIn',
  'Slack',
  'Discord',
  'UptimeRobot',
  'Pingdom',
]

// ============================================================================
// User-Agent Analyzer
// ============================================================================

/**
 * Analyze a User-Agent string for bot patterns
 */
export function analyzeUserAgent(
  userAgent: string | null,
  options: UserAgentOptions = {}
): BotDetectionResult {
  const {
    blockAllBots = false,
    allowCategories = DEFAULT_ALLOWED_CATEGORIES,
    allowList = DEFAULT_ALLOWED_BOTS,
    blockList = [],
    customPatterns = [],
    blockEmptyUA = true,
    blockSuspiciousUA = true,
  } = options

  // Empty User-Agent check
  if (!userAgent || userAgent.trim() === '') {
    return {
      isBot: blockEmptyUA,
      category: 'unknown',
      confidence: blockEmptyUA ? 0.9 : 0,
      reason: 'Empty User-Agent',
      userAgent: userAgent || '',
    }
  }

  // Combine built-in and custom patterns
  const allPatterns = [...customPatterns, ...KNOWN_BOT_PATTERNS]

  // First, check if it matches any known bot pattern
  // This takes priority over suspicious UA checks
  let matchedPattern: BotPattern | null = null
  for (const pattern of allPatterns) {
    if (pattern.pattern.test(userAgent)) {
      matchedPattern = pattern
      break
    }
  }

  // If no known pattern matched, check for suspicious UA
  if (!matchedPattern && blockSuspiciousUA && isSuspiciousUA(userAgent)) {
    return {
      isBot: true,
      category: 'unknown',
      confidence: 0.8,
      reason: 'Suspicious User-Agent pattern',
      userAgent,
    }
  }

  // If no pattern matched at all, it's likely a real browser
  if (!matchedPattern) {
    return {
      isBot: false,
      confidence: 0.1,
      reason: 'No bot pattern matched',
      userAgent,
    }
  }

  // We have a matched pattern, apply the rules

  // Check if explicitly blocked (highest priority)
  if (blockList.includes(matchedPattern.name)) {
    return {
      isBot: true,
      category: matchedPattern.category,
      name: matchedPattern.name,
      confidence: 0.95,
      reason: `Blocked bot: ${matchedPattern.name}`,
      userAgent,
    }
  }

  // Block all bots mode (takes priority over allow lists)
  if (blockAllBots) {
    return {
      isBot: true,
      category: matchedPattern.category,
      name: matchedPattern.name,
      confidence: 0.9,
      reason: `Bot blocked (blockAllBots mode): ${matchedPattern.name}`,
      userAgent,
    }
  }

  // Check if explicitly allowed
  if (allowList.includes(matchedPattern.name)) {
    return {
      isBot: true,
      category: matchedPattern.category,
      name: matchedPattern.name,
      confidence: 0.95,
      reason: `Allowed bot: ${matchedPattern.name}`,
      userAgent,
    }
  }

  // Check category allowlist
  if (allowCategories.includes(matchedPattern.category)) {
    return {
      isBot: true,
      category: matchedPattern.category,
      name: matchedPattern.name,
      confidence: 0.9,
      reason: `Allowed category: ${matchedPattern.category}`,
      userAgent,
    }
  }

  // Pattern's default behavior
  return {
    isBot: true,
    category: matchedPattern.category,
    name: matchedPattern.name,
    confidence: 0.85,
    reason: matchedPattern.allowed
      ? `Allowed bot: ${matchedPattern.name}`
      : `Blocked bot: ${matchedPattern.name}`,
    userAgent,
  }
}

/**
 * Check if User-Agent appears suspicious
 */
export function isSuspiciousUA(userAgent: string): boolean {
  // Too short
  if (userAgent.length < 10) {
    return true
  }

  // Only numbers or random characters
  if (/^[0-9a-f]{8,}$/i.test(userAgent)) {
    return true
  }

  // Missing typical browser indicators
  const hasBrowserIndicator = /Mozilla|Chrome|Safari|Firefox|Edge|Opera|MSIE|Trident/i.test(userAgent)
  const hasOSIndicator = /Windows|Mac|Linux|Android|iOS|iPhone|iPad/i.test(userAgent)

  // If it looks like a browser but missing OS, it's suspicious
  if (hasBrowserIndicator && !hasOSIndicator && userAgent.length < 50) {
    return true
  }

  // Very old or fake versions
  if (/Chrome\/[0-4]\./i.test(userAgent) || /Firefox\/[0-3]\./i.test(userAgent)) {
    return true
  }

  return false
}

/**
 * Check if a specific bot is allowed
 */
export function isBotAllowed(
  botName: string,
  options: UserAgentOptions = {}
): boolean {
  const {
    blockAllBots = false,
    allowCategories = DEFAULT_ALLOWED_CATEGORIES,
    allowList = DEFAULT_ALLOWED_BOTS,
    blockList = [],
  } = options

  // Explicitly blocked (highest priority)
  if (blockList.includes(botName)) {
    return false
  }

  // Block all mode (takes priority over allow lists)
  if (blockAllBots) {
    return false
  }

  // Explicitly allowed
  if (allowList.includes(botName)) {
    return true
  }

  // Check category
  const pattern = KNOWN_BOT_PATTERNS.find(p => p.name === botName)
  if (pattern && allowCategories.includes(pattern.category)) {
    return true
  }

  // Default to pattern's setting
  return pattern?.allowed ?? false
}

/**
 * Get all known bot patterns for a category
 */
export function getBotsByCategory(category: BotCategory): BotPattern[] {
  return KNOWN_BOT_PATTERNS.filter(p => p.category === category)
}

/**
 * Create a custom bot pattern
 */
export function createBotPattern(
  name: string,
  pattern: RegExp | string,
  category: BotCategory,
  allowed: boolean = false,
  description?: string
): BotPattern {
  return {
    name,
    pattern: typeof pattern === 'string' ? new RegExp(pattern, 'i') : pattern,
    category,
    allowed,
    description,
  }
}
