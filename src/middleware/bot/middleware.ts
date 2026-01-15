/**
 * Bot Protection Middleware
 * @module nextjs-secure/bot
 *
 * Combined bot detection middleware that integrates:
 * - User-Agent analysis
 * - Honeypot fields
 * - Behavior analysis
 * - CAPTCHA verification
 */

import type { NextRequest } from 'next/server'
import type {
  BotProtectionOptions,
  BotDetectionResult,
  BotContext,
  UserAgentOptions,
  HoneypotOptions,
  BehaviorOptions,
  CaptchaOptions,
} from './types'
import { analyzeUserAgent, DEFAULT_ALLOWED_CATEGORIES, DEFAULT_ALLOWED_BOTS } from './user-agent'
import { checkHoneypot } from './honeypot'
import { checkBehavior, getGlobalBehaviorStore } from './behavior'
import { checkCaptcha } from './captcha'

// ============================================================================
// Default Bot Response
// ============================================================================

/**
 * Default response when bot is detected
 */
function defaultBotResponse(result: BotDetectionResult): Response {
  return new Response(
    JSON.stringify({
      error: 'Forbidden',
      message: result.reason || 'Request blocked',
      code: 'BOT_DETECTED',
      category: result.category,
    }),
    {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'X-Bot-Detection': 'true',
      },
    }
  )
}

// ============================================================================
// Combined Bot Detection
// ============================================================================

/**
 * Run all enabled bot detection checks
 */
export async function detectBot(
  req: NextRequest,
  options: BotProtectionOptions = {}
): Promise<BotDetectionResult> {
  const results: BotDetectionResult[] = []

  // 1. User-Agent analysis
  if (options.userAgent !== false) {
    const uaOptions: UserAgentOptions = options.userAgent === true ? {} : (options.userAgent || {})
    const userAgent = req.headers.get('user-agent')
    const uaResult = analyzeUserAgent(userAgent, uaOptions)

    // Only add if detected as bot AND not allowed
    if (uaResult.isBot && !isAllowedBot(uaResult, uaOptions)) {
      results.push(uaResult)
    }
  }

  // 2. Honeypot check (only for POST/PUT/PATCH)
  if (options.honeypot !== false && hasBody(req)) {
    const hpOptions: HoneypotOptions = options.honeypot === true ? {} : (options.honeypot || {})
    const hpResult = await checkHoneypot(req, hpOptions)
    if (hpResult.isBot) {
      results.push(hpResult)
    }
  }

  // 3. Behavior analysis
  if (options.behavior !== false) {
    const behaviorOptions: BehaviorOptions = options.behavior === true ? {} : (options.behavior || {})
    // Use global store if not provided
    if (!behaviorOptions.store) {
      behaviorOptions.store = getGlobalBehaviorStore()
    }
    const behaviorResult = await checkBehavior(req, behaviorOptions)
    if (behaviorResult.isBot) {
      results.push(behaviorResult)
    }
  }

  // 4. CAPTCHA verification (only if configured)
  if (options.captcha) {
    const captchaResult = await checkCaptcha(req, options.captcha)
    if (captchaResult.isBot) {
      results.push(captchaResult)
    }
  }

  // Combine results
  if (results.length === 0) {
    return {
      isBot: false,
      confidence: 0,
      reason: 'All checks passed',
      ip: getClientIP(req),
      userAgent: req.headers.get('user-agent') || undefined,
    }
  }

  // Find highest confidence result
  const highestConfidence = results.reduce((prev, curr) =>
    curr.confidence > prev.confidence ? curr : prev
  )

  // Combine all reasons
  const allReasons = results.map(r => r.reason).filter(Boolean).join('; ')

  return {
    isBot: true,
    category: highestConfidence.category,
    name: highestConfidence.name,
    confidence: highestConfidence.confidence,
    reason: allReasons,
    ip: getClientIP(req),
    userAgent: req.headers.get('user-agent') || undefined,
  }
}

/**
 * Check if a detected bot is allowed
 */
function isAllowedBot(result: BotDetectionResult, options: UserAgentOptions): boolean {
  const {
    allowCategories = DEFAULT_ALLOWED_CATEGORIES,
    allowList = DEFAULT_ALLOWED_BOTS,
    blockList = [],
    blockAllBots = false,
  } = options

  // Explicitly blocked
  if (result.name && blockList.includes(result.name)) {
    return false
  }

  // Block all mode
  if (blockAllBots) {
    return false
  }

  // Explicitly allowed by name
  if (result.name && allowList.includes(result.name)) {
    return true
  }

  // Allowed by category
  if (result.category && allowCategories.includes(result.category)) {
    return true
  }

  return false
}

// ============================================================================
// Main Bot Protection Middleware
// ============================================================================

/**
 * Create bot protection middleware
 *
 * @example
 * ```typescript
 * import { withBotProtection } from 'nextjs-secure/bot'
 *
 * export const POST = withBotProtection(handler, {
 *   userAgent: {
 *     blockAllBots: false,
 *     allowList: ['Googlebot', 'Bingbot'],
 *   },
 *   honeypot: {
 *     fieldName: '_hp_email',
 *   },
 *   behavior: {
 *     maxRequestsPerSecond: 10,
 *   },
 * })
 * ```
 */
export function withBotProtection<T = unknown>(
  handler: (req: NextRequest, ctx: T & BotContext) => Response | Promise<Response>,
  options: BotProtectionOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  const {
    skip,
    onBot,
    log,
    mode = 'block',
  } = options

  return async (req: NextRequest, ctx: T): Promise<Response> => {
    // Check skip condition
    if (skip && await skip(req)) {
      return handler(req, { ...ctx, bot: undefined })
    }

    // Run bot detection
    const result = await detectBot(req, options)

    // Log if enabled
    if (log) {
      if (typeof log === 'function') {
        log(result)
      } else if (result.isBot) {
        console.log('[Bot Detection]', JSON.stringify(result))
      }
    }

    // Handle bot detection
    if (result.isBot) {
      if (mode === 'block') {
        // Custom response handler
        if (onBot) {
          return onBot(req, result)
        }
        return defaultBotResponse(result)
      }
      // Detect mode - continue but add bot info to context
    }

    // Add bot info to context and continue
    const extendedCtx: T & BotContext = {
      ...ctx,
      bot: result,
    }

    return handler(req, extendedCtx)
  }
}

// ============================================================================
// Convenience Middleware Functions
// ============================================================================

/**
 * User-Agent only bot protection
 */
export function withUserAgentProtection<T = unknown>(
  handler: (req: NextRequest, ctx: T & BotContext) => Response | Promise<Response>,
  options: UserAgentOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  return withBotProtection(handler, {
    userAgent: options,
    honeypot: false,
    behavior: false,
  })
}

/**
 * Honeypot only protection
 */
export function withHoneypotProtection<T = unknown>(
  handler: (req: NextRequest, ctx: T & BotContext) => Response | Promise<Response>,
  options: HoneypotOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  return withBotProtection(handler, {
    userAgent: false,
    honeypot: options,
    behavior: false,
  })
}

/**
 * Behavior analysis only protection
 */
export function withBehaviorProtection<T = unknown>(
  handler: (req: NextRequest, ctx: T & BotContext) => Response | Promise<Response>,
  options: BehaviorOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  return withBotProtection(handler, {
    userAgent: false,
    honeypot: false,
    behavior: options,
  })
}

/**
 * CAPTCHA only protection
 */
export function withCaptchaProtection<T = unknown>(
  handler: (req: NextRequest, ctx: T & BotContext) => Response | Promise<Response>,
  options: CaptchaOptions
): (req: NextRequest, ctx: T) => Promise<Response> {
  return withBotProtection(handler, {
    userAgent: false,
    honeypot: false,
    behavior: false,
    captcha: options,
  })
}

// ============================================================================
// Preset Configurations
// ============================================================================

/**
 * Preset bot protection configurations
 */
export const BOT_PROTECTION_PRESETS = {
  /**
   * Relaxed - Only blocks obvious bots
   */
  relaxed: {
    userAgent: {
      blockAllBots: false,
      allowCategories: ['search_engine', 'social_media', 'monitoring', 'feed_reader', 'preview', 'seo'],
    },
    honeypot: false,
    behavior: false,
  } as BotProtectionOptions,

  /**
   * Standard - Good balance of protection
   */
  standard: {
    userAgent: {
      blockAllBots: false,
      allowCategories: ['search_engine', 'social_media', 'monitoring'],
    },
    honeypot: true,
    behavior: {
      maxRequestsPerSecond: 10,
    },
  } as BotProtectionOptions,

  /**
   * Strict - Maximum protection
   */
  strict: {
    userAgent: {
      blockAllBots: false,
      allowCategories: ['search_engine'],
      blockEmptyUA: true,
      blockSuspiciousUA: true,
    },
    honeypot: {
      additionalFields: ['_hp_name', '_hp_phone'],
    },
    behavior: {
      maxRequestsPerSecond: 5,
      minRequestInterval: 200,
    },
  } as BotProtectionOptions,

  /**
   * API - For API endpoints
   */
  api: {
    userAgent: {
      blockAllBots: true,
      blockEmptyUA: true,
    },
    honeypot: false,
    behavior: {
      maxRequestsPerSecond: 20,
    },
  } as BotProtectionOptions,
} as const

/**
 * Create bot protection with preset
 */
export function withBotProtectionPreset<T = unknown>(
  handler: (req: NextRequest, ctx: T & BotContext) => Response | Promise<Response>,
  preset: keyof typeof BOT_PROTECTION_PRESETS,
  overrides: BotProtectionOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  const presetOptions = BOT_PROTECTION_PRESETS[preset]
  const mergedOptions = { ...presetOptions, ...overrides }
  return withBotProtection(handler, mergedOptions)
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Check if request has a body
 */
function hasBody(req: NextRequest): boolean {
  const method = req.method.toUpperCase()
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
}

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
