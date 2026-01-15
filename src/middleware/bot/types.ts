/**
 * Bot Detection Types
 * @module nextjs-secure/bot
 */

import type { NextRequest } from 'next/server'

// ============================================================================
// Bot Categories
// ============================================================================

/**
 * Bot classification categories
 */
export type BotCategory =
  | 'search_engine'      // Google, Bing, Yahoo, etc.
  | 'social_media'       // Facebook, Twitter, LinkedIn crawlers
  | 'monitoring'         // Uptime monitors, health checkers
  | 'seo'                // SEO tools like Ahrefs, Semrush
  | 'ai_crawler'         // ChatGPT, Claude, AI training crawlers
  | 'feed_reader'        // RSS readers
  | 'preview'            // Link preview generators
  | 'security'           // Security scanners
  | 'scraper'            // Known scrapers
  | 'spam'               // Known spam bots
  | 'malicious'          // Malicious bots
  | 'unknown'            // Unknown bot pattern

/**
 * Bot detection result
 */
export interface BotDetectionResult {
  isBot: boolean
  category?: BotCategory
  name?: string
  confidence: number  // 0-1
  reason?: string
  userAgent?: string
  ip?: string
}

// ============================================================================
// User-Agent Analysis
// ============================================================================

/**
 * Known bot pattern definition
 */
export interface BotPattern {
  name: string
  pattern: RegExp
  category: BotCategory
  allowed: boolean
  description?: string
}

/**
 * User-Agent analysis options
 */
export interface UserAgentOptions {
  /**
   * Block all detected bots
   * @default false
   */
  blockAllBots?: boolean

  /**
   * Allow specific bot categories
   * @default ['search_engine', 'social_media', 'monitoring']
   */
  allowCategories?: BotCategory[]

  /**
   * Allow specific bots by name
   * @default ['Googlebot', 'Bingbot', 'Slurp']
   */
  allowList?: string[]

  /**
   * Block specific bots by name (overrides allowList)
   */
  blockList?: string[]

  /**
   * Custom bot patterns
   */
  customPatterns?: BotPattern[]

  /**
   * Block empty user agents
   * @default true
   */
  blockEmptyUA?: boolean

  /**
   * Block suspicious user agents (very short, random strings)
   * @default true
   */
  blockSuspiciousUA?: boolean
}

// ============================================================================
// Honeypot
// ============================================================================

/**
 * Honeypot field configuration
 */
export interface HoneypotOptions {
  /**
   * Field name for the honeypot (should look like a real field)
   * @default '_hp_email'
   */
  fieldName?: string

  /**
   * Additional honeypot field names
   */
  additionalFields?: string[]

  /**
   * Check for honeypot in these sources
   * @default ['body', 'query']
   */
  checkIn?: ('body' | 'query' | 'headers')[]

  /**
   * Custom validation function
   */
  validate?: (value: unknown) => boolean
}

// ============================================================================
// Behavior Analysis
// ============================================================================

/**
 * Behavior analysis options
 */
export interface BehaviorOptions {
  /**
   * Minimum time between requests from same IP (ms)
   * @default 100
   */
  minRequestInterval?: number

  /**
   * Maximum requests per second from same IP
   * @default 10
   */
  maxRequestsPerSecond?: number

  /**
   * Time window for behavior analysis (ms)
   * @default 60000 (1 minute)
   */
  windowMs?: number

  /**
   * Store for tracking request patterns
   */
  store?: BehaviorStore

  /**
   * Identifier function for grouping requests
   * @default IP-based
   */
  identifier?: (req: NextRequest) => string | Promise<string>

  /**
   * Suspicious patterns to detect
   */
  patterns?: {
    /**
     * Detect sequential URL access patterns
     * @default true
     */
    sequentialAccess?: boolean

    /**
     * Detect unusual request timing (too regular)
     * @default true
     */
    regularTiming?: boolean

    /**
     * Detect missing typical browser headers
     * @default true
     */
    missingHeaders?: boolean
  }
}

/**
 * Behavior tracking store interface
 */
export interface BehaviorStore {
  /**
   * Record a request
   */
  record(identifier: string, timestamp: number, path: string): Promise<void>

  /**
   * Get request history for an identifier
   */
  getHistory(identifier: string, windowMs: number): Promise<RequestRecord[]>

  /**
   * Clear old records
   */
  cleanup?(maxAge: number): Promise<void>
}

/**
 * Request record for behavior tracking
 */
export interface RequestRecord {
  timestamp: number
  path: string
}

/**
 * Behavior analysis result
 */
export interface BehaviorAnalysisResult {
  suspicious: boolean
  score: number  // 0-1 (1 = definitely bot)
  reasons: string[]
  requestCount: number
  avgInterval: number
}

// ============================================================================
// CAPTCHA
// ============================================================================

/**
 * Supported CAPTCHA providers
 */
export type CaptchaProvider = 'recaptcha' | 'hcaptcha' | 'turnstile'

/**
 * CAPTCHA verification options
 */
export interface CaptchaOptions {
  /**
   * CAPTCHA provider
   */
  provider: CaptchaProvider

  /**
   * Site key (public)
   */
  siteKey: string

  /**
   * Secret key (private)
   */
  secretKey: string

  /**
   * Minimum score threshold (for reCAPTCHA v3)
   * @default 0.5
   */
  threshold?: number

  /**
   * Field name for the CAPTCHA token
   * @default 'captchaToken' or provider-specific
   */
  tokenField?: string

  /**
   * Action name (for reCAPTCHA v3)
   */
  action?: string

  /**
   * Skip CAPTCHA for certain conditions
   */
  skip?: (req: NextRequest) => boolean | Promise<boolean>
}

/**
 * CAPTCHA verification result
 */
export interface CaptchaResult {
  success: boolean
  score?: number
  action?: string
  hostname?: string
  errorCodes?: string[]
  challengeTs?: string
}

// ============================================================================
// Challenge-Response
// ============================================================================

/**
 * Challenge types
 */
export type ChallengeType =
  | 'javascript'    // Requires JS execution
  | 'cookie'        // Requires cookie support
  | 'pow'           // Proof of work
  | 'redirect'      // Redirect challenge

/**
 * Challenge options
 */
export interface ChallengeOptions {
  /**
   * Challenge type
   * @default 'javascript'
   */
  type?: ChallengeType

  /**
   * Challenge difficulty (for PoW)
   * @default 4
   */
  difficulty?: number

  /**
   * Challenge expiry time (ms)
   * @default 300000 (5 minutes)
   */
  expiryMs?: number

  /**
   * Cookie name for challenge token
   * @default '__bot_challenge'
   */
  cookieName?: string

  /**
   * Secret for signing challenge tokens
   */
  secret?: string
}

// ============================================================================
// Main Bot Protection Options
// ============================================================================

/**
 * Combined bot protection options
 */
export interface BotProtectionOptions {
  /**
   * User-Agent analysis options
   */
  userAgent?: UserAgentOptions | boolean

  /**
   * Honeypot options
   */
  honeypot?: HoneypotOptions | boolean

  /**
   * Behavior analysis options
   */
  behavior?: BehaviorOptions | boolean

  /**
   * CAPTCHA options
   */
  captcha?: CaptchaOptions

  /**
   * Challenge-response options
   */
  challenge?: ChallengeOptions | boolean

  /**
   * Skip bot protection for certain conditions
   */
  skip?: (req: NextRequest) => boolean | Promise<boolean>

  /**
   * Custom response when bot is detected
   */
  onBot?: (req: NextRequest, result: BotDetectionResult) => Response | Promise<Response>

  /**
   * Log bot detections
   * @default false
   */
  log?: boolean | ((result: BotDetectionResult) => void)

  /**
   * Mode: 'block' blocks bots, 'detect' only detects
   * @default 'block'
   */
  mode?: 'block' | 'detect'
}

// ============================================================================
// Handler Types
// ============================================================================

/**
 * Extended context with bot detection info
 */
export interface BotContext {
  bot?: BotDetectionResult
}

/**
 * Bot-protected handler type
 */
export type BotProtectedHandler<T = unknown> = (
  req: NextRequest,
  ctx: T & BotContext
) => Response | Promise<Response>
