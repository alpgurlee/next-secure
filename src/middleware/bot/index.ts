/**
 * Bot Detection Module
 * @module nextjs-secure/bot
 *
 * Provides comprehensive bot detection and protection:
 * - User-Agent analysis with 50+ known bot patterns
 * - Honeypot fields for form spam protection
 * - Behavior analysis for detecting automated requests
 * - CAPTCHA integration (reCAPTCHA, hCaptcha, Turnstile)
 */

// Types
export type {
  BotCategory,
  BotDetectionResult,
  BotPattern,
  UserAgentOptions,
  HoneypotOptions,
  BehaviorOptions,
  BehaviorStore,
  RequestRecord,
  BehaviorAnalysisResult,
  CaptchaProvider,
  CaptchaOptions,
  CaptchaResult,
  ChallengeType,
  ChallengeOptions,
  BotProtectionOptions,
  BotContext,
  BotProtectedHandler,
} from './types'

// User-Agent Analysis
export {
  KNOWN_BOT_PATTERNS,
  DEFAULT_ALLOWED_CATEGORIES,
  DEFAULT_ALLOWED_BOTS,
  analyzeUserAgent,
  isSuspiciousUA,
  isBotAllowed,
  getBotsByCategory,
  createBotPattern,
} from './user-agent'

// Honeypot
export {
  DEFAULT_HONEYPOT_FIELDS,
  DEFAULT_HONEYPOT_OPTIONS,
  checkHoneypot,
  withHoneypot,
  generateHoneypotHTML,
  generateHoneypotCSS,
} from './honeypot'

// Behavior Analysis
export {
  DEFAULT_BEHAVIOR_OPTIONS,
  MemoryBehaviorStore,
  analyzeBehavior,
  checkBehavior,
  getGlobalBehaviorStore,
  withBehaviorAnalysis,
} from './behavior'

// CAPTCHA
export {
  verifyCaptcha,
  extractCaptchaToken,
  checkCaptcha,
  withCaptcha,
  generateRecaptchaV2,
  generateRecaptchaV3,
  generateHCaptcha,
  generateTurnstile,
} from './captcha'

// Main Middleware
export {
  detectBot,
  withBotProtection,
  withUserAgentProtection,
  withHoneypotProtection,
  withBehaviorProtection,
  withCaptchaProtection,
  BOT_PROTECTION_PRESETS,
  withBotProtectionPreset,
} from './middleware'
