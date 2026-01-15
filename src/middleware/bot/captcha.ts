/**
 * CAPTCHA Integration for Bot Detection
 * @module nextjs-secure/bot
 *
 * Supports:
 * - Google reCAPTCHA v2 & v3
 * - hCaptcha
 * - Cloudflare Turnstile
 */

import type { NextRequest } from 'next/server'
import type { CaptchaOptions, CaptchaResult, CaptchaProvider, BotDetectionResult } from './types'

// ============================================================================
// CAPTCHA Verification URLs
// ============================================================================

const CAPTCHA_VERIFY_URLS: Record<CaptchaProvider, string> = {
  recaptcha: 'https://www.google.com/recaptcha/api/siteverify',
  hcaptcha: 'https://hcaptcha.com/siteverify',
  turnstile: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
}

/**
 * Default token field names per provider
 */
const DEFAULT_TOKEN_FIELDS: Record<CaptchaProvider, string> = {
  recaptcha: 'g-recaptcha-response',
  hcaptcha: 'h-captcha-response',
  turnstile: 'cf-turnstile-response',
}

// ============================================================================
// CAPTCHA Verification
// ============================================================================

/**
 * Verify CAPTCHA token with provider
 */
export async function verifyCaptcha(
  token: string,
  options: CaptchaOptions
): Promise<CaptchaResult> {
  const { provider, secretKey, action } = options

  const verifyUrl = CAPTCHA_VERIFY_URLS[provider]

  // Build form data
  const formData = new URLSearchParams()
  formData.append('secret', secretKey)
  formData.append('response', token)

  try {
    const response = await fetch(verifyUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData.toString(),
    })

    if (!response.ok) {
      return {
        success: false,
        errorCodes: [`HTTP ${response.status}`],
      }
    }

    const data = await response.json()

    // Parse response based on provider
    return parseCaptchaResponse(data, provider, action)
  } catch (error) {
    return {
      success: false,
      errorCodes: ['verification-failed', String(error)],
    }
  }
}

/**
 * Parse CAPTCHA verification response
 */
function parseCaptchaResponse(
  data: Record<string, unknown>,
  provider: CaptchaProvider,
  expectedAction?: string
): CaptchaResult {
  switch (provider) {
    case 'recaptcha':
      return parseRecaptchaResponse(data, expectedAction)
    case 'hcaptcha':
      return parseHCaptchaResponse(data)
    case 'turnstile':
      return parseTurnstileResponse(data)
    default:
      return {
        success: false,
        errorCodes: ['unknown-provider'],
      }
  }
}

/**
 * Parse reCAPTCHA response
 */
function parseRecaptchaResponse(
  data: Record<string, unknown>,
  expectedAction?: string
): CaptchaResult {
  const result: CaptchaResult = {
    success: data.success === true,
    score: typeof data.score === 'number' ? data.score : undefined,
    action: typeof data.action === 'string' ? data.action : undefined,
    hostname: typeof data.hostname === 'string' ? data.hostname : undefined,
    challengeTs: typeof data.challenge_ts === 'string' ? data.challenge_ts : undefined,
    errorCodes: Array.isArray(data['error-codes']) ? data['error-codes'] as string[] : undefined,
  }

  // For reCAPTCHA v3, verify action matches if specified
  if (result.success && expectedAction && result.action !== expectedAction) {
    result.success = false
    result.errorCodes = ['action-mismatch']
  }

  return result
}

/**
 * Parse hCaptcha response
 */
function parseHCaptchaResponse(data: Record<string, unknown>): CaptchaResult {
  return {
    success: data.success === true,
    hostname: typeof data.hostname === 'string' ? data.hostname : undefined,
    challengeTs: typeof data.challenge_ts === 'string' ? data.challenge_ts : undefined,
    errorCodes: Array.isArray(data['error-codes']) ? data['error-codes'] as string[] : undefined,
  }
}

/**
 * Parse Turnstile response
 */
function parseTurnstileResponse(data: Record<string, unknown>): CaptchaResult {
  return {
    success: data.success === true,
    hostname: typeof data.hostname === 'string' ? data.hostname : undefined,
    challengeTs: typeof data.challenge_ts === 'string' ? data.challenge_ts : undefined,
    action: typeof data.action === 'string' ? data.action : undefined,
    errorCodes: Array.isArray(data['error-codes']) ? data['error-codes'] as string[] : undefined,
  }
}

// ============================================================================
// CAPTCHA Token Extraction
// ============================================================================

/**
 * Extract CAPTCHA token from request
 */
export async function extractCaptchaToken(
  req: NextRequest,
  options: CaptchaOptions
): Promise<string | null> {
  const { provider, tokenField } = options
  const fieldName = tokenField || DEFAULT_TOKEN_FIELDS[provider]

  // Try query parameters first
  const url = new URL(req.url)
  const queryToken = url.searchParams.get(fieldName)
  if (queryToken) {
    return queryToken
  }

  // Try request body
  if (hasBody(req)) {
    try {
      const body = await getRequestBody(req)
      if (body && typeof body === 'object') {
        const bodyToken = (body as Record<string, unknown>)[fieldName]
        if (typeof bodyToken === 'string') {
          return bodyToken
        }
      }
    } catch {
      // Ignore body parsing errors
    }
  }

  // Try headers
  const headerToken = req.headers.get(`x-${fieldName}`)
  if (headerToken) {
    return headerToken
  }

  return null
}

// ============================================================================
// CAPTCHA Check
// ============================================================================

/**
 * Check CAPTCHA and return bot detection result
 */
export async function checkCaptcha(
  req: NextRequest,
  options: CaptchaOptions
): Promise<BotDetectionResult> {
  const { threshold = 0.5, skip } = options

  // Check skip condition
  if (skip && await skip(req)) {
    return {
      isBot: false,
      confidence: 0,
      reason: 'CAPTCHA check skipped',
    }
  }

  // Extract token
  const token = await extractCaptchaToken(req, options)

  if (!token) {
    return {
      isBot: true,
      confidence: 0.9,
      reason: 'CAPTCHA token missing',
      ip: getClientIP(req),
    }
  }

  // Verify token
  const result = await verifyCaptcha(token, options)

  if (!result.success) {
    return {
      isBot: true,
      confidence: 0.95,
      reason: `CAPTCHA verification failed: ${result.errorCodes?.join(', ') || 'unknown'}`,
      ip: getClientIP(req),
    }
  }

  // For reCAPTCHA v3, check score threshold
  if (result.score !== undefined && result.score < threshold) {
    return {
      isBot: true,
      confidence: 1 - result.score,
      reason: `CAPTCHA score too low: ${result.score} (threshold: ${threshold})`,
      ip: getClientIP(req),
    }
  }

  return {
    isBot: false,
    confidence: result.score !== undefined ? 1 - result.score : 0.1,
    reason: 'CAPTCHA verification passed',
  }
}

// ============================================================================
// CAPTCHA Middleware
// ============================================================================

/**
 * Create CAPTCHA verification middleware
 */
export function withCaptcha<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: CaptchaOptions
): (req: NextRequest, ctx: T) => Promise<Response> {
  return async (req: NextRequest, ctx: T): Promise<Response> => {
    const result = await checkCaptcha(req, options)

    if (result.isBot) {
      return new Response(
        JSON.stringify({
          error: 'CAPTCHA Required',
          message: result.reason,
          code: 'CAPTCHA_FAILED',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }

    return handler(req, ctx)
  }
}

// ============================================================================
// CAPTCHA HTML Generators
// ============================================================================

/**
 * Generate reCAPTCHA v2 checkbox HTML
 */
export function generateRecaptchaV2(siteKey: string, options: {
  theme?: 'light' | 'dark'
  size?: 'normal' | 'compact'
} = {}): string {
  const { theme = 'light', size = 'normal' } = options

  return `
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<div class="g-recaptcha" data-sitekey="${siteKey}" data-theme="${theme}" data-size="${size}"></div>
`.trim()
}

/**
 * Generate reCAPTCHA v3 HTML
 */
export function generateRecaptchaV3(siteKey: string, action: string = 'submit'): string {
  return `
<script src="https://www.google.com/recaptcha/api.js?render=${siteKey}"></script>
<script>
  function getRecaptchaToken() {
    return new Promise((resolve, reject) => {
      grecaptcha.ready(() => {
        grecaptcha.execute('${siteKey}', { action: '${action}' })
          .then(resolve)
          .catch(reject);
      });
    });
  }
</script>
`.trim()
}

/**
 * Generate hCaptcha HTML
 */
export function generateHCaptcha(siteKey: string, options: {
  theme?: 'light' | 'dark'
  size?: 'normal' | 'compact'
} = {}): string {
  const { theme = 'light', size = 'normal' } = options

  return `
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<div class="h-captcha" data-sitekey="${siteKey}" data-theme="${theme}" data-size="${size}"></div>
`.trim()
}

/**
 * Generate Cloudflare Turnstile HTML
 */
export function generateTurnstile(siteKey: string, options: {
  theme?: 'light' | 'dark' | 'auto'
  size?: 'normal' | 'compact'
} = {}): string {
  const { theme = 'auto', size = 'normal' } = options

  return `
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<div class="cf-turnstile" data-sitekey="${siteKey}" data-theme="${theme}" data-size="${size}"></div>
`.trim()
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
 * Get request body
 */
async function getRequestBody(req: NextRequest): Promise<unknown> {
  try {
    const contentType = req.headers.get('content-type') || ''

    if (contentType.includes('application/json')) {
      const cloned = req.clone()
      return await cloned.json()
    }

    if (contentType.includes('application/x-www-form-urlencoded')) {
      const cloned = req.clone()
      const text = await cloned.text()
      return Object.fromEntries(new URLSearchParams(text))
    }

    if (contentType.includes('multipart/form-data')) {
      const cloned = req.clone()
      const formData = await cloned.formData()
      const obj: Record<string, unknown> = {}
      formData.forEach((value, key) => {
        obj[key] = value
      })
      return obj
    }

    return null
  } catch {
    return null
  }
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
