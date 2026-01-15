/**
 * Honeypot Protection for Bot Detection
 * @module nextjs-secure/bot
 */

import type { NextRequest } from 'next/server'
import type { HoneypotOptions, BotDetectionResult } from './types'

// ============================================================================
// Default Configuration
// ============================================================================

/**
 * Default honeypot field names that look legitimate
 */
export const DEFAULT_HONEYPOT_FIELDS = [
  '_hp_email',
  '_hp_name',
  '_hp_website',
  '_hp_phone',
  '_hp_address',
  'email_confirm',
  'website_url',
  'fax_number',
]

/**
 * Default honeypot options
 */
export const DEFAULT_HONEYPOT_OPTIONS: Required<Omit<HoneypotOptions, 'validate'>> & Pick<HoneypotOptions, 'validate'> = {
  fieldName: '_hp_email',
  additionalFields: [],
  checkIn: ['body', 'query'],
  validate: undefined,
}

// ============================================================================
// Honeypot Detection
// ============================================================================

/**
 * Check for honeypot field values in request
 */
export async function checkHoneypot(
  req: NextRequest,
  options: HoneypotOptions = {}
): Promise<BotDetectionResult> {
  const {
    fieldName = DEFAULT_HONEYPOT_OPTIONS.fieldName,
    additionalFields = DEFAULT_HONEYPOT_OPTIONS.additionalFields,
    checkIn = DEFAULT_HONEYPOT_OPTIONS.checkIn,
    validate,
  } = options

  const allFields = [fieldName, ...additionalFields]
  const filledFields: string[] = []

  // Check query parameters
  if (checkIn.includes('query')) {
    const url = new URL(req.url)
    for (const field of allFields) {
      const value = url.searchParams.get(field)
      if (value !== null && value !== '') {
        filledFields.push(`query:${field}`)
      }
    }
  }

  // Check request body (for POST/PUT/PATCH)
  if (checkIn.includes('body') && hasBody(req)) {
    try {
      const body = await getRequestBody(req)
      if (body && typeof body === 'object') {
        for (const field of allFields) {
          const value = (body as Record<string, unknown>)[field]
          if (value !== undefined && value !== null && value !== '') {
            // Custom validation if provided
            if (validate && !validate(value)) {
              continue
            }
            filledFields.push(`body:${field}`)
          }
        }
      }
    } catch {
      // Ignore body parsing errors
    }
  }

  // Check headers
  if (checkIn.includes('headers')) {
    for (const field of allFields) {
      const headerName = `x-${field.replace(/_/g, '-')}`
      const value = req.headers.get(headerName)
      if (value !== null && value !== '') {
        filledFields.push(`header:${headerName}`)
      }
    }
  }

  // Bot detected if any honeypot field is filled
  if (filledFields.length > 0) {
    return {
      isBot: true,
      category: 'spam',
      confidence: 0.95,
      reason: `Honeypot triggered: ${filledFields.join(', ')}`,
      ip: getClientIP(req),
    }
  }

  return {
    isBot: false,
    confidence: 0,
    reason: 'Honeypot check passed',
  }
}

// ============================================================================
// Honeypot Middleware
// ============================================================================

/**
 * Create honeypot middleware
 */
export function withHoneypot<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: HoneypotOptions = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  return async (req: NextRequest, ctx: T): Promise<Response> => {
    const result = await checkHoneypot(req, options)

    if (result.isBot) {
      // Return 403 but make it look like a success to confuse bots
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Request rejected',
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
// Honeypot HTML Generator
// ============================================================================

/**
 * Generate honeypot field HTML
 * These fields should be hidden with CSS, not display:none
 * Bots often ignore display:none but fill visible fields
 */
export function generateHoneypotHTML(options: HoneypotOptions = {}): string {
  const {
    fieldName = DEFAULT_HONEYPOT_OPTIONS.fieldName,
    additionalFields = [],
  } = options

  const allFields = [fieldName, ...additionalFields]

  const fields = allFields.map(field => {
    // Use various hiding techniques that bots might not detect
    const style = getRandomHidingStyle()
    const labelText = humanizeFieldName(field)

    return `
    <div style="${style}" aria-hidden="true" tabindex="-1">
      <label for="${field}">${labelText}</label>
      <input
        type="text"
        id="${field}"
        name="${field}"
        autocomplete="off"
        tabindex="-1"
      />
    </div>`
  }).join('\n')

  return `<!-- Honeypot fields - Do not fill these -->\n${fields}`
}

/**
 * Generate CSS for honeypot fields
 */
export function generateHoneypotCSS(options: HoneypotOptions = {}): string {
  const {
    fieldName = DEFAULT_HONEYPOT_OPTIONS.fieldName,
    additionalFields = [],
  } = options

  const allFields = [fieldName, ...additionalFields]
  const selectors = allFields.map(f => `#${f}`).join(', ')

  return `
/* Honeypot field hiding */
${selectors} {
  position: absolute !important;
  left: -9999px !important;
  top: -9999px !important;
  opacity: 0 !important;
  height: 0 !important;
  width: 0 !important;
  z-index: -1 !important;
  pointer-events: none !important;
}
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
 * Get request body (cached to avoid consuming stream)
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

/**
 * Get random hiding style to make detection harder
 */
function getRandomHidingStyle(): string {
  const styles = [
    'position: absolute; left: -9999px; top: -9999px;',
    'position: fixed; left: -100vw; visibility: hidden;',
    'opacity: 0; height: 0; width: 0; overflow: hidden;',
    'clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;',
    'transform: scale(0); position: absolute;',
  ]
  return styles[Math.floor(Math.random() * styles.length)]
}

/**
 * Convert field name to human-readable label
 */
function humanizeFieldName(field: string): string {
  return field
    .replace(/^_hp_/, '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
}
