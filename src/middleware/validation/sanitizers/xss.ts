import type { SanitizeConfig } from '../types'

/**
 * Default allowed tags for 'allow-safe' mode
 */
const DEFAULT_ALLOWED_TAGS = [
  'a', 'abbr', 'b', 'blockquote', 'br', 'code', 'del', 'em', 'h1', 'h2', 'h3',
  'h4', 'h5', 'h6', 'hr', 'i', 'ins', 'li', 'mark', 'ol', 'p', 'pre', 'q',
  's', 'small', 'span', 'strong', 'sub', 'sup', 'u', 'ul',
]

/**
 * Default allowed attributes per tag
 */
const DEFAULT_ALLOWED_ATTRIBUTES: Record<string, string[]> = {
  a: ['href', 'title', 'target', 'rel'],
  img: ['src', 'alt', 'title', 'width', 'height'],
  abbr: ['title'],
  q: ['cite'],
  blockquote: ['cite'],
}

/**
 * Safe protocols for URLs
 */
const DEFAULT_SAFE_PROTOCOLS = ['http:', 'https:', 'mailto:', 'tel:']

/**
 * Dangerous patterns to detect
 */
const DANGEROUS_PATTERNS = [
  // Event handlers
  /\bon\w+\s*=/gi,
  // JavaScript protocol
  /javascript\s*:/gi,
  // VBScript protocol
  /vbscript\s*:/gi,
  // Data URI with scripts
  /data\s*:[^,]*(?:text\/html|application\/javascript|text\/javascript)/gi,
  // Expression in CSS
  /expression\s*\(/gi,
  // Binding in CSS (Firefox)
  /-moz-binding\s*:/gi,
  // Behavior in CSS (IE)
  /behavior\s*:/gi,
  // Import in CSS
  /@import/gi,
  // Script tags
  /<\s*script/gi,
  // Style tags with expressions
  /<\s*style[^>]*>[^<]*expression/gi,
  // SVG with scripts
  /<\s*svg[^>]*onload/gi,
  // Object/embed/applet tags
  /<\s*(object|embed|applet)/gi,
  // Base tag (can redirect resources)
  /<\s*base/gi,
  // Meta refresh
  /<\s*meta[^>]*http-equiv\s*=\s*["']?refresh/gi,
  // Form action hijacking
  /<\s*form[^>]*action\s*=\s*["']?javascript/gi,
  // Link tag with import
  /<\s*link[^>]*rel\s*=\s*["']?import/gi,
]

/**
 * HTML entities map
 */
const HTML_ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;',
}

/**
 * Escape HTML special characters
 */
export function escapeHtml(str: string): string {
  return str.replace(/[&<>"'`=/]/g, char => HTML_ENTITIES[char] || char)
}

/**
 * Unescape HTML entities
 */
export function unescapeHtml(str: string): string {
  const entityMap: Record<string, string> = {
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&#x27;': "'",
    '&#x2F;': '/',
    '&#x60;': '`',
    '&#x3D;': '=',
    '&#39;': "'",
    '&#47;': '/',
  }

  return str.replace(/&(?:amp|lt|gt|quot|#x27|#x2F|#x60|#x3D|#39|#47);/gi, entity => {
    return entityMap[entity.toLowerCase()] || entity
  })
}

/**
 * Strip all HTML tags
 */
export function stripHtml(str: string): string {
  // Remove script and style content completely
  let result = str.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
  result = result.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')

  // Remove all HTML tags
  result = result.replace(/<[^>]*>/g, '')

  // Decode entities
  result = unescapeHtml(result)

  // Remove null bytes
  result = result.replace(/\0/g, '')

  return result.trim()
}

/**
 * Check if a URL is safe
 */
export function isSafeUrl(url: string, allowedProtocols: string[] = DEFAULT_SAFE_PROTOCOLS): boolean {
  if (!url) return true

  // Normalize
  const trimmed = url.trim().toLowerCase()

  // Check for dangerous protocols
  if (trimmed.startsWith('javascript:')) return false
  if (trimmed.startsWith('vbscript:')) return false

  // Allow data:image URLs (commonly used for base64 images)
  if (trimmed.startsWith('data:image/')) return true

  // Block other data URLs
  if (trimmed.startsWith('data:')) return false

  // Check if protocol is allowed
  try {
    const parsed = new URL(url, 'https://example.com')
    if (parsed.protocol && !allowedProtocols.includes(parsed.protocol)) {
      // Allow relative URLs
      if (!url.includes(':')) return true
      return false
    }
  } catch {
    // Relative URL, allow
    return true
  }

  return true
}

/**
 * Sanitize HTML with allowed tags
 */
export function sanitizeHtml(
  str: string,
  allowedTags: string[] = DEFAULT_ALLOWED_TAGS,
  allowedAttributes: Record<string, string[]> = DEFAULT_ALLOWED_ATTRIBUTES,
  allowedProtocols: string[] = DEFAULT_SAFE_PROTOCOLS
): string {
  // Remove null bytes first
  let result = str.replace(/\0/g, '')

  // Remove script and style content completely
  result = result.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
  result = result.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')

  // Remove comments
  result = result.replace(/<!--[\s\S]*?-->/g, '')

  // Process tags
  result = result.replace(/<\/?([a-z][a-z0-9]*)\b([^>]*)>/gi, (match, tagName, attributes) => {
    const lowerTag = tagName.toLowerCase()
    const isClosing = match.startsWith('</')

    // Check if tag is allowed
    if (!allowedTags.includes(lowerTag)) {
      return ''
    }

    if (isClosing) {
      return `</${lowerTag}>`
    }

    // Process attributes
    const allowedAttrs = allowedAttributes[lowerTag] || []
    const safeAttrs: string[] = []

    // Parse attributes
    const attrRegex = /([a-z][a-z0-9-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*))/gi
    let attrMatch

    while ((attrMatch = attrRegex.exec(attributes)) !== null) {
      const attrName = attrMatch[1].toLowerCase()
      const attrValue = attrMatch[2] || attrMatch[3] || attrMatch[4] || ''

      // Check if attribute is allowed
      if (!allowedAttrs.includes(attrName)) continue

      // Check for dangerous patterns in value
      if (DANGEROUS_PATTERNS.some(pattern => pattern.test(attrValue))) continue

      // Check URL attributes
      if (['href', 'src', 'action', 'formaction'].includes(attrName)) {
        if (!isSafeUrl(attrValue, allowedProtocols)) continue
      }

      // Escape attribute value
      const safeValue = escapeHtml(attrValue)
      safeAttrs.push(`${attrName}="${safeValue}"`)
    }

    const attrStr = safeAttrs.length > 0 ? ' ' + safeAttrs.join(' ') : ''
    return `<${lowerTag}${attrStr}>`
  })

  // Final check for any remaining dangerous patterns
  for (const pattern of DANGEROUS_PATTERNS) {
    result = result.replace(pattern, '')
  }

  return result
}

/**
 * Detect if string contains potential XSS
 */
export function detectXSS(str: string): boolean {
  if (!str || typeof str !== 'string') return false

  // Normalize
  const normalized = str
    .replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);?/gi, (_, dec) => String.fromCharCode(parseInt(dec, 10)))

  // Reset lastIndex for global regexes before testing
  for (const pattern of DANGEROUS_PATTERNS) {
    pattern.lastIndex = 0
    if (pattern.test(normalized)) {
      return true
    }
  }

  return false
}

/**
 * Main sanitize function
 */
export function sanitize(input: string, config: SanitizeConfig = {}): string {
  if (!input || typeof input !== 'string') return ''

  const {
    mode = 'escape',
    allowedTags = DEFAULT_ALLOWED_TAGS,
    allowedAttributes = DEFAULT_ALLOWED_ATTRIBUTES,
    allowedProtocols = DEFAULT_SAFE_PROTOCOLS,
    maxLength,
    stripNull = true,
  } = config

  let result = input

  // Strip null bytes
  if (stripNull) {
    result = result.replace(/\0/g, '')
  }

  // Apply sanitization based on mode
  switch (mode) {
    case 'escape':
      result = escapeHtml(result)
      break

    case 'strip':
      result = stripHtml(result)
      break

    case 'allow-safe':
      result = sanitizeHtml(result, allowedTags, allowedAttributes, allowedProtocols)
      break
  }

  // Apply max length
  if (maxLength !== undefined && result.length > maxLength) {
    result = result.slice(0, maxLength)
  }

  return result
}

/**
 * Sanitize object values recursively
 */
export function sanitizeObject<T>(obj: T, config: SanitizeConfig = {}): T {
  if (typeof obj === 'string') {
    return sanitize(obj, config) as T
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, config)) as T
  }

  if (typeof obj === 'object' && obj !== null) {
    const result: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj)) {
      result[key] = sanitizeObject(value, config)
    }
    return result as T
  }

  return obj
}

/**
 * Sanitize specific fields in an object
 */
export function sanitizeFields<T extends Record<string, unknown>>(
  obj: T,
  fields: string[],
  config: SanitizeConfig = {}
): T {
  const result = { ...obj }

  for (const field of fields) {
    if (field in result && typeof result[field] === 'string') {
      (result as Record<string, unknown>)[field] = sanitize(result[field] as string, config)
    }
  }

  return result
}
