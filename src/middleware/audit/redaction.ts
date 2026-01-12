import type { PIIConfig } from './types'

/**
 * Default PII fields to redact
 */
export const DEFAULT_PII_FIELDS = [
  // Authentication
  'password',
  'passwd',
  'secret',
  'token',
  'api_key',
  'apiKey',
  'api-key',
  'access_token',
  'accessToken',
  'refresh_token',
  'refreshToken',
  'authorization',
  'auth',

  // Personal information
  'ssn',
  'social_security',
  'socialSecurity',
  'credit_card',
  'creditCard',
  'card_number',
  'cardNumber',
  'cvv',
  'cvc',
  'pin',

  // Contact
  'email',
  'phone',
  'phone_number',
  'phoneNumber',
  'mobile',
  'address',
  'street',
  'zip',
  'zipcode',
  'postal_code',
  'postalCode',

  // Identity
  'date_of_birth',
  'dateOfBirth',
  'dob',
  'birth_date',
  'birthDate',
  'passport',
  'license',
  'national_id',
  'nationalId',
]

/**
 * Mask a value with asterisks
 */
export function mask(
  value: string,
  options: {
    char?: string
    preserveLength?: boolean
    showFirst?: number
    showLast?: number
  } = {}
): string {
  const {
    char = '*',
    preserveLength = false,
    showFirst = 0,
    showLast = 0,
  } = options

  if (!value) return value

  const len = value.length

  if (preserveLength) {
    const first = value.slice(0, showFirst)
    const last = value.slice(-showLast || len)
    const middle = char.repeat(Math.max(0, len - showFirst - showLast))
    return first + middle + (showLast > 0 ? last : '')
  }

  // Default: show first/last chars with fixed mask
  const maskLen = 8
  const first = showFirst > 0 ? value.slice(0, showFirst) : ''
  const last = showLast > 0 ? value.slice(-showLast) : ''

  return first + char.repeat(maskLen) + last
}

/**
 * Simple hash function for Edge Runtime compatibility
 * Uses a fast, deterministic string hash (not cryptographic)
 */
export function hash(value: string, salt = ''): string {
  const str = salt + value
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash // Convert to 32bit integer
  }
  // Convert to hex and ensure positive, pad to 16 chars
  const hex = Math.abs(hash).toString(16).padStart(8, '0')
  return hex + hex.slice(0, 8) // Return 16 char string
}

/**
 * Redact a single value
 */
export function redactValue(
  value: unknown,
  field: string,
  config: PIIConfig
): unknown {
  if (typeof value !== 'string') return value
  if (!value) return value

  // Check if field should be redacted
  const shouldRedact = config.fields.some(f => {
    const fieldLower = field.toLowerCase()
    const fLower = f.toLowerCase()
    return fieldLower === fLower ||
           fieldLower.endsWith('.' + fLower) ||
           fieldLower.includes('[' + fLower + ']')
  })

  if (!shouldRedact) return value

  // Apply custom redactor if provided
  if (config.customRedactor) {
    return config.customRedactor(value, field)
  }

  // Apply redaction based on mode
  switch (config.mode) {
    case 'mask':
      return mask(value, {
        char: config.maskChar || '*',
        preserveLength: config.preserveLength,
        showFirst: 2,
        showLast: 2,
      })

    case 'hash':
      return `[HASH:${hash(value)}]`

    case 'remove':
      return '[REDACTED]'

    default:
      return '[REDACTED]'
  }
}

/**
 * Redact PII from an object recursively
 */
export function redactObject<T>(obj: T, config: PIIConfig, path = ''): T {
  if (typeof obj === 'string') {
    return redactValue(obj, path, config) as T
  }

  if (Array.isArray(obj)) {
    return obj.map((item, i) => redactObject(item, config, `${path}[${i}]`)) as T
  }

  if (typeof obj === 'object' && obj !== null) {
    const result: Record<string, unknown> = {}

    for (const [key, value] of Object.entries(obj)) {
      const newPath = path ? `${path}.${key}` : key
      result[key] = redactObject(value, config, newPath)
    }

    return result as T
  }

  return obj
}

/**
 * Create a redactor function with preset config
 */
export function createRedactor(config: Partial<PIIConfig> = {}): <T>(obj: T) => T {
  const fullConfig: PIIConfig = {
    fields: config.fields || DEFAULT_PII_FIELDS,
    mode: config.mode || 'mask',
    maskChar: config.maskChar || '*',
    preserveLength: config.preserveLength || false,
    customRedactor: config.customRedactor,
  }

  return <T>(obj: T) => redactObject(obj, fullConfig)
}

/**
 * Redact sensitive headers
 */
export function redactHeaders(
  headers: Record<string, string>,
  sensitiveHeaders: string[] = ['authorization', 'cookie', 'x-api-key', 'x-auth-token']
): Record<string, string> {
  const result: Record<string, string> = {}

  for (const [key, value] of Object.entries(headers)) {
    const keyLower = key.toLowerCase()
    if (sensitiveHeaders.some(h => keyLower === h.toLowerCase())) {
      result[key] = '[REDACTED]'
    } else {
      result[key] = value
    }
  }

  return result
}

/**
 * Redact query parameters
 */
export function redactQuery(
  query: Record<string, string>,
  sensitiveParams: string[] = ['token', 'key', 'secret', 'password', 'auth']
): Record<string, string> {
  const result: Record<string, string> = {}

  for (const [key, value] of Object.entries(query)) {
    const keyLower = key.toLowerCase()
    if (sensitiveParams.some(p => keyLower.includes(p.toLowerCase()))) {
      result[key] = '[REDACTED]'
    } else {
      result[key] = value
    }
  }

  return result
}

/**
 * Redact email (show only domain)
 */
export function redactEmail(email: string): string {
  if (!email || !email.includes('@')) return mask(email)

  const [, domain] = email.split('@')
  return `****@${domain}`
}

/**
 * Redact credit card number (show last 4 digits)
 */
export function redactCreditCard(cardNumber: string): string {
  const cleaned = cardNumber.replace(/\D/g, '')
  if (cleaned.length < 4) return mask(cardNumber)

  return '**** **** **** ' + cleaned.slice(-4)
}

/**
 * Redact phone number
 */
export function redactPhone(phone: string): string {
  const cleaned = phone.replace(/\D/g, '')
  if (cleaned.length < 4) return mask(phone)

  return mask(phone, { preserveLength: true, showLast: 4 })
}

/**
 * Redact IP address (show only first two octets for IPv4)
 */
export function redactIP(ip: string): string {
  if (ip.includes(':')) {
    // IPv6 - show first segment
    const parts = ip.split(':')
    return parts[0] + ':****:****:****'
  }

  // IPv4 - show first two octets
  const parts = ip.split('.')
  if (parts.length !== 4) return mask(ip)

  return `${parts[0]}.${parts[1]}.*.*`
}
