/**
 * Request Signing for API Security
 * @module nextjs-secure/api
 */

import type { NextRequest } from 'next/server'
import type {
  SigningOptions,
  SignatureResult,
  SigningAlgorithm,
  SignatureEncoding,
  SignatureComponents,
} from './types'

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_SIGNING_OPTIONS: Required<Omit<SigningOptions, 'secret' | 'canonicalBuilder' | 'onInvalid' | 'skip'>> = {
  algorithm: 'sha256',
  encoding: 'hex',
  signatureHeader: 'x-signature',
  timestampHeader: 'x-timestamp',
  nonceHeader: 'x-nonce',
  components: {
    method: true,
    path: true,
    query: true,
    body: true,
    headers: [],
    timestamp: true,
    nonce: false,
  },
  timestampTolerance: 300, // 5 minutes
}

// ============================================================================
// Crypto Utilities
// ============================================================================

/**
 * Create HMAC signature using Web Crypto API
 */
export async function createHMAC(
  data: string,
  secret: string,
  algorithm: SigningAlgorithm = 'sha256',
  encoding: SignatureEncoding = 'hex'
): Promise<string> {
  const encoder = new TextEncoder()
  const keyData = encoder.encode(secret)
  const messageData = encoder.encode(data)

  // Map algorithm names to Web Crypto format
  const hashName = {
    sha1: 'SHA-1',
    sha256: 'SHA-256',
    sha384: 'SHA-384',
    sha512: 'SHA-512',
  }[algorithm]

  // Import the key
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: hashName },
    false,
    ['sign']
  )

  // Sign the data
  const signature = await crypto.subtle.sign('HMAC', key, messageData)

  // Convert to specified encoding
  return encodeSignature(new Uint8Array(signature), encoding)
}

/**
 * Encode signature bytes to string
 */
function encodeSignature(bytes: Uint8Array, encoding: SignatureEncoding): string {
  switch (encoding) {
    case 'hex':
      return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
    case 'base64':
      return btoa(String.fromCharCode(...bytes))
    case 'base64url':
      return btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')
    default:
      return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
  }
}

/**
 * Timing-safe string comparison
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

  return result === 0
}

// ============================================================================
// Canonical String Building
// ============================================================================

/**
 * Build canonical string for signing
 */
export async function buildCanonicalString(
  req: NextRequest,
  components: SignatureComponents,
  options: { timestampHeader?: string; nonceHeader?: string } = {}
): Promise<string> {
  const parts: string[] = []

  // Method
  if (components.method) {
    parts.push(req.method.toUpperCase())
  }

  // Path
  if (components.path) {
    const url = new URL(req.url)
    parts.push(url.pathname)
  }

  // Query string (sorted)
  if (components.query) {
    const url = new URL(req.url)
    const params = new URLSearchParams(url.search)
    const sortedParams = Array.from(params.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([k, v]) => `${k}=${v}`)
      .join('&')
    parts.push(sortedParams)
  }

  // Request body
  if (components.body) {
    try {
      const cloned = req.clone()
      const body = await cloned.text()
      if (body) {
        parts.push(body)
      }
    } catch {
      // No body or error reading
    }
  }

  // Specific headers (sorted)
  if (components.headers && components.headers.length > 0) {
    const headerParts = components.headers
      .map(h => h.toLowerCase())
      .sort()
      .map(h => `${h}:${req.headers.get(h) || ''}`)
    parts.push(headerParts.join('\n'))
  }

  // Timestamp
  if (components.timestamp) {
    const timestampHeader = options.timestampHeader || 'x-timestamp'
    const timestamp = req.headers.get(timestampHeader) || ''
    parts.push(timestamp)
  }

  // Nonce
  if (components.nonce) {
    const nonceHeader = options.nonceHeader || 'x-nonce'
    const nonce = req.headers.get(nonceHeader) || ''
    parts.push(nonce)
  }

  return parts.join('\n')
}

// ============================================================================
// Signature Generation
// ============================================================================

/**
 * Generate signature for a request
 */
export async function generateSignature(
  req: NextRequest,
  options: SigningOptions
): Promise<string> {
  const {
    secret,
    algorithm = DEFAULT_SIGNING_OPTIONS.algorithm,
    encoding = DEFAULT_SIGNING_OPTIONS.encoding,
    components = DEFAULT_SIGNING_OPTIONS.components,
    timestampHeader = DEFAULT_SIGNING_OPTIONS.timestampHeader,
    nonceHeader = DEFAULT_SIGNING_OPTIONS.nonceHeader,
    canonicalBuilder,
  } = options

  // Build canonical string
  const canonical = canonicalBuilder
    ? await canonicalBuilder(req, components)
    : await buildCanonicalString(req, components, { timestampHeader, nonceHeader })

  // Generate HMAC
  return createHMAC(canonical, secret, algorithm, encoding)
}

/**
 * Generate signature headers for outgoing requests
 */
export async function generateSignatureHeaders(
  method: string,
  url: string,
  body: string | null,
  options: SigningOptions & { includeTimestamp?: boolean; includeNonce?: boolean }
): Promise<Record<string, string>> {
  const {
    secret,
    algorithm = DEFAULT_SIGNING_OPTIONS.algorithm,
    encoding = DEFAULT_SIGNING_OPTIONS.encoding,
    components = DEFAULT_SIGNING_OPTIONS.components,
    signatureHeader = DEFAULT_SIGNING_OPTIONS.signatureHeader,
    timestampHeader = DEFAULT_SIGNING_OPTIONS.timestampHeader,
    nonceHeader = DEFAULT_SIGNING_OPTIONS.nonceHeader,
    includeTimestamp = true,
    includeNonce = false,
  } = options

  const headers: Record<string, string> = {}
  const parts: string[] = []

  // Method
  if (components.method) {
    parts.push(method.toUpperCase())
  }

  // Path
  if (components.path) {
    const parsedUrl = new URL(url)
    parts.push(parsedUrl.pathname)
  }

  // Query
  if (components.query) {
    const parsedUrl = new URL(url)
    const params = new URLSearchParams(parsedUrl.search)
    const sortedParams = Array.from(params.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([k, v]) => `${k}=${v}`)
      .join('&')
    parts.push(sortedParams)
  }

  // Body
  if (components.body && body) {
    parts.push(body)
  }

  // Timestamp
  if (components.timestamp && includeTimestamp) {
    const timestamp = Math.floor(Date.now() / 1000).toString()
    headers[timestampHeader] = timestamp
    parts.push(timestamp)
  }

  // Nonce
  if (components.nonce && includeNonce) {
    const nonce = generateNonce()
    headers[nonceHeader] = nonce
    parts.push(nonce)
  }

  const canonical = parts.join('\n')
  const signature = await createHMAC(canonical, secret, algorithm, encoding)
  headers[signatureHeader] = signature

  return headers
}

/**
 * Generate a random nonce
 */
function generateNonce(length: number = 32): string {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

// ============================================================================
// Signature Verification
// ============================================================================

/**
 * Verify request signature
 */
export async function verifySignature(
  req: NextRequest,
  options: SigningOptions
): Promise<SignatureResult> {
  const {
    secret,
    algorithm = DEFAULT_SIGNING_OPTIONS.algorithm,
    encoding = DEFAULT_SIGNING_OPTIONS.encoding,
    signatureHeader = DEFAULT_SIGNING_OPTIONS.signatureHeader,
    timestampHeader = DEFAULT_SIGNING_OPTIONS.timestampHeader,
    nonceHeader = DEFAULT_SIGNING_OPTIONS.nonceHeader,
    components = DEFAULT_SIGNING_OPTIONS.components,
    timestampTolerance = DEFAULT_SIGNING_OPTIONS.timestampTolerance,
    canonicalBuilder,
  } = options

  // Get provided signature
  const providedSignature = req.headers.get(signatureHeader)
  if (!providedSignature) {
    return {
      valid: false,
      reason: 'Missing signature header',
    }
  }

  // Validate timestamp if required
  if (components.timestamp) {
    const timestamp = req.headers.get(timestampHeader)
    if (!timestamp) {
      return {
        valid: false,
        reason: 'Missing timestamp header',
      }
    }

    const timestampNum = parseInt(timestamp, 10)
    if (isNaN(timestampNum)) {
      return {
        valid: false,
        reason: 'Invalid timestamp format',
      }
    }

    const now = Math.floor(Date.now() / 1000)
    const age = Math.abs(now - timestampNum)
    if (age > timestampTolerance) {
      return {
        valid: false,
        reason: `Timestamp too old or too far in future (age: ${age}s, max: ${timestampTolerance}s)`,
      }
    }
  }

  // Build canonical string
  const canonical = canonicalBuilder
    ? await canonicalBuilder(req, components)
    : await buildCanonicalString(req, components, { timestampHeader, nonceHeader })

  // Compute expected signature
  const computedSignature = await createHMAC(canonical, secret, algorithm, encoding)

  // Compare signatures (timing-safe)
  const valid = timingSafeEqual(providedSignature, computedSignature)

  return {
    valid,
    reason: valid ? undefined : 'Signature mismatch',
    computed: computedSignature,
    provided: providedSignature,
    canonical,
  }
}

// ============================================================================
// Signing Middleware
// ============================================================================

/**
 * Default response for invalid signature
 */
function defaultInvalidResponse(reason: string): Response {
  return new Response(
    JSON.stringify({
      error: 'Unauthorized',
      message: reason,
      code: 'INVALID_SIGNATURE',
    }),
    {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Create request signing middleware
 */
export function withRequestSigning<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: SigningOptions
): (req: NextRequest, ctx: T) => Promise<Response> {
  return async (req: NextRequest, ctx: T): Promise<Response> => {
    // Check if should skip
    if (options.skip && await options.skip(req)) {
      return handler(req, ctx)
    }

    // Verify signature
    const result = await verifySignature(req, options)

    if (!result.valid) {
      const onInvalid = options.onInvalid || defaultInvalidResponse
      return onInvalid(result.reason || 'Invalid signature')
    }

    return handler(req, ctx)
  }
}

// ============================================================================
// Utility Exports
// ============================================================================

export {
  generateNonce as createNonce,
}
