import { webcrypto } from 'node:crypto'
import type { JWTPayload, JWTConfig, AuthError } from './types'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/**
 * Base64URL decode
 */
function base64UrlDecode(str: string): Uint8Array {
  // Add padding if needed
  const pad = str.length % 4
  if (pad) {
    str += '='.repeat(4 - pad)
  }

  // Replace URL-safe chars
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')

  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/**
 * Parse JWT without verification (for header inspection)
 */
export function decodeJWT(token: string): {
  header: Record<string, unknown>
  payload: JWTPayload
  signature: Uint8Array
} | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null

    const header = JSON.parse(decoder.decode(base64UrlDecode(parts[0])))
    const payload = JSON.parse(decoder.decode(base64UrlDecode(parts[1])))
    const signature = base64UrlDecode(parts[2])

    return { header, payload, signature }
  } catch {
    return null
  }
}

/**
 * Get crypto algorithm params from JWT algorithm
 */
function getAlgorithmParams(alg: string): {
  name: string
  hash?: string
  namedCurve?: string
} | null {
  switch (alg) {
    case 'HS256':
      return { name: 'HMAC', hash: 'SHA-256' }
    case 'HS384':
      return { name: 'HMAC', hash: 'SHA-384' }
    case 'HS512':
      return { name: 'HMAC', hash: 'SHA-512' }
    case 'RS256':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    case 'RS384':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }
    case 'RS512':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }
    case 'ES256':
      return { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }
    case 'ES384':
      return { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }
    case 'ES512':
      return { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }
    default:
      return null
  }
}

/**
 * Verify HMAC signature
 */
async function verifyHMAC(
  data: string,
  signature: Uint8Array,
  secret: string,
  hash: string
): Promise<boolean> {
  const key = await webcrypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash },
    false,
    ['verify']
  )

  return webcrypto.subtle.verify('HMAC', key, signature, encoder.encode(data))
}

/**
 * Import PEM public key
 */
async function importPublicKey(
  pem: string,
  algorithm: { name: string; hash?: string; namedCurve?: string }
): Promise<CryptoKey> {
  // Remove PEM headers and decode
  const pemContents = pem
    .replace(/-----BEGIN.*-----/, '')
    .replace(/-----END.*-----/, '')
    .replace(/\s/g, '')

  const binaryDer = base64UrlDecode(pemContents.replace(/\+/g, '-').replace(/\//g, '_'))

  const keyUsages: KeyUsage[] = ['verify']

  if (algorithm.name === 'RSASSA-PKCS1-v1_5') {
    return webcrypto.subtle.importKey(
      'spki',
      binaryDer,
      { name: algorithm.name, hash: algorithm.hash! },
      false,
      keyUsages
    )
  }

  if (algorithm.name === 'ECDSA') {
    return webcrypto.subtle.importKey(
      'spki',
      binaryDer,
      { name: algorithm.name, namedCurve: algorithm.namedCurve! },
      false,
      keyUsages
    )
  }

  throw new Error(`Unsupported algorithm: ${algorithm.name}`)
}

/**
 * Verify RSA/ECDSA signature
 */
async function verifyAsymmetric(
  data: string,
  signature: Uint8Array,
  publicKey: string,
  algorithm: { name: string; hash?: string; namedCurve?: string }
): Promise<boolean> {
  const key = await importPublicKey(publicKey, algorithm)

  const params = algorithm.name === 'ECDSA'
    ? { name: 'ECDSA', hash: algorithm.hash! } as EcdsaParams
    : algorithm.name

  return webcrypto.subtle.verify(params, key, signature, encoder.encode(data))
}

/**
 * Validate JWT claims
 */
function validateClaims(
  payload: JWTPayload,
  config: JWTConfig
): AuthError | null {
  const now = Math.floor(Date.now() / 1000)
  const tolerance = config.clockTolerance || 0

  // Check expiration
  if (payload.exp !== undefined && payload.exp < now - tolerance) {
    return {
      code: 'expired_token',
      message: 'Token has expired',
      status: 401,
    }
  }

  // Check not before
  if (payload.nbf !== undefined && payload.nbf > now + tolerance) {
    return {
      code: 'invalid_token',
      message: 'Token not yet valid',
      status: 401,
    }
  }

  // Check issuer
  if (config.issuer) {
    const issuers = Array.isArray(config.issuer) ? config.issuer : [config.issuer]
    if (!payload.iss || !issuers.includes(payload.iss)) {
      return {
        code: 'invalid_token',
        message: 'Invalid token issuer',
        status: 401,
      }
    }
  }

  // Check audience
  if (config.audience) {
    const audiences = Array.isArray(config.audience) ? config.audience : [config.audience]
    const tokenAudiences = Array.isArray(payload.aud)
      ? payload.aud
      : payload.aud
        ? [payload.aud]
        : []

    const hasValidAudience = audiences.some((aud) => tokenAudiences.includes(aud))
    if (!hasValidAudience) {
      return {
        code: 'invalid_token',
        message: 'Invalid token audience',
        status: 401,
      }
    }
  }

  return null
}

/**
 * Verify and decode JWT
 */
export async function verifyJWT(
  token: string,
  config: JWTConfig
): Promise<{ payload: JWTPayload; error: null } | { payload: null; error: AuthError }> {
  // Decode token
  const decoded = decodeJWT(token)
  if (!decoded) {
    return {
      payload: null,
      error: {
        code: 'invalid_token',
        message: 'Malformed token',
        status: 401,
      },
    }
  }

  const { header, payload, signature } = decoded
  const alg = header.alg as string

  // Check algorithm
  const allowedAlgorithms = config.algorithms || ['HS256']
  if (!allowedAlgorithms.includes(alg)) {
    return {
      payload: null,
      error: {
        code: 'invalid_token',
        message: `Algorithm ${alg} not allowed`,
        status: 401,
      },
    }
  }

  // Get algorithm params
  const algorithmParams = getAlgorithmParams(alg)
  if (!algorithmParams) {
    return {
      payload: null,
      error: {
        code: 'invalid_token',
        message: `Unsupported algorithm: ${alg}`,
        status: 401,
      },
    }
  }

  // Verify signature
  const parts = token.split('.')
  const signedData = `${parts[0]}.${parts[1]}`
  let isValid = false

  try {
    if (algorithmParams.name === 'HMAC') {
      if (!config.secret) {
        return {
          payload: null,
          error: {
            code: 'invalid_token',
            message: 'Secret required for HMAC algorithms',
            status: 500,
          },
        }
      }
      isValid = await verifyHMAC(signedData, signature, config.secret, algorithmParams.hash!)
    } else {
      if (!config.publicKey) {
        return {
          payload: null,
          error: {
            code: 'invalid_token',
            message: 'Public key required for asymmetric algorithms',
            status: 500,
          },
        }
      }
      isValid = await verifyAsymmetric(signedData, signature, config.publicKey, algorithmParams)
    }
  } catch {
    isValid = false
  }

  if (!isValid) {
    return {
      payload: null,
      error: {
        code: 'invalid_signature',
        message: 'Invalid token signature',
        status: 401,
      },
    }
  }

  // Validate claims
  const claimsError = validateClaims(payload, config)
  if (claimsError) {
    return { payload: null, error: claimsError }
  }

  return { payload, error: null }
}

/**
 * Extract token from Authorization header
 */
export function extractBearerToken(authHeader: string | null): string | null {
  if (!authHeader) return null
  if (!authHeader.startsWith('Bearer ')) return null
  return authHeader.slice(7)
}
