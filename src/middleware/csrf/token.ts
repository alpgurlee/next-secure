import { webcrypto } from 'node:crypto'

const encoder = new TextEncoder()

/**
 * Generate random bytes as hex string
 */
export function randomBytes(length: number): string {
  const bytes = new Uint8Array(length)
  webcrypto.getRandomValues(bytes)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Create HMAC signature
 */
async function createSignature(data: string, secret: string): Promise<string> {
  const key = await webcrypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )

  const sig = await webcrypto.subtle.sign('HMAC', key, encoder.encode(data))
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return result === 0
}

/**
 * Create a signed CSRF token
 */
export async function createToken(
  secret: string,
  length: number = 32
): Promise<string> {
  const data = randomBytes(length)
  const sig = await createSignature(data, secret)
  return `${data}.${sig}`
}

/**
 * Verify a signed CSRF token
 */
export async function verifyToken(
  token: string,
  secret: string
): Promise<boolean> {
  if (!token || typeof token !== 'string') return false

  const parts = token.split('.')
  if (parts.length !== 2) return false

  const [data, sig] = parts
  if (!data || !sig) return false

  try {
    const expected = await createSignature(data, secret)
    return safeCompare(sig, expected)
  } catch {
    return false
  }
}

/**
 * Compare two tokens (constant-time)
 */
export function tokensMatch(a: string, b: string): boolean {
  if (!a || !b) return false
  return safeCompare(a, b)
}
