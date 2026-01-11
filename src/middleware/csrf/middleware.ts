import type { NextRequest } from 'next/server'
import type { CSRFConfig, CSRFCookieOptions } from './types'
import { createToken, verifyToken, tokensMatch } from './token'

type RouteHandler = (req: NextRequest) => Response | Promise<Response>

const DEFAULT_COOKIE: CSRFCookieOptions = {
  name: '__csrf',
  path: '/',
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 86400, // 24h
}

const DEFAULT_CONFIG: Required<Omit<CSRFConfig, 'skip' | 'onError'>> = {
  cookie: DEFAULT_COOKIE,
  headerName: 'x-csrf-token',
  fieldName: '_csrf',
  secret: '',
  tokenLength: 32,
  protectedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],
}

function getSecret(config: CSRFConfig): string {
  const secret = config.secret || process.env.CSRF_SECRET
  if (!secret) {
    throw new Error(
      'CSRF secret is required. Set config.secret or CSRF_SECRET env variable.'
    )
  }
  return secret
}

function buildCookieString(name: string, value: string, opts: CSRFCookieOptions): string {
  let cookie = `${name}=${value}`

  if (opts.path) cookie += `; Path=${opts.path}`
  if (opts.domain) cookie += `; Domain=${opts.domain}`
  if (opts.maxAge) cookie += `; Max-Age=${opts.maxAge}`
  if (opts.httpOnly) cookie += '; HttpOnly'
  if (opts.secure) cookie += '; Secure'
  if (opts.sameSite) cookie += `; SameSite=${opts.sameSite}`

  return cookie
}

/**
 * Extract token from request (header or body)
 */
async function extractToken(
  req: NextRequest,
  headerName: string,
  fieldName: string
): Promise<string | null> {
  // check header first
  const headerToken = req.headers.get(headerName)
  if (headerToken) return headerToken

  // try to get from form data
  const contentType = req.headers.get('content-type') || ''

  if (contentType.includes('application/x-www-form-urlencoded')) {
    try {
      const cloned = req.clone()
      const formData = await cloned.formData()
      const token = formData.get(fieldName)
      if (typeof token === 'string') return token
    } catch {
      // ignore parse errors
    }
  }

  if (contentType.includes('application/json')) {
    try {
      const cloned = req.clone()
      const body = await cloned.json()
      if (body && typeof body[fieldName] === 'string') {
        return body[fieldName]
      }
    } catch {
      // ignore parse errors
    }
  }

  return null
}

function defaultErrorResponse(_req: NextRequest, reason: string): Response {
  return new Response(JSON.stringify({ error: 'CSRF validation failed', reason }), {
    status: 403,
    headers: { 'Content-Type': 'application/json' },
  })
}

/**
 * CSRF protection middleware
 *
 * Uses double submit cookie pattern:
 * 1. Server sets a signed token in a cookie
 * 2. Client sends the same token in header/body
 * 3. Server compares both values
 */
export function withCSRF(handler: RouteHandler, config: CSRFConfig = {}): RouteHandler {
  const secret = getSecret(config)
  const cookieOpts = { ...DEFAULT_COOKIE, ...config.cookie }
  const headerName = config.headerName || DEFAULT_CONFIG.headerName
  const fieldName = config.fieldName || DEFAULT_CONFIG.fieldName
  const protectedMethods = config.protectedMethods || DEFAULT_CONFIG.protectedMethods
  const onError = config.onError || defaultErrorResponse

  return async (req: NextRequest): Promise<Response> => {
    const method = req.method.toUpperCase()

    // skip unprotected methods
    if (!protectedMethods.includes(method)) {
      return handler(req)
    }

    // custom skip logic
    if (config.skip) {
      const shouldSkip = await config.skip(req)
      if (shouldSkip) return handler(req)
    }

    const cookieName = cookieOpts.name || '__csrf'
    const cookieToken = req.cookies.get(cookieName)?.value

    // no cookie = first request, reject
    if (!cookieToken) {
      return onError(req, 'missing_cookie')
    }

    // verify cookie token is valid (signed by us)
    const cookieValid = await verifyToken(cookieToken, secret)
    if (!cookieValid) {
      return onError(req, 'invalid_cookie')
    }

    // get token from request
    const requestToken = await extractToken(req, headerName, fieldName)
    if (!requestToken) {
      return onError(req, 'missing_token')
    }

    // compare tokens
    if (!tokensMatch(cookieToken, requestToken)) {
      return onError(req, 'token_mismatch')
    }

    return handler(req)
  }
}

/**
 * Generate a new CSRF token and cookie header
 * Use this in GET routes to set the initial token
 */
export async function generateCSRF(config: CSRFConfig = {}): Promise<{
  token: string
  cookieHeader: string
}> {
  const secret = getSecret(config)
  const cookieOpts = { ...DEFAULT_COOKIE, ...config.cookie }
  const tokenLength = config.tokenLength || DEFAULT_CONFIG.tokenLength
  const cookieName = cookieOpts.name || '__csrf'

  const token = await createToken(secret, tokenLength)
  const cookieHeader = buildCookieString(cookieName, token, cookieOpts)

  return { token, cookieHeader }
}

/**
 * Validate a CSRF token without middleware
 * Useful for custom validation flows
 */
export async function validateCSRF(
  req: NextRequest,
  config: CSRFConfig = {}
): Promise<{ valid: boolean; reason?: string }> {
  const secret = getSecret(config)
  const cookieOpts = { ...DEFAULT_COOKIE, ...config.cookie }
  const headerName = config.headerName || DEFAULT_CONFIG.headerName
  const fieldName = config.fieldName || DEFAULT_CONFIG.fieldName
  const cookieName = cookieOpts.name || '__csrf'

  const cookieToken = req.cookies.get(cookieName)?.value
  if (!cookieToken) {
    return { valid: false, reason: 'missing_cookie' }
  }

  const cookieValid = await verifyToken(cookieToken, secret)
  if (!cookieValid) {
    return { valid: false, reason: 'invalid_cookie' }
  }

  const requestToken = await extractToken(req, headerName, fieldName)
  if (!requestToken) {
    return { valid: false, reason: 'missing_token' }
  }

  if (!tokensMatch(cookieToken, requestToken)) {
    return { valid: false, reason: 'token_mismatch' }
  }

  return { valid: true }
}
