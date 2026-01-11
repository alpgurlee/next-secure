import type { NextRequest } from 'next/server'

/**
 * User object attached to request after authentication
 */
export interface AuthUser {
  id: string
  email?: string
  name?: string
  roles?: string[]
  permissions?: string[]
  [key: string]: unknown
}

/**
 * JWT payload structure
 */
export interface JWTPayload {
  sub?: string
  iss?: string
  aud?: string | string[]
  exp?: number
  iat?: number
  nbf?: number
  jti?: string
  [key: string]: unknown
}

/**
 * JWT verification options
 */
export interface JWTConfig {
  /** Secret key for HS256/HS384/HS512 */
  secret?: string

  /** Public key for RS256/RS384/RS512/ES256/ES384/ES512 */
  publicKey?: string

  /** JWKS endpoint URL */
  jwksUri?: string

  /** Expected issuer */
  issuer?: string | string[]

  /** Expected audience */
  audience?: string | string[]

  /** Algorithms to accept */
  algorithms?: string[]

  /** Clock tolerance in seconds */
  clockTolerance?: number

  /** Extract token from request (default: Authorization header) */
  getToken?: (req: NextRequest) => string | null | Promise<string | null>

  /** Map JWT payload to user object */
  mapUser?: (payload: JWTPayload) => AuthUser | Promise<AuthUser>
}

/**
 * API Key authentication config
 */
export interface APIKeyConfig {
  /** Header name to check (default: x-api-key) */
  headerName?: string

  /** Query parameter name (default: api_key) */
  queryParam?: string

  /** Validate API key and return user */
  validate: (key: string, req: NextRequest) => AuthUser | null | Promise<AuthUser | null>
}

/**
 * Session/Cookie authentication config
 */
export interface SessionConfig {
  /** Cookie name (default: session) */
  cookieName?: string

  /** Validate session and return user */
  validate: (sessionId: string, req: NextRequest) => AuthUser | null | Promise<AuthUser | null>
}

/**
 * Role-based access control config
 */
export interface RBACConfig {
  /** Required roles (user must have at least one) */
  roles?: string[]

  /** Required permissions (user must have all) */
  permissions?: string[]

  /** Get user roles from request */
  getUserRoles?: (user: AuthUser) => string[]

  /** Get user permissions from request */
  getUserPermissions?: (user: AuthUser) => string[]

  /** Custom authorization check */
  authorize?: (user: AuthUser, req: NextRequest) => boolean | Promise<boolean>
}

/**
 * Combined auth configuration
 */
export interface AuthConfig {
  /** JWT authentication */
  jwt?: JWTConfig

  /** API Key authentication */
  apiKey?: APIKeyConfig

  /** Session/Cookie authentication */
  session?: SessionConfig

  /** Role-based access control */
  rbac?: RBACConfig

  /** Custom error response */
  onError?: (req: NextRequest, error: AuthError) => Response | Promise<Response>

  /** Called on successful auth */
  onSuccess?: (req: NextRequest, user: AuthUser) => void | Promise<void>
}

/**
 * Auth error types
 */
export type AuthErrorCode =
  | 'missing_token'
  | 'invalid_token'
  | 'expired_token'
  | 'invalid_signature'
  | 'missing_api_key'
  | 'invalid_api_key'
  | 'missing_session'
  | 'invalid_session'
  | 'insufficient_roles'
  | 'insufficient_permissions'
  | 'unauthorized'

export interface AuthError {
  code: AuthErrorCode
  message: string
  status: number
}

/**
 * Extended request with auth context
 */
export interface AuthenticatedRequest extends NextRequest {
  auth: {
    user: AuthUser
    token?: string
    method: 'jwt' | 'apiKey' | 'session'
  }
}
