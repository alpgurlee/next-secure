import type { NextRequest } from 'next/server'
import type {
  AuthConfig,
  AuthUser,
  AuthError,
  JWTConfig,
  APIKeyConfig,
  SessionConfig,
  RBACConfig,
} from './types'
import { verifyJWT, extractBearerToken } from './jwt'

type RouteHandler = (req: NextRequest) => Response | Promise<Response>
type AuthenticatedHandler = (
  req: NextRequest,
  ctx: { user: AuthUser; token?: string }
) => Response | Promise<Response>

/**
 * Default error response
 */
function defaultErrorResponse(_req: NextRequest, error: AuthError): Response {
  return new Response(
    JSON.stringify({
      error: error.code,
      message: error.message,
    }),
    {
      status: error.status,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Extract token from request
 */
async function getTokenFromRequest(
  req: NextRequest,
  config?: JWTConfig
): Promise<string | null> {
  // Custom extractor
  if (config?.getToken) {
    return config.getToken(req)
  }

  // Default: Authorization header
  return extractBearerToken(req.headers.get('authorization'))
}

/**
 * JWT Authentication middleware
 */
export function withJWT(
  handler: AuthenticatedHandler,
  config: JWTConfig
): RouteHandler {
  const secret = config.secret || process.env.JWT_SECRET
  const effectiveConfig = { ...config, secret }

  return async (req: NextRequest): Promise<Response> => {
    const token = await getTokenFromRequest(req, effectiveConfig)

    if (!token) {
      return defaultErrorResponse(req, {
        code: 'missing_token',
        message: 'Authentication required',
        status: 401,
      })
    }

    const { payload, error } = await verifyJWT(token, effectiveConfig)

    if (error) {
      return defaultErrorResponse(req, error)
    }

    // Map payload to user
    const user: AuthUser = effectiveConfig.mapUser
      ? await effectiveConfig.mapUser(payload)
      : {
          id: payload.sub || '',
          email: payload.email as string | undefined,
          name: payload.name as string | undefined,
          roles: payload.roles as string[] | undefined,
          permissions: payload.permissions as string[] | undefined,
        }

    return handler(req, { user, token })
  }
}

/**
 * API Key Authentication middleware
 */
export function withAPIKey(
  handler: AuthenticatedHandler,
  config: APIKeyConfig
): RouteHandler {
  const headerName = config.headerName || 'x-api-key'
  const queryParam = config.queryParam || 'api_key'

  return async (req: NextRequest): Promise<Response> => {
    // Try header first
    let apiKey = req.headers.get(headerName)

    // Try query param
    if (!apiKey) {
      const url = new URL(req.url)
      apiKey = url.searchParams.get(queryParam)
    }

    if (!apiKey) {
      return defaultErrorResponse(req, {
        code: 'missing_api_key',
        message: 'API key required',
        status: 401,
      })
    }

    const user = await config.validate(apiKey, req)

    if (!user) {
      return defaultErrorResponse(req, {
        code: 'invalid_api_key',
        message: 'Invalid API key',
        status: 401,
      })
    }

    return handler(req, { user })
  }
}

/**
 * Session/Cookie Authentication middleware
 */
export function withSession(
  handler: AuthenticatedHandler,
  config: SessionConfig
): RouteHandler {
  const cookieName = config.cookieName || 'session'

  return async (req: NextRequest): Promise<Response> => {
    const sessionId = req.cookies.get(cookieName)?.value

    if (!sessionId) {
      return defaultErrorResponse(req, {
        code: 'missing_session',
        message: 'Session required',
        status: 401,
      })
    }

    const user = await config.validate(sessionId, req)

    if (!user) {
      return defaultErrorResponse(req, {
        code: 'invalid_session',
        message: 'Invalid or expired session',
        status: 401,
      })
    }

    return handler(req, { user })
  }
}

/**
 * Role-based access control middleware
 * Must be used after authentication middleware
 */
export function withRoles(
  handler: AuthenticatedHandler,
  config: RBACConfig
): (req: NextRequest, ctx: { user: AuthUser; token?: string }) => Promise<Response> {
  return async (
    req: NextRequest,
    ctx: { user: AuthUser; token?: string }
  ): Promise<Response> => {
    const { user } = ctx

    // Get user roles
    const userRoles = config.getUserRoles
      ? config.getUserRoles(user)
      : user.roles || []

    // Check required roles (any match)
    if (config.roles && config.roles.length > 0) {
      const hasRole = config.roles.some((role) => userRoles.includes(role))
      if (!hasRole) {
        return defaultErrorResponse(req, {
          code: 'insufficient_roles',
          message: 'Insufficient permissions',
          status: 403,
        })
      }
    }

    // Get user permissions
    const userPermissions = config.getUserPermissions
      ? config.getUserPermissions(user)
      : user.permissions || []

    // Check required permissions (all required)
    if (config.permissions && config.permissions.length > 0) {
      const hasAllPermissions = config.permissions.every((perm) =>
        userPermissions.includes(perm)
      )
      if (!hasAllPermissions) {
        return defaultErrorResponse(req, {
          code: 'insufficient_permissions',
          message: 'Insufficient permissions',
          status: 403,
        })
      }
    }

    // Custom authorization
    if (config.authorize) {
      const authorized = await config.authorize(user, req)
      if (!authorized) {
        return defaultErrorResponse(req, {
          code: 'unauthorized',
          message: 'Unauthorized',
          status: 403,
        })
      }
    }

    return handler(req, ctx)
  }
}

/**
 * Combined auth middleware with multiple strategies
 */
export function withAuth(
  handler: AuthenticatedHandler,
  config: AuthConfig
): RouteHandler {
  const onError = config.onError || defaultErrorResponse

  return async (req: NextRequest): Promise<Response> => {
    let user: AuthUser | null = null
    let token: string | undefined

    // Try JWT auth
    if (config.jwt) {
      const secret = config.jwt.secret || process.env.JWT_SECRET
      const jwtConfig = { ...config.jwt, secret }
      const jwtToken = await getTokenFromRequest(req, jwtConfig)

      if (jwtToken) {
        const { payload, error } = await verifyJWT(jwtToken, jwtConfig)
        if (!error && payload) {
          user = jwtConfig.mapUser
            ? await jwtConfig.mapUser(payload)
            : {
                id: payload.sub || '',
                email: payload.email as string | undefined,
                name: payload.name as string | undefined,
                roles: payload.roles as string[] | undefined,
              }
          token = jwtToken
        }
      }
    }

    // Try API Key auth
    if (!user && config.apiKey) {
      const headerName = config.apiKey.headerName || 'x-api-key'
      const queryParam = config.apiKey.queryParam || 'api_key'

      let apiKey = req.headers.get(headerName)
      if (!apiKey) {
        const url = new URL(req.url)
        apiKey = url.searchParams.get(queryParam)
      }

      if (apiKey) {
        const apiUser = await config.apiKey.validate(apiKey, req)
        if (apiUser) {
          user = apiUser
        }
      }
    }

    // Try Session auth
    if (!user && config.session) {
      const cookieName = config.session.cookieName || 'session'
      const sessionId = req.cookies.get(cookieName)?.value

      if (sessionId) {
        const sessionUser = await config.session.validate(sessionId, req)
        if (sessionUser) {
          user = sessionUser
        }
      }
    }

    // No authentication found
    if (!user) {
      return onError(req, {
        code: 'unauthorized',
        message: 'Authentication required',
        status: 401,
      })
    }

    // RBAC check
    if (config.rbac) {
      const userRoles = config.rbac.getUserRoles
        ? config.rbac.getUserRoles(user)
        : user.roles || []

      if (config.rbac.roles && config.rbac.roles.length > 0) {
        const hasRole = config.rbac.roles.some((role) => userRoles.includes(role))
        if (!hasRole) {
          return onError(req, {
            code: 'insufficient_roles',
            message: 'Insufficient permissions',
            status: 403,
          })
        }
      }

      const userPermissions = config.rbac.getUserPermissions
        ? config.rbac.getUserPermissions(user)
        : user.permissions || []

      if (config.rbac.permissions && config.rbac.permissions.length > 0) {
        const hasAllPermissions = config.rbac.permissions.every((perm) =>
          userPermissions.includes(perm)
        )
        if (!hasAllPermissions) {
          return onError(req, {
            code: 'insufficient_permissions',
            message: 'Insufficient permissions',
            status: 403,
          })
        }
      }

      if (config.rbac.authorize) {
        const authorized = await config.rbac.authorize(user, req)
        if (!authorized) {
          return onError(req, {
            code: 'unauthorized',
            message: 'Unauthorized',
            status: 403,
          })
        }
      }
    }

    // Success callback
    if (config.onSuccess) {
      await config.onSuccess(req, user)
    }

    return handler(req, { user, token })
  }
}

/**
 * Optional auth - doesn't fail if no auth present
 */
export function withOptionalAuth(
  handler: (
    req: NextRequest,
    ctx: { user: AuthUser | null; token?: string }
  ) => Response | Promise<Response>,
  config: Omit<AuthConfig, 'rbac'>
): RouteHandler {
  return async (req: NextRequest): Promise<Response> => {
    let user: AuthUser | null = null
    let token: string | undefined

    // Try JWT auth
    if (config.jwt) {
      const secret = config.jwt.secret || process.env.JWT_SECRET
      const jwtConfig = { ...config.jwt, secret }
      const jwtToken = await getTokenFromRequest(req, jwtConfig)

      if (jwtToken) {
        const { payload, error } = await verifyJWT(jwtToken, jwtConfig)
        if (!error && payload) {
          user = jwtConfig.mapUser
            ? await jwtConfig.mapUser(payload)
            : {
                id: payload.sub || '',
                email: payload.email as string | undefined,
                name: payload.name as string | undefined,
                roles: payload.roles as string[] | undefined,
              }
          token = jwtToken
        }
      }
    }

    // Try API Key auth
    if (!user && config.apiKey) {
      const headerName = config.apiKey.headerName || 'x-api-key'
      let apiKey = req.headers.get(headerName)

      if (apiKey) {
        const apiUser = await config.apiKey.validate(apiKey, req)
        if (apiUser) user = apiUser
      }
    }

    // Try Session auth
    if (!user && config.session) {
      const cookieName = config.session.cookieName || 'session'
      const sessionId = req.cookies.get(cookieName)?.value

      if (sessionId) {
        const sessionUser = await config.session.validate(sessionId, req)
        if (sessionUser) user = sessionUser
      }
    }

    return handler(req, { user, token })
  }
}
