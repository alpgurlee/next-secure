/**
 * Authentication Middleware
 *
 * @example
 * ```typescript
 * import { withJWT, withAuth } from 'nextjs-secure/auth'
 *
 * // JWT authentication
 * export const GET = withJWT(
 *   async (req, ctx) => {
 *     return Response.json({ user: ctx.user })
 *   },
 *   { secret: process.env.JWT_SECRET }
 * )
 *
 * // Combined auth with RBAC
 * export const POST = withAuth(
 *   async (req, ctx) => {
 *     return Response.json({ user: ctx.user })
 *   },
 *   {
 *     jwt: { secret: process.env.JWT_SECRET },
 *     rbac: { roles: ['admin'] }
 *   }
 * )
 * ```
 *
 * @packageDocumentation
 */

export {
  withJWT,
  withAPIKey,
  withSession,
  withAuth,
  withRoles,
  withOptionalAuth,
} from './middleware'

export { verifyJWT, decodeJWT, extractBearerToken } from './jwt'

export type {
  AuthUser,
  AuthConfig,
  AuthError,
  AuthErrorCode,
  JWTConfig,
  JWTPayload,
  APIKeyConfig,
  SessionConfig,
  RBACConfig,
  AuthenticatedRequest,
} from './types'
