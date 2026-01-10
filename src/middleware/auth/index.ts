/**
 * Authentication Middleware (Coming Soon)
 *
 * @example
 * ```typescript
 * import { withAuth } from 'next-secure/auth'
 *
 * export const GET = withAuth(
 *   async (req, ctx) => {
 *     return Response.json({ user: ctx.user })
 *   },
 *   { roles: ['admin'] }
 * )
 * ```
 *
 * @packageDocumentation
 */

// Placeholder for auth middleware
export function withAuth() {
  throw new Error('Auth middleware coming soon in v0.2.0')
}

export function createAuthProvider() {
  throw new Error('Auth providers coming soon in v0.2.0')
}
