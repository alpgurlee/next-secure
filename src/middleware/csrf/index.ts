/**
 * CSRF Protection Middleware (Coming Soon)
 *
 * @example
 * ```typescript
 * import { withCsrf, generateCsrfToken } from 'next-secure/csrf'
 *
 * // Generate token
 * export async function GET() {
 *   const token = await generateCsrfToken()
 *   return Response.json({ csrfToken: token })
 * }
 *
 * // Validate token
 * export const POST = withCsrf(async (req) => {
 *   return Response.json({ ok: true })
 * })
 * ```
 *
 * @packageDocumentation
 */

// Placeholder for CSRF middleware
export function withCsrf() {
  throw new Error('CSRF middleware coming soon in v0.2.0')
}

export function generateCsrfToken() {
  throw new Error('CSRF middleware coming soon in v0.2.0')
}

export function validateCsrfToken() {
  throw new Error('CSRF middleware coming soon in v0.2.0')
}
