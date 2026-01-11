/**
 * CSRF Protection Middleware
 *
 * @example
 * ```typescript
 * import { withCSRF, generateCSRF } from 'nextjs-secure/csrf'
 *
 * // GET: Generate token for forms
 * export async function GET() {
 *   const { token, cookieHeader } = await generateCSRF()
 *   return Response.json(
 *     { csrfToken: token },
 *     { headers: { 'Set-Cookie': cookieHeader } }
 *   )
 * }
 *
 * // POST: Protected endpoint
 * export const POST = withCSRF(async (req) => {
 *   return Response.json({ success: true })
 * })
 * ```
 *
 * @packageDocumentation
 */

export { withCSRF, generateCSRF, validateCSRF } from './middleware'
export { createToken, verifyToken, tokensMatch } from './token'
export type { CSRFConfig, CSRFCookieOptions, CSRFToken } from './types'
