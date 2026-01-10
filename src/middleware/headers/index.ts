/**
 * Security Headers Middleware (Coming Soon)
 *
 * @example
 * ```typescript
 * // next.config.js
 * import { securityHeaders } from 'next-secure/headers'
 *
 * export default {
 *   async headers() {
 *     return [
 *       {
 *         source: '/:path*',
 *         headers: securityHeaders({
 *           contentSecurityPolicy: {
 *             directives: {
 *               defaultSrc: ["'self'"],
 *               scriptSrc: ["'self'", "'unsafe-inline'"],
 *             }
 *           },
 *           strictTransportSecurity: true,
 *           xFrameOptions: 'DENY',
 *         })
 *       }
 *     ]
 *   }
 * }
 * ```
 *
 * @packageDocumentation
 */

// Placeholder for security headers
export function securityHeaders() {
  throw new Error('Security headers coming soon in v0.2.0')
}

export function createCsp() {
  throw new Error('Security headers coming soon in v0.2.0')
}
