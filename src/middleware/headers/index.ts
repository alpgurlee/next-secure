/**
 * Security Headers Middleware
 *
 * @example
 * ```typescript
 * import { withSecurityHeaders } from 'nextjs-secure/headers'
 *
 * // Use strict preset (default)
 * export const GET = withSecurityHeaders(handler)
 *
 * // Use specific preset
 * export const GET = withSecurityHeaders(handler, { preset: 'api' })
 *
 * // Custom configuration
 * export const GET = withSecurityHeaders(handler, {
 *   config: {
 *     xFrameOptions: 'SAMEORIGIN',
 *     contentSecurityPolicy: {
 *       defaultSrc: ["'self'"],
 *       scriptSrc: ["'self'", "'unsafe-inline'"]
 *     }
 *   }
 * })
 * ```
 *
 * @packageDocumentation
 */

export {
  withSecurityHeaders,
  createSecurityHeaders,
  createSecurityHeadersObject,
} from './middleware'

export {
  buildCSP,
  buildHSTS,
  buildPermissionsPolicy,
  buildHeaders,
  getPreset,
  PRESET_STRICT,
  PRESET_RELAXED,
  PRESET_API,
} from './builder'

export type {
  ContentSecurityPolicy,
  StrictTransportSecurity,
  PermissionsPolicy,
  SecurityHeadersConfig,
  SecurityHeadersPreset,
  XFrameOptions,
  ReferrerPolicy,
  CrossOriginOpenerPolicy,
  CrossOriginEmbedderPolicy,
  CrossOriginResourcePolicy,
} from './types'
