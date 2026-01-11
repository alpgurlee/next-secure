import type { NextRequest } from 'next/server'
import type { SecurityHeadersConfig, SecurityHeadersPreset } from './types'
import { buildHeaders, getPreset, PRESET_STRICT } from './builder'

type RouteHandler = (req: NextRequest) => Response | Promise<Response>

export interface WithSecurityHeadersOptions {
  /** Use a preset configuration */
  preset?: SecurityHeadersPreset

  /** Custom header configuration (merged with preset if provided) */
  config?: SecurityHeadersConfig

  /** Override response headers instead of merging */
  override?: boolean
}

/**
 * Merge two configs, with custom taking precedence
 */
function mergeConfigs(
  base: SecurityHeadersConfig,
  custom: SecurityHeadersConfig
): SecurityHeadersConfig {
  return {
    ...base,
    ...custom,
    // Deep merge CSP if both exist
    contentSecurityPolicy:
      custom.contentSecurityPolicy === false
        ? false
        : custom.contentSecurityPolicy
          ? base.contentSecurityPolicy
            ? { ...(base.contentSecurityPolicy as object), ...custom.contentSecurityPolicy }
            : custom.contentSecurityPolicy
          : base.contentSecurityPolicy,
    // Deep merge HSTS if both exist
    strictTransportSecurity:
      custom.strictTransportSecurity === false
        ? false
        : custom.strictTransportSecurity
          ? base.strictTransportSecurity
            ? { ...(base.strictTransportSecurity as object), ...custom.strictTransportSecurity }
            : custom.strictTransportSecurity
          : base.strictTransportSecurity,
    // Deep merge Permissions-Policy if both exist
    permissionsPolicy:
      custom.permissionsPolicy === false
        ? false
        : custom.permissionsPolicy
          ? base.permissionsPolicy
            ? { ...(base.permissionsPolicy as object), ...custom.permissionsPolicy }
            : custom.permissionsPolicy
          : base.permissionsPolicy,
  }
}

/**
 * Security headers middleware
 *
 * Adds security headers to responses. Use presets for quick setup
 * or provide custom configuration.
 *
 * @example
 * ```typescript
 * // Use strict preset
 * export const GET = withSecurityHeaders(handler, { preset: 'strict' })
 *
 * // Custom config
 * export const GET = withSecurityHeaders(handler, {
 *   config: {
 *     xFrameOptions: 'SAMEORIGIN',
 *     referrerPolicy: 'no-referrer'
 *   }
 * })
 * ```
 */
export function withSecurityHeaders(
  handler: RouteHandler,
  options: WithSecurityHeadersOptions = {}
): RouteHandler {
  const { preset, config, override = false } = options

  // Get base config from preset or default to strict
  let baseConfig: SecurityHeadersConfig = preset ? getPreset(preset) : PRESET_STRICT

  // Merge with custom config if provided
  if (config) {
    baseConfig = mergeConfigs(baseConfig, config)
  }

  // Pre-build headers for performance
  const securityHeaders = buildHeaders(baseConfig)

  return async (req: NextRequest): Promise<Response> => {
    const response = await handler(req)

    // Clone response to modify headers
    const newHeaders = new Headers(response.headers)

    // Add security headers
    securityHeaders.forEach((value, key) => {
      if (override || !newHeaders.has(key)) {
        newHeaders.set(key, value)
      }
    })

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    })
  }
}

/**
 * Create headers object for use in responses
 * Useful when you want to add headers manually
 *
 * @example
 * ```typescript
 * const headers = createSecurityHeaders({ preset: 'api' })
 *
 * return Response.json(data, { headers })
 * ```
 */
export function createSecurityHeaders(
  options: WithSecurityHeadersOptions = {}
): Headers {
  const { preset, config } = options

  let baseConfig: SecurityHeadersConfig = preset ? getPreset(preset) : PRESET_STRICT

  if (config) {
    baseConfig = mergeConfigs(baseConfig, config)
  }

  return buildHeaders(baseConfig)
}

/**
 * Create a headers object as a plain object (for Next.js headers())
 */
export function createSecurityHeadersObject(
  options: WithSecurityHeadersOptions = {}
): Record<string, string> {
  const headers = createSecurityHeaders(options)
  const obj: Record<string, string> = {}

  headers.forEach((value, key) => {
    obj[key] = value
  })

  return obj
}
