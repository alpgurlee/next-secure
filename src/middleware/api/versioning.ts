/**
 * API Versioning for API Security
 * @module nextjs-secure/api
 */

import type { NextRequest } from 'next/server'
import type { VersioningOptions, VersionResult, VersionSource, VersionStatus } from './types'

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_VERSIONING_OPTIONS: Required<Omit<VersioningOptions, 'current' | 'supported' | 'deprecated' | 'sunset' | 'sunsetDates' | 'pathPattern' | 'acceptPattern' | 'parseVersion' | 'onUnsupported' | 'onDeprecated' | 'skip'>> = {
  source: 'header',
  versionHeader: 'x-api-version',
  versionQuery: 'version',
  addDeprecationHeaders: true,
}

// ============================================================================
// Version Extraction
// ============================================================================

/**
 * Extract version from header
 */
function extractFromHeader(req: NextRequest, headerName: string): string | null {
  return req.headers.get(headerName)
}

/**
 * Extract version from query string
 */
function extractFromQuery(req: NextRequest, queryParam: string): string | null {
  const url = new URL(req.url)
  return url.searchParams.get(queryParam)
}

/**
 * Extract version from path
 */
function extractFromPath(req: NextRequest, pattern?: RegExp): string | null {
  if (!pattern) {
    // Default pattern: /v1/, /v2/, etc.
    pattern = /\/v(\d+(?:\.\d+)?)\//
  }

  const url = new URL(req.url)
  const match = url.pathname.match(pattern)

  if (match && match[1]) {
    return match[1]
  }

  return null
}

/**
 * Extract version from Accept header
 */
function extractFromAccept(req: NextRequest, pattern?: RegExp): string | null {
  const accept = req.headers.get('accept')
  if (!accept) {
    return null
  }

  if (!pattern) {
    // Default pattern: application/vnd.api+json; version=1
    pattern = /version=(\d+(?:\.\d+)?)/
  }

  const match = accept.match(pattern)
  if (match && match[1]) {
    return match[1]
  }

  return null
}

/**
 * Extract version from request
 */
export function extractVersion(
  req: NextRequest,
  options: VersioningOptions
): { version: string | null; source: VersionSource | null } {
  const {
    source = DEFAULT_VERSIONING_OPTIONS.source,
    versionHeader = DEFAULT_VERSIONING_OPTIONS.versionHeader,
    versionQuery = DEFAULT_VERSIONING_OPTIONS.versionQuery,
    pathPattern,
    acceptPattern,
    parseVersion,
  } = options

  let version: string | null = null
  let extractedSource: VersionSource | null = null

  switch (source) {
    case 'header':
      version = extractFromHeader(req, versionHeader)
      extractedSource = version ? 'header' : null
      break

    case 'query':
      version = extractFromQuery(req, versionQuery)
      extractedSource = version ? 'query' : null
      break

    case 'path':
      version = extractFromPath(req, pathPattern)
      extractedSource = version ? 'path' : null
      break

    case 'accept':
      version = extractFromAccept(req, acceptPattern)
      extractedSource = version ? 'accept' : null
      break
  }

  // Apply custom parser
  if (version && parseVersion) {
    version = parseVersion(version)
  }

  return { version, source: extractedSource }
}

/**
 * Try to extract version from multiple sources
 */
export function extractVersionMultiSource(
  req: NextRequest,
  options: VersioningOptions,
  sources: VersionSource[] = ['header', 'query', 'path', 'accept']
): { version: string | null; source: VersionSource | null } {
  for (const source of sources) {
    const result = extractVersion(req, { ...options, source })
    if (result.version) {
      return result
    }
  }

  return { version: null, source: null }
}

// ============================================================================
// Version Status
// ============================================================================

/**
 * Get version status
 */
export function getVersionStatus(
  version: string,
  options: VersioningOptions
): VersionStatus | null {
  const { current, supported, deprecated = [], sunset = [] } = options

  if (version === current) {
    return 'current'
  }

  if (sunset.includes(version)) {
    return 'sunset'
  }

  if (deprecated.includes(version)) {
    return 'deprecated'
  }

  if (supported.includes(version)) {
    return 'supported'
  }

  return null
}

/**
 * Check if version is supported
 */
export function isVersionSupported(version: string, options: VersioningOptions): boolean {
  const status = getVersionStatus(version, options)
  return status === 'current' || status === 'supported' || status === 'deprecated'
}

// ============================================================================
// Version Validation
// ============================================================================

/**
 * Validate request version
 */
export function validateVersion(
  req: NextRequest,
  options: VersioningOptions
): VersionResult {
  const { current, supported, deprecated = [], sunset = [], sunsetDates = {} } = options

  // Extract version
  const { version, source } = extractVersion(req, options)

  // No version provided - use default
  if (!version) {
    return {
      version: current,
      source: null,
      status: 'current',
      valid: true,
    }
  }

  // Check if sunset (no longer available)
  if (sunset.includes(version)) {
    const sunsetDate = sunsetDates[version]
    return {
      version,
      source,
      status: 'sunset',
      valid: false,
      reason: `API version ${version} has been sunset${sunsetDate ? ` on ${sunsetDate.toISOString()}` : ''}`,
      sunsetDate,
    }
  }

  // Check if deprecated
  if (deprecated.includes(version)) {
    const sunsetDate = sunsetDates[version]
    return {
      version,
      source,
      status: 'deprecated',
      valid: true,
      sunsetDate,
    }
  }

  // Check if current
  if (version === current) {
    return {
      version,
      source,
      status: 'current',
      valid: true,
    }
  }

  // Check if supported
  if (supported.includes(version)) {
    return {
      version,
      source,
      status: 'supported',
      valid: true,
    }
  }

  // Unknown version
  return {
    version,
    source,
    status: null,
    valid: false,
    reason: `Unsupported API version: ${version}. Supported versions: ${[current, ...supported].join(', ')}`,
  }
}

// ============================================================================
// Deprecation Headers
// ============================================================================

/**
 * Add deprecation headers to response
 */
export function addDeprecationHeaders(
  response: Response,
  version: string,
  sunsetDate?: Date
): Response {
  const headers = new Headers(response.headers)

  // Add Deprecation header (RFC 8594)
  headers.set('Deprecation', 'true')

  // Add Sunset header if date is known
  if (sunsetDate) {
    headers.set('Sunset', sunsetDate.toUTCString())
  }

  // Add warning
  headers.set(
    'Warning',
    `299 - "API version ${version} is deprecated${sunsetDate ? ` and will be removed on ${sunsetDate.toISOString().split('T')[0]}` : ''}"`
  )

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

// ============================================================================
// Versioning Middleware
// ============================================================================

/**
 * Default response for unsupported version
 */
function defaultUnsupportedResponse(version: string, supportedVersions: string[]): Response {
  return new Response(
    JSON.stringify({
      error: 'Bad Request',
      message: `Unsupported API version: ${version}`,
      code: 'UNSUPPORTED_VERSION',
      supportedVersions,
    }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Default response for sunset version
 */
function defaultSunsetResponse(version: string, sunsetDate?: Date): Response {
  return new Response(
    JSON.stringify({
      error: 'Gone',
      message: `API version ${version} is no longer available${sunsetDate ? `. It was sunset on ${sunsetDate.toISOString().split('T')[0]}` : ''}`,
      code: 'VERSION_SUNSET',
    }),
    {
      status: 410,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Create API versioning middleware
 */
export function withAPIVersion<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: VersioningOptions
): (req: NextRequest, ctx: T) => Promise<Response> {
  return async (req: NextRequest, ctx: T): Promise<Response> => {
    // Check if should skip
    if (options.skip && await options.skip(req)) {
      return handler(req, ctx)
    }

    // Validate version
    const result = validateVersion(req, options)

    // Handle sunset version
    if (result.status === 'sunset') {
      return defaultSunsetResponse(result.version!, result.sunsetDate)
    }

    // Handle unsupported version
    if (!result.valid) {
      const onUnsupported = options.onUnsupported || (
        (v: string) => defaultUnsupportedResponse(v, [options.current, ...options.supported])
      )
      return onUnsupported(result.version!)
    }

    // Call handler
    let response = await handler(req, ctx)

    // Handle deprecated version
    if (result.status === 'deprecated') {
      // Call deprecation callback
      if (options.onDeprecated) {
        options.onDeprecated(result.version!, result.sunsetDate)
      }

      // Add deprecation headers
      if (options.addDeprecationHeaders !== false) {
        response = addDeprecationHeaders(response, result.version!, result.sunsetDate)
      }
    }

    return response
  }
}

// ============================================================================
// Version Router
// ============================================================================

type VersionHandler<T> = (req: NextRequest, ctx: T) => Response | Promise<Response>

/**
 * Create version-based router
 */
export function createVersionRouter<T = unknown>(
  handlers: Record<string, VersionHandler<T>>,
  options: Omit<VersioningOptions, 'current' | 'supported'> & { default?: string }
): (req: NextRequest, ctx: T) => Promise<Response> {
  const versions = Object.keys(handlers)
  const defaultVersion = options.default || versions[versions.length - 1]

  return async (req: NextRequest, ctx: T): Promise<Response> => {
    // Extract version
    const { version } = extractVersion(req, {
      ...options,
      current: defaultVersion,
      supported: versions,
    })

    // Use default if not specified
    const targetVersion = version || defaultVersion

    // Get handler
    const handler = handlers[targetVersion]
    if (!handler) {
      return defaultUnsupportedResponse(targetVersion, versions)
    }

    return handler(req, ctx)
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Compare semantic versions
 */
export function compareVersions(a: string, b: string): number {
  const partsA = a.split('.').map(Number)
  const partsB = b.split('.').map(Number)

  const maxLength = Math.max(partsA.length, partsB.length)

  for (let i = 0; i < maxLength; i++) {
    const numA = partsA[i] || 0
    const numB = partsB[i] || 0

    if (numA > numB) return 1
    if (numA < numB) return -1
  }

  return 0
}

/**
 * Check if version is greater than or equal to minimum
 */
export function isVersionAtLeast(version: string, minimum: string): boolean {
  return compareVersions(version, minimum) >= 0
}

/**
 * Normalize version string
 */
export function normalizeVersion(version: string): string {
  // Remove 'v' prefix if present
  version = version.replace(/^v/i, '')

  // Ensure at least major.minor format
  const parts = version.split('.')
  while (parts.length < 2) {
    parts.push('0')
  }

  return parts.join('.')
}
