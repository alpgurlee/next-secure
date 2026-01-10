/**
 * IP address extraction and validation utilities
 */

import type { NextRequest } from '../core/types'

/**
 * Headers to check for client IP (in order of priority)
 */
const IP_HEADERS = [
  // Cloudflare
  'cf-connecting-ip',
  // Vercel
  'x-real-ip',
  // Standard forwarded header (RFC 7239)
  'x-forwarded-for',
  // AWS ELB
  'x-client-ip',
  // Azure
  'client-ip',
  // Fastly
  'fastly-client-ip',
  // Akamai
  'true-client-ip',
  // Google Cloud
  'x-appengine-user-ip',
  // Fly.io
  'fly-client-ip',
] as const

/**
 * Localhost/private IP patterns
 */
const PRIVATE_IP_PATTERNS = [
  /^127\./,                           // IPv4 loopback
  /^10\./,                            // Private class A
  /^172\.(1[6-9]|2[0-9]|3[01])\./,   // Private class B
  /^192\.168\./,                      // Private class C
  /^::1$/,                            // IPv6 loopback
  /^fe80:/i,                          // IPv6 link-local
  /^fc00:/i,                          // IPv6 unique local
  /^fd[0-9a-f]{2}:/i,                // IPv6 unique local
]

/**
 * IPv4 validation regex
 */
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/

/**
 * IPv6 validation regex (simplified)
 */
const IPV6_REGEX = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^::1$|^::$|^(?:[a-fA-F0-9]{1,4}:)*:(?:[a-fA-F0-9]{1,4}:)*[a-fA-F0-9]{1,4}$/

/**
 * Options for IP extraction
 */
export interface GetIpOptions {
  /**
   * Trust proxy headers (default: true)
   * Set to false in direct-to-client setups
   */
  trustProxy?: boolean

  /**
   * Additional headers to check (checked first)
   */
  customHeaders?: string[]

  /**
   * Fallback IP when none found
   */
  fallback?: string
}

/**
 * Extract client IP address from request
 *
 * @example
 * ```typescript
 * // Basic usage
 * const ip = getClientIp(request)
 *
 * // With options
 * const ip = getClientIp(request, {
 *   trustProxy: true,
 *   customHeaders: ['my-custom-ip-header'],
 *   fallback: '0.0.0.0'
 * })
 * ```
 *
 * @param request - Next.js request object
 * @param options - Extraction options
 * @returns Client IP address or fallback
 */
export function getClientIp(request: NextRequest, options: GetIpOptions = {}): string {
  const { trustProxy = true, customHeaders = [], fallback = '127.0.0.1' } = options

  // First, check if Next.js has already extracted the IP
  if (request.ip) {
    return normalizeIp(request.ip)
  }

  if (!trustProxy) {
    return fallback
  }

  // Check custom headers first
  for (const header of customHeaders) {
    const value = request.headers.get(header)
    if (value) {
      const ip = parseIpFromHeader(value)
      if (ip) return ip
    }
  }

  // Check standard headers
  for (const header of IP_HEADERS) {
    const value = request.headers.get(header)
    if (value) {
      const ip = parseIpFromHeader(value)
      if (ip) return ip
    }
  }

  return fallback
}

/**
 * Parse IP from header value
 * Handles comma-separated lists (x-forwarded-for)
 */
function parseIpFromHeader(headerValue: string): string | null {
  // x-forwarded-for can have multiple IPs: "client, proxy1, proxy2"
  // The first one is the client IP
  const ips = headerValue.split(',').map((ip) => ip.trim())

  for (const ip of ips) {
    const normalized = normalizeIp(ip)
    if (isValidIp(normalized)) {
      return normalized
    }
  }

  return null
}

/**
 * Normalize an IP address
 * - Removes IPv6 brackets
 * - Removes port numbers
 * - Trims whitespace
 */
export function normalizeIp(ip: string): string {
  let normalized = ip.trim()

  // Remove IPv6 brackets: [::1] -> ::1
  if (normalized.startsWith('[') && normalized.includes(']')) {
    normalized = normalized.slice(1, normalized.indexOf(']'))
  }

  // Remove port: 192.168.1.1:8080 -> 192.168.1.1
  // For IPv4 with port
  if (normalized.includes(':') && !normalized.includes('::')) {
    const lastColon = normalized.lastIndexOf(':')
    const potentialPort = normalized.slice(lastColon + 1)
    if (/^\d+$/.test(potentialPort)) {
      normalized = normalized.slice(0, lastColon)
    }
  }

  // Handle IPv4-mapped IPv6: ::ffff:192.168.1.1 -> 192.168.1.1
  if (normalized.toLowerCase().startsWith('::ffff:')) {
    const ipv4Part = normalized.slice(7)
    if (isValidIpv4(ipv4Part)) {
      return ipv4Part
    }
  }

  return normalized
}

/**
 * Check if an IP address is valid
 */
export function isValidIp(ip: string): boolean {
  return isValidIpv4(ip) || isValidIpv6(ip)
}

/**
 * Check if an IPv4 address is valid
 */
export function isValidIpv4(ip: string): boolean {
  return IPV4_REGEX.test(ip)
}

/**
 * Check if an IPv6 address is valid
 */
export function isValidIpv6(ip: string): boolean {
  return IPV6_REGEX.test(ip) || ip === '::1' || ip === '::'
}

/**
 * Check if an IP is a private/local address
 */
export function isPrivateIp(ip: string): boolean {
  return PRIVATE_IP_PATTERNS.some((pattern) => pattern.test(ip))
}

/**
 * Check if an IP is localhost
 */
export function isLocalhost(ip: string): boolean {
  return ip === '127.0.0.1' || ip === '::1' || ip === 'localhost'
}

/**
 * Create a rate limit key from IP
 * Normalizes and optionally hashes the IP
 */
export function createIpKey(
  ip: string,
  options: {
    prefix?: string
    hash?: boolean
  } = {}
): string {
  const { prefix = 'rl', hash = false } = options
  const normalizedIp = normalizeIp(ip)

  if (hash) {
    // Simple hash for privacy (not cryptographic)
    const hashCode = simpleHash(normalizedIp)
    return `${prefix}:ip:${hashCode}`
  }

  return `${prefix}:ip:${normalizedIp}`
}

/**
 * Simple non-cryptographic hash (for key generation)
 */
function simpleHash(str: string): string {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(36)
}

/**
 * Anonymize an IP address (for logging)
 * IPv4: 192.168.1.100 -> 192.168.1.xxx
 * IPv6: 2001:db8::1 -> 2001:db8::xxx
 */
export function anonymizeIp(ip: string): string {
  const normalized = normalizeIp(ip)

  if (isValidIpv4(normalized)) {
    const parts = normalized.split('.')
    parts[3] = 'xxx'
    return parts.join('.')
  }

  if (isValidIpv6(normalized)) {
    const parts = normalized.split(':')
    if (parts.length > 0) {
      parts[parts.length - 1] = 'xxxx'
    }
    return parts.join(':')
  }

  return 'xxx.xxx.xxx.xxx'
}

/**
 * Get geolocation info from request (if available)
 * Works with Vercel Edge and Cloudflare
 */
export function getGeoInfo(request: NextRequest): {
  country?: string
  city?: string
  region?: string
  latitude?: string
  longitude?: string
} {
  // Vercel provides geo info on the request
  if (request.geo) {
    return {
      country: request.geo.country,
      city: request.geo.city,
      region: request.geo.region,
      latitude: request.geo.latitude,
      longitude: request.geo.longitude,
    }
  }

  // Cloudflare headers
  return {
    country: request.headers.get('cf-ipcountry') ?? undefined,
    city: request.headers.get('cf-ipcity') ?? undefined,
    region: request.headers.get('cf-region') ?? undefined,
    latitude: request.headers.get('cf-iplat') ?? undefined,
    longitude: request.headers.get('cf-iplong') ?? undefined,
  }
}
