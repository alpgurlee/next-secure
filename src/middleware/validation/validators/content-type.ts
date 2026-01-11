import type { NextRequest } from 'next/server'
import type { ContentTypeConfig } from '../types'

/**
 * Common MIME types
 */
export const MIME_TYPES = {
  // Text
  TEXT_PLAIN: 'text/plain',
  TEXT_HTML: 'text/html',
  TEXT_CSS: 'text/css',
  TEXT_JAVASCRIPT: 'text/javascript',

  // Application
  JSON: 'application/json',
  FORM_URLENCODED: 'application/x-www-form-urlencoded',
  MULTIPART_FORM: 'multipart/form-data',
  XML: 'application/xml',
  PDF: 'application/pdf',
  ZIP: 'application/zip',
  GZIP: 'application/gzip',
  OCTET_STREAM: 'application/octet-stream',

  // Image
  IMAGE_PNG: 'image/png',
  IMAGE_JPEG: 'image/jpeg',
  IMAGE_GIF: 'image/gif',
  IMAGE_WEBP: 'image/webp',
  IMAGE_SVG: 'image/svg+xml',

  // Audio
  AUDIO_MP3: 'audio/mpeg',
  AUDIO_WAV: 'audio/wav',
  AUDIO_OGG: 'audio/ogg',

  // Video
  VIDEO_MP4: 'video/mp4',
  VIDEO_WEBM: 'video/webm',
} as const

/**
 * Parse Content-Type header
 */
export function parseContentType(header: string | null): {
  type: string
  subtype: string
  mediaType: string
  charset?: string
  boundary?: string
  parameters: Record<string, string>
} {
  if (!header) {
    return {
      type: '',
      subtype: '',
      mediaType: '',
      parameters: {},
    }
  }

  // Split by semicolon to separate media type from parameters
  const parts = header.split(';').map(p => p.trim())
  const mediaType = parts[0].toLowerCase()

  // Split media type into type/subtype
  const [type = '', subtype = ''] = mediaType.split('/')

  // Parse parameters
  const parameters: Record<string, string> = {}
  for (let i = 1; i < parts.length; i++) {
    const [key, value] = parts[i].split('=').map(p => p.trim())
    if (key && value) {
      // Remove quotes if present
      parameters[key.toLowerCase()] = value.replace(/^["']|["']$/g, '')
    }
  }

  return {
    type,
    subtype,
    mediaType,
    charset: parameters['charset'],
    boundary: parameters['boundary'],
    parameters,
  }
}

/**
 * Check if Content-Type matches allowed types
 */
export function isAllowedContentType(
  contentType: string | null,
  allowedTypes: string[],
  strict = false
): boolean {
  if (!contentType) {
    return !strict
  }

  const { mediaType } = parseContentType(contentType)

  return allowedTypes.some(allowed => {
    const normalizedAllowed = allowed.toLowerCase().trim()

    // Exact match
    if (mediaType === normalizedAllowed) {
      return true
    }

    // Wildcard match (e.g., 'application/*' matches 'application/json')
    if (normalizedAllowed.endsWith('/*')) {
      const prefix = normalizedAllowed.slice(0, -2)
      return mediaType.startsWith(prefix + '/')
    }

    // Type-only match (e.g., 'application' matches 'application/json')
    if (!normalizedAllowed.includes('/')) {
      const { type } = parseContentType(contentType)
      return type === normalizedAllowed
    }

    return false
  })
}

/**
 * Validate Content-Type header
 */
export function validateContentType(
  request: NextRequest,
  config: ContentTypeConfig
): { valid: boolean; contentType: string | null; reason?: string } {
  const contentType = request.headers.get('content-type')
  const { allowed, strict = false, charset } = config

  // Check if Content-Type is required but missing
  if (strict && !contentType) {
    return {
      valid: false,
      contentType: null,
      reason: 'Content-Type header is required',
    }
  }

  // Check if Content-Type is allowed
  if (contentType && !isAllowedContentType(contentType, allowed, strict)) {
    return {
      valid: false,
      contentType,
      reason: `Content-Type '${contentType}' is not allowed`,
    }
  }

  // Check charset if specified
  if (charset && contentType) {
    const parsed = parseContentType(contentType)
    if (parsed.charset && parsed.charset.toLowerCase() !== charset.toLowerCase()) {
      return {
        valid: false,
        contentType,
        reason: `Charset '${parsed.charset}' is not allowed, expected '${charset}'`,
      }
    }
  }

  return { valid: true, contentType }
}

/**
 * Default Content-Type validation error response
 */
export function defaultContentTypeErrorResponse(
  contentType: string | null,
  reason: string
): Response {
  return new Response(
    JSON.stringify({
      error: 'invalid_content_type',
      message: reason,
      received: contentType,
    }),
    {
      status: 415,  // Unsupported Media Type
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Check if request has JSON content type
 */
export function isJsonRequest(request: NextRequest): boolean {
  return isAllowedContentType(
    request.headers.get('content-type'),
    [MIME_TYPES.JSON]
  )
}

/**
 * Check if request has form content type
 */
export function isFormRequest(request: NextRequest): boolean {
  return isAllowedContentType(
    request.headers.get('content-type'),
    [MIME_TYPES.FORM_URLENCODED, MIME_TYPES.MULTIPART_FORM]
  )
}

/**
 * Check if request has multipart content type
 */
export function isMultipartRequest(request: NextRequest): boolean {
  return isAllowedContentType(
    request.headers.get('content-type'),
    [MIME_TYPES.MULTIPART_FORM]
  )
}

/**
 * Get boundary from multipart Content-Type
 */
export function getMultipartBoundary(request: NextRequest): string | null {
  const contentType = request.headers.get('content-type')
  if (!contentType) return null

  const { boundary } = parseContentType(contentType)
  return boundary || null
}
