import type { PathValidationConfig, PathValidationResult } from '../types'

/**
 * Dangerous path patterns
 */
const DANGEROUS_PATTERNS = [
  // Unix path traversal
  /\.\.\//g,
  /\.\./g,
  // Windows path traversal
  /\.\.\\/g,
  // Null byte (can truncate paths in some systems)
  /%00/g,
  /\0/g,
  // URL encoded traversal
  /%2e%2e%2f/gi,  // ../
  /%2e%2e\//gi,   // ../
  /%2e%2e%5c/gi,  // ..\
  /%2e%2e\\/gi,   // ..\
  // Double URL encoding
  /%252e%252e%252f/gi,
  /%252e%252e%255c/gi,
  // Unicode encoding
  /\.%u002e\//gi,
  /%u002e%u002e%u002f/gi,
  // Overlong UTF-8 encoding
  /%c0%ae%c0%ae%c0%af/gi,
  /%c1%9c/gi,  // Backslash variant
]

/**
 * Default blocked extensions
 */
const DEFAULT_BLOCKED_EXTENSIONS = [
  '.exe', '.dll', '.so', '.dylib',  // Executables
  '.sh', '.bash', '.bat', '.cmd', '.ps1',  // Scripts
  '.php', '.asp', '.aspx', '.jsp', '.cgi',  // Server scripts
  '.htaccess', '.htpasswd',  // Apache config
  '.env', '.git', '.svn',  // Config/VCS
]

/**
 * Normalize path separators
 */
function normalizePathSeparators(path: string): string {
  return path.replace(/\\/g, '/')
}

/**
 * URL decode a path (handles double encoding)
 */
function decodePathComponent(path: string): string {
  let result = path
  let previous = ''

  // Keep decoding until no more changes (handles double encoding)
  while (result !== previous) {
    previous = result
    try {
      result = decodeURIComponent(result)
    } catch {
      break
    }
  }

  return result
}

/**
 * Check if path contains traversal patterns
 */
export function hasPathTraversal(path: string): boolean {
  if (!path || typeof path !== 'string') return false

  // Normalize and decode
  const normalized = normalizePathSeparators(decodePathComponent(path))

  // Check for dangerous patterns
  for (const pattern of DANGEROUS_PATTERNS) {
    pattern.lastIndex = 0
    if (pattern.test(normalized)) {
      return true
    }
  }

  // Check for .. sequences (already handled by patterns but double check)
  if (normalized.includes('..')) {
    return true
  }

  return false
}

/**
 * Validate and sanitize a path
 */
export function validatePath(
  path: string,
  config: PathValidationConfig = {}
): PathValidationResult {
  if (!path || typeof path !== 'string') {
    return { valid: false, reason: 'Path is empty or not a string' }
  }

  const {
    allowAbsolute = false,
    allowedPrefixes = [],
    allowedExtensions,
    blockedExtensions = DEFAULT_BLOCKED_EXTENSIONS,
    maxDepth = 10,
    maxLength = 255,
    normalize = true,
  } = config

  // Check length
  if (path.length > maxLength) {
    return { valid: false, reason: `Path exceeds maximum length of ${maxLength}` }
  }

  // Decode and normalize
  let normalized = decodePathComponent(path)
  if (normalize) {
    normalized = normalizePathSeparators(normalized)
  }

  // Check for null bytes
  if (normalized.includes('\0') || path.includes('%00')) {
    return { valid: false, reason: 'Path contains null bytes' }
  }

  // Check for path traversal
  if (hasPathTraversal(path)) {
    return { valid: false, reason: 'Path contains traversal sequences' }
  }

  // Check absolute path
  const isAbsolute = normalized.startsWith('/') ||
    /^[a-zA-Z]:/.test(normalized) ||  // Windows drive letter
    normalized.startsWith('\\\\')  // UNC path

  if (isAbsolute && !allowAbsolute) {
    return { valid: false, reason: 'Absolute paths are not allowed' }
  }

  // Check allowed prefixes
  if (allowedPrefixes.length > 0) {
    const hasValidPrefix = allowedPrefixes.some(prefix => {
      const normalizedPrefix = normalizePathSeparators(prefix)
      return normalized.startsWith(normalizedPrefix)
    })

    if (!hasValidPrefix) {
      return { valid: false, reason: 'Path does not start with an allowed prefix' }
    }
  }

  // Check path depth
  const segments = normalized.split('/').filter(s => s && s !== '.')
  if (segments.length > maxDepth) {
    return { valid: false, reason: `Path depth exceeds maximum of ${maxDepth}` }
  }

  // Get extension
  const lastSegment = segments[segments.length - 1] || ''
  const dotIndex = lastSegment.lastIndexOf('.')
  const extension = dotIndex > 0 ? lastSegment.slice(dotIndex).toLowerCase() : ''

  // Check blocked extensions
  if (extension && blockedExtensions.length > 0) {
    if (blockedExtensions.map(e => e.toLowerCase()).includes(extension)) {
      return { valid: false, reason: `Extension ${extension} is not allowed` }
    }
  }

  // Check allowed extensions
  if (extension && allowedExtensions && allowedExtensions.length > 0) {
    if (!allowedExtensions.map(e => e.toLowerCase()).includes(extension)) {
      return { valid: false, reason: `Extension ${extension} is not in allowed list` }
    }
  }

  // Normalize double slashes
  const sanitized = normalized.replace(/\/+/g, '/')

  return { valid: true, sanitized }
}

/**
 * Sanitize a path by removing dangerous elements
 */
export function sanitizePath(
  path: string,
  config: PathValidationConfig = {}
): string {
  if (!path || typeof path !== 'string') return ''

  const { normalize = true, maxLength = 255 } = config

  // Decode
  let result = decodePathComponent(path)

  // Normalize separators
  if (normalize) {
    result = normalizePathSeparators(result)
  }

  // Remove null bytes
  result = result.replace(/\0/g, '').replace(/%00/g, '')

  // Remove traversal sequences
  result = result.replace(/\.\.\//g, '').replace(/\.\.\\/g, '')

  // Remove leading slashes if not allowed absolute
  if (!config.allowAbsolute) {
    result = result.replace(/^\/+/, '')
    result = result.replace(/^[a-zA-Z]:/, '')
    result = result.replace(/^\\\\/, '')
  }

  // Remove double slashes
  result = result.replace(/\/+/g, '/')

  // Remove trailing slashes
  result = result.replace(/\/+$/, '')

  // Limit length
  if (result.length > maxLength) {
    result = result.slice(0, maxLength)
  }

  return result
}

/**
 * Check if a path is within a base directory (safe containment)
 */
export function isPathContained(path: string, baseDir: string): boolean {
  if (!path || !baseDir) return false

  // Normalize both paths
  const normalizedPath = normalizePathSeparators(decodePathComponent(path))
  const normalizedBase = normalizePathSeparators(baseDir)

  // Resolve the path (simulate what a file system would do)
  const resolvedPath = resolvePath(normalizedPath, normalizedBase)

  // Check if resolved path starts with base directory
  return resolvedPath.startsWith(normalizedBase.replace(/\/$/, '') + '/')
}

/**
 * Simple path resolver (simulates path.resolve)
 */
function resolvePath(path: string, base: string): string {
  // Combine base and path
  let combined: string
  if (path.startsWith('/')) {
    combined = path
  } else {
    combined = `${base.replace(/\/$/, '')}/${path}`
  }

  // Resolve . and ..
  const segments: string[] = []
  for (const segment of combined.split('/')) {
    if (segment === '' || segment === '.') {
      continue
    }
    if (segment === '..') {
      segments.pop()
    } else {
      segments.push(segment)
    }
  }

  return '/' + segments.join('/')
}

/**
 * Get the file extension from a path
 */
export function getExtension(path: string): string {
  if (!path || typeof path !== 'string') return ''

  const normalized = normalizePathSeparators(path)
  const segments = normalized.split('/')
  const filename = segments[segments.length - 1] || ''

  const dotIndex = filename.lastIndexOf('.')
  if (dotIndex <= 0) return ''  // No extension or hidden file

  return filename.slice(dotIndex).toLowerCase()
}

/**
 * Get the filename from a path
 */
export function getFilename(path: string): string {
  if (!path || typeof path !== 'string') return ''

  const normalized = normalizePathSeparators(path)
  const segments = normalized.split('/')

  return segments[segments.length - 1] || ''
}

/**
 * Sanitize a filename (remove dangerous characters)
 */
export function sanitizeFilename(filename: string): string {
  if (typeof filename !== 'string') return 'file'
  if (!filename) return 'file'

  let result = filename

  // Remove path separators
  result = result.replace(/[/\\]/g, '')

  // Remove null bytes
  result = result.replace(/\0/g, '')

  // Remove control characters
  result = result.replace(/[\x00-\x1f\x7f]/g, '')

  // Remove dangerous characters for file systems
  result = result.replace(/[<>:"|?*]/g, '')

  // Remove leading/trailing dots and spaces
  result = result.replace(/^[.\s]+|[.\s]+$/g, '')

  // Limit length (common file system limit)
  if (result.length > 255) {
    const ext = getExtension(result)
    const name = result.slice(0, 255 - ext.length)
    result = name + ext
  }

  return result || 'file'
}

/**
 * Check if path is a hidden file (starts with dot)
 */
export function isHiddenPath(path: string): boolean {
  if (!path) return false

  const normalized = normalizePathSeparators(path)
  const segments = normalized.split('/').filter(Boolean)

  return segments.some(segment => segment.startsWith('.'))
}
