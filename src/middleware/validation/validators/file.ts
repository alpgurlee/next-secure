import type { NextRequest } from 'next/server'
import type { FileValidationConfig, FileValidationError, FileInfo, MagicNumber } from '../types'
import { sanitizeFilename, getExtension } from '../sanitizers/path'

/**
 * Known magic numbers for file type validation
 */
const MAGIC_NUMBERS: MagicNumber[] = [
  // Images
  { type: 'image/jpeg', extension: '.jpg', signature: [0xFF, 0xD8, 0xFF] },
  { type: 'image/png', extension: '.png', signature: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
  { type: 'image/gif', extension: '.gif', signature: [0x47, 0x49, 0x46, 0x38] },  // GIF87a or GIF89a
  { type: 'image/webp', extension: '.webp', signature: [0x52, 0x49, 0x46, 0x46], offset: 0 },  // RIFF
  { type: 'image/bmp', extension: '.bmp', signature: [0x42, 0x4D] },
  { type: 'image/tiff', extension: '.tiff', signature: [0x49, 0x49, 0x2A, 0x00] },  // Little endian
  { type: 'image/tiff', extension: '.tiff', signature: [0x4D, 0x4D, 0x00, 0x2A] },  // Big endian
  { type: 'image/x-icon', extension: '.ico', signature: [0x00, 0x00, 0x01, 0x00] },
  { type: 'image/svg+xml', extension: '.svg', signature: [0x3C, 0x3F, 0x78, 0x6D, 0x6C] },  // <?xml

  // Documents
  { type: 'application/pdf', extension: '.pdf', signature: [0x25, 0x50, 0x44, 0x46] },  // %PDF
  { type: 'application/zip', extension: '.zip', signature: [0x50, 0x4B, 0x03, 0x04] },  // PK
  { type: 'application/gzip', extension: '.gz', signature: [0x1F, 0x8B] },
  { type: 'application/x-rar-compressed', extension: '.rar', signature: [0x52, 0x61, 0x72, 0x21] },
  { type: 'application/x-7z-compressed', extension: '.7z', signature: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },

  // Microsoft Office (new format - zip based)
  { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', extension: '.xlsx', signature: [0x50, 0x4B, 0x03, 0x04] },
  { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', extension: '.docx', signature: [0x50, 0x4B, 0x03, 0x04] },
  { type: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', extension: '.pptx', signature: [0x50, 0x4B, 0x03, 0x04] },

  // Microsoft Office (old format)
  { type: 'application/msword', extension: '.doc', signature: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },
  { type: 'application/vnd.ms-excel', extension: '.xls', signature: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },

  // Audio
  { type: 'audio/mpeg', extension: '.mp3', signature: [0xFF, 0xFB] },  // MP3 frame sync
  { type: 'audio/mpeg', extension: '.mp3', signature: [0x49, 0x44, 0x33] },  // ID3
  { type: 'audio/wav', extension: '.wav', signature: [0x52, 0x49, 0x46, 0x46] },  // RIFF
  { type: 'audio/ogg', extension: '.ogg', signature: [0x4F, 0x67, 0x67, 0x53] },
  { type: 'audio/flac', extension: '.flac', signature: [0x66, 0x4C, 0x61, 0x43] },

  // Video
  { type: 'video/mp4', extension: '.mp4', signature: [0x00, 0x00, 0x00], offset: 0 },  // Partial match
  { type: 'video/webm', extension: '.webm', signature: [0x1A, 0x45, 0xDF, 0xA3] },
  { type: 'video/avi', extension: '.avi', signature: [0x52, 0x49, 0x46, 0x46] },  // RIFF
  { type: 'video/quicktime', extension: '.mov', signature: [0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70] },

  // Web
  { type: 'application/wasm', extension: '.wasm', signature: [0x00, 0x61, 0x73, 0x6D] },  // \0asm

  // Fonts
  { type: 'font/woff', extension: '.woff', signature: [0x77, 0x4F, 0x46, 0x46] },
  { type: 'font/woff2', extension: '.woff2', signature: [0x77, 0x4F, 0x46, 0x32] },
]

/**
 * Default file size limits
 */
export const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  // 10MB
export const DEFAULT_MAX_FILES = 10

/**
 * Dangerous file extensions to block by default
 */
export const DANGEROUS_EXTENSIONS = [
  '.exe', '.dll', '.so', '.dylib', '.bin',
  '.sh', '.bash', '.bat', '.cmd', '.ps1', '.vbs',
  '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl',
  '.py', '.rb', '.jar', '.class',
  '.msi', '.dmg', '.pkg', '.deb', '.rpm',
  '.scr', '.pif', '.com', '.hta',
]

/**
 * Check magic number signature
 */
export function checkMagicNumber(bytes: Uint8Array, magicNumber: MagicNumber): boolean {
  const offset = magicNumber.offset || 0
  const signature = magicNumber.signature

  if (bytes.length < offset + signature.length) {
    return false
  }

  for (let i = 0; i < signature.length; i++) {
    if (bytes[offset + i] !== signature[i]) {
      return false
    }
  }

  return true
}

/**
 * Detect file type from magic number
 */
export function detectFileType(bytes: Uint8Array): { type: string; extension: string } | null {
  for (const magic of MAGIC_NUMBERS) {
    if (checkMagicNumber(bytes, magic)) {
      return { type: magic.type, extension: magic.extension }
    }
  }
  return null
}

/**
 * Validate a single file
 */
export async function validateFile(
  file: File,
  config: FileValidationConfig = {}
): Promise<{ valid: boolean; info: FileInfo; errors: FileValidationError[] }> {
  const {
    maxSize = DEFAULT_MAX_FILE_SIZE,
    minSize = 0,
    allowedTypes = [],
    blockedTypes = [],
    allowedExtensions = [],
    blockedExtensions = DANGEROUS_EXTENSIONS,
    validateMagicNumbers = true,
    sanitizeFilename: doSanitize = true,
  } = config

  const errors: FileValidationError[] = []
  const extension = getExtension(file.name)

  const info: FileInfo = {
    filename: doSanitize ? sanitizeFilename(file.name) : file.name,
    size: file.size,
    type: file.type,
    extension,
  }

  // Check size
  if (file.size > maxSize) {
    errors.push({
      filename: file.name,
      code: 'size_exceeded',
      message: `File size (${formatBytes(file.size)}) exceeds maximum allowed (${formatBytes(maxSize)})`,
      details: { size: file.size, maxSize },
    })
  }

  if (file.size < minSize) {
    errors.push({
      filename: file.name,
      code: 'size_too_small',
      message: `File size (${formatBytes(file.size)}) is below minimum required (${formatBytes(minSize)})`,
      details: { size: file.size, minSize },
    })
  }

  // Check extension
  if (blockedExtensions.length > 0 && extension) {
    if (blockedExtensions.map(e => e.toLowerCase()).includes(extension.toLowerCase())) {
      errors.push({
        filename: file.name,
        code: 'extension_not_allowed',
        message: `File extension '${extension}' is not allowed`,
        details: { extension, blockedExtensions },
      })
    }
  }

  if (allowedExtensions.length > 0 && extension) {
    if (!allowedExtensions.map(e => e.toLowerCase()).includes(extension.toLowerCase())) {
      errors.push({
        filename: file.name,
        code: 'extension_not_allowed',
        message: `File extension '${extension}' is not in allowed list`,
        details: { extension, allowedExtensions },
      })
    }
  }

  // Check MIME type
  if (blockedTypes.length > 0 && file.type) {
    if (blockedTypes.includes(file.type)) {
      errors.push({
        filename: file.name,
        code: 'type_not_allowed',
        message: `File type '${file.type}' is not allowed`,
        details: { type: file.type, blockedTypes },
      })
    }
  }

  if (allowedTypes.length > 0) {
    if (!allowedTypes.includes(file.type)) {
      errors.push({
        filename: file.name,
        code: 'type_not_allowed',
        message: `File type '${file.type}' is not in allowed list`,
        details: { type: file.type, allowedTypes },
      })
    }
  }

  // Validate magic numbers
  if (validateMagicNumbers && errors.length === 0) {
    try {
      const buffer = await file.arrayBuffer()
      const bytes = new Uint8Array(buffer.slice(0, 32))  // Read first 32 bytes
      const detected = detectFileType(bytes)

      if (detected) {
        // Check if detected type matches claimed type
        if (file.type && detected.type !== file.type) {
          // Allow some flexibility for similar types
          const isSimilar =
            (detected.type.startsWith('image/') && file.type.startsWith('image/')) ||
            (detected.type.startsWith('audio/') && file.type.startsWith('audio/')) ||
            (detected.type.startsWith('video/') && file.type.startsWith('video/'))

          if (!isSimilar) {
            errors.push({
              filename: file.name,
              code: 'invalid_content',
              message: `File content doesn't match declared type (claimed: ${file.type}, detected: ${detected.type})`,
              details: { claimed: file.type, detected: detected.type },
            })
          }
        }
      }
    } catch {
      // Ignore read errors
    }
  }

  return {
    valid: errors.length === 0,
    info,
    errors,
  }
}

/**
 * Validate multiple files
 */
export async function validateFiles(
  files: File[],
  config: FileValidationConfig = {}
): Promise<{ valid: boolean; infos: FileInfo[]; errors: FileValidationError[] }> {
  const { maxFiles = DEFAULT_MAX_FILES } = config

  const allErrors: FileValidationError[] = []
  const infos: FileInfo[] = []

  // Check total file count
  if (files.length > maxFiles) {
    allErrors.push({
      filename: '',
      code: 'too_many_files',
      message: `Too many files (${files.length}), maximum allowed is ${maxFiles}`,
      details: { count: files.length, maxFiles },
    })
  }

  // Validate each file
  for (const file of files) {
    const result = await validateFile(file, config)
    infos.push(result.info)
    allErrors.push(...result.errors)
  }

  return {
    valid: allErrors.length === 0,
    infos,
    errors: allErrors,
  }
}

/**
 * Extract files from FormData
 */
export function extractFilesFromFormData(formData: FormData): Map<string, File[]> {
  const files = new Map<string, File[]>()

  formData.forEach((value, key) => {
    if (value instanceof File) {
      const existing = files.get(key) || []
      existing.push(value)
      files.set(key, existing)
    }
  })

  return files
}

/**
 * Validate files from a request
 */
export async function validateFilesFromRequest(
  request: NextRequest,
  config: FileValidationConfig = {}
): Promise<{ valid: boolean; files: Map<string, FileInfo[]>; errors: FileValidationError[] }> {
  const contentType = request.headers.get('content-type') || ''

  if (!contentType.includes('multipart/form-data')) {
    return { valid: true, files: new Map(), errors: [] }
  }

  try {
    const formData = await request.formData()
    const fileMap = extractFilesFromFormData(formData)

    const allInfos = new Map<string, FileInfo[]>()
    const allErrors: FileValidationError[] = []

    let totalFileCount = 0

    for (const [field, files] of fileMap.entries()) {
      totalFileCount += files.length
      const result = await validateFiles(files, { ...config, maxFiles: Infinity })  // Check max later

      allInfos.set(field, result.infos)
      allErrors.push(...result.errors.map(e => ({ ...e, field })))
    }

    // Check total file count across all fields
    const maxFiles = config.maxFiles ?? DEFAULT_MAX_FILES
    if (totalFileCount > maxFiles) {
      allErrors.push({
        filename: '',
        code: 'too_many_files',
        message: `Total file count (${totalFileCount}) exceeds maximum (${maxFiles})`,
        details: { count: totalFileCount, maxFiles },
      })
    }

    return {
      valid: allErrors.length === 0,
      files: allInfos,
      errors: allErrors,
    }
  } catch {
    return {
      valid: false,
      files: new Map(),
      errors: [{
        filename: '',
        code: 'invalid_content',
        message: 'Failed to parse multipart form data',
      }],
    }
  }
}

/**
 * Default file validation error response
 */
export function defaultFileErrorResponse(errors: FileValidationError[]): Response {
  return new Response(
    JSON.stringify({
      error: 'file_validation_error',
      message: 'File validation failed',
      details: errors.map(e => ({
        filename: e.filename,
        field: e.field,
        code: e.code,
        message: e.message,
      })),
    }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'

  const units = ['B', 'KB', 'MB', 'GB']
  const k = 1024
  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${units[i]}`
}
