import { describe, it, expect } from 'vitest'
import {
  checkMagicNumber,
  detectFileType,
  DEFAULT_MAX_FILE_SIZE,
  DANGEROUS_EXTENSIONS,
} from '../../../src/middleware/validation'

describe('checkMagicNumber', () => {
  it('detects JPEG magic number', () => {
    const jpegBytes = new Uint8Array([0xFF, 0xD8, 0xFF, 0xE0])
    const result = checkMagicNumber(jpegBytes, {
      type: 'image/jpeg',
      extension: '.jpg',
      signature: [0xFF, 0xD8, 0xFF],
    })
    expect(result).toBe(true)
  })

  it('detects PNG magic number', () => {
    const pngBytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    const result = checkMagicNumber(pngBytes, {
      type: 'image/png',
      extension: '.png',
      signature: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    })
    expect(result).toBe(true)
  })

  it('detects PDF magic number', () => {
    const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2D])
    const result = checkMagicNumber(pdfBytes, {
      type: 'application/pdf',
      extension: '.pdf',
      signature: [0x25, 0x50, 0x44, 0x46],
    })
    expect(result).toBe(true)
  })

  it('returns false for non-matching signature', () => {
    const randomBytes = new Uint8Array([0x00, 0x01, 0x02, 0x03])
    const result = checkMagicNumber(randomBytes, {
      type: 'image/jpeg',
      extension: '.jpg',
      signature: [0xFF, 0xD8, 0xFF],
    })
    expect(result).toBe(false)
  })

  it('returns false for insufficient bytes', () => {
    const shortBytes = new Uint8Array([0xFF, 0xD8])
    const result = checkMagicNumber(shortBytes, {
      type: 'image/jpeg',
      extension: '.jpg',
      signature: [0xFF, 0xD8, 0xFF],
    })
    expect(result).toBe(false)
  })

  it('handles offset parameter', () => {
    const bytes = new Uint8Array([0x00, 0x00, 0x89, 0x50, 0x4E, 0x47])
    const result = checkMagicNumber(bytes, {
      type: 'image/png',
      extension: '.png',
      signature: [0x89, 0x50, 0x4E, 0x47],
      offset: 2,
    })
    expect(result).toBe(true)
  })
})

describe('detectFileType', () => {
  it('detects JPEG files', () => {
    const bytes = new Uint8Array([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
    const result = detectFileType(bytes)
    expect(result).not.toBeNull()
    expect(result?.type).toBe('image/jpeg')
    expect(result?.extension).toBe('.jpg')
  })

  it('detects PNG files', () => {
    const bytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    const result = detectFileType(bytes)
    expect(result).not.toBeNull()
    expect(result?.type).toBe('image/png')
    expect(result?.extension).toBe('.png')
  })

  it('detects GIF files', () => {
    const bytes = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])  // GIF89a
    const result = detectFileType(bytes)
    expect(result).not.toBeNull()
    expect(result?.type).toBe('image/gif')
    expect(result?.extension).toBe('.gif')
  })

  it('detects PDF files', () => {
    const bytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31])  // %PDF-1
    const result = detectFileType(bytes)
    expect(result).not.toBeNull()
    expect(result?.type).toBe('application/pdf')
    expect(result?.extension).toBe('.pdf')
  })

  it('detects ZIP files', () => {
    const bytes = new Uint8Array([0x50, 0x4B, 0x03, 0x04])
    const result = detectFileType(bytes)
    expect(result).not.toBeNull()
    expect(result?.type).toBe('application/zip')
    expect(result?.extension).toBe('.zip')
  })

  it('returns null for unknown file types', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0x02, 0x03])
    const result = detectFileType(bytes)
    expect(result).toBeNull()
  })

  it('returns null for empty bytes', () => {
    const bytes = new Uint8Array([])
    const result = detectFileType(bytes)
    expect(result).toBeNull()
  })
})

describe('constants', () => {
  it('has correct default max file size', () => {
    expect(DEFAULT_MAX_FILE_SIZE).toBe(10 * 1024 * 1024)  // 10MB
  })

  it('includes common dangerous extensions', () => {
    expect(DANGEROUS_EXTENSIONS).toContain('.exe')
    expect(DANGEROUS_EXTENSIONS).toContain('.dll')
    expect(DANGEROUS_EXTENSIONS).toContain('.sh')
    expect(DANGEROUS_EXTENSIONS).toContain('.php')
    expect(DANGEROUS_EXTENSIONS).toContain('.bat')
    expect(DANGEROUS_EXTENSIONS).toContain('.ps1')
  })

  it('blocks script extensions', () => {
    const scriptExtensions = ['.sh', '.bash', '.bat', '.cmd', '.ps1', '.vbs']
    scriptExtensions.forEach(ext => {
      expect(DANGEROUS_EXTENSIONS).toContain(ext)
    })
  })

  it('blocks server-side code extensions', () => {
    const serverExtensions = ['.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl']
    serverExtensions.forEach(ext => {
      expect(DANGEROUS_EXTENSIONS).toContain(ext)
    })
  })
})
