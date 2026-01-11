import { describe, it, expect } from 'vitest'
import {
  validatePath,
  sanitizePath,
  hasPathTraversal,
  isPathContained,
  getExtension,
  getFilename,
  sanitizeFilename,
  isHiddenPath,
} from '../../../src/middleware/validation'

describe('hasPathTraversal', () => {
  it('detects unix path traversal', () => {
    expect(hasPathTraversal('../etc/passwd')).toBe(true)
    expect(hasPathTraversal('../../secret')).toBe(true)
    expect(hasPathTraversal('dir/../../../etc')).toBe(true)
  })

  it('detects windows path traversal', () => {
    expect(hasPathTraversal('..\\windows\\system32')).toBe(true)
    expect(hasPathTraversal('..\\..\\secret')).toBe(true)
  })

  it('detects URL encoded traversal', () => {
    expect(hasPathTraversal('%2e%2e%2f')).toBe(true)
    expect(hasPathTraversal('%2e%2e/')).toBe(true)
    expect(hasPathTraversal('..%2f')).toBe(true)
  })

  it('detects double URL encoding', () => {
    expect(hasPathTraversal('%252e%252e%252f')).toBe(true)
  })

  it('detects null byte injection', () => {
    expect(hasPathTraversal('file.txt%00.jpg')).toBe(true)
  })

  it('returns false for safe paths', () => {
    expect(hasPathTraversal('file.txt')).toBe(false)
    expect(hasPathTraversal('dir/file.txt')).toBe(false)
    expect(hasPathTraversal('path/to/file')).toBe(false)
  })
})

describe('validatePath', () => {
  it('validates safe relative paths', () => {
    const result = validatePath('uploads/file.txt')
    expect(result.valid).toBe(true)
  })

  it('rejects path traversal', () => {
    const result = validatePath('../secret/file.txt')
    expect(result.valid).toBe(false)
    expect(result.reason).toContain('traversal')
  })

  it('rejects absolute paths by default', () => {
    const result = validatePath('/etc/passwd')
    expect(result.valid).toBe(false)
    expect(result.reason).toContain('Absolute')
  })

  it('allows absolute paths when configured', () => {
    const result = validatePath('/uploads/file.txt', { allowAbsolute: true })
    expect(result.valid).toBe(true)
  })

  it('validates allowed prefixes', () => {
    const config = { allowedPrefixes: ['uploads/', 'public/'] }

    expect(validatePath('uploads/file.txt', config).valid).toBe(true)
    expect(validatePath('private/file.txt', config).valid).toBe(false)
  })

  it('validates allowed extensions', () => {
    const config = { allowedExtensions: ['.jpg', '.png'] }

    expect(validatePath('image.jpg', config).valid).toBe(true)
    expect(validatePath('script.exe', config).valid).toBe(false)
  })

  it('blocks dangerous extensions', () => {
    expect(validatePath('shell.exe').valid).toBe(false)
    expect(validatePath('backdoor.php').valid).toBe(false)
    expect(validatePath('script.sh').valid).toBe(false)
  })

  it('validates path depth', () => {
    const config = { maxDepth: 3 }

    expect(validatePath('a/b/c.txt', config).valid).toBe(true)
    expect(validatePath('a/b/c/d/e.txt', config).valid).toBe(false)
  })

  it('validates path length', () => {
    const longPath = 'a'.repeat(300) + '.txt'
    expect(validatePath(longPath).valid).toBe(false)
  })

  it('returns sanitized path', () => {
    const result = validatePath('path//to///file.txt')
    expect(result.valid).toBe(true)
    expect(result.sanitized).toBe('path/to/file.txt')
  })
})

describe('sanitizePath', () => {
  it('removes traversal sequences', () => {
    expect(sanitizePath('../secret')).toBe('secret')
    expect(sanitizePath('../../etc/passwd')).toBe('etc/passwd')
  })

  it('normalizes path separators', () => {
    expect(sanitizePath('path\\to\\file')).toBe('path/to/file')
  })

  it('removes double slashes', () => {
    expect(sanitizePath('path//to///file')).toBe('path/to/file')
  })

  it('removes leading slashes when not allowed', () => {
    expect(sanitizePath('/etc/passwd')).toBe('etc/passwd')
  })

  it('removes null bytes', () => {
    expect(sanitizePath('file.txt%00.jpg')).toBe('file.txt.jpg')
  })

  it('removes trailing slashes', () => {
    expect(sanitizePath('path/to/dir/')).toBe('path/to/dir')
  })
})

describe('isPathContained', () => {
  it('returns true for contained paths', () => {
    expect(isPathContained('uploads/file.txt', '/var/www/uploads')).toBe(true)
    expect(isPathContained('file.txt', '/var/www')).toBe(true)
  })

  it('returns false for escaped paths', () => {
    expect(isPathContained('../etc/passwd', '/var/www')).toBe(false)
    expect(isPathContained('../../secret', '/var/www/uploads')).toBe(false)
  })
})

describe('getExtension', () => {
  it('extracts file extension', () => {
    expect(getExtension('file.txt')).toBe('.txt')
    expect(getExtension('image.png')).toBe('.png')
    expect(getExtension('path/to/file.js')).toBe('.js')
  })

  it('returns empty for no extension', () => {
    expect(getExtension('filename')).toBe('')
    expect(getExtension('Makefile')).toBe('')
  })

  it('handles hidden files', () => {
    expect(getExtension('.gitignore')).toBe('')
    expect(getExtension('.env.local')).toBe('.local')
  })

  it('handles multiple dots', () => {
    expect(getExtension('file.test.ts')).toBe('.ts')
    expect(getExtension('archive.tar.gz')).toBe('.gz')
  })
})

describe('getFilename', () => {
  it('extracts filename from path', () => {
    expect(getFilename('/path/to/file.txt')).toBe('file.txt')
    expect(getFilename('file.txt')).toBe('file.txt')
    expect(getFilename('path/file')).toBe('file')
  })

  it('handles trailing slashes', () => {
    expect(getFilename('/path/to/')).toBe('')
  })
})

describe('sanitizeFilename', () => {
  it('removes path separators', () => {
    expect(sanitizeFilename('path/file.txt')).toBe('pathfile.txt')
    expect(sanitizeFilename('path\\file.txt')).toBe('pathfile.txt')
  })

  it('removes dangerous characters', () => {
    expect(sanitizeFilename('file<>:"|?*.txt')).toBe('file.txt')
  })

  it('removes null bytes', () => {
    expect(sanitizeFilename('file\0.txt')).toBe('file.txt')
  })

  it('removes leading dots', () => {
    expect(sanitizeFilename('..file.txt')).toBe('file.txt')
    expect(sanitizeFilename('.hidden')).toBe('hidden')
  })

  it('limits length', () => {
    const longName = 'a'.repeat(300) + '.txt'
    const result = sanitizeFilename(longName)
    expect(result.length).toBeLessThanOrEqual(255)
    expect(result.endsWith('.txt')).toBe(true)
  })

  it('returns "file" for empty result', () => {
    expect(sanitizeFilename('')).toBe('file')
    expect(sanitizeFilename('...')).toBe('file')
  })
})

describe('isHiddenPath', () => {
  it('detects hidden files', () => {
    expect(isHiddenPath('.gitignore')).toBe(true)
    expect(isHiddenPath('.env')).toBe(true)
  })

  it('detects hidden directories', () => {
    expect(isHiddenPath('.git/config')).toBe(true)
    expect(isHiddenPath('path/.hidden/file')).toBe(true)
  })

  it('returns false for normal paths', () => {
    expect(isHiddenPath('file.txt')).toBe(false)
    expect(isHiddenPath('path/to/file')).toBe(false)
  })
})
