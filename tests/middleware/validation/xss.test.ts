import { describe, it, expect } from 'vitest'
import {
  sanitize,
  escapeHtml,
  stripHtml,
  sanitizeHtml,
  detectXSS,
  isSafeUrl,
  sanitizeObject,
  sanitizeFields,
} from '../../../src/middleware/validation'

describe('escapeHtml', () => {
  it('escapes HTML special characters', () => {
    expect(escapeHtml('<script>')).toBe('&lt;script&gt;')
    expect(escapeHtml('"test"')).toBe('&quot;test&quot;')
    expect(escapeHtml("'test'")).toBe('&#x27;test&#x27;')
    expect(escapeHtml('a & b')).toBe('a &amp; b')
  })

  it('handles multiple characters', () => {
    // Note: = is also escaped to &#x3D; for extra safety
    expect(escapeHtml('<a href="test">')).toBe('&lt;a href&#x3D;&quot;test&quot;&gt;')
  })

  it('returns empty string for empty input', () => {
    expect(escapeHtml('')).toBe('')
  })
})

describe('stripHtml', () => {
  it('removes all HTML tags', () => {
    expect(stripHtml('<p>Hello</p>')).toBe('Hello')
    expect(stripHtml('<div><span>Test</span></div>')).toBe('Test')
  })

  it('removes script tags with content', () => {
    expect(stripHtml('<script>alert("xss")</script>')).toBe('')
    expect(stripHtml('Hello<script>evil()</script>World')).toBe('HelloWorld')
  })

  it('removes style tags with content', () => {
    expect(stripHtml('<style>.evil{}</style>Text')).toBe('Text')
  })

  it('decodes HTML entities', () => {
    expect(stripHtml('&lt;test&gt;')).toBe('<test>')
  })
})

describe('sanitizeHtml', () => {
  it('allows safe tags', () => {
    expect(sanitizeHtml('<p>Hello</p>')).toBe('<p>Hello</p>')
    expect(sanitizeHtml('<b>Bold</b>')).toBe('<b>Bold</b>')
    expect(sanitizeHtml('<em>Italic</em>')).toBe('<em>Italic</em>')
  })

  it('removes dangerous tags', () => {
    expect(sanitizeHtml('<script>alert(1)</script>')).toBe('')
    expect(sanitizeHtml('<iframe src="evil.com"></iframe>')).toBe('')
  })

  it('removes event handlers', () => {
    const input = '<p onclick="evil()">Click me</p>'
    const result = sanitizeHtml(input)
    expect(result).not.toContain('onclick')
    expect(result).toContain('<p>')
  })

  it('removes javascript: URLs', () => {
    const input = '<a href="javascript:alert(1)">Click</a>'
    const result = sanitizeHtml(input)
    expect(result).not.toContain('javascript')
  })

  it('allows safe attributes', () => {
    expect(sanitizeHtml('<a href="https://example.com" title="Link">Test</a>'))
      .toContain('href=')
  })
})

describe('detectXSS', () => {
  it('detects script tags', () => {
    expect(detectXSS('<script>alert(1)</script>')).toBe(true)
    expect(detectXSS('<SCRIPT>alert(1)</SCRIPT>')).toBe(true)
  })

  it('detects event handlers', () => {
    expect(detectXSS('<img onerror="alert(1)">')).toBe(true)
    expect(detectXSS('<div onmouseover="evil()">')).toBe(true)
  })

  it('detects javascript: protocol', () => {
    expect(detectXSS('javascript:alert(1)')).toBe(true)
    expect(detectXSS('JAVASCRIPT:alert(1)')).toBe(true)
  })

  it('detects encoded attacks', () => {
    expect(detectXSS('&#x3C;script&#x3E;')).toBe(true)
  })

  it('returns false for safe content', () => {
    expect(detectXSS('Hello World')).toBe(false)
    expect(detectXSS('This is a test')).toBe(false)
    expect(detectXSS('<p>Safe paragraph</p>')).toBe(false)
  })
})

describe('isSafeUrl', () => {
  it('allows safe URLs', () => {
    expect(isSafeUrl('https://example.com')).toBe(true)
    expect(isSafeUrl('http://example.com')).toBe(true)
    expect(isSafeUrl('/path/to/page')).toBe(true)
    expect(isSafeUrl('mailto:test@example.com')).toBe(true)
  })

  it('blocks dangerous protocols', () => {
    expect(isSafeUrl('javascript:alert(1)')).toBe(false)
    expect(isSafeUrl('vbscript:msgbox')).toBe(false)
    expect(isSafeUrl('data:text/html,<script>alert(1)</script>')).toBe(false)
  })

  it('allows data: URLs for images', () => {
    expect(isSafeUrl('data:image/png;base64,abc123')).toBe(true)
  })

  it('handles empty and null URLs', () => {
    expect(isSafeUrl('')).toBe(true)
    expect(isSafeUrl(null as unknown as string)).toBe(true)
  })
})

describe('sanitize', () => {
  it('uses escape mode by default', () => {
    const result = sanitize('<script>alert(1)</script>')
    expect(result).toBe('&lt;script&gt;alert(1)&lt;&#x2F;script&gt;')
  })

  it('supports strip mode', () => {
    const result = sanitize('<p>Hello <b>World</b></p>', { mode: 'strip' })
    expect(result).toBe('Hello World')
  })

  it('supports allow-safe mode', () => {
    const result = sanitize('<p>Hello <script>evil()</script></p>', { mode: 'allow-safe' })
    expect(result).toContain('<p>')
    expect(result).not.toContain('script')
  })

  it('respects maxLength', () => {
    const result = sanitize('Hello World', { maxLength: 5 })
    expect(result).toBe('Hello')
  })

  it('strips null bytes', () => {
    const result = sanitize('Hello\0World')
    expect(result).not.toContain('\0')
  })
})

describe('sanitizeObject', () => {
  it('sanitizes all string values', () => {
    const obj = {
      name: '<script>evil</script>',
      bio: '<b>Bold</b>',
      age: 25,
    }
    const result = sanitizeObject(obj)
    expect(result.name).not.toContain('<script>')
    expect(result.age).toBe(25)
  })

  it('handles nested objects', () => {
    const obj = {
      user: {
        name: '<script>evil</script>',
      },
    }
    const result = sanitizeObject(obj)
    expect((result as any).user.name).not.toContain('<script>')
  })

  it('handles arrays', () => {
    const arr = ['<script>1</script>', '<script>2</script>']
    const result = sanitizeObject(arr)
    expect((result as string[])[0]).not.toContain('<script>')
    expect((result as string[])[1]).not.toContain('<script>')
  })
})

describe('sanitizeFields', () => {
  it('only sanitizes specified fields', () => {
    const obj = {
      content: '<script>evil</script>',
      title: '<script>also evil</script>',
    }
    const result = sanitizeFields(obj, ['content'])
    expect(result.content).not.toContain('<script>')
    expect(result.title).toContain('<script>')  // Not sanitized
  })
})
