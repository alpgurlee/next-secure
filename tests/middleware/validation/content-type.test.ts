import { describe, it, expect } from 'vitest'
import {
  parseContentType,
  isAllowedContentType,
  MIME_TYPES,
} from '../../../src/middleware/validation'

describe('parseContentType', () => {
  it('parses simple content type', () => {
    const result = parseContentType('application/json')
    expect(result.mediaType).toBe('application/json')
    expect(result.type).toBe('application')
    expect(result.subtype).toBe('json')
    expect(result.parameters).toEqual({})
  })

  it('parses content type with charset', () => {
    const result = parseContentType('application/json; charset=utf-8')
    expect(result.mediaType).toBe('application/json')
    expect(result.parameters.charset).toBe('utf-8')
    expect(result.charset).toBe('utf-8')
  })

  it('parses content type with multiple parameters', () => {
    const result = parseContentType('multipart/form-data; boundary=----WebKitFormBoundary; charset=utf-8')
    expect(result.mediaType).toBe('multipart/form-data')
    expect(result.parameters.boundary).toBe('----WebKitFormBoundary')
    expect(result.parameters.charset).toBe('utf-8')
  })

  it('handles missing content type', () => {
    const result = parseContentType(null)
    expect(result.mediaType).toBe('')
    expect(result.parameters).toEqual({})
  })

  it('handles empty string', () => {
    const result = parseContentType('')
    expect(result.mediaType).toBe('')
  })

  it('normalizes to lowercase', () => {
    const result = parseContentType('APPLICATION/JSON')
    expect(result.mediaType).toBe('application/json')
  })

  it('trims whitespace', () => {
    const result = parseContentType('  application/json  ; charset = utf-8  ')
    expect(result.mediaType).toBe('application/json')
  })
})

describe('isAllowedContentType', () => {
  it('allows exact match', () => {
    const allowed = ['application/json', 'text/html']
    expect(isAllowedContentType('application/json', allowed)).toBe(true)
    expect(isAllowedContentType('text/html', allowed)).toBe(true)
  })

  it('rejects non-allowed types', () => {
    const allowed = ['application/json']
    expect(isAllowedContentType('text/html', allowed)).toBe(false)
    expect(isAllowedContentType('application/xml', allowed)).toBe(false)
  })

  it('supports wildcard patterns', () => {
    const allowed = ['application/*', 'text/*']
    expect(isAllowedContentType('application/json', allowed)).toBe(true)
    expect(isAllowedContentType('application/xml', allowed)).toBe(true)
    expect(isAllowedContentType('text/html', allowed)).toBe(true)
    expect(isAllowedContentType('image/png', allowed)).toBe(false)
  })

  it('supports category wildcards', () => {
    const allowed = ['image/*']
    expect(isAllowedContentType('image/png', allowed)).toBe(true)
    expect(isAllowedContentType('image/jpeg', allowed)).toBe(true)
    expect(isAllowedContentType('image/gif', allowed)).toBe(true)
    expect(isAllowedContentType('video/mp4', allowed)).toBe(false)
  })

  it('handles empty allowed list', () => {
    expect(isAllowedContentType('application/json', [])).toBe(false)
  })

  it('is case insensitive', () => {
    const allowed = ['application/json']
    expect(isAllowedContentType('APPLICATION/JSON', allowed)).toBe(true)
  })
})

describe('MIME_TYPES', () => {
  it('has JSON type', () => {
    expect(MIME_TYPES.JSON).toBe('application/json')
  })

  it('has form types', () => {
    expect(MIME_TYPES.FORM_URLENCODED).toBe('application/x-www-form-urlencoded')
    expect(MIME_TYPES.MULTIPART_FORM).toBe('multipart/form-data')
  })

  it('has text types', () => {
    expect(MIME_TYPES.TEXT_PLAIN).toBe('text/plain')
    expect(MIME_TYPES.TEXT_HTML).toBe('text/html')
    expect(MIME_TYPES.XML).toBe('application/xml')
  })

  it('has binary types', () => {
    expect(MIME_TYPES.OCTET_STREAM).toBe('application/octet-stream')
  })
})
