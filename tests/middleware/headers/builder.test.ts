import { describe, it, expect } from 'vitest'
import {
  buildCSP,
  buildHSTS,
  buildPermissionsPolicy,
  buildHeaders,
  getPreset,
  PRESET_STRICT,
  PRESET_RELAXED,
  PRESET_API,
} from '../../../src/middleware/headers'

describe('buildCSP', () => {
  it('builds basic CSP', () => {
    const csp = buildCSP({
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
    })

    expect(csp).toBe("default-src 'self'; script-src 'self' 'unsafe-inline'")
  })

  it('handles string values', () => {
    const csp = buildCSP({
      defaultSrc: "'self'",
    })

    expect(csp).toBe("default-src 'self'")
  })

  it('includes upgrade-insecure-requests', () => {
    const csp = buildCSP({
      defaultSrc: ["'self'"],
      upgradeInsecureRequests: true,
    })

    expect(csp).toContain('upgrade-insecure-requests')
  })

  it('includes block-all-mixed-content', () => {
    const csp = buildCSP({
      blockAllMixedContent: true,
    })

    expect(csp).toBe('block-all-mixed-content')
  })

  it('handles all directives', () => {
    const csp = buildCSP({
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    })

    expect(csp).toContain("default-src 'self'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).toContain("frame-ancestors 'none'")
  })
})

describe('buildHSTS', () => {
  it('builds basic HSTS', () => {
    const hsts = buildHSTS({ maxAge: 31536000 })
    expect(hsts).toBe('max-age=31536000')
  })

  it('includes includeSubDomains', () => {
    const hsts = buildHSTS({
      maxAge: 31536000,
      includeSubDomains: true,
    })
    expect(hsts).toBe('max-age=31536000; includeSubDomains')
  })

  it('includes preload', () => {
    const hsts = buildHSTS({
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    })
    expect(hsts).toBe('max-age=31536000; includeSubDomains; preload')
  })
})

describe('buildPermissionsPolicy', () => {
  it('builds empty permissions', () => {
    const pp = buildPermissionsPolicy({
      camera: [],
      microphone: [],
    })
    expect(pp).toBe('camera=(), microphone=()')
  })

  it('builds self permissions', () => {
    const pp = buildPermissionsPolicy({
      camera: ['self'],
      geolocation: ['self'],
    })
    expect(pp).toBe('camera=(self), geolocation=(self)')
  })

  it('builds specific origin permissions', () => {
    const pp = buildPermissionsPolicy({
      camera: ['self', 'https://example.com'],
    })
    expect(pp).toBe('camera=(self "https://example.com")')
  })
})

describe('getPreset', () => {
  it('returns strict preset', () => {
    const preset = getPreset('strict')
    expect(preset).toEqual(PRESET_STRICT)
  })

  it('returns relaxed preset', () => {
    const preset = getPreset('relaxed')
    expect(preset).toEqual(PRESET_RELAXED)
  })

  it('returns api preset', () => {
    const preset = getPreset('api')
    expect(preset).toEqual(PRESET_API)
  })
})

describe('buildHeaders', () => {
  it('builds all headers from strict preset', () => {
    const headers = buildHeaders(PRESET_STRICT)

    expect(headers.get('Content-Security-Policy')).toBeTruthy()
    expect(headers.get('Strict-Transport-Security')).toBeTruthy()
    expect(headers.get('X-Frame-Options')).toBe('DENY')
    expect(headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin')
  })

  it('builds API preset headers', () => {
    const headers = buildHeaders(PRESET_API)

    expect(headers.get('X-Frame-Options')).toBe('DENY')
    expect(headers.get('Referrer-Policy')).toBe('no-referrer')
    expect(headers.get('Cross-Origin-Resource-Policy')).toBe('same-origin')
  })

  it('handles disabled headers', () => {
    const headers = buildHeaders({
      xFrameOptions: false,
      xContentTypeOptions: false,
    })

    expect(headers.has('X-Frame-Options')).toBe(false)
    expect(headers.has('X-Content-Type-Options')).toBe(false)
  })

  it('handles referrer-policy array', () => {
    const headers = buildHeaders({
      referrerPolicy: ['no-referrer', 'strict-origin-when-cross-origin'],
    })

    expect(headers.get('Referrer-Policy')).toBe(
      'no-referrer, strict-origin-when-cross-origin'
    )
  })

  it('sets cross-origin headers', () => {
    const headers = buildHeaders({
      crossOriginOpenerPolicy: 'same-origin',
      crossOriginEmbedderPolicy: 'require-corp',
      crossOriginResourcePolicy: 'same-origin',
    })

    expect(headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin')
    expect(headers.get('Cross-Origin-Embedder-Policy')).toBe('require-corp')
    expect(headers.get('Cross-Origin-Resource-Policy')).toBe('same-origin')
  })

  it('sets origin-agent-cluster', () => {
    const headers = buildHeaders({
      originAgentCluster: true,
    })

    expect(headers.get('Origin-Agent-Cluster')).toBe('?1')
  })
})
