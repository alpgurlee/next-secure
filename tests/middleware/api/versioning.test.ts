import { describe, it, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'
import {
  extractVersion,
  validateVersion,
  getVersionStatus,
  isVersionSupported,
  withAPIVersion,
  createVersionRouter,
  compareVersions,
  normalizeVersion,
} from '../../../src/middleware/api/versioning'

function createRequest(options: {
  path?: string
  headers?: Record<string, string>
  query?: Record<string, string>
} = {}): NextRequest {
  const { path = '/api/test', headers = {}, query = {} } = options

  const url = new URL(`http://localhost${path}`)
  Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v))

  return new NextRequest(url, {
    method: 'GET',
    headers,
  })
}

const versioningOptions = {
  current: 'v2',
  supported: ['v1', 'v2', 'v3'],
  deprecated: ['v1'],
  sunset: ['v0'],
}

describe('API Versioning', () => {
  describe('extractVersion', () => {
    it('should extract version from header', () => {
      const req = createRequest({ headers: { 'x-api-version': 'v2' } })

      const { version, source } = extractVersion(req, {
        ...versioningOptions,
        source: 'header',
      })

      expect(version).toBe('v2')
      expect(source).toBe('header')
    })

    it('should extract version from query', () => {
      const req = createRequest({ query: { version: 'v2' } })

      const { version, source } = extractVersion(req, {
        ...versioningOptions,
        source: 'query',
      })

      expect(version).toBe('v2')
      expect(source).toBe('query')
    })

    it('should extract version from path', () => {
      const req = createRequest({ path: '/v2/api/users' })

      const { version, source } = extractVersion(req, {
        ...versioningOptions,
        source: 'path',
      })

      expect(version).toBe('2')
      expect(source).toBe('path')
    })

    it('should extract version from accept header', () => {
      const req = createRequest({ headers: { accept: 'application/json; version=2' } })

      const { version, source } = extractVersion(req, {
        ...versioningOptions,
        source: 'accept',
      })

      expect(version).toBe('2')
      expect(source).toBe('accept')
    })

    it('should return null if version not found', () => {
      const req = createRequest()

      const { version, source } = extractVersion(req, {
        ...versioningOptions,
        source: 'header',
      })

      expect(version).toBeNull()
      expect(source).toBeNull()
    })
  })

  describe('getVersionStatus', () => {
    it('should return current for current version', () => {
      expect(getVersionStatus('v2', versioningOptions)).toBe('current')
    })

    it('should return supported for supported version', () => {
      expect(getVersionStatus('v3', versioningOptions)).toBe('supported')
    })

    it('should return deprecated for deprecated version', () => {
      expect(getVersionStatus('v1', versioningOptions)).toBe('deprecated')
    })

    it('should return sunset for sunset version', () => {
      expect(getVersionStatus('v0', versioningOptions)).toBe('sunset')
    })

    it('should return null for unknown version', () => {
      expect(getVersionStatus('v99', versioningOptions)).toBeNull()
    })
  })

  describe('isVersionSupported', () => {
    it('should return true for current version', () => {
      expect(isVersionSupported('v2', versioningOptions)).toBe(true)
    })

    it('should return true for supported version', () => {
      expect(isVersionSupported('v3', versioningOptions)).toBe(true)
    })

    it('should return true for deprecated version', () => {
      expect(isVersionSupported('v1', versioningOptions)).toBe(true)
    })

    it('should return false for sunset version', () => {
      expect(isVersionSupported('v0', versioningOptions)).toBe(false)
    })

    it('should return false for unknown version', () => {
      expect(isVersionSupported('v99', versioningOptions)).toBe(false)
    })
  })

  describe('validateVersion', () => {
    it('should accept current version', () => {
      const req = createRequest({ headers: { 'x-api-version': 'v2' } })

      const result = validateVersion(req, versioningOptions)

      expect(result.valid).toBe(true)
      expect(result.status).toBe('current')
    })

    it('should accept supported version', () => {
      const req = createRequest({ headers: { 'x-api-version': 'v3' } })

      const result = validateVersion(req, versioningOptions)

      expect(result.valid).toBe(true)
      expect(result.status).toBe('supported')
    })

    it('should accept deprecated version with warning', () => {
      const req = createRequest({ headers: { 'x-api-version': 'v1' } })

      const result = validateVersion(req, versioningOptions)

      expect(result.valid).toBe(true)
      expect(result.status).toBe('deprecated')
    })

    it('should reject sunset version', () => {
      const req = createRequest({ headers: { 'x-api-version': 'v0' } })

      const result = validateVersion(req, versioningOptions)

      expect(result.valid).toBe(false)
      expect(result.status).toBe('sunset')
      expect(result.reason).toContain('sunset')
    })

    it('should reject unsupported version', () => {
      const req = createRequest({ headers: { 'x-api-version': 'v99' } })

      const result = validateVersion(req, versioningOptions)

      expect(result.valid).toBe(false)
      expect(result.reason).toContain('Unsupported')
    })

    it('should use default version when not provided', () => {
      const req = createRequest()

      const result = validateVersion(req, versioningOptions)

      expect(result.valid).toBe(true)
      expect(result.version).toBe('v2') // current is default
    })
  })

  describe('withAPIVersion', () => {
    it('should allow supported version', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withAPIVersion(handler, versioningOptions)

      const req = createRequest({ headers: { 'x-api-version': 'v2' } })
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.status).not.toBe(400)
    })

    it('should reject sunset version with 410', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withAPIVersion(handler, versioningOptions)

      const req = createRequest({ headers: { 'x-api-version': 'v0' } })
      const response = await wrapped(req, {})

      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(410)
    })

    it('should reject unsupported version with 400', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withAPIVersion(handler, versioningOptions)

      const req = createRequest({ headers: { 'x-api-version': 'v99' } })
      const response = await wrapped(req, {})

      expect(handler).not.toHaveBeenCalled()
      expect(response.status).toBe(400)
    })

    it('should add deprecation headers for deprecated version', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withAPIVersion(handler, {
        ...versioningOptions,
        addDeprecationHeaders: true,
      })

      const req = createRequest({ headers: { 'x-api-version': 'v1' } })
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
      expect(response.headers.get('deprecation')).toBe('true')
    })

    it('should skip when configured', async () => {
      const handler = vi.fn().mockResolvedValue(new Response('OK'))
      const wrapped = withAPIVersion(handler, {
        ...versioningOptions,
        skip: () => true,
      })

      const req = createRequest({ headers: { 'x-api-version': 'v99' } })
      const response = await wrapped(req, {})

      expect(handler).toHaveBeenCalled()
    })
  })

  describe('createVersionRouter', () => {
    it('should route to correct version handler', async () => {
      const v1Handler = vi.fn().mockResolvedValue(new Response('v1'))
      const v2Handler = vi.fn().mockResolvedValue(new Response('v2'))

      const router = createVersionRouter({
        v1: v1Handler,
        v2: v2Handler,
      }, { default: 'v2' })

      const req = createRequest({ headers: { 'x-api-version': 'v1' } })
      await router(req, {})

      expect(v1Handler).toHaveBeenCalled()
      expect(v2Handler).not.toHaveBeenCalled()
    })

    it('should use default version when not specified', async () => {
      const v1Handler = vi.fn().mockResolvedValue(new Response('v1'))
      const v2Handler = vi.fn().mockResolvedValue(new Response('v2'))

      const router = createVersionRouter({
        v1: v1Handler,
        v2: v2Handler,
      }, { default: 'v2' })

      const req = createRequest()
      await router(req, {})

      expect(v2Handler).toHaveBeenCalled()
      expect(v1Handler).not.toHaveBeenCalled()
    })
  })

  describe('compareVersions', () => {
    it('should compare major versions', () => {
      expect(compareVersions('2', '1')).toBe(1)
      expect(compareVersions('1', '2')).toBe(-1)
      expect(compareVersions('1', '1')).toBe(0)
    })

    it('should compare minor versions', () => {
      expect(compareVersions('1.2', '1.1')).toBe(1)
      expect(compareVersions('1.1', '1.2')).toBe(-1)
      expect(compareVersions('1.1', '1.1')).toBe(0)
    })

    it('should compare patch versions', () => {
      expect(compareVersions('1.1.2', '1.1.1')).toBe(1)
      expect(compareVersions('1.1.1', '1.1.2')).toBe(-1)
    })

    it('should handle missing parts', () => {
      expect(compareVersions('1.1', '1.1.0')).toBe(0)
      expect(compareVersions('1', '1.0.0')).toBe(0)
    })
  })

  describe('normalizeVersion', () => {
    it('should remove v prefix', () => {
      expect(normalizeVersion('v1.2')).toBe('1.2')
      expect(normalizeVersion('V1.2')).toBe('1.2')
    })

    it('should ensure minor version', () => {
      expect(normalizeVersion('1')).toBe('1.0')
    })

    it('should pass through valid versions', () => {
      expect(normalizeVersion('1.2.3')).toBe('1.2.3')
    })
  })
})
