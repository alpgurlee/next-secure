/**
 * IP utility tests
 */

import { describe, it, expect } from 'vitest'
import {
  getClientIp,
  normalizeIp,
  isValidIp,
  isValidIpv4,
  isValidIpv6,
  isPrivateIp,
  isLocalhost,
  anonymizeIp,
  createIpKey,
} from '../../src/utils/ip'

// Mock request factory
function createMockRequest(options: {
  ip?: string
  headers?: Record<string, string>
} = {}): Parameters<typeof getClientIp>[0] {
  const headers = new Map(Object.entries(options.headers ?? {}))

  return {
    ip: options.ip,
    headers: {
      get: (key: string) => headers.get(key.toLowerCase()) ?? null,
    },
  } as Parameters<typeof getClientIp>[0]
}

describe('getClientIp', () => {
  it('should use request.ip if available', () => {
    const req = createMockRequest({ ip: '192.168.1.100' })
    expect(getClientIp(req)).toBe('192.168.1.100')
  })

  it('should extract from cf-connecting-ip', () => {
    const req = createMockRequest({
      headers: { 'cf-connecting-ip': '1.2.3.4' },
    })
    expect(getClientIp(req)).toBe('1.2.3.4')
  })

  it('should extract from x-real-ip', () => {
    const req = createMockRequest({
      headers: { 'x-real-ip': '5.6.7.8' },
    })
    expect(getClientIp(req)).toBe('5.6.7.8')
  })

  it('should extract first IP from x-forwarded-for', () => {
    const req = createMockRequest({
      headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3' },
    })
    expect(getClientIp(req)).toBe('1.1.1.1')
  })

  it('should return fallback when trustProxy is false', () => {
    const req = createMockRequest({
      headers: { 'x-forwarded-for': '1.1.1.1' },
    })
    expect(getClientIp(req, { trustProxy: false })).toBe('127.0.0.1')
  })

  it('should use custom headers first', () => {
    const req = createMockRequest({
      headers: {
        'x-forwarded-for': '1.1.1.1',
        'my-custom-ip': '9.9.9.9',
      },
    })
    expect(getClientIp(req, { customHeaders: ['my-custom-ip'] })).toBe('9.9.9.9')
  })

  it('should return fallback when no IP found', () => {
    const req = createMockRequest()
    expect(getClientIp(req)).toBe('127.0.0.1')
    expect(getClientIp(req, { fallback: '0.0.0.0' })).toBe('0.0.0.0')
  })
})

describe('normalizeIp', () => {
  it('should trim whitespace', () => {
    expect(normalizeIp('  192.168.1.1  ')).toBe('192.168.1.1')
  })

  it('should remove IPv6 brackets', () => {
    expect(normalizeIp('[::1]')).toBe('::1')
    expect(normalizeIp('[2001:db8::1]')).toBe('2001:db8::1')
  })

  it('should remove port from IPv4', () => {
    expect(normalizeIp('192.168.1.1:8080')).toBe('192.168.1.1')
  })

  it('should convert IPv4-mapped IPv6 to IPv4', () => {
    expect(normalizeIp('::ffff:192.168.1.1')).toBe('192.168.1.1')
    expect(normalizeIp('::FFFF:10.0.0.1')).toBe('10.0.0.1')
  })
})

describe('isValidIp', () => {
  it('should validate IPv4 addresses', () => {
    expect(isValidIp('192.168.1.1')).toBe(true)
    expect(isValidIp('0.0.0.0')).toBe(true)
    expect(isValidIp('255.255.255.255')).toBe(true)
    expect(isValidIp('256.1.1.1')).toBe(false)
    expect(isValidIp('1.2.3')).toBe(false)
  })

  it('should validate IPv6 addresses', () => {
    expect(isValidIp('::1')).toBe(true)
    expect(isValidIp('2001:db8::1')).toBe(true)
    expect(isValidIp('fe80::1')).toBe(true)
  })
})

describe('isValidIpv4', () => {
  it('should validate correct IPv4 addresses', () => {
    expect(isValidIpv4('192.168.1.1')).toBe(true)
    expect(isValidIpv4('10.0.0.1')).toBe(true)
    expect(isValidIpv4('172.16.0.1')).toBe(true)
    expect(isValidIpv4('0.0.0.0')).toBe(true)
    expect(isValidIpv4('255.255.255.255')).toBe(true)
  })

  it('should reject invalid IPv4 addresses', () => {
    expect(isValidIpv4('256.1.1.1')).toBe(false)
    expect(isValidIpv4('1.2.3')).toBe(false)
    expect(isValidIpv4('1.2.3.4.5')).toBe(false)
    expect(isValidIpv4('::1')).toBe(false)
    expect(isValidIpv4('not-an-ip')).toBe(false)
  })
})

describe('isValidIpv6', () => {
  it('should validate correct IPv6 addresses', () => {
    expect(isValidIpv6('::1')).toBe(true)
    expect(isValidIpv6('::')).toBe(true)
    expect(isValidIpv6('2001:db8:85a3:0:0:8a2e:370:7334')).toBe(true)
  })

  it('should reject invalid IPv6 addresses', () => {
    expect(isValidIpv6('192.168.1.1')).toBe(false)
    expect(isValidIpv6('not-an-ip')).toBe(false)
  })
})

describe('isPrivateIp', () => {
  it('should identify private IPv4 addresses', () => {
    // 127.x.x.x
    expect(isPrivateIp('127.0.0.1')).toBe(true)
    expect(isPrivateIp('127.255.255.255')).toBe(true)

    // 10.x.x.x
    expect(isPrivateIp('10.0.0.1')).toBe(true)
    expect(isPrivateIp('10.255.255.255')).toBe(true)

    // 172.16.x.x - 172.31.x.x
    expect(isPrivateIp('172.16.0.1')).toBe(true)
    expect(isPrivateIp('172.31.255.255')).toBe(true)
    expect(isPrivateIp('172.15.0.1')).toBe(false)
    expect(isPrivateIp('172.32.0.1')).toBe(false)

    // 192.168.x.x
    expect(isPrivateIp('192.168.0.1')).toBe(true)
    expect(isPrivateIp('192.168.255.255')).toBe(true)
  })

  it('should identify private IPv6 addresses', () => {
    expect(isPrivateIp('::1')).toBe(true)
    expect(isPrivateIp('fe80::1')).toBe(true)
    expect(isPrivateIp('fc00::1')).toBe(true)
  })

  it('should return false for public addresses', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false)
    expect(isPrivateIp('1.1.1.1')).toBe(false)
    expect(isPrivateIp('2001:db8::1')).toBe(false)
  })
})

describe('isLocalhost', () => {
  it('should identify localhost addresses', () => {
    expect(isLocalhost('127.0.0.1')).toBe(true)
    expect(isLocalhost('::1')).toBe(true)
    expect(isLocalhost('localhost')).toBe(true)
  })

  it('should return false for non-localhost addresses', () => {
    expect(isLocalhost('192.168.1.1')).toBe(false)
    expect(isLocalhost('8.8.8.8')).toBe(false)
  })
})

describe('anonymizeIp', () => {
  it('should anonymize IPv4 addresses', () => {
    expect(anonymizeIp('192.168.1.100')).toBe('192.168.1.xxx')
    expect(anonymizeIp('8.8.8.8')).toBe('8.8.8.xxx')
  })

  it('should anonymize IPv6 addresses', () => {
    expect(anonymizeIp('2001:db8::1')).toBe('2001:db8::xxxx')
  })

  it('should handle invalid IPs', () => {
    expect(anonymizeIp('invalid')).toBe('xxx.xxx.xxx.xxx')
  })
})

describe('createIpKey', () => {
  it('should create a key with default prefix', () => {
    expect(createIpKey('192.168.1.1')).toBe('rl:ip:192.168.1.1')
  })

  it('should use custom prefix', () => {
    expect(createIpKey('192.168.1.1', { prefix: 'custom' })).toBe('custom:ip:192.168.1.1')
  })

  it('should hash IP when requested', () => {
    const key = createIpKey('192.168.1.1', { hash: true })
    expect(key).toMatch(/^rl:ip:[a-z0-9]+$/)
    expect(key).not.toContain('192.168.1.1')
  })
})
