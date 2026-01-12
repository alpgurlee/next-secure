import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  SecurityEventTracker,
  createSecurityTracker,
  trackSecurityEvent,
} from '../../../src/middleware/audit/events'
import { MemoryStore } from '../../../src/middleware/audit/stores'
import type { SecurityEventEntry } from '../../../src/middleware/audit/types'

describe('SecurityEventTracker', () => {
  let store: MemoryStore
  let tracker: SecurityEventTracker

  beforeEach(() => {
    store = new MemoryStore()
    tracker = new SecurityEventTracker({ store })
  })

  describe('track', () => {
    it('should track security events', async () => {
      const event = await tracker.track({
        event: 'auth.failed',
        message: 'Login attempt failed',
        severity: 'medium',
      })

      expect(event.id).toBeDefined()
      expect(event.type).toBe('security')
      expect(event.event).toBe('auth.failed')
      expect(event.severity).toBe('medium')

      const stored = await store.query({})
      expect(stored).toHaveLength(1)
    })

    it('should use default severity', async () => {
      const trackerWithDefault = new SecurityEventTracker({
        store,
        defaultSeverity: 'high',
      })

      const event = await trackerWithDefault.track({
        event: 'custom',
        message: 'Custom event',
      })

      expect(event.severity).toBe('high')
    })

    it('should include source info', async () => {
      const event = await tracker.track({
        event: 'auth.failed',
        message: 'Failed login',
        source: {
          ip: '192.168.1.1',
          userAgent: 'Mozilla/5.0',
          userId: 'user123',
        },
      })

      expect(event.source?.ip).toBe('192.168.1.1')
      expect(event.source?.userAgent).toBe('Mozilla/5.0')
      expect(event.source?.userId).toBe('user123')
    })

    it('should include target info', async () => {
      const event = await tracker.track({
        event: 'auth.permission_denied',
        message: 'Access denied',
        target: {
          resource: '/admin/users',
          action: 'delete',
        },
      })

      expect(event.target?.resource).toBe('/admin/users')
      expect(event.target?.action).toBe('delete')
    })

    it('should call onEvent handler', async () => {
      const onEvent = vi.fn()
      const trackerWithHandler = new SecurityEventTracker({
        store,
        onEvent,
      })

      await trackerWithHandler.track({
        event: 'custom',
        message: 'Test event',
      })

      expect(onEvent).toHaveBeenCalledTimes(1)
      expect(onEvent).toHaveBeenCalledWith(
        expect.objectContaining({ event: 'custom' })
      )
    })

    it('should map severity to log level', async () => {
      const lowEvent = await tracker.track({
        event: 'custom',
        message: 'Low severity',
        severity: 'low',
      })
      expect(lowEvent.level).toBe('info')

      const mediumEvent = await tracker.track({
        event: 'custom',
        message: 'Medium severity',
        severity: 'medium',
      })
      expect(mediumEvent.level).toBe('warn')

      const highEvent = await tracker.track({
        event: 'custom',
        message: 'High severity',
        severity: 'high',
      })
      expect(highEvent.level).toBe('error')

      const criticalEvent = await tracker.track({
        event: 'custom',
        message: 'Critical severity',
        severity: 'critical',
      })
      expect(criticalEvent.level).toBe('critical')
    })
  })

  describe('authFailed', () => {
    it('should track authentication failures', async () => {
      const event = await tracker.authFailed({
        ip: '192.168.1.1',
        email: 'user@example.com',
        reason: 'Invalid password',
      })

      expect(event.event).toBe('auth.failed')
      expect(event.severity).toBe('medium')
      expect(event.details?.attemptedEmail).toBe('user@example.com')
    })
  })

  describe('authLogin', () => {
    it('should track successful logins', async () => {
      const event = await tracker.authLogin({
        userId: 'user123',
        ip: '192.168.1.1',
        method: 'password',
      })

      expect(event.event).toBe('auth.login')
      expect(event.severity).toBe('low')
      expect(event.source?.userId).toBe('user123')
    })
  })

  describe('authLogout', () => {
    it('should track logouts', async () => {
      const event = await tracker.authLogout({
        userId: 'user123',
        reason: 'timeout',
      })

      expect(event.event).toBe('auth.logout')
      expect(event.details?.reason).toBe('timeout')
    })
  })

  describe('permissionDenied', () => {
    it('should track permission denials', async () => {
      const event = await tracker.permissionDenied({
        userId: 'user123',
        resource: '/admin/settings',
        action: 'update',
        requiredRole: 'admin',
      })

      expect(event.event).toBe('auth.permission_denied')
      expect(event.severity).toBe('medium')
      expect(event.target?.resource).toBe('/admin/settings')
    })
  })

  describe('rateLimitExceeded', () => {
    it('should track rate limit violations', async () => {
      const event = await tracker.rateLimitExceeded({
        ip: '192.168.1.1',
        endpoint: '/api/login',
        limit: 10,
        window: '15m',
      })

      expect(event.event).toBe('ratelimit.exceeded')
      expect(event.details?.limit).toBe(10)
      expect(event.details?.window).toBe('15m')
    })
  })

  describe('csrfInvalid', () => {
    it('should track CSRF failures', async () => {
      const event = await tracker.csrfInvalid({
        ip: '192.168.1.1',
        endpoint: '/api/transfer',
        reason: 'Token mismatch',
      })

      expect(event.event).toBe('csrf.invalid')
      expect(event.severity).toBe('high')
    })
  })

  describe('xssDetected', () => {
    it('should track XSS attempts', async () => {
      const event = await tracker.xssDetected({
        ip: '192.168.1.1',
        field: 'comment',
        payload: '<script>alert(1)</script>',
        endpoint: '/api/comments',
      })

      expect(event.event).toBe('xss.detected')
      expect(event.severity).toBe('high')
      expect(event.mitigated).toBe(true)
    })

    it('should truncate long payloads', async () => {
      const longPayload = 'x'.repeat(200)
      const event = await tracker.xssDetected({
        field: 'input',
        payload: longPayload,
        endpoint: '/api/test',
      })

      expect((event.details?.payload as string).length).toBeLessThanOrEqual(100)
    })
  })

  describe('sqliDetected', () => {
    it('should track SQL injection attempts', async () => {
      const event = await tracker.sqliDetected({
        ip: '192.168.1.1',
        field: 'username',
        pattern: 'UNION SELECT',
        endpoint: '/api/users',
      })

      expect(event.event).toBe('sqli.detected')
      expect(event.severity).toBe('high')
      expect(event.mitigated).toBe(true)
    })
  })

  describe('ipBlocked', () => {
    it('should track IP blocks', async () => {
      const event = await tracker.ipBlocked({
        ip: '192.168.1.1',
        reason: 'Too many failed attempts',
        duration: 3600,
      })

      expect(event.event).toBe('ip.blocked')
      expect(event.severity).toBe('high')
      expect(event.details?.duration).toBe(3600)
    })
  })

  describe('suspicious', () => {
    it('should track suspicious activity', async () => {
      const event = await tracker.suspicious({
        ip: '192.168.1.1',
        activity: 'Unusual login pattern detected',
        severity: 'high',
        details: { attempts: 50, timeframe: '1h' },
      })

      expect(event.event).toBe('ip.suspicious')
      expect(event.details?.attempts).toBe(50)
    })
  })

  describe('custom', () => {
    it('should track custom events', async () => {
      const event = await tracker.custom({
        message: 'Custom security event',
        severity: 'medium',
        details: { custom: 'data' },
      })

      expect(event.event).toBe('custom')
      expect(event.details?.custom).toBe('data')
    })
  })
})

describe('createSecurityTracker', () => {
  it('should create tracker instance', () => {
    const store = new MemoryStore()
    const tracker = createSecurityTracker({ store })

    expect(tracker).toBeInstanceOf(SecurityEventTracker)
  })
})

describe('trackSecurityEvent', () => {
  it('should track event without creating tracker', async () => {
    const store = new MemoryStore()

    const event = await trackSecurityEvent(store, {
      event: 'auth.failed',
      message: 'Login failed',
      severity: 'medium',
    })

    expect(event.event).toBe('auth.failed')

    const stored = await store.query({})
    expect(stored).toHaveLength(1)
  })
})
