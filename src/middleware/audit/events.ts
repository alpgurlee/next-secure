import type {
  SecurityEventEntry,
  SecurityEventType,
  SecurityEventConfig,
  LogStore,
  LogLevel,
} from './types'

/**
 * Generate unique ID
 */
function generateId(): string {
  return `evt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`
}

/**
 * Map severity to log level
 */
function severityToLevel(severity: 'low' | 'medium' | 'high' | 'critical'): LogLevel {
  switch (severity) {
    case 'low': return 'info'
    case 'medium': return 'warn'
    case 'high': return 'error'
    case 'critical': return 'critical'
  }
}

/**
 * Security event tracker
 */
export class SecurityEventTracker {
  private store: LogStore
  private defaultSeverity: 'low' | 'medium' | 'high' | 'critical'
  private onEvent?: (event: SecurityEventEntry) => void | Promise<void>

  constructor(config: SecurityEventConfig) {
    this.store = config.store
    this.defaultSeverity = config.defaultSeverity || 'medium'
    this.onEvent = config.onEvent
  }

  /**
   * Track a security event
   */
  async track(options: {
    event: SecurityEventType
    message: string
    severity?: 'low' | 'medium' | 'high' | 'critical'
    source?: {
      ip?: string
      userAgent?: string
      userId?: string
    }
    target?: {
      resource?: string
      action?: string
      userId?: string
    }
    details?: Record<string, unknown>
    mitigated?: boolean
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    const severity = options.severity || this.defaultSeverity

    const entry: SecurityEventEntry = {
      id: generateId(),
      timestamp: new Date(),
      type: 'security',
      level: severityToLevel(severity),
      message: options.message,
      event: options.event,
      severity,
      source: options.source || {},
      target: options.target,
      details: options.details,
      mitigated: options.mitigated,
      metadata: options.metadata,
    }

    // Write to store
    await this.store.write(entry)

    // Call event handler
    if (this.onEvent) {
      await this.onEvent(entry)
    }

    return entry
  }

  // Convenience methods for common events

  /**
   * Track failed authentication
   */
  async authFailed(options: {
    ip?: string
    userAgent?: string
    email?: string
    reason?: string
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'auth.failed',
      message: options.reason || 'Authentication failed',
      severity: 'medium',
      source: {
        ip: options.ip,
        userAgent: options.userAgent,
      },
      details: {
        attemptedEmail: options.email,
        reason: options.reason,
      },
      metadata: options.metadata,
    })
  }

  /**
   * Track successful login
   */
  async authLogin(options: {
    userId: string
    ip?: string
    userAgent?: string
    method?: string
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'auth.login',
      message: `User ${options.userId} logged in`,
      severity: 'low',
      source: {
        ip: options.ip,
        userAgent: options.userAgent,
        userId: options.userId,
      },
      details: {
        method: options.method || 'credentials',
      },
      metadata: options.metadata,
    })
  }

  /**
   * Track logout
   */
  async authLogout(options: {
    userId: string
    ip?: string
    reason?: 'user' | 'timeout' | 'forced'
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'auth.logout',
      message: `User ${options.userId} logged out`,
      severity: 'low',
      source: {
        ip: options.ip,
        userId: options.userId,
      },
      details: {
        reason: options.reason || 'user',
      },
      metadata: options.metadata,
    })
  }

  /**
   * Track permission denied
   */
  async permissionDenied(options: {
    userId?: string
    ip?: string
    resource: string
    action: string
    requiredRole?: string
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'auth.permission_denied',
      message: `Permission denied for ${options.action} on ${options.resource}`,
      severity: 'medium',
      source: {
        ip: options.ip,
        userId: options.userId,
      },
      target: {
        resource: options.resource,
        action: options.action,
      },
      details: {
        requiredRole: options.requiredRole,
      },
      metadata: options.metadata,
    })
  }

  /**
   * Track rate limit exceeded
   */
  async rateLimitExceeded(options: {
    ip?: string
    userId?: string
    endpoint: string
    limit: number
    window: string
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'ratelimit.exceeded',
      message: `Rate limit exceeded for ${options.endpoint}`,
      severity: 'medium',
      source: {
        ip: options.ip,
        userId: options.userId,
      },
      target: {
        resource: options.endpoint,
      },
      details: {
        limit: options.limit,
        window: options.window,
      },
      metadata: options.metadata,
    })
  }

  /**
   * Track CSRF validation failure
   */
  async csrfInvalid(options: {
    ip?: string
    userId?: string
    endpoint: string
    reason?: string
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'csrf.invalid',
      message: `CSRF validation failed for ${options.endpoint}`,
      severity: 'high',
      source: {
        ip: options.ip,
        userId: options.userId,
      },
      target: {
        resource: options.endpoint,
      },
      details: {
        reason: options.reason,
      },
      metadata: options.metadata,
    })
  }

  /**
   * Track XSS detection
   */
  async xssDetected(options: {
    ip?: string
    userId?: string
    field: string
    payload?: string
    endpoint: string
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'xss.detected',
      message: `XSS payload detected in ${options.field}`,
      severity: 'high',
      source: {
        ip: options.ip,
        userId: options.userId,
      },
      target: {
        resource: options.endpoint,
      },
      details: {
        field: options.field,
        payload: options.payload?.slice(0, 100), // Truncate
      },
      mitigated: true,
      metadata: options.metadata,
    })
  }

  /**
   * Track SQL injection detection
   */
  async sqliDetected(options: {
    ip?: string
    userId?: string
    field: string
    pattern: string
    severity?: 'low' | 'medium' | 'high'
    endpoint: string
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'sqli.detected',
      message: `SQL injection attempt detected in ${options.field}`,
      severity: options.severity || 'high',
      source: {
        ip: options.ip,
        userId: options.userId,
      },
      target: {
        resource: options.endpoint,
      },
      details: {
        field: options.field,
        pattern: options.pattern,
      },
      mitigated: true,
      metadata: options.metadata,
    })
  }

  /**
   * Track IP block
   */
  async ipBlocked(options: {
    ip: string
    reason: string
    duration?: number
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'ip.blocked',
      message: `IP ${options.ip} blocked: ${options.reason}`,
      severity: 'high',
      source: {
        ip: options.ip,
      },
      details: {
        reason: options.reason,
        duration: options.duration,
      },
      metadata: options.metadata,
    })
  }

  /**
   * Track suspicious activity
   */
  async suspicious(options: {
    ip?: string
    userId?: string
    activity: string
    severity?: 'low' | 'medium' | 'high' | 'critical'
    details?: Record<string, unknown>
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'ip.suspicious',
      message: options.activity,
      severity: options.severity || 'medium',
      source: {
        ip: options.ip,
        userId: options.userId,
      },
      details: options.details,
      metadata: options.metadata,
    })
  }

  /**
   * Track custom event
   */
  async custom(options: {
    message: string
    severity?: 'low' | 'medium' | 'high' | 'critical'
    source?: {
      ip?: string
      userAgent?: string
      userId?: string
    }
    target?: {
      resource?: string
      action?: string
    }
    details?: Record<string, unknown>
    metadata?: Record<string, unknown>
  }): Promise<SecurityEventEntry> {
    return this.track({
      event: 'custom',
      ...options,
    })
  }
}

/**
 * Create a security event tracker
 */
export function createSecurityTracker(config: SecurityEventConfig): SecurityEventTracker {
  return new SecurityEventTracker(config)
}

/**
 * Standalone function to track security events
 */
export async function trackSecurityEvent(
  store: LogStore,
  options: {
    event: SecurityEventType
    message: string
    severity?: 'low' | 'medium' | 'high' | 'critical'
    source?: {
      ip?: string
      userAgent?: string
      userId?: string
    }
    target?: {
      resource?: string
      action?: string
      userId?: string
    }
    details?: Record<string, unknown>
    metadata?: Record<string, unknown>
  }
): Promise<SecurityEventEntry> {
  const tracker = new SecurityEventTracker({ store })
  return tracker.track(options)
}
