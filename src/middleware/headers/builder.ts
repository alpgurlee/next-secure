import type {
  ContentSecurityPolicy,
  StrictTransportSecurity,
  PermissionsPolicy,
  SecurityHeadersConfig,
  SecurityHeadersPreset,
} from './types'

/**
 * Build CSP header string from config
 */
export function buildCSP(policy: ContentSecurityPolicy): string {
  const directives: string[] = []

  const directiveMap: Record<string, string> = {
    defaultSrc: 'default-src',
    scriptSrc: 'script-src',
    styleSrc: 'style-src',
    imgSrc: 'img-src',
    fontSrc: 'font-src',
    connectSrc: 'connect-src',
    mediaSrc: 'media-src',
    objectSrc: 'object-src',
    frameSrc: 'frame-src',
    childSrc: 'child-src',
    workerSrc: 'worker-src',
    frameAncestors: 'frame-ancestors',
    formAction: 'form-action',
    baseUri: 'base-uri',
    manifestSrc: 'manifest-src',
    reportUri: 'report-uri',
    reportTo: 'report-to',
  }

  for (const [key, directive] of Object.entries(directiveMap)) {
    const value = policy[key as keyof ContentSecurityPolicy]
    if (value !== undefined && value !== false) {
      if (Array.isArray(value)) {
        directives.push(`${directive} ${value.join(' ')}`)
      } else if (typeof value === 'string') {
        directives.push(`${directive} ${value}`)
      }
    }
  }

  if (policy.upgradeInsecureRequests) {
    directives.push('upgrade-insecure-requests')
  }

  if (policy.blockAllMixedContent) {
    directives.push('block-all-mixed-content')
  }

  return directives.join('; ')
}

/**
 * Build HSTS header string
 */
export function buildHSTS(config: StrictTransportSecurity): string {
  let value = `max-age=${config.maxAge}`

  if (config.includeSubDomains) {
    value += '; includeSubDomains'
  }

  if (config.preload) {
    value += '; preload'
  }

  return value
}

/**
 * Build Permissions-Policy header string
 */
export function buildPermissionsPolicy(policy: PermissionsPolicy): string {
  const directives: string[] = []

  const featureMap: Record<string, string> = {
    accelerometer: 'accelerometer',
    ambientLightSensor: 'ambient-light-sensor',
    autoplay: 'autoplay',
    battery: 'battery',
    camera: 'camera',
    displayCapture: 'display-capture',
    documentDomain: 'document-domain',
    encryptedMedia: 'encrypted-media',
    fullscreen: 'fullscreen',
    geolocation: 'geolocation',
    gyroscope: 'gyroscope',
    magnetometer: 'magnetometer',
    microphone: 'microphone',
    midi: 'midi',
    payment: 'payment',
    pictureInPicture: 'picture-in-picture',
    publicKeyCredentialsGet: 'publickey-credentials-get',
    screenWakeLock: 'screen-wake-lock',
    syncXhr: 'sync-xhr',
    usb: 'usb',
    webShare: 'web-share',
    xrSpatialTracking: 'xr-spatial-tracking',
  }

  for (const [key, feature] of Object.entries(featureMap)) {
    const origins = policy[key as keyof PermissionsPolicy]
    if (origins !== undefined) {
      if (origins.length === 0) {
        directives.push(`${feature}=()`)
      } else {
        const formatted = origins.map((o) => (o === 'self' ? 'self' : `"${o}"`)).join(' ')
        directives.push(`${feature}=(${formatted})`)
      }
    }
  }

  return directives.join(', ')
}

/**
 * Preset: Strict security headers
 */
export const PRESET_STRICT: SecurityHeadersConfig = {
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", 'data:'],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameAncestors: ["'none'"],
    formAction: ["'self'"],
    baseUri: ["'self'"],
    upgradeInsecureRequests: true,
  },
  strictTransportSecurity: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  xFrameOptions: 'DENY',
  xContentTypeOptions: true,
  xDnsPrefetchControl: 'off',
  xDownloadOptions: true,
  xPermittedCrossDomainPolicies: 'none',
  referrerPolicy: 'strict-origin-when-cross-origin',
  crossOriginOpenerPolicy: 'same-origin',
  crossOriginEmbedderPolicy: 'require-corp',
  crossOriginResourcePolicy: 'same-origin',
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
    payment: [],
  },
  originAgentCluster: true,
}

/**
 * Preset: Relaxed security headers (for development or less strict needs)
 */
export const PRESET_RELAXED: SecurityHeadersConfig = {
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
    fontSrc: ["'self'", 'https:', 'data:'],
    connectSrc: ["'self'", 'https:', 'wss:'],
    frameSrc: ["'self'"],
  },
  strictTransportSecurity: {
    maxAge: 86400, // 1 day
    includeSubDomains: false,
  },
  xFrameOptions: 'SAMEORIGIN',
  xContentTypeOptions: true,
  referrerPolicy: 'no-referrer-when-downgrade',
}

/**
 * Preset: API-focused security headers
 */
export const PRESET_API: SecurityHeadersConfig = {
  contentSecurityPolicy: {
    defaultSrc: ["'none'"],
    frameAncestors: ["'none'"],
  },
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
  xFrameOptions: 'DENY',
  xContentTypeOptions: true,
  referrerPolicy: 'no-referrer',
  crossOriginResourcePolicy: 'same-origin',
}

/**
 * Get preset config by name
 */
export function getPreset(name: SecurityHeadersPreset): SecurityHeadersConfig {
  switch (name) {
    case 'strict':
      return PRESET_STRICT
    case 'relaxed':
      return PRESET_RELAXED
    case 'api':
      return PRESET_API
    default:
      return PRESET_STRICT
  }
}

/**
 * Build all headers from config
 */
export function buildHeaders(config: SecurityHeadersConfig): Headers {
  const headers = new Headers()

  // CSP
  if (config.contentSecurityPolicy) {
    const csp = buildCSP(config.contentSecurityPolicy)
    if (csp) headers.set('Content-Security-Policy', csp)
  }

  // HSTS
  if (config.strictTransportSecurity) {
    headers.set('Strict-Transport-Security', buildHSTS(config.strictTransportSecurity))
  }

  // X-Frame-Options
  if (config.xFrameOptions) {
    headers.set('X-Frame-Options', config.xFrameOptions)
  }

  // X-Content-Type-Options
  if (config.xContentTypeOptions) {
    headers.set('X-Content-Type-Options', 'nosniff')
  }

  // X-DNS-Prefetch-Control
  if (config.xDnsPrefetchControl) {
    headers.set('X-DNS-Prefetch-Control', config.xDnsPrefetchControl)
  }

  // X-Download-Options
  if (config.xDownloadOptions) {
    headers.set('X-Download-Options', 'noopen')
  }

  // X-Permitted-Cross-Domain-Policies
  if (config.xPermittedCrossDomainPolicies) {
    headers.set('X-Permitted-Cross-Domain-Policies', config.xPermittedCrossDomainPolicies)
  }

  // Referrer-Policy
  if (config.referrerPolicy) {
    const value = Array.isArray(config.referrerPolicy)
      ? config.referrerPolicy.join(', ')
      : config.referrerPolicy
    headers.set('Referrer-Policy', value)
  }

  // COOP
  if (config.crossOriginOpenerPolicy) {
    headers.set('Cross-Origin-Opener-Policy', config.crossOriginOpenerPolicy)
  }

  // COEP
  if (config.crossOriginEmbedderPolicy) {
    headers.set('Cross-Origin-Embedder-Policy', config.crossOriginEmbedderPolicy)
  }

  // CORP
  if (config.crossOriginResourcePolicy) {
    headers.set('Cross-Origin-Resource-Policy', config.crossOriginResourcePolicy)
  }

  // Permissions-Policy
  if (config.permissionsPolicy) {
    const pp = buildPermissionsPolicy(config.permissionsPolicy)
    if (pp) headers.set('Permissions-Policy', pp)
  }

  // Origin-Agent-Cluster
  if (config.originAgentCluster) {
    headers.set('Origin-Agent-Cluster', '?1')
  }

  return headers
}
