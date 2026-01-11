/**
 * Content-Security-Policy directive values
 */
export type CSPDirectiveValue = string | string[]

export interface ContentSecurityPolicy {
  defaultSrc?: CSPDirectiveValue
  scriptSrc?: CSPDirectiveValue
  styleSrc?: CSPDirectiveValue
  imgSrc?: CSPDirectiveValue
  fontSrc?: CSPDirectiveValue
  connectSrc?: CSPDirectiveValue
  mediaSrc?: CSPDirectiveValue
  objectSrc?: CSPDirectiveValue
  frameSrc?: CSPDirectiveValue
  childSrc?: CSPDirectiveValue
  workerSrc?: CSPDirectiveValue
  frameAncestors?: CSPDirectiveValue
  formAction?: CSPDirectiveValue
  baseUri?: CSPDirectiveValue
  manifestSrc?: CSPDirectiveValue
  upgradeInsecureRequests?: boolean
  blockAllMixedContent?: boolean
  reportUri?: string
  reportTo?: string
}

export interface StrictTransportSecurity {
  maxAge: number
  includeSubDomains?: boolean
  preload?: boolean
}

export type XFrameOptions = 'DENY' | 'SAMEORIGIN'

export type ReferrerPolicy =
  | 'no-referrer'
  | 'no-referrer-when-downgrade'
  | 'origin'
  | 'origin-when-cross-origin'
  | 'same-origin'
  | 'strict-origin'
  | 'strict-origin-when-cross-origin'
  | 'unsafe-url'

export type CrossOriginOpenerPolicy =
  | 'unsafe-none'
  | 'same-origin-allow-popups'
  | 'same-origin'

export type CrossOriginEmbedderPolicy =
  | 'unsafe-none'
  | 'require-corp'
  | 'credentialless'

export type CrossOriginResourcePolicy =
  | 'same-site'
  | 'same-origin'
  | 'cross-origin'

export interface PermissionsPolicy {
  accelerometer?: string[]
  ambientLightSensor?: string[]
  autoplay?: string[]
  battery?: string[]
  camera?: string[]
  displayCapture?: string[]
  documentDomain?: string[]
  encryptedMedia?: string[]
  fullscreen?: string[]
  geolocation?: string[]
  gyroscope?: string[]
  magnetometer?: string[]
  microphone?: string[]
  midi?: string[]
  payment?: string[]
  pictureInPicture?: string[]
  publicKeyCredentialsGet?: string[]
  screenWakeLock?: string[]
  syncXhr?: string[]
  usb?: string[]
  webShare?: string[]
  xrSpatialTracking?: string[]
}

export interface SecurityHeadersConfig {
  /** Content-Security-Policy */
  contentSecurityPolicy?: ContentSecurityPolicy | false

  /** Strict-Transport-Security */
  strictTransportSecurity?: StrictTransportSecurity | false

  /** X-Frame-Options */
  xFrameOptions?: XFrameOptions | false

  /** X-Content-Type-Options: nosniff */
  xContentTypeOptions?: boolean

  /** X-DNS-Prefetch-Control */
  xDnsPrefetchControl?: 'on' | 'off' | false

  /** X-Download-Options: noopen (IE specific) */
  xDownloadOptions?: boolean

  /** X-Permitted-Cross-Domain-Policies */
  xPermittedCrossDomainPolicies?: 'none' | 'master-only' | 'by-content-type' | 'all' | false

  /** Referrer-Policy */
  referrerPolicy?: ReferrerPolicy | ReferrerPolicy[] | false

  /** Cross-Origin-Opener-Policy */
  crossOriginOpenerPolicy?: CrossOriginOpenerPolicy | false

  /** Cross-Origin-Embedder-Policy */
  crossOriginEmbedderPolicy?: CrossOriginEmbedderPolicy | false

  /** Cross-Origin-Resource-Policy */
  crossOriginResourcePolicy?: CrossOriginResourcePolicy | false

  /** Permissions-Policy */
  permissionsPolicy?: PermissionsPolicy | false

  /** Origin-Agent-Cluster */
  originAgentCluster?: boolean
}

export type SecurityHeadersPreset = 'strict' | 'relaxed' | 'api'
