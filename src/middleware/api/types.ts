/**
 * API Security Types
 * @module nextjs-secure/api
 */

// ============================================================================
// Request Signing Types
// ============================================================================

/**
 * Supported signing algorithms
 */
export type SigningAlgorithm = 'sha256' | 'sha512' | 'sha384' | 'sha1'

/**
 * Signature encoding format
 */
export type SignatureEncoding = 'hex' | 'base64' | 'base64url'

/**
 * Components to include in signature
 */
export interface SignatureComponents {
  /** Include HTTP method */
  method?: boolean
  /** Include request path */
  path?: boolean
  /** Include query string */
  query?: boolean
  /** Include request body */
  body?: boolean
  /** Include specific headers */
  headers?: string[]
  /** Include timestamp */
  timestamp?: boolean
  /** Include nonce */
  nonce?: boolean
}

/**
 * Request signing options
 */
export interface SigningOptions {
  /** Secret key for HMAC signing */
  secret: string
  /** Signing algorithm (default: sha256) */
  algorithm?: SigningAlgorithm
  /** Signature encoding (default: hex) */
  encoding?: SignatureEncoding
  /** Header name for signature (default: x-signature) */
  signatureHeader?: string
  /** Header name for timestamp (default: x-timestamp) */
  timestampHeader?: string
  /** Header name for nonce (default: x-nonce) */
  nonceHeader?: string
  /** Components to include in signature */
  components?: SignatureComponents
  /** Timestamp tolerance in seconds (default: 300) */
  timestampTolerance?: number
  /** Custom canonical string builder */
  canonicalBuilder?: (req: Request, components: SignatureComponents) => Promise<string>
  /** Custom error response */
  onInvalid?: (reason: string) => Response | Promise<Response>
  /** Skip signing for certain requests */
  skip?: (req: Request) => boolean | Promise<boolean>
}

/**
 * Signature verification result
 */
export interface SignatureResult {
  /** Whether signature is valid */
  valid: boolean
  /** Reason for failure (if invalid) */
  reason?: string
  /** Computed signature (for debugging) */
  computed?: string
  /** Provided signature */
  provided?: string
  /** Canonical string used */
  canonical?: string
}

// ============================================================================
// Replay Prevention Types
// ============================================================================

/**
 * Nonce store interface for replay prevention
 */
export interface NonceStore {
  /** Check if nonce exists (has been used) */
  exists(nonce: string): Promise<boolean>
  /** Store a nonce with TTL */
  set(nonce: string, ttl: number): Promise<void>
  /** Remove expired nonces (optional cleanup) */
  cleanup?(): Promise<void>
  /** Get store statistics */
  getStats?(): { size: number; oldestTimestamp?: number }
}

/**
 * Replay prevention options
 */
export interface ReplayPreventionOptions {
  /** Nonce store instance */
  store?: NonceStore
  /** Header name for nonce (default: x-nonce) */
  nonceHeader?: string
  /** Query param name for nonce (optional) */
  nonceQuery?: string
  /** TTL for nonces in milliseconds (default: 300000 = 5 minutes) */
  ttl?: number
  /** Require nonce on all requests (default: true) */
  required?: boolean
  /** Minimum nonce length (default: 16) */
  minLength?: number
  /** Maximum nonce length (default: 128) */
  maxLength?: number
  /** Custom nonce validator */
  validate?: (nonce: string) => boolean | Promise<boolean>
  /** Custom error response */
  onReplay?: (nonce: string) => Response | Promise<Response>
  /** Skip replay check for certain requests */
  skip?: (req: Request) => boolean | Promise<boolean>
}

/**
 * Replay check result
 */
export interface ReplayCheckResult {
  /** Whether request is a replay */
  isReplay: boolean
  /** Nonce value */
  nonce?: string
  /** Reason for failure */
  reason?: string
}

// ============================================================================
// Timestamp Validation Types
// ============================================================================

/**
 * Timestamp format
 */
export type TimestampFormat = 'unix' | 'unix-ms' | 'iso8601'

/**
 * Timestamp validation options
 */
export interface TimestampOptions {
  /** Header name for timestamp (default: x-timestamp) */
  timestampHeader?: string
  /** Query param name for timestamp (optional) */
  timestampQuery?: string
  /** Expected timestamp format (default: unix) */
  format?: TimestampFormat
  /** Maximum age in seconds (default: 300 = 5 minutes) */
  maxAge?: number
  /** Allow future timestamps (default: false) */
  allowFuture?: boolean
  /** Maximum future time in seconds (default: 60) */
  maxFuture?: number
  /** Require timestamp on all requests (default: true) */
  required?: boolean
  /** Custom error response */
  onInvalid?: (reason: string) => Response | Promise<Response>
  /** Skip timestamp check for certain requests */
  skip?: (req: Request) => boolean | Promise<boolean>
}

/**
 * Timestamp validation result
 */
export interface TimestampResult {
  /** Whether timestamp is valid */
  valid: boolean
  /** Parsed timestamp value */
  timestamp?: number
  /** Age of request in seconds */
  age?: number
  /** Reason for failure */
  reason?: string
}

// ============================================================================
// API Versioning Types
// ============================================================================

/**
 * Version extraction source
 */
export type VersionSource = 'header' | 'path' | 'query' | 'accept'

/**
 * Version status
 */
export type VersionStatus = 'current' | 'supported' | 'deprecated' | 'sunset'

/**
 * Version information
 */
export interface VersionInfo {
  /** Version string */
  version: string
  /** Version status */
  status: VersionStatus
  /** Sunset date (for deprecated versions) */
  sunsetDate?: Date
  /** Deprecation message */
  deprecationMessage?: string
}

/**
 * API versioning options
 */
export interface VersioningOptions {
  /** Version extraction source (default: header) */
  source?: VersionSource
  /** Header name for version (default: x-api-version) */
  versionHeader?: string
  /** Query param name for version */
  versionQuery?: string
  /** Path prefix pattern (e.g., /v{version}/) */
  pathPattern?: RegExp
  /** Accept header media type pattern */
  acceptPattern?: RegExp
  /** Current/default version */
  current: string
  /** All supported versions */
  supported: string[]
  /** Deprecated versions (still work but show warning) */
  deprecated?: string[]
  /** Sunset versions (no longer work) */
  sunset?: string[]
  /** Sunset dates for deprecated versions */
  sunsetDates?: Record<string, Date>
  /** Add deprecation headers to response */
  addDeprecationHeaders?: boolean
  /** Custom version parser */
  parseVersion?: (value: string) => string | null
  /** Custom error response for unsupported version */
  onUnsupported?: (version: string) => Response | Promise<Response>
  /** Custom warning response for deprecated version */
  onDeprecated?: (version: string, sunsetDate?: Date) => void
  /** Skip version check for certain requests */
  skip?: (req: Request) => boolean | Promise<boolean>
}

/**
 * Version extraction result
 */
export interface VersionResult {
  /** Extracted version */
  version: string | null
  /** Version source */
  source: VersionSource | null
  /** Version status */
  status: VersionStatus | null
  /** Whether version is valid */
  valid: boolean
  /** Reason for failure */
  reason?: string
  /** Sunset date (if deprecated) */
  sunsetDate?: Date
}

// ============================================================================
// Idempotency Types
// ============================================================================

/**
 * Cached response for idempotency
 */
export interface CachedResponse {
  /** Response status code */
  status: number
  /** Response headers */
  headers: Record<string, string>
  /** Response body */
  body: string
  /** Timestamp when cached */
  cachedAt: number
  /** Request hash for validation */
  requestHash?: string
}

/**
 * Idempotency store interface
 */
export interface IdempotencyStore {
  /** Get cached response for key */
  get(key: string): Promise<CachedResponse | null>
  /** Store response with TTL */
  set(key: string, response: CachedResponse, ttl: number): Promise<void>
  /** Check if key is currently being processed (for concurrent requests) */
  isProcessing(key: string): Promise<boolean>
  /** Mark key as being processed */
  startProcessing(key: string, timeout: number): Promise<boolean>
  /** Mark key as done processing */
  endProcessing(key: string): Promise<void>
  /** Remove a key */
  delete(key: string): Promise<void>
  /** Cleanup expired entries */
  cleanup?(): Promise<void>
}

/**
 * Idempotency options
 */
export interface IdempotencyOptions {
  /** Idempotency store instance */
  store?: IdempotencyStore
  /** Header name for idempotency key (default: idempotency-key) */
  keyHeader?: string
  /** TTL for cached responses in milliseconds (default: 86400000 = 24 hours) */
  ttl?: number
  /** Require idempotency key for mutating requests (default: false) */
  required?: boolean
  /** HTTP methods that require idempotency (default: POST, PUT, PATCH) */
  methods?: string[]
  /** Minimum key length (default: 16) */
  minKeyLength?: number
  /** Maximum key length (default: 256) */
  maxKeyLength?: number
  /** Include request body hash in cache key (default: true) */
  hashRequestBody?: boolean
  /** Lock timeout for concurrent requests in ms (default: 30000) */
  lockTimeout?: number
  /** Wait for lock instead of failing (default: true) */
  waitForLock?: boolean
  /** Max wait time for lock in ms (default: 10000) */
  maxWaitTime?: number
  /** Custom key validator */
  validateKey?: (key: string) => boolean | Promise<boolean>
  /** Custom error response */
  onError?: (reason: string) => Response | Promise<Response>
  /** Skip idempotency for certain requests */
  skip?: (req: Request) => boolean | Promise<boolean>
  /** Called when returning cached response */
  onCacheHit?: (key: string, response: CachedResponse) => void
}

/**
 * Idempotency check result
 */
export interface IdempotencyResult {
  /** Idempotency key */
  key: string | null
  /** Whether response was from cache */
  fromCache: boolean
  /** Cached response (if from cache) */
  cachedResponse?: CachedResponse
  /** Whether request is currently being processed */
  isProcessing: boolean
  /** Reason for any errors */
  reason?: string
}

// ============================================================================
// Combined API Protection Types
// ============================================================================

/**
 * API protection preset names
 */
export type APIProtectionPreset = 'basic' | 'standard' | 'strict' | 'financial'

/**
 * Combined API protection options
 */
export interface APIProtectionOptions {
  /** Request signing options (false to disable) */
  signing?: SigningOptions | false
  /** Replay prevention options (false to disable) */
  replay?: ReplayPreventionOptions | false
  /** Timestamp validation options (false to disable) */
  timestamp?: TimestampOptions | false
  /** API versioning options (false to disable) */
  versioning?: VersioningOptions | false
  /** Idempotency options (false to disable) */
  idempotency?: IdempotencyOptions | false
  /** Custom error handler */
  onError?: (error: APISecurityError) => Response | Promise<Response>
  /** Skip all checks for certain requests */
  skip?: (req: Request) => boolean | Promise<boolean>
}

/**
 * API security error
 */
export interface APISecurityError {
  /** Error type */
  type: 'signing' | 'replay' | 'timestamp' | 'versioning' | 'idempotency'
  /** Error message */
  message: string
  /** Additional details */
  details?: Record<string, unknown>
}

/**
 * API protection result
 */
export interface APIProtectionResult {
  /** Whether all checks passed */
  passed: boolean
  /** Signing result */
  signing?: SignatureResult
  /** Replay check result */
  replay?: ReplayCheckResult
  /** Timestamp result */
  timestamp?: TimestampResult
  /** Version result */
  version?: VersionResult
  /** Idempotency result */
  idempotency?: IdempotencyResult
  /** Error if any check failed */
  error?: APISecurityError
}

// ============================================================================
// Preset Configurations
// ============================================================================

/**
 * API protection presets
 */
export const API_PROTECTION_PRESETS: Record<APIProtectionPreset, Partial<APIProtectionOptions>> = {
  /** Basic: Only timestamp and versioning */
  basic: {
    signing: false,
    replay: false,
    timestamp: {
      maxAge: 600, // 10 minutes
      required: false,
    },
    versioning: false,
    idempotency: false,
  },

  /** Standard: Timestamp, replay prevention, versioning */
  standard: {
    signing: false,
    replay: {
      ttl: 300000, // 5 minutes
      required: true,
    },
    timestamp: {
      maxAge: 300, // 5 minutes
      required: true,
    },
    versioning: false,
    idempotency: {
      required: false,
    },
  },

  /** Strict: All protections enabled */
  strict: {
    signing: {
      secret: '', // Must be provided
      algorithm: 'sha256',
      timestampTolerance: 300,
    },
    replay: {
      ttl: 300000,
      required: true,
      minLength: 32,
    },
    timestamp: {
      maxAge: 300,
      required: true,
      allowFuture: false,
    },
    versioning: false,
    idempotency: {
      required: true,
      methods: ['POST', 'PUT', 'PATCH', 'DELETE'],
    },
  },

  /** Financial: Maximum security for financial APIs */
  financial: {
    signing: {
      secret: '', // Must be provided
      algorithm: 'sha512',
      timestampTolerance: 60, // 1 minute
      components: {
        method: true,
        path: true,
        query: true,
        body: true,
        timestamp: true,
        nonce: true,
      },
    },
    replay: {
      ttl: 86400000, // 24 hours
      required: true,
      minLength: 64,
    },
    timestamp: {
      maxAge: 60, // 1 minute
      required: true,
      allowFuture: false,
      maxFuture: 10,
    },
    versioning: false,
    idempotency: {
      required: true,
      ttl: 604800000, // 7 days
      methods: ['POST', 'PUT', 'PATCH', 'DELETE'],
      hashRequestBody: true,
    },
  },
}
