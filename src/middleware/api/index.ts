/**
 * API Security Module
 * @module nextjs-secure/api
 */

// Types
export type {
  // Signing types
  SigningAlgorithm,
  SignatureEncoding,
  SignatureComponents,
  SigningOptions,
  SignatureResult,
  // Replay types
  NonceStore,
  ReplayPreventionOptions,
  ReplayCheckResult,
  // Timestamp types
  TimestampFormat,
  TimestampOptions,
  TimestampResult,
  // Versioning types
  VersionSource,
  VersionStatus,
  VersionInfo,
  VersioningOptions,
  VersionResult,
  // Idempotency types
  CachedResponse,
  IdempotencyStore,
  IdempotencyOptions,
  IdempotencyResult,
  // Combined types
  APIProtectionPreset,
  APIProtectionOptions,
  APISecurityError,
  APIProtectionResult,
} from './types'

// Constants
export { API_PROTECTION_PRESETS } from './types'

// Signing
export {
  DEFAULT_SIGNING_OPTIONS,
  createHMAC,
  timingSafeEqual,
  buildCanonicalString,
  generateSignature,
  generateSignatureHeaders,
  verifySignature,
  withRequestSigning,
  createNonce,
} from './signing'

// Replay Prevention
export {
  DEFAULT_REPLAY_OPTIONS,
  MemoryNonceStore,
  getGlobalNonceStore,
  generateNonce,
  isValidNonceFormat,
  extractNonce,
  checkReplay,
  withReplayPrevention,
  addNonceHeader,
} from './replay'

// Timestamp Validation
export {
  DEFAULT_TIMESTAMP_OPTIONS,
  parseTimestamp,
  formatTimestamp,
  extractTimestamp,
  validateTimestamp,
  isTimestampValid,
  withTimestamp,
  addTimestampHeader,
  getRequestAge,
} from './timestamp'

// API Versioning
export {
  DEFAULT_VERSIONING_OPTIONS,
  extractVersion,
  extractVersionMultiSource,
  getVersionStatus,
  isVersionSupported,
  validateVersion,
  addDeprecationHeaders,
  withAPIVersion,
  createVersionRouter,
  compareVersions,
  isVersionAtLeast,
  normalizeVersion,
} from './versioning'

// Idempotency
export {
  DEFAULT_IDEMPOTENCY_OPTIONS,
  MemoryIdempotencyStore,
  getGlobalIdempotencyStore,
  generateIdempotencyKey,
  hashRequestBody,
  isValidIdempotencyKey,
  createCacheKey,
  extractIdempotencyKey,
  checkIdempotency,
  cacheResponse,
  createResponseFromCache,
  withIdempotency,
  addIdempotencyHeader,
} from './idempotency'

// Combined Middleware
export {
  checkAPIProtection,
  withAPIProtection,
  withAPIProtectionPreset,
} from './middleware'
