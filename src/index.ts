/**
 * next-secure
 *
 * Production-ready security middleware for Next.js 13+ App Router.
 *
 * @example
 * ```typescript
 * import { withRateLimit, withAuth, secure } from 'next-secure'
 *
 * // Simple rate limiting
 * export const GET = withRateLimit(
 *   async (req) => Response.json({ ok: true }),
 *   { limit: 100, window: '15m' }
 * )
 *
 * // Builder pattern
 * export const POST = secure()
 *   .rateLimit({ limit: 10, window: '1m' })
 *   .auth({ roles: ['admin'] })
 *   .handle(async (req, ctx) => {
 *     return Response.json({ user: ctx.user })
 *   })
 * ```
 *
 * @packageDocumentation
 */

// =============================================================================
// Core
// =============================================================================

export type {
  NextRequest,
  SecureContext,
  SecureHandler,
  Middleware,
  ErrorResponse,
  RateLimitInfo,
  Duration,
  RateLimitAlgorithm,
  RateLimitIdentifier,
} from './core/types'

export {
  SecureError,
  RateLimitError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  CsrfError,
  ConfigurationError,
  isSecureError,
  toSecureError,
} from './core/errors'

// =============================================================================
// Rate Limiting
// =============================================================================

export {
  withRateLimit,
  createRateLimiter,
  checkRateLimit,
  resetRateLimit,
  getRateLimitStatus,
  clearAllRateLimits,
} from './middleware/rate-limit'

export type {
  RateLimitConfig,
  RateLimitStore,
  MemoryStoreOptions,
  RedisStoreOptions,
  UpstashStoreOptions,
} from './middleware/rate-limit'

export {
  MemoryStore,
  createMemoryStore,
  getGlobalMemoryStore,
} from './middleware/rate-limit'

// =============================================================================
// CSRF Protection
// =============================================================================

export {
  withCSRF,
  generateCSRF,
  validateCSRF,
  createToken as createCSRFToken,
  verifyToken as verifyCSRFToken,
  tokensMatch,
} from './middleware/csrf'

export type {
  CSRFConfig,
  CSRFCookieOptions,
  CSRFToken,
} from './middleware/csrf'

// =============================================================================
// Security Headers
// =============================================================================

export {
  withSecurityHeaders,
  createSecurityHeaders,
  createSecurityHeadersObject,
  buildCSP,
  buildHSTS,
  buildPermissionsPolicy,
  getPreset,
  PRESET_STRICT,
  PRESET_RELAXED,
  PRESET_API,
} from './middleware/headers'

export type {
  ContentSecurityPolicy,
  StrictTransportSecurity,
  PermissionsPolicy,
  SecurityHeadersConfig,
  SecurityHeadersPreset,
  XFrameOptions,
  ReferrerPolicy,
} from './middleware/headers'

// =============================================================================
// Authentication
// =============================================================================

export {
  withJWT,
  withAPIKey,
  withSession,
  withAuth,
  withRoles,
  withOptionalAuth,
  verifyJWT,
  decodeJWT,
  extractBearerToken,
} from './middleware/auth'

export type {
  AuthUser,
  AuthConfig,
  AuthError,
  AuthErrorCode,
  JWTConfig,
  JWTPayload,
  APIKeyConfig,
  SessionConfig,
  RBACConfig,
} from './middleware/auth'

// =============================================================================
// Input Validation
// =============================================================================

export {
  // Middleware
  withValidation,
  withSanitization,
  withXSSProtection,
  withSQLProtection,
  withContentType,
  withFileValidation,
  withSecureValidation,
  // Schema validation
  validate,
  validateBody,
  validateQuery,
  validateRequest,
  createValidator,
  // XSS
  sanitize,
  sanitizeObject,
  sanitizeFields,
  escapeHtml,
  stripHtml,
  detectXSS,
  // SQL
  detectSQLInjection,
  hasSQLInjection,
  sanitizeSQLInput,
  // Path
  validatePath,
  sanitizePath,
  hasPathTraversal,
  sanitizeFilename,
  // Content-Type
  validateContentType,
  isJsonRequest,
  isFormRequest,
  MIME_TYPES,
  // File
  validateFile,
  validateFiles,
  detectFileType,
  DANGEROUS_EXTENSIONS,
} from './middleware/validation'

export type {
  ValidationError as InputValidationError,
  ValidationResult,
  ValidationConfig,
  ValidatedContext,
  SanitizeConfig,
  SanitizeMode,
  SQLDetection,
  SQLProtectionConfig,
  PathValidationConfig,
  PathValidationResult,
  ContentTypeConfig,
  FileValidationConfig,
  FileValidationError,
  FileInfo,
  FieldRule,
  FieldType,
  CustomSchema,
} from './middleware/validation'

// =============================================================================
// Audit Logging
// =============================================================================

export {
  // Middleware
  withAuditLog,
  createAuditMiddleware,
  withRequestId,
  withTiming,
  // Stores
  MemoryStore as AuditMemoryStore,
  createMemoryStore as createAuditMemoryStore,
  ConsoleStore,
  createConsoleStore,
  ExternalStore,
  createExternalStore,
  createDatadogStore,
  MultiStore,
  createMultiStore,
  // Formatters
  JSONFormatter,
  TextFormatter,
  CLFFormatter,
  StructuredFormatter,
  createJSONFormatter,
  createTextFormatter,
  createCLFFormatter,
  createStructuredFormatter,
  // Redaction
  DEFAULT_PII_FIELDS,
  mask,
  redactObject,
  createRedactor,
  redactHeaders,
  redactQuery,
  redactEmail,
  redactCreditCard,
  redactPhone,
  redactIP,
  // Security Events
  SecurityEventTracker,
  createSecurityTracker,
  trackSecurityEvent,
} from './middleware/audit'

export type {
  LogLevel,
  SecurityEventType,
  LogEntry,
  RequestLogEntry,
  SecurityEventEntry,
  AuditLogEntry,
  LogStore,
  LogQueryOptions,
  LogFormatter,
  PIIConfig,
  AuditConfig,
  SecurityEventConfig,
  ConsoleStoreOptions,
  MemoryStoreOptions as AuditMemoryStoreOptions,
  ExternalStoreOptions,
} from './middleware/audit'

// =============================================================================
// Bot Detection
// =============================================================================

export {
  // Main middleware
  withBotProtection,
  withUserAgentProtection,
  withHoneypotProtection,
  withBehaviorProtection,
  withCaptchaProtection,
  withBotProtectionPreset,
  detectBot,
  BOT_PROTECTION_PRESETS,
  // User-Agent
  analyzeUserAgent,
  isSuspiciousUA,
  isBotAllowed,
  getBotsByCategory,
  createBotPattern,
  KNOWN_BOT_PATTERNS,
  DEFAULT_ALLOWED_CATEGORIES,
  DEFAULT_ALLOWED_BOTS,
  // Honeypot
  checkHoneypot,
  withHoneypot,
  generateHoneypotHTML,
  generateHoneypotCSS,
  DEFAULT_HONEYPOT_FIELDS,
  // Behavior
  MemoryBehaviorStore,
  analyzeBehavior,
  checkBehavior,
  getGlobalBehaviorStore,
  withBehaviorAnalysis,
  // CAPTCHA
  verifyCaptcha,
  checkCaptcha,
  withCaptcha,
  generateRecaptchaV2,
  generateRecaptchaV3,
  generateHCaptcha,
  generateTurnstile,
} from './middleware/bot'

export type {
  BotCategory,
  BotDetectionResult,
  BotPattern,
  UserAgentOptions,
  HoneypotOptions,
  BehaviorOptions,
  BehaviorStore,
  BehaviorAnalysisResult,
  CaptchaProvider,
  CaptchaOptions,
  CaptchaResult,
  BotProtectionOptions,
  BotContext,
} from './middleware/bot'

// =============================================================================
// API Security
// =============================================================================

export {
  // Main middleware
  withAPIProtection,
  withAPIProtectionPreset,
  checkAPIProtection,
  API_PROTECTION_PRESETS,
  // Signing
  withRequestSigning,
  verifySignature,
  generateSignature,
  generateSignatureHeaders,
  createHMAC,
  timingSafeEqual,
  buildCanonicalString,
  // Replay Prevention
  withReplayPrevention,
  checkReplay,
  MemoryNonceStore,
  getGlobalNonceStore,
  generateNonce,
  isValidNonceFormat,
  addNonceHeader,
  // Timestamp
  withTimestamp,
  validateTimestamp,
  parseTimestamp,
  formatTimestamp,
  isTimestampValid,
  addTimestampHeader,
  getRequestAge,
  // Versioning
  withAPIVersion,
  validateVersion,
  extractVersion,
  getVersionStatus,
  isVersionSupported,
  createVersionRouter,
  addDeprecationHeaders,
  compareVersions,
  normalizeVersion,
  // Idempotency
  withIdempotency,
  checkIdempotency,
  cacheResponse,
  MemoryIdempotencyStore,
  getGlobalIdempotencyStore,
  generateIdempotencyKey,
  hashRequestBody,
  isValidIdempotencyKey,
  createResponseFromCache,
  addIdempotencyHeader,
} from './middleware/api'

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
} from './middleware/api'

// =============================================================================
// Utilities
// =============================================================================

export {
  parseDuration,
  formatDuration,
  nowInSeconds,
  nowInMs,
  sleep,
} from './utils/time'

export {
  getClientIp,
  normalizeIp,
  isValidIp,
  isPrivateIp,
  isLocalhost,
  anonymizeIp,
  getGeoInfo,
} from './utils/ip'

// =============================================================================
// Version
// =============================================================================

/**
 * Package version
 */
export const VERSION = '0.8.0'
