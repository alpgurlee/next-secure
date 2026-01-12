// Types
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
  FileStoreOptions,
  MemoryStoreOptions,
  ExternalStoreOptions,
} from './types'

// Stores
export {
  MemoryStore,
  createMemoryStore,
  ConsoleStore,
  createConsoleStore,
  ExternalStore,
  createExternalStore,
  createDatadogStore,
  MultiStore,
  createMultiStore,
} from './stores'

// Formatters
export {
  JSONFormatter,
  TextFormatter,
  CLFFormatter,
  StructuredFormatter,
  createJSONFormatter,
  createTextFormatter,
  createCLFFormatter,
  createStructuredFormatter,
} from './formatters'

// Redaction
export {
  DEFAULT_PII_FIELDS,
  mask,
  hash,
  redactValue,
  redactObject,
  createRedactor,
  redactHeaders,
  redactQuery,
  redactEmail,
  redactCreditCard,
  redactPhone,
  redactIP,
} from './redaction'

// Security Events
export {
  SecurityEventTracker,
  createSecurityTracker,
  trackSecurityEvent,
} from './events'

// Middleware
export {
  withAuditLog,
  createAuditMiddleware,
  withRequestId,
  withTiming,
} from './middleware'
