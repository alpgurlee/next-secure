// Types
export type {
  ValidationError,
  ValidationResult,
  Schema,
  SchemaIssue,
  FieldType,
  FieldRule,
  CustomSchema,
  ValidationConfig,
  ValidatedContext,
  SanitizeMode,
  SanitizeConfig,
  SanitizationMiddlewareConfig,
  SanitizationChange,
  SQLProtectionConfig,
  SQLDetection,
  PathValidationConfig,
  PathValidationResult,
  ContentTypeConfig,
  FileValidationConfig,
  FileValidationError,
  FileInfo,
  MagicNumber,
} from './types'

// Middleware
export {
  withValidation,
  withSanitization,
  withXSSProtection,
  withSQLProtection,
  withContentType,
  withFileValidation,
  withSecureValidation,
} from './middleware'

// Schema validation
export {
  validate,
  validateBody,
  validateQuery,
  validateParams,
  validateRequest,
  createValidator,
  allValid,
  mergeErrors,
  defaultValidationErrorResponse,
} from './validators/schema'

// Content-Type validation
export {
  validateContentType,
  parseContentType,
  isAllowedContentType,
  isJsonRequest,
  isFormRequest,
  isMultipartRequest,
  getMultipartBoundary,
  defaultContentTypeErrorResponse,
  MIME_TYPES,
} from './validators/content-type'

// File validation
export {
  validateFile,
  validateFiles,
  validateFilesFromRequest,
  extractFilesFromFormData,
  detectFileType,
  checkMagicNumber,
  defaultFileErrorResponse,
  DEFAULT_MAX_FILE_SIZE,
  DEFAULT_MAX_FILES,
  DANGEROUS_EXTENSIONS,
} from './validators/file'

// XSS sanitization
export {
  sanitize,
  sanitizeObject,
  sanitizeFields,
  escapeHtml,
  unescapeHtml,
  stripHtml,
  sanitizeHtml,
  detectXSS,
  isSafeUrl,
} from './sanitizers/xss'

// SQL injection detection
export {
  detectSQLInjection,
  detectSQLInjectionInObject,
  hasSQLInjection,
  sanitizeSQLInput,
  isAllowedValue,
} from './sanitizers/sql'

// Path validation
export {
  validatePath,
  sanitizePath,
  hasPathTraversal,
  isPathContained,
  getExtension,
  getFilename,
  sanitizeFilename,
  isHiddenPath,
} from './sanitizers/path'

// Utilities
export {
  isZodSchema,
  isCustomSchema,
  validateField,
  validateCustomSchema,
  validateZodSchema,
  getByPath,
  setByPath,
  walkObject,
  parseQueryString,
} from './utils'
