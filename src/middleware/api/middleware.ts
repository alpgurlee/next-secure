/**
 * Combined API Security Middleware
 * @module nextjs-secure/api
 */

import type { NextRequest } from 'next/server'
import type {
  APIProtectionOptions,
  APIProtectionResult,
  APISecurityError,
  APIProtectionPreset,
  SigningOptions,
  ReplayPreventionOptions,
  TimestampOptions,
  VersioningOptions,
  IdempotencyOptions,
} from './types'
import { API_PROTECTION_PRESETS } from './types'
import { verifySignature } from './signing'
import { checkReplay, getGlobalNonceStore } from './replay'
import { validateTimestamp } from './timestamp'
import { validateVersion, addDeprecationHeaders } from './versioning'
import { checkIdempotency, cacheResponse, createResponseFromCache, getGlobalIdempotencyStore } from './idempotency'

// ============================================================================
// Combined API Protection
// ============================================================================

/**
 * Check all API security measures
 */
export async function checkAPIProtection(
  req: NextRequest,
  options: APIProtectionOptions
): Promise<APIProtectionResult> {
  const result: APIProtectionResult = {
    passed: true,
  }

  // 1. Timestamp validation (check first - fastest)
  if (options.timestamp !== false) {
    const timestampResult = validateTimestamp(req, options.timestamp as TimestampOptions)
    result.timestamp = timestampResult

    if (!timestampResult.valid) {
      result.passed = false
      result.error = {
        type: 'timestamp',
        message: timestampResult.reason || 'Invalid timestamp',
      }
      return result
    }
  }

  // 2. Replay prevention (check early)
  if (options.replay !== false) {
    const replayOpts = options.replay as ReplayPreventionOptions
    const replayResult = await checkReplay(req, {
      ...replayOpts,
      store: replayOpts.store || getGlobalNonceStore(),
    })
    result.replay = replayResult

    if (replayResult.isReplay) {
      result.passed = false
      result.error = {
        type: 'replay',
        message: 'Request replay detected',
        details: { nonce: replayResult.nonce },
      }
      return result
    }

    if (replayResult.reason && replayOpts.required !== false) {
      result.passed = false
      result.error = {
        type: 'replay',
        message: replayResult.reason,
      }
      return result
    }
  }

  // 3. Signature verification
  if (options.signing !== false) {
    const signingOpts = options.signing as SigningOptions
    const signingResult = await verifySignature(req, signingOpts)
    result.signing = signingResult

    if (!signingResult.valid) {
      result.passed = false
      result.error = {
        type: 'signing',
        message: signingResult.reason || 'Invalid signature',
      }
      return result
    }
  }

  // 4. API versioning
  if (options.versioning !== false) {
    const versioningOpts = options.versioning as VersioningOptions
    const versionResult = validateVersion(req, versioningOpts)
    result.version = versionResult

    if (!versionResult.valid) {
      result.passed = false
      result.error = {
        type: 'versioning',
        message: versionResult.reason || 'Unsupported version',
        details: { version: versionResult.version },
      }
      return result
    }
  }

  // 5. Idempotency (check last - may have side effects)
  if (options.idempotency !== false) {
    const idempotencyOpts = options.idempotency as IdempotencyOptions
    const idempotencyResult = await checkIdempotency(req, {
      ...idempotencyOpts,
      store: idempotencyOpts.store || getGlobalIdempotencyStore(),
    })
    result.idempotency = idempotencyResult

    // Error (invalid key format, etc.)
    if (idempotencyResult.reason && !idempotencyResult.isProcessing && !idempotencyResult.fromCache) {
      if (idempotencyOpts.required) {
        result.passed = false
        result.error = {
          type: 'idempotency',
          message: idempotencyResult.reason,
          details: { key: idempotencyResult.key },
        }
        return result
      }
    }
  }

  return result
}

// ============================================================================
// Combined Middleware
// ============================================================================

/**
 * Default error response
 */
function defaultErrorResponse(error: APISecurityError): Response {
  const statusMap: Record<APISecurityError['type'], number> = {
    signing: 401,
    replay: 403,
    timestamp: 400,
    versioning: 400,
    idempotency: 400,
  }

  const codeMap: Record<APISecurityError['type'], string> = {
    signing: 'INVALID_SIGNATURE',
    replay: 'REPLAY_DETECTED',
    timestamp: 'INVALID_TIMESTAMP',
    versioning: 'UNSUPPORTED_VERSION',
    idempotency: 'IDEMPOTENCY_ERROR',
  }

  return new Response(
    JSON.stringify({
      error: error.type === 'signing' ? 'Unauthorized' : error.type === 'replay' ? 'Forbidden' : 'Bad Request',
      message: error.message,
      code: codeMap[error.type],
      ...(error.details || {}),
    }),
    {
      status: statusMap[error.type],
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

/**
 * Create combined API protection middleware
 */
export function withAPIProtection<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  options: APIProtectionOptions
): (req: NextRequest, ctx: T) => Promise<Response> {
  return async (req: NextRequest, ctx: T): Promise<Response> => {
    // Check if should skip all checks
    if (options.skip && await options.skip(req)) {
      return handler(req, ctx)
    }

    // Run all checks
    const result = await checkAPIProtection(req, options)

    // Handle error
    if (!result.passed && result.error) {
      const onError = options.onError || defaultErrorResponse
      return onError(result.error)
    }

    // Handle idempotency cache hit
    if (result.idempotency?.fromCache && result.idempotency.cachedResponse) {
      const idempotencyOpts = options.idempotency as IdempotencyOptions
      if (idempotencyOpts.onCacheHit) {
        idempotencyOpts.onCacheHit(result.idempotency.key!, result.idempotency.cachedResponse)
      }
      return createResponseFromCache(result.idempotency.cachedResponse)
    }

    // Handle idempotency conflict (concurrent request)
    if (result.idempotency?.isProcessing) {
      return new Response(
        JSON.stringify({
          error: 'Conflict',
          message: 'Request with this idempotency key is currently being processed',
          code: 'IDEMPOTENCY_CONFLICT',
        }),
        {
          status: 409,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }

    // Execute handler
    let response = await handler(req, ctx)

    // Add deprecation headers if needed
    if (result.version?.status === 'deprecated') {
      const versioningOpts = options.versioning as VersioningOptions
      if (versioningOpts.addDeprecationHeaders !== false) {
        response = addDeprecationHeaders(response, result.version.version!, result.version.sunsetDate)
      }
      if (versioningOpts.onDeprecated) {
        versioningOpts.onDeprecated(result.version.version!, result.version.sunsetDate)
      }
    }

    // Cache response for idempotency
    if (result.idempotency?.key && options.idempotency !== false) {
      const idempotencyOpts = options.idempotency as IdempotencyOptions
      if (response.status >= 200 && response.status < 300) {
        await cacheResponse(result.idempotency.key, req, response, idempotencyOpts)
      }
    }

    return response
  }
}

// ============================================================================
// Preset-based Middleware
// ============================================================================

/**
 * Create API protection middleware using preset
 */
export function withAPIProtectionPreset<T = unknown>(
  handler: (req: NextRequest, ctx: T) => Response | Promise<Response>,
  preset: APIProtectionPreset,
  overrides: Partial<APIProtectionOptions> = {}
): (req: NextRequest, ctx: T) => Promise<Response> {
  const presetConfig = API_PROTECTION_PRESETS[preset]
  const mergedOptions: APIProtectionOptions = {
    ...presetConfig,
    ...overrides,
  }

  // Handle nested options merging (only merge if both preset and override have objects, not false)
  if (presetConfig.signing && typeof presetConfig.signing === 'object' &&
      overrides.signing && typeof overrides.signing === 'object') {
    mergedOptions.signing = { ...presetConfig.signing, ...overrides.signing }
  }
  if (presetConfig.replay && typeof presetConfig.replay === 'object' &&
      overrides.replay && typeof overrides.replay === 'object') {
    mergedOptions.replay = { ...presetConfig.replay, ...overrides.replay }
  }
  if (presetConfig.timestamp && typeof presetConfig.timestamp === 'object' &&
      overrides.timestamp && typeof overrides.timestamp === 'object') {
    mergedOptions.timestamp = { ...presetConfig.timestamp, ...overrides.timestamp }
  }
  if (presetConfig.idempotency && typeof presetConfig.idempotency === 'object' &&
      overrides.idempotency && typeof overrides.idempotency === 'object') {
    mergedOptions.idempotency = { ...presetConfig.idempotency, ...overrides.idempotency }
  }

  return withAPIProtection(handler, mergedOptions)
}

// ============================================================================
// Convenience Exports
// ============================================================================

// Re-export individual middleware for selective use
export { withRequestSigning } from './signing'
export { withReplayPrevention } from './replay'
export { withTimestamp } from './timestamp'
export { withAPIVersion } from './versioning'
export { withIdempotency } from './idempotency'
