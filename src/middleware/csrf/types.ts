import type { NextRequest } from 'next/server'

export interface CSRFCookieOptions {
  name?: string
  path?: string
  domain?: string
  secure?: boolean
  httpOnly?: boolean
  sameSite?: 'strict' | 'lax' | 'none'
  maxAge?: number
}

export interface CSRFConfig {
  /** Cookie settings */
  cookie?: CSRFCookieOptions

  /** Header name to check for token (default: x-csrf-token) */
  headerName?: string

  /** Form field name (default: _csrf) */
  fieldName?: string

  /** Secret for signing tokens */
  secret?: string

  /** Token length in bytes (default: 32) */
  tokenLength?: number

  /** Methods to protect (default: POST, PUT, PATCH, DELETE) */
  protectedMethods?: string[]

  /** Skip CSRF check for specific requests */
  skip?: (req: NextRequest) => boolean | Promise<boolean>

  /** Called when CSRF validation fails */
  onError?: (req: NextRequest, reason: string) => Response | Promise<Response>
}

export interface CSRFToken {
  value: string
  cookie: string
}
