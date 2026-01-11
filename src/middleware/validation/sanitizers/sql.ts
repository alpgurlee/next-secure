import type { SQLDetection } from '../types'

/**
 * SQL injection patterns with severity levels
 */
interface SQLPattern {
  pattern: RegExp
  name: string
  severity: 'low' | 'medium' | 'high'
}

/**
 * Common SQL injection patterns
 */
const SQL_PATTERNS: SQLPattern[] = [
  // High severity - Definite attacks
  {
    pattern: /'\s*OR\s+'?\d+'?\s*=\s*'?\d+'?/gi,
    name: "OR '1'='1' attack",
    severity: 'high',
  },
  {
    pattern: /'\s*OR\s+'[^']*'\s*=\s*'[^']*'/gi,
    name: "OR 'x'='x' attack",
    severity: 'high',
  },
  {
    pattern: /;\s*DROP\s+(TABLE|DATABASE|INDEX|VIEW)/gi,
    name: 'DROP statement',
    severity: 'high',
  },
  {
    pattern: /;\s*DELETE\s+FROM/gi,
    name: 'DELETE statement',
    severity: 'high',
  },
  {
    pattern: /;\s*TRUNCATE\s+/gi,
    name: 'TRUNCATE statement',
    severity: 'high',
  },
  {
    pattern: /;\s*INSERT\s+INTO/gi,
    name: 'INSERT statement',
    severity: 'high',
  },
  {
    pattern: /;\s*UPDATE\s+\w+\s+SET/gi,
    name: 'UPDATE statement',
    severity: 'high',
  },
  {
    pattern: /UNION\s+(ALL\s+)?SELECT/gi,
    name: 'UNION SELECT attack',
    severity: 'high',
  },
  {
    pattern: /EXEC(\s+|\()+(sp_|xp_)/gi,
    name: 'SQL Server stored procedure',
    severity: 'high',
  },
  {
    pattern: /EXECUTE\s+IMMEDIATE/gi,
    name: 'Oracle EXECUTE IMMEDIATE',
    severity: 'high',
  },
  {
    pattern: /INTO\s+(OUT|DUMP)FILE/gi,
    name: 'MySQL file write',
    severity: 'high',
  },
  {
    pattern: /LOAD_FILE\s*\(/gi,
    name: 'MySQL file read',
    severity: 'high',
  },
  {
    pattern: /BENCHMARK\s*\(\s*\d+\s*,/gi,
    name: 'MySQL BENCHMARK DoS',
    severity: 'high',
  },
  {
    pattern: /SLEEP\s*\(\s*\d+\s*\)/gi,
    name: 'SQL SLEEP time-based attack',
    severity: 'high',
  },
  {
    pattern: /WAITFOR\s+DELAY/gi,
    name: 'SQL Server WAITFOR DELAY',
    severity: 'high',
  },
  {
    pattern: /PG_SLEEP\s*\(/gi,
    name: 'PostgreSQL pg_sleep',
    severity: 'high',
  },

  // Medium severity - Likely attacks
  {
    pattern: /'\s*--/g,
    name: 'SQL comment injection',
    severity: 'medium',
  },
  {
    pattern: /'\s*#/g,
    name: 'MySQL comment injection',
    severity: 'medium',
  },
  {
    pattern: /\/\*[\s\S]*?\*\//g,
    name: 'Block comment',
    severity: 'medium',
  },
  {
    pattern: /'\s*;\s*$/g,
    name: 'Statement terminator',
    severity: 'medium',
  },
  {
    pattern: /HAVING\s+\d+\s*=\s*\d+/gi,
    name: 'HAVING clause injection',
    severity: 'medium',
  },
  {
    pattern: /GROUP\s+BY\s+\d+/gi,
    name: 'GROUP BY injection',
    severity: 'medium',
  },
  {
    pattern: /ORDER\s+BY\s+\d+/gi,
    name: 'ORDER BY injection',
    severity: 'medium',
  },
  {
    pattern: /CONCAT\s*\(/gi,
    name: 'CONCAT function',
    severity: 'medium',
  },
  {
    pattern: /CHAR\s*\(\s*\d+\s*\)/gi,
    name: 'CHAR function bypass',
    severity: 'medium',
  },
  {
    pattern: /0x[0-9a-f]{2,}/gi,
    name: 'Hex encoded value',
    severity: 'medium',
  },
  {
    pattern: /CONVERT\s*\(/gi,
    name: 'CONVERT function',
    severity: 'medium',
  },
  {
    pattern: /CAST\s*\(/gi,
    name: 'CAST function',
    severity: 'medium',
  },

  // Low severity - Suspicious but may be false positives
  {
    pattern: /'\s*AND\s+'?\d+'?\s*=\s*'?\d+'?/gi,
    name: "AND '1'='1' pattern",
    severity: 'low',
  },
  {
    pattern: /'\s*AND\s+'[^']*'\s*=\s*'[^']*'/gi,
    name: "AND 'x'='x' pattern",
    severity: 'low',
  },
  {
    pattern: /SELECT\s+[\w\s,*]+\s+FROM/gi,
    name: 'SELECT statement',
    severity: 'low',
  },
  {
    pattern: /'\s*\+\s*'/g,
    name: 'String concatenation',
    severity: 'low',
  },
  {
    pattern: /'\s*\|\|\s*'/g,
    name: 'Oracle string concatenation',
    severity: 'low',
  },
]

/**
 * Additional encoded patterns (URL, hex, unicode)
 * Note: These match on the NORMALIZED (decoded) input
 */
const ENCODED_PATTERNS: SQLPattern[] = [
  {
    pattern: /%27\s*%4f%52\s*%27/gi,  // URL encoded ' OR '
    name: 'URL encoded OR injection',
    severity: 'high',
  },
  {
    pattern: /%27\s*%2d%2d/gi,  // URL encoded ' --
    name: 'URL encoded comment injection',
    severity: 'medium',
  },
  {
    pattern: /\0|%00/g,  // Null byte (decoded or encoded)
    name: 'Null byte injection',
    severity: 'high',
  },
  {
    pattern: /\\x27/gi,  // Hex escape
    name: 'Hex escaped quote',
    severity: 'medium',
  },
  {
    pattern: /\\u0027/gi,  // Unicode escape
    name: 'Unicode escaped quote',
    severity: 'medium',
  },
]

/**
 * Normalize input by decoding common encodings
 */
function normalizeInput(input: string): string {
  let result = input

  // URL decode
  try {
    result = decodeURIComponent(result)
  } catch {
    // Ignore decode errors
  }

  // HTML entity decode
  result = result
    .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);?/gi, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&')

  // Hex escape decode
  result = result.replace(/\\x([0-9a-f]{2})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  )

  // Unicode escape decode
  result = result.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  )

  return result
}

/**
 * Detect SQL injection in a string
 */
export function detectSQLInjection(
  input: string,
  options: {
    customPatterns?: RegExp[]
    checkEncoded?: boolean
    minSeverity?: 'low' | 'medium' | 'high'
  } = {}
): SQLDetection[] {
  if (!input || typeof input !== 'string') return []

  const {
    customPatterns = [],
    checkEncoded = true,
    minSeverity = 'low',
  } = options

  const severityOrder = { low: 0, medium: 1, high: 2 }
  const minSeverityLevel = severityOrder[minSeverity]

  const detections: SQLDetection[] = []
  const seenPatterns = new Set<string>()

  // Normalize input for encoded pattern detection
  const normalizedInput = checkEncoded ? normalizeInput(input) : input

  // Check all patterns
  const allPatterns = [
    ...SQL_PATTERNS,
    ...(checkEncoded ? ENCODED_PATTERNS : []),
    ...customPatterns.map(p => ({ pattern: p, name: 'Custom pattern', severity: 'high' as const })),
  ]

  for (const { pattern, name, severity } of allPatterns) {
    if (severityOrder[severity] < minSeverityLevel) continue

    // Reset regex state
    pattern.lastIndex = 0

    const testInput = checkEncoded ? normalizedInput : input
    if (pattern.test(testInput)) {
      const key = `${name}:${severity}`
      if (!seenPatterns.has(key)) {
        seenPatterns.add(key)
        detections.push({
          field: '',  // Will be set by caller
          value: input,
          pattern: name,
          severity,
        })
      }
    }
  }

  return detections
}

/**
 * Check if string contains SQL injection (boolean check)
 */
export function hasSQLInjection(
  input: string,
  minSeverity: 'low' | 'medium' | 'high' = 'medium'
): boolean {
  return detectSQLInjection(input, { minSeverity }).length > 0
}

/**
 * Sanitize input to prevent SQL injection
 * NOTE: This should NOT be a replacement for parameterized queries!
 */
export function sanitizeSQLInput(input: string): string {
  if (!input || typeof input !== 'string') return ''

  let result = input

  // Remove null bytes
  result = result.replace(/\0/g, '')

  // Escape single quotes
  result = result.replace(/'/g, "''")

  // Remove dangerous characters
  result = result.replace(/;/g, '')
  result = result.replace(/--/g, '')
  result = result.replace(/\/\*/g, '')
  result = result.replace(/\*\//g, '')

  // Remove hex encoded values
  result = result.replace(/0x[0-9a-f]+/gi, '')

  return result
}

/**
 * Detect SQL injection in object fields
 */
export function detectSQLInjectionInObject(
  obj: unknown,
  options: {
    fields?: string[]
    deep?: boolean
    customPatterns?: RegExp[]
    minSeverity?: 'low' | 'medium' | 'high'
  } = {}
): SQLDetection[] {
  const { fields, deep = true, customPatterns, minSeverity } = options
  const detections: SQLDetection[] = []

  function walk(value: unknown, path: string): void {
    if (typeof value === 'string') {
      // If fields specified, only check those
      if (fields && fields.length > 0) {
        const fieldName = path.split('.').pop() || path
        if (!fields.includes(fieldName)) return
      }

      const detected = detectSQLInjection(value, { customPatterns, minSeverity })
      for (const d of detected) {
        detections.push({ ...d, field: path })
      }
    } else if (deep && Array.isArray(value)) {
      value.forEach((item, i) => walk(item, `${path}[${i}]`))
    } else if (deep && typeof value === 'object' && value !== null) {
      for (const [key, val] of Object.entries(value)) {
        walk(val, path ? `${path}.${key}` : key)
      }
    }
  }

  walk(obj, '')
  return detections
}

/**
 * Check if value is in allowlist (safe values)
 */
export function isAllowedValue(value: string, allowList: string[]): boolean {
  if (!allowList || allowList.length === 0) return false
  return allowList.includes(value)
}
