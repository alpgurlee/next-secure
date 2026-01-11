import { describe, it, expect } from 'vitest'
import {
  detectSQLInjection,
  hasSQLInjection,
  sanitizeSQLInput,
  detectSQLInjectionInObject,
} from '../../../src/middleware/validation'

describe('detectSQLInjection', () => {
  describe('high severity attacks', () => {
    it('detects OR 1=1 attacks', () => {
      const detections = detectSQLInjection("' OR '1'='1")
      expect(detections.length).toBeGreaterThan(0)
      expect(detections[0].severity).toBe('high')
    })

    it('detects UNION SELECT attacks', () => {
      const detections = detectSQLInjection("' UNION SELECT * FROM users--")
      expect(detections.length).toBeGreaterThan(0)
      expect(detections.some(d => d.pattern.includes('UNION'))).toBe(true)
    })

    it('detects DROP TABLE attacks', () => {
      const detections = detectSQLInjection("; DROP TABLE users;")
      expect(detections.length).toBeGreaterThan(0)
      expect(detections[0].severity).toBe('high')
    })

    it('detects DELETE attacks', () => {
      const detections = detectSQLInjection("; DELETE FROM users WHERE 1=1")
      expect(detections.length).toBeGreaterThan(0)
    })

    it('detects time-based attacks', () => {
      expect(detectSQLInjection("'; SLEEP(5);--").length).toBeGreaterThan(0)
      expect(detectSQLInjection("'; WAITFOR DELAY '0:0:5'--").length).toBeGreaterThan(0)
    })

    it('detects file operations', () => {
      expect(detectSQLInjection("' UNION SELECT LOAD_FILE('/etc/passwd')--").length).toBeGreaterThan(0)
      expect(detectSQLInjection("' INTO OUTFILE '/tmp/shell.php'--").length).toBeGreaterThan(0)
    })
  })

  describe('medium severity attacks', () => {
    it('detects comment injection', () => {
      const detections = detectSQLInjection("admin'--")
      expect(detections.length).toBeGreaterThan(0)
      expect(detections[0].severity).toBe('medium')
    })

    it('detects hex encoding', () => {
      const detections = detectSQLInjection("0x61646D696E")
      expect(detections.length).toBeGreaterThan(0)
    })
  })

  describe('low severity patterns', () => {
    it('detects SELECT statements', () => {
      const detections = detectSQLInjection("SELECT * FROM users", { minSeverity: 'low' })
      expect(detections.length).toBeGreaterThan(0)
    })

    it('detects string concatenation', () => {
      const detections = detectSQLInjection("' + 'injection", { minSeverity: 'low' })
      expect(detections.length).toBeGreaterThan(0)
    })
  })

  describe('encoded attacks', () => {
    it('detects URL encoded attacks', () => {
      const detections = detectSQLInjection("%27%20OR%20%271%27%3D%271")
      expect(detections.length).toBeGreaterThan(0)
    })

    it('detects null byte injection', () => {
      const detections = detectSQLInjection("admin%00")
      expect(detections.length).toBeGreaterThan(0)
    })
  })

  it('returns empty array for safe input', () => {
    expect(detectSQLInjection('Hello World')).toEqual([])
    expect(detectSQLInjection('john.doe@example.com')).toEqual([])
    expect(detectSQLInjection('Regular search query')).toEqual([])
  })

  it('respects minSeverity option', () => {
    const input = "SELECT * FROM users"
    expect(detectSQLInjection(input, { minSeverity: 'high' })).toEqual([])
    expect(detectSQLInjection(input, { minSeverity: 'low' }).length).toBeGreaterThan(0)
  })

  it('supports custom patterns', () => {
    const customPattern = /CUSTOM_ATTACK/gi
    const detections = detectSQLInjection('CUSTOM_ATTACK test', {
      customPatterns: [customPattern],
    })
    expect(detections.length).toBeGreaterThan(0)
  })
})

describe('hasSQLInjection', () => {
  it('returns true for SQL injection', () => {
    expect(hasSQLInjection("' OR '1'='1")).toBe(true)
  })

  it('returns false for safe input', () => {
    expect(hasSQLInjection('Hello World')).toBe(false)
  })

  it('respects minSeverity', () => {
    const input = "admin'--"
    expect(hasSQLInjection(input, 'high')).toBe(false)
    expect(hasSQLInjection(input, 'medium')).toBe(true)
  })
})

describe('sanitizeSQLInput', () => {
  it('escapes single quotes', () => {
    expect(sanitizeSQLInput("O'Brien")).toBe("O''Brien")
  })

  it('removes semicolons', () => {
    expect(sanitizeSQLInput('test; DROP TABLE users')).toBe("test DROP TABLE users")
  })

  it('removes comment sequences', () => {
    expect(sanitizeSQLInput('test -- comment')).toBe('test  comment')
    expect(sanitizeSQLInput('test /* comment */')).toBe('test  comment ')
  })

  it('removes null bytes', () => {
    expect(sanitizeSQLInput('test\0')).toBe('test')
  })

  it('removes hex values', () => {
    expect(sanitizeSQLInput('test 0x41424344')).toBe('test ')
  })
})

describe('detectSQLInjectionInObject', () => {
  it('detects injection in object fields', () => {
    const obj = {
      username: "admin",
      password: "' OR '1'='1",
    }
    const detections = detectSQLInjectionInObject(obj)
    expect(detections.length).toBeGreaterThan(0)
    expect(detections[0].field).toBe('password')
  })

  it('handles nested objects', () => {
    const obj = {
      user: {
        query: "'; DROP TABLE users--",
      },
    }
    const detections = detectSQLInjectionInObject(obj)
    expect(detections.length).toBeGreaterThan(0)
    expect(detections[0].field).toBe('user.query')
  })

  it('filters by field names', () => {
    const obj = {
      safe: "' OR '1'='1",
      query: "' OR '1'='1",
    }
    const detections = detectSQLInjectionInObject(obj, { fields: ['query'] })
    expect(detections.length).toBe(1)
    expect(detections[0].field).toBe('query')
  })

  it('handles arrays', () => {
    const obj = {
      queries: ["SELECT * FROM users", "' OR '1'='1"],
    }
    const detections = detectSQLInjectionInObject(obj, { minSeverity: 'low' })
    expect(detections.length).toBeGreaterThan(0)
  })
})
