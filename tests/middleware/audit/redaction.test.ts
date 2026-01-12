import { describe, it, expect } from 'vitest'
import {
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
} from '../../../src/middleware/audit/redaction'
import type { PIIConfig } from '../../../src/middleware/audit/types'

describe('DEFAULT_PII_FIELDS', () => {
  it('should include common sensitive fields', () => {
    expect(DEFAULT_PII_FIELDS).toContain('password')
    expect(DEFAULT_PII_FIELDS).toContain('token')
    expect(DEFAULT_PII_FIELDS).toContain('email')
    expect(DEFAULT_PII_FIELDS).toContain('ssn')
    expect(DEFAULT_PII_FIELDS).toContain('credit_card')
    expect(DEFAULT_PII_FIELDS).toContain('phone')
  })
})

describe('mask', () => {
  it('should mask value with asterisks', () => {
    const result = mask('sensitive_data')
    expect(result).toContain('*')
    expect(result).not.toBe('sensitive_data')
  })

  it('should preserve first and last characters', () => {
    const result = mask('secret123', { showFirst: 2, showLast: 2 })
    expect(result).toMatch(/^se\*+23$/)
  })

  it('should preserve length when option set', () => {
    const value = 'password123'
    const result = mask(value, { preserveLength: true })
    expect(result.length).toBe(value.length)
  })

  it('should use custom mask character', () => {
    const result = mask('test', { char: '#', preserveLength: true })
    expect(result).toBe('####')
  })

  it('should handle empty values', () => {
    expect(mask('')).toBe('')
  })
})

describe('hash', () => {
  it('should return hashed value', () => {
    const result = hash('secret')
    expect(result).toHaveLength(16)
    expect(result).not.toBe('secret')
  })

  it('should produce consistent hashes', () => {
    const hash1 = hash('test')
    const hash2 = hash('test')
    expect(hash1).toBe(hash2)
  })

  it('should produce different hashes with salt', () => {
    const hash1 = hash('test', 'salt1')
    const hash2 = hash('test', 'salt2')
    expect(hash1).not.toBe(hash2)
  })
})

describe('redactValue', () => {
  const config: PIIConfig = {
    fields: ['password', 'email'],
    mode: 'mask',
  }

  it('should redact matching fields', () => {
    const result = redactValue('secret123', 'password', config)
    expect(result).not.toBe('secret123')
  })

  it('should not redact non-matching fields', () => {
    const result = redactValue('John Doe', 'name', config)
    expect(result).toBe('John Doe')
  })

  it('should handle hash mode', () => {
    const hashConfig: PIIConfig = { fields: ['password'], mode: 'hash' }
    const result = redactValue('secret', 'password', hashConfig)
    expect(result).toContain('[HASH:')
  })

  it('should handle remove mode', () => {
    const removeConfig: PIIConfig = { fields: ['password'], mode: 'remove' }
    const result = redactValue('secret', 'password', removeConfig)
    expect(result).toBe('[REDACTED]')
  })

  it('should use custom redactor', () => {
    const customConfig: PIIConfig = {
      fields: ['password'],
      mode: 'mask',
      customRedactor: () => '***CUSTOM***',
    }
    const result = redactValue('secret', 'password', customConfig)
    expect(result).toBe('***CUSTOM***')
  })
})

describe('redactObject', () => {
  const config: PIIConfig = {
    fields: ['password', 'email', 'token'],
    mode: 'mask',
  }

  it('should redact fields in object', () => {
    const obj = {
      username: 'john',
      password: 'secret123',
      email: 'john@example.com',
    }

    const result = redactObject(obj, config)

    expect(result.username).toBe('john')
    expect(result.password).not.toBe('secret123')
    expect(result.email).not.toBe('john@example.com')
  })

  it('should handle nested objects', () => {
    const obj = {
      user: {
        name: 'John',
        credentials: {
          password: 'secret',
        },
      },
    }

    const result = redactObject(obj, config)

    expect(result.user.name).toBe('John')
    expect(result.user.credentials.password).not.toBe('secret')
  })

  it('should handle arrays', () => {
    const obj = {
      users: [
        { name: 'John', password: 'pass1' },
        { name: 'Jane', password: 'pass2' },
      ],
    }

    const result = redactObject(obj, config)

    expect(result.users[0].name).toBe('John')
    expect(result.users[0].password).not.toBe('pass1')
    expect(result.users[1].password).not.toBe('pass2')
  })

  it('should handle null and undefined', () => {
    const obj = {
      nullField: null,
      undefinedField: undefined,
      password: 'secret',
    }

    const result = redactObject(obj, config)

    expect(result.nullField).toBeNull()
    expect(result.undefinedField).toBeUndefined()
  })
})

describe('createRedactor', () => {
  it('should create reusable redactor function', () => {
    const redactor = createRedactor({ fields: ['password'], mode: 'remove' })

    const obj1 = { password: 'pass1' }
    const obj2 = { password: 'pass2' }

    expect(redactor(obj1).password).toBe('[REDACTED]')
    expect(redactor(obj2).password).toBe('[REDACTED]')
  })

  it('should use default config', () => {
    const redactor = createRedactor()
    const obj = { password: 'secret' }

    expect(redactor(obj).password).not.toBe('secret')
  })
})

describe('redactHeaders', () => {
  it('should redact sensitive headers', () => {
    const headers = {
      'content-type': 'application/json',
      authorization: 'Bearer token123',
      'x-api-key': 'api-key-123',
      cookie: 'session=abc123',
    }

    const result = redactHeaders(headers)

    expect(result['content-type']).toBe('application/json')
    expect(result['authorization']).toBe('[REDACTED]')
    expect(result['x-api-key']).toBe('[REDACTED]')
    expect(result['cookie']).toBe('[REDACTED]')
  })

  it('should use custom sensitive headers list', () => {
    const headers = {
      'x-custom-secret': 'secret123',
      authorization: 'Bearer token',
    }

    const result = redactHeaders(headers, ['x-custom-secret'])

    expect(result['x-custom-secret']).toBe('[REDACTED]')
    expect(result['authorization']).toBe('Bearer token')
  })
})

describe('redactQuery', () => {
  it('should redact sensitive query params', () => {
    const query = {
      search: 'hello',
      api_token: 'token123',
      secret_key: 'secret',
    }

    const result = redactQuery(query)

    expect(result.search).toBe('hello')
    expect(result.api_token).toBe('[REDACTED]')
    expect(result.secret_key).toBe('[REDACTED]')
  })

  it('should use custom sensitive params list', () => {
    const query = {
      id: '123',
      custom_secret: 'secret',
    }

    const result = redactQuery(query, ['custom_secret'])

    expect(result.id).toBe('123')
    expect(result.custom_secret).toBe('[REDACTED]')
  })
})

describe('redactEmail', () => {
  it('should hide email username', () => {
    const result = redactEmail('john.doe@example.com')
    expect(result).toBe('****@example.com')
  })

  it('should handle invalid email', () => {
    const result = redactEmail('not-an-email')
    expect(result).toContain('*')
  })

  it('should handle empty string', () => {
    const result = redactEmail('')
    expect(result).toBe('')
  })
})

describe('redactCreditCard', () => {
  it('should show only last 4 digits', () => {
    const result = redactCreditCard('4111111111111111')
    expect(result).toBe('**** **** **** 1111')
  })

  it('should handle formatted card numbers', () => {
    const result = redactCreditCard('4111-1111-1111-1111')
    expect(result).toBe('**** **** **** 1111')
  })

  it('should handle short numbers', () => {
    const result = redactCreditCard('123')
    expect(result).toContain('*')
  })
})

describe('redactPhone', () => {
  it('should show last 4 digits', () => {
    const result = redactPhone('555-123-4567')
    expect(result).toContain('4567')
    expect(result).toContain('*')
  })

  it('should handle various formats', () => {
    const result = redactPhone('+1 (555) 123-4567')
    expect(result).toContain('4567')
  })
})

describe('redactIP', () => {
  it('should show first two octets for IPv4', () => {
    const result = redactIP('192.168.1.100')
    expect(result).toBe('192.168.*.*')
  })

  it('should redact IPv6', () => {
    const result = redactIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
    expect(result).toBe('2001:****:****:****')
  })

  it('should handle invalid IP', () => {
    const result = redactIP('not-an-ip')
    expect(result).toContain('*')
  })
})
