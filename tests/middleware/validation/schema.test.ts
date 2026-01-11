import { describe, it, expect } from 'vitest'
import {
  validate,
  createValidator,
  allValid,
  mergeErrors,
} from '../../../src/middleware/validation'

describe('validate with custom schema', () => {
  describe('string validation', () => {
    it('validates required string', () => {
      const schema = { name: { type: 'string' as const, required: true } }

      expect(validate({ name: 'John' }, schema).success).toBe(true)
      expect(validate({ name: '' }, schema).success).toBe(false)
      expect(validate({}, schema).success).toBe(false)
    })

    it('validates minLength', () => {
      const schema = { password: { type: 'string' as const, minLength: 8 } }

      expect(validate({ password: '12345678' }, schema).success).toBe(true)
      expect(validate({ password: '1234567' }, schema).success).toBe(false)
    })

    it('validates maxLength', () => {
      const schema = { username: { type: 'string' as const, maxLength: 20 } }

      expect(validate({ username: 'short' }, schema).success).toBe(true)
      expect(validate({ username: 'a'.repeat(21) }, schema).success).toBe(false)
    })

    it('validates pattern', () => {
      const schema = { code: { type: 'string' as const, pattern: /^[A-Z]{3}$/ } }

      expect(validate({ code: 'ABC' }, schema).success).toBe(true)
      expect(validate({ code: 'abc' }, schema).success).toBe(false)
      expect(validate({ code: 'ABCD' }, schema).success).toBe(false)
    })
  })

  describe('number validation', () => {
    it('validates number type', () => {
      const schema = { age: { type: 'number' as const, required: true } }

      expect(validate({ age: 25 }, schema).success).toBe(true)
      expect(validate({ age: '25' }, schema).success).toBe(true)
      expect(validate({ age: 'abc' }, schema).success).toBe(false)
    })

    it('validates min value', () => {
      const schema = { age: { type: 'number' as const, min: 0 } }

      expect(validate({ age: 0 }, schema).success).toBe(true)
      expect(validate({ age: -1 }, schema).success).toBe(false)
    })

    it('validates max value', () => {
      const schema = { age: { type: 'number' as const, max: 150 } }

      expect(validate({ age: 100 }, schema).success).toBe(true)
      expect(validate({ age: 200 }, schema).success).toBe(false)
    })

    it('validates integer', () => {
      const schema = { count: { type: 'number' as const, integer: true } }

      expect(validate({ count: 10 }, schema).success).toBe(true)
      expect(validate({ count: 10.5 }, schema).success).toBe(false)
    })
  })

  describe('email validation', () => {
    const schema = { email: { type: 'email' as const, required: true } }

    it('validates valid emails', () => {
      expect(validate({ email: 'test@example.com' }, schema).success).toBe(true)
      expect(validate({ email: 'user.name@domain.co' }, schema).success).toBe(true)
    })

    it('rejects invalid emails', () => {
      expect(validate({ email: 'invalid' }, schema).success).toBe(false)
      expect(validate({ email: 'test@' }, schema).success).toBe(false)
      expect(validate({ email: '@example.com' }, schema).success).toBe(false)
    })
  })

  describe('url validation', () => {
    const schema = { website: { type: 'url' as const } }

    it('validates valid URLs', () => {
      expect(validate({ website: 'https://example.com' }, schema).success).toBe(true)
      expect(validate({ website: 'http://localhost:3000' }, schema).success).toBe(true)
    })

    it('rejects invalid URLs', () => {
      expect(validate({ website: 'not-a-url' }, schema).success).toBe(false)
      expect(validate({ website: 'ftp://server' }, schema).success).toBe(false)
    })
  })

  describe('uuid validation', () => {
    const schema = { id: { type: 'uuid' as const } }

    it('validates valid UUIDs', () => {
      expect(validate({ id: '550e8400-e29b-41d4-a716-446655440000' }, schema).success).toBe(true)
    })

    it('rejects invalid UUIDs', () => {
      expect(validate({ id: 'not-a-uuid' }, schema).success).toBe(false)
      expect(validate({ id: '12345678' }, schema).success).toBe(false)
    })
  })

  describe('date validation', () => {
    const schema = { date: { type: 'date' as const } }

    it('validates ISO date strings', () => {
      expect(validate({ date: '2024-01-15' }, schema).success).toBe(true)
      expect(validate({ date: '2024-01-15T10:30:00Z' }, schema).success).toBe(true)
    })

    it('rejects invalid dates', () => {
      expect(validate({ date: 'not-a-date' }, schema).success).toBe(false)
    })
  })

  describe('boolean validation', () => {
    const schema = { active: { type: 'boolean' as const } }

    it('validates boolean values', () => {
      expect(validate({ active: true }, schema).success).toBe(true)
      expect(validate({ active: false }, schema).success).toBe(true)
      expect(validate({ active: 'true' }, schema).success).toBe(true)
      expect(validate({ active: 'false' }, schema).success).toBe(true)
    })

    it('rejects non-boolean values', () => {
      expect(validate({ active: 'yes' }, schema).success).toBe(false)
      expect(validate({ active: 1 }, schema).success).toBe(false)
    })
  })

  describe('array validation', () => {
    it('validates array type', () => {
      const schema = { tags: { type: 'array' as const } }

      expect(validate({ tags: ['a', 'b'] }, schema).success).toBe(true)
      expect(validate({ tags: 'not-array' }, schema).success).toBe(false)
    })

    it('validates minItems', () => {
      const schema = { tags: { type: 'array' as const, minItems: 1 } }

      expect(validate({ tags: ['a'] }, schema).success).toBe(true)
      expect(validate({ tags: [] }, schema).success).toBe(false)
    })

    it('validates maxItems', () => {
      const schema = { tags: { type: 'array' as const, maxItems: 3 } }

      expect(validate({ tags: ['a', 'b'] }, schema).success).toBe(true)
      expect(validate({ tags: ['a', 'b', 'c', 'd'] }, schema).success).toBe(false)
    })

    it('validates array items', () => {
      const schema = {
        tags: {
          type: 'array' as const,
          items: { type: 'string' as const, minLength: 2 },
        },
      }

      expect(validate({ tags: ['abc', 'def'] }, schema).success).toBe(true)
      expect(validate({ tags: ['a'] }, schema).success).toBe(false)
    })
  })

  describe('object validation', () => {
    const schema = { data: { type: 'object' as const } }
    const requiredSchema = { data: { type: 'object' as const, required: true } }

    it('validates object type', () => {
      expect(validate({ data: {} }, schema).success).toBe(true)
      expect(validate({ data: { key: 'value' } }, schema).success).toBe(true)
    })

    it('rejects non-objects', () => {
      expect(validate({ data: 'string' }, schema).success).toBe(false)
      expect(validate({ data: ['array'] }, schema).success).toBe(false)
    })

    it('allows null for optional object field', () => {
      // Without required: true, null is treated as "no value"
      expect(validate({ data: null }, schema).success).toBe(true)
    })

    it('rejects null for required object field', () => {
      expect(validate({ data: null }, requiredSchema).success).toBe(false)
    })
  })

  describe('custom validation', () => {
    it('uses custom validator function', () => {
      const schema = {
        age: {
          type: 'number' as const,
          custom: (v: unknown) => (v as number) >= 18 || 'Must be 18 or older',
        },
      }

      expect(validate({ age: 20 }, schema).success).toBe(true)
      expect(validate({ age: 16 }, schema).success).toBe(false)
    })

    it('uses custom error message', () => {
      const schema = {
        age: {
          type: 'number' as const,
          custom: (v: unknown) => (v as number) >= 18 || 'Too young',
        },
      }

      const result = validate({ age: 16 }, schema)
      expect(result.success).toBe(false)
      expect(result.errors?.[0].message).toBe('Too young')
    })
  })

  describe('error messages', () => {
    it('uses custom message', () => {
      const schema = {
        name: { type: 'string' as const, required: true, message: 'Name is required' },
      }

      const result = validate({}, schema)
      expect(result.errors?.[0].message).toBe('Name is required')
    })

    it('provides field name in error', () => {
      const schema = { username: { type: 'string' as const, required: true } }

      const result = validate({}, schema)
      expect(result.errors?.[0].field).toBe('username')
    })

    it('provides error code', () => {
      const schema = { email: { type: 'email' as const, required: true } }

      expect(validate({}, schema).errors?.[0].code).toBe('required')
      expect(validate({ email: 'invalid' }, schema).errors?.[0].code).toBe('invalid_email')
    })
  })
})

describe('createValidator', () => {
  it('creates a reusable validator', () => {
    const schema = { name: { type: 'string' as const, required: true } }
    const validator = createValidator(schema)

    expect(validator({ name: 'John' }).success).toBe(true)
    expect(validator({}).success).toBe(false)
  })
})

describe('allValid', () => {
  it('returns true when all results are valid', () => {
    expect(allValid({ success: true }, { success: true })).toBe(true)
  })

  it('returns false when any result is invalid', () => {
    expect(allValid({ success: true }, { success: false })).toBe(false)
  })
})

describe('mergeErrors', () => {
  it('merges errors from multiple results', () => {
    const result1 = { success: false, errors: [{ field: 'a', code: 'e1', message: 'm1' }] }
    const result2 = { success: false, errors: [{ field: 'b', code: 'e2', message: 'm2' }] }

    const errors = mergeErrors(result1, result2)
    expect(errors.length).toBe(2)
    expect(errors[0].field).toBe('a')
    expect(errors[1].field).toBe('b')
  })

  it('handles results without errors', () => {
    const result1 = { success: true }
    const result2 = { success: false, errors: [{ field: 'a', code: 'e1', message: 'm1' }] }

    const errors = mergeErrors(result1, result2)
    expect(errors.length).toBe(1)
  })
})
