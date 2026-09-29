import { describe, it, expect } from 'vitest';
const { validatePhoneNumber } = require('../utils/validation');

describe('Validation Utilities (back/utils/validation)', () => {
    describe('validatePhoneNumber', () => {
        it('debe retornar null para valores vacíos, nulos o indefinidos', () => {
            expect(validatePhoneNumber(null)).toBeNull();
            expect(validatePhoneNumber(undefined)).toBeNull();
            expect(validatePhoneNumber('')).toBeNull();
        });

        it('debe normalizar y retornar número en formato E.164 para teléfonos válidos', () => {
            // Venezuela
            expect(validatePhoneNumber('+58 412 1234567')).toBe('+584121234567');
            // USA
            expect(validatePhoneNumber('+1 (415) 555-2671')).toBe('+14155552671');
            // España
            expect(validatePhoneNumber('+34 612 34 56 78')).toBe('+34612345678');
        });

        it('debe retornar null para números de teléfono inválidos o incompletos', () => {
            expect(validatePhoneNumber('123')).toBeNull();
            expect(validatePhoneNumber('telefono-invalido')).toBeNull();
            expect(validatePhoneNumber('+0000000000')).toBeNull();
            expect(validatePhoneNumber('+1234')).toBeNull();
        });
    });
});
